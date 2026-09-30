package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.sitemap.SiteMapFilter
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.logging.AgentActionLog
import net.portswigger.mcp.schema.encodeHistoryItem
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.DataAccessType

/**
 * Reconnaissance tools that read Burp's target site map and scope, so an MCP client can map a
 * target's attack surface without paging through the entire proxy HTTP history.
 *
 * All of these are read-only over data Burp already holds, except set_scope_rule which is gated on
 * the "Enable tools that can edit your config" option, mirroring how the official server gates config edits.
 */
internal fun Server.registerReconTools(api: MontoyaApi, config: McpConfig) {

    mcpPaginatedTool<GetSiteMap>(
        "Lists endpoints from Burp's target site map, optionally filtered by URL prefix. Compact mode (default) " +
        "returns one deduplicated line per endpoint: 'METHOD path -> statusCodes | params: type:name,... | mimeType', " +
        "which maps a target's attack surface without dumping full HTTP history. Set detail=true to instead return " +
        "the full request/response for each matching entry (paginated and truncated). Use urlPrefix to narrow to a " +
        "host or path, e.g. https://example.com/api/. By default ALL site map entries are returned; set " +
        "inScopeOnly=true to keep only entries within Burp's target scope (note: an empty scope matches nothing)."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.SITE_MAP, config, api, "site map")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Site map access denied by Burp Suite")
        }

        val prefix = urlPrefix
        val entries = if (prefix.isNullOrBlank()) {
            api.siteMap().requestResponses()
        } else {
            api.siteMap().requestResponses(SiteMapFilter.prefixFilter(prefix))
        }

        // Scope filtering is opt-in: an empty Target scope makes isInScope() false for everything, which
        // would otherwise silently drop every entry. Default is to return all entries.
        val requestedInScope = inScopeOnly == true
        val scoped = if (requestedInScope) {
            entries.filter { safeCall { it.request()?.isInScope() } == true }
        } else {
            entries
        }

        if (entries.isEmpty()) {
            return@mcpPaginatedTool sequenceOf(
                "Site map is empty for this filter" + (prefix?.let { " (prefix: $it)" } ?: "") +
                ". Browse or crawl the target first so it appears in Target > Site map."
            )
        }

        if (requestedInScope && scoped.isEmpty()) {
            return@mcpPaginatedTool sequenceOf(
                "None of the ${entries.size} matching site map entrie(s) are in scope. Your Target scope may be " +
                "empty or may exclude these hosts. Re-run with inScopeOnly=false, or add the host in Target > Scope."
            )
        }

        if (detail == true) {
            scoped.asSequence().map { encodeHistoryItem(it.toSerializableForm()) }
        } else {
            summarizeEndpoints(scoped)
        }
    }

    mcpTool<IsInScope>("Checks whether a URL is within Burp's current target scope (Target > Scope).") {
        val inScope = api.scope().isInScope(url)
        "URL: $url\nIn scope: $inScope"
    }

    mcpTool(
        "get_scope",
        "Returns Burp's current target scope (include/exclude rules) from Target > Scope, so you can see what is " +
        "in scope before sending traffic. Read-only."
    ) {
        try {
            val json = api.burpSuite().exportProjectOptionsAsJson()
            val scope = Json.parseToJsonElement(json).jsonObject["target"]?.jsonObject?.get("scope")
            scope?.toString() ?: "No scope configured in this project"
        } catch (e: Exception) {
            "Could not read scope: ${e.message}"
        }
    }

    mcpTool<SetScopeRule>(
        "Adds or removes a URL prefix from Burp's target scope. exclude=true removes it, otherwise it is added. " +
        "Requires 'Enable tools that can edit your config' in the MCP tab; disabled by default so an agent cannot " +
        "widen its own scope without your consent."
    ) {
        if (!config.configEditingTooling) {
            return@mcpTool "Config-editing tools are disabled. Enable them in the MCP tab to modify scope."
        }

        val excluding = exclude == true
        if (excluding) {
            api.scope().excludeFromScope(url)
        } else {
            api.scope().includeInScope(url)
        }

        val action = if (excluding) "exclude_from_scope" else "include_in_scope"
        api.logging().logToOutput("MCP set_scope_rule $action $url")
        AgentActionLog.record(
            api = api,
            config = config,
            tool = "set_scope_rule",
            action = action,
            allowed = true,
            reason = "config editing enabled",
            target = url,
            url = url
        )

        "Scope updated: ${if (excluding) "excluded" else "included"} $url"
    }
}

private class EndpointAgg {
    val statuses = sortedSetOf<Int>()
    val params = sortedSetOf<String>()
    val mimeTypes = linkedSetOf<String>()
}

/**
 * Collapses a list of site map request/responses into one line per (method, path), aggregating the status
 * codes seen, the parameter names (as type:name) and the response MIME types. Bodies are never included.
 */
private fun summarizeEndpoints(entries: List<HttpRequestResponse>): Sequence<String> {
    val byEndpoint = LinkedHashMap<Pair<String, String>, EndpointAgg>()

    for (rr in entries) {
        val request = rr.request() ?: continue
        val method = safeCall { request.method() } ?: "?"
        val path = safeCall { request.pathWithoutQuery() } ?: safeCall { request.path() } ?: "/"

        val agg = byEndpoint.getOrPut(method to path) { EndpointAgg() }

        safeCall { request.parameters() }?.forEach { p ->
            val name = safeCall { "${p.type()}:${p.name()}" }
            if (name != null) agg.params.add(name)
        }

        val response = rr.response()
        if (response != null) {
            safeCall { response.statusCode().toInt() }?.let { agg.statuses.add(it) }
            safeCall { response.mimeType()?.name }?.let { if (it != "NONE") agg.mimeTypes.add(it) }
        }
    }

    if (byEndpoint.isEmpty()) return sequenceOf("No matching site map entries")

    return byEndpoint.entries.asSequence().map { (endpoint, agg) ->
        buildString {
            append(endpoint.first).append(' ').append(endpoint.second)
            if (agg.statuses.isNotEmpty()) append(" -> ").append(agg.statuses.joinToString(","))
            if (agg.params.isNotEmpty()) append(" | params: ").append(agg.params.joinToString(","))
            if (agg.mimeTypes.isNotEmpty()) append(" | ").append(agg.mimeTypes.joinToString(","))
        }
    }
}

private inline fun <T> safeCall(block: () -> T): T? = try {
    block()
} catch (_: Exception) {
    null
}

@Serializable
data class GetSiteMap(
    val urlPrefix: String? = null,
    val inScopeOnly: Boolean? = null,
    val detail: Boolean? = null,
    override val count: Int,
    override val offset: Int
) : Paginated

@Serializable
data class IsInScope(val url: String)

@Serializable
data class SetScopeRule(val url: String, val exclude: Boolean? = null)
