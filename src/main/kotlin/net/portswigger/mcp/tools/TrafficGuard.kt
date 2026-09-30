package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.logging.AgentActionLog
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.RequestDecision

/**
 * Single entry point for every MCP tool that makes Burp generate traffic.
 *
 * Runs the scope + host approval checks for [request] and writes the decision to the agent action log.
 * Callers must only send (or scan) when the returned decision is allowed.
 */
internal fun authorizeTraffic(
    api: MontoyaApi,
    config: McpConfig,
    tool: String,
    host: String,
    port: Int,
    request: HttpRequest,
    displayContent: String = request.toString(),
    action: String = "send_request"
): RequestDecision {
    val url = safeUrl(request)

    val decision = runBlocking {
        HttpRequestSecurity.evaluateHttpRequest(host, port, config, displayContent, api, url)
    }

    api.logging().logToOutput("MCP $tool $host:$port -> ${decision.reason}")

    AgentActionLog.record(
        api = api,
        config = config,
        tool = tool,
        action = action,
        allowed = decision.allowed,
        reason = decision.reason,
        target = "$host:$port",
        url = url,
        method = safeMethod(request),
        rawRequest = request.toString()
    )

    return decision
}

/**
 * Same as [authorizeTraffic] for tools that only know a seed URL (e.g. crawls).
 */
internal fun authorizeUrl(
    api: MontoyaApi,
    config: McpConfig,
    tool: String,
    url: String,
    action: String
): RequestDecision {
    val parsed = try {
        java.net.URI(url).toURL()
    } catch (e: Exception) {
        return RequestDecision(false, "Denied: invalid URL '$url'")
    }

    val host = parsed.host ?: return RequestDecision(false, "Denied: URL has no host '$url'")
    val port = if (parsed.port != -1) parsed.port else parsed.defaultPort

    val decision = runBlocking {
        HttpRequestSecurity.evaluateHttpRequest(host, port, config, "$action: $url", api, url)
    }

    api.logging().logToOutput("MCP $tool $url -> ${decision.reason}")

    AgentActionLog.record(
        api = api,
        config = config,
        tool = tool,
        action = action,
        allowed = decision.allowed,
        reason = decision.reason,
        target = "$host:$port",
        url = url
    )

    return decision
}

/** Convenience overload for requests whose service comes from Burp itself (history, site map). */
internal fun authorizeTraffic(
    api: MontoyaApi,
    config: McpConfig,
    tool: String,
    request: HttpRequest,
    action: String = "send_request"
): RequestDecision {
    val service = request.httpService()
    return authorizeTraffic(api, config, tool, service.host(), service.port(), request, request.toString(), action)
}

internal fun safeUrl(request: HttpRequest): String? = try {
    request.url()
} catch (_: Exception) {
    null
}

internal fun safeMethod(request: HttpRequest): String? = try {
    request.method()
} catch (_: Exception) {
    null
}
