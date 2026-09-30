package net.portswigger.mcp.security

import burp.api.montoya.MontoyaApi
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.config.ScopeEnforcementMode
import javax.swing.SwingUtilities
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

interface UserApprovalHandler {
    suspend fun requestApproval(
        hostname: String, port: Int, config: McpConfig, requestContent: String? = null, api: MontoyaApi? = null
    ): Boolean
}

class SwingUserApprovalHandler : UserApprovalHandler {
    override suspend fun requestApproval(
        hostname: String, port: Int, config: McpConfig, requestContent: String?, api: MontoyaApi?
    ): Boolean {
        return suspendCoroutine { continuation ->
            SwingUtilities.invokeLater {
                val message = buildString {
                    appendLine("An MCP client is requesting to send an HTTP request to:")
                    appendLine()
                    appendLine("Target: $hostname:$port")
                    appendLine()
                }

                val options = arrayOf(
                    "Allow Once", "Always Allow Host", "Always Allow Host:Port", "Deny"
                )

                val burpFrame = findBurpFrame()

                val result = Dialogs.showOptionDialog(
                    burpFrame, message, options, requestContent, api
                )

                when (result) {
                    0 -> {
                        continuation.resume(true)
                    }

                    1 -> {
                        config.addAutoApproveTarget(hostname)
                        continuation.resume(true)
                    }

                    2 -> {
                        config.addAutoApproveTarget("$hostname:$port")
                        continuation.resume(true)
                    }

                    else -> {
                        continuation.resume(false)
                    }
                }
            }
        }
    }
}

object HttpRequestSecurity {

    var approvalHandler: UserApprovalHandler = SwingUserApprovalHandler()

    private fun isAutoApproved(hostname: String, port: Int, config: McpConfig): Boolean {
        val target = "$hostname:$port"
        val hostOnly = hostname
        val targets = config.getAutoApproveTargetsList()

        return targets.any { approved ->
            when {
                approved.equals(target, ignoreCase = true) -> true

                approved.equals(hostOnly, ignoreCase = true) -> true

                approved.startsWith("*.") -> {
                    val domain = approved.substring(2)
                    isValidWildcardMatch(hostname, domain)
                }

                else -> false
            }
        }
    }

    private fun isValidWildcardMatch(hostname: String, domain: String): Boolean {
        if (domain.isEmpty() || domain.contains("*")) return false

        if (hostname.length <= domain.length) return false

        val expectedSuffix = ".$domain"
        if (!hostname.endsWith(expectedSuffix, ignoreCase = true)) return false

        val subdomain = hostname.substring(0, hostname.length - expectedSuffix.length)

        if (subdomain.isEmpty()) return false

        return subdomain.split(".").all { label ->
            label.isNotEmpty() && label.length <= 63 && !label.startsWith("-") && !label.endsWith("-") && label.matches(
                Regex("^[a-zA-Z0-9-]+$")
            )
        }
    }

    suspend fun checkHttpRequestPermission(
        hostname: String,
        port: Int,
        config: McpConfig,
        requestContent: String? = null,
        api: MontoyaApi? = null,
        url: String? = null
    ): Boolean = evaluateHttpRequest(hostname, port, config, requestContent, api, url).allowed

    /**
     * Decides whether MCP-generated traffic to [hostname]:[port] may be sent, and why.
     *
     * Order of checks:
     *  1. Burp target scope, according to [McpConfig.scopeEnforcementMode]. Out-of-scope targets are
     *     denied even when host approval is disabled or the host is on the auto-approve list.
     *  2. The original per-host approval (auto-approve list, then dialog).
     *
     * [url] should be the full request URL (scheme, host, port and path) so that path-based scope
     * rules are honoured. When it is missing, a root URL for the target is used.
     *
     * The scope check needs [api]. Production callers always pass it; it is only null in unit tests
     * that exercise the host-approval logic in isolation.
     */
    suspend fun evaluateHttpRequest(
        hostname: String,
        port: Int,
        config: McpConfig,
        requestContent: String? = null,
        api: MontoyaApi? = null,
        url: String? = null
    ): RequestDecision {
        val mode = config.scopeEnforcementMode

        if (mode != ScopeEnforcementMode.OFF && api != null) {
            val target = url ?: rootUrl(hostname, port)
            val inScope = try {
                api.scope().isInScope(target)
            } catch (e: Exception) {
                api.logging().logToError("MCP scope check failed for $target: ${e.message}")
                false
            }

            if (!inScope) {
                return RequestDecision(false, "Denied: $target is outside the Burp Suite target scope")
            }

            if (mode == ScopeEnforcementMode.BLOCK_AND_AUTO_APPROVE_IN_SCOPE) {
                return RequestDecision(true, "Allowed: target is in scope (auto-approved)")
            }
        }

        if (!config.requireHttpRequestApproval) {
            return RequestDecision(true, "Allowed: host approval is disabled")
        }

        if (isAutoApproved(hostname, port, config)) {
            return RequestDecision(true, "Allowed: host is on the auto-approve list")
        }

        val approved = approvalHandler.requestApproval(hostname, port, config, requestContent, api)
        return if (approved) {
            RequestDecision(true, "Allowed: approved by user")
        } else {
            RequestDecision(false, "Denied by user")
        }
    }

    private fun rootUrl(hostname: String, port: Int): String {
        val scheme = if (port == 443 || port == 8443) "https" else "http"
        return "$scheme://$hostname:$port/"
    }
}

data class RequestDecision(val allowed: Boolean, val reason: String)