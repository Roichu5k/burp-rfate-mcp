package net.portswigger.mcp.logging

import burp.api.montoya.MontoyaApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.time.LocalDate
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

/**
 * Append-only audit trail of what the MCP client did through Burp: traffic sent (or denied),
 * scans started, scope changes, annotations, BCheck imports.
 *
 * One JSON object per line, one file per day: ~/.burp-mcp/logs/agent-actions-YYYY-MM-DD.jsonl
 *
 * Request bodies and headers are never written: only the request line, its size and a SHA-256,
 * so the log can prove what was sent without duplicating client credentials into another file.
 *
 * Logging must never break a tool call, so every failure is reported to Burp's error log and swallowed.
 */
object AgentActionLog {

    private val json = Json { encodeDefaults = true }
    private val lock = Any()

    var logDirectory: Path = Paths.get(System.getProperty("user.home"), ".burp-mcp", "logs")

    @Serializable
    data class Entry(
        val timestamp: String,
        val project: String?,
        val tool: String,
        val action: String,
        val allowed: Boolean,
        val reason: String? = null,
        val target: String? = null,
        val url: String? = null,
        val method: String? = null,
        val requestLine: String? = null,
        val requestBytes: Int? = null,
        val requestSha256: String? = null,
        val details: String? = null
    )

    fun record(
        api: MontoyaApi,
        config: McpConfig,
        tool: String,
        action: String,
        allowed: Boolean,
        reason: String? = null,
        target: String? = null,
        url: String? = null,
        method: String? = null,
        rawRequest: String? = null,
        details: String? = null
    ) {
        if (!config.agentActionLogEnabled) return

        try {
            val entry = Entry(
                timestamp = ZonedDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME),
                project = projectName(api),
                tool = tool,
                action = action,
                allowed = allowed,
                reason = reason,
                target = target,
                url = url,
                method = method,
                requestLine = rawRequest?.lineSequence()?.firstOrNull()?.trim()?.take(2_000),
                requestBytes = rawRequest?.toByteArray(StandardCharsets.UTF_8)?.size,
                requestSha256 = rawRequest?.let { sha256(it) },
                details = details?.take(2_000)
            )
            write(json.encodeToString(Entry.serializer(), entry))
        } catch (e: Exception) {
            try {
                api.logging().logToError("MCP agent action log write failed: ${e.message}")
            } catch (_: Exception) {
            }
        }
    }

    fun currentLogFile(): Path = logDirectory.resolve("agent-actions-${LocalDate.now()}.jsonl")

    private fun write(line: String) {
        synchronized(lock) {
            Files.createDirectories(logDirectory)
            Files.writeString(
                currentLogFile(),
                line + "\n",
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND
            )
        }
    }

    private fun projectName(api: MontoyaApi): String? = try {
        api.project().name()
    } catch (_: Exception) {
        null
    }

    private fun sha256(value: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
}
