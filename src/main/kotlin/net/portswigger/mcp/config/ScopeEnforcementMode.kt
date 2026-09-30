package net.portswigger.mcp.config

/**
 * How the Burp target scope constrains traffic generated through MCP tools.
 *
 * Scope checks run before (and independently of) the per-host approval dialog, so
 * they also apply when "Require approval for HTTP requests" is switched off.
 */
enum class ScopeEnforcementMode(val displayName: String) {
    /** Original behaviour: only the per-host approval dialog applies. */
    OFF("Off (host approval only)"),

    /** Out-of-scope targets are always denied; in-scope targets still go through host approval. */
    BLOCK_OUT_OF_SCOPE("Block out-of-scope targets"),

    /** Out-of-scope targets are always denied; in-scope targets are sent without asking. */
    BLOCK_AND_AUTO_APPROVE_IN_SCOPE("Block out-of-scope, auto-approve in-scope");

    override fun toString(): String = displayName

    companion object {
        val DEFAULT = BLOCK_OUT_OF_SCOPE

        /** Unknown or corrupted stored values fall back to the safe default, never to OFF. */
        fun fromStored(value: String?): ScopeEnforcementMode =
            entries.firstOrNull { it.name == value } ?: DEFAULT
    }
}
