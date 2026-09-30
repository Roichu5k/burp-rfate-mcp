# burp-rfate-mcp

Fork of [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server) (the official Burp Suite MCP
extension) with extra recon tooling and scope-based guardrails, for authorized web/API assessments.

Upstream `main` is tracked as the `upstream` remote so official updates can be merged in.

## What this fork adds on top of upstream

### Site map / recon tools
So an agent can map a target's attack surface without paging through the entire proxy HTTP history:

- **`get_site_map`** — lists endpoints from Burp's target site map. Compact mode (default) returns one
  deduplicated line per endpoint (`METHOD path -> statusCodes | params: type:name,... | mimeType`);
  `detail=true` returns full request/response per entry. Filters: `urlPrefix`, `inScopeOnly` (default **false** —
  returns all entries; set true to keep only in-scope, but note an empty Target scope matches nothing), plus
  `count`/`offset` paging. Gated behind the site-map data-access permission.
- **`is_in_scope`** — whether a URL is in the current Target scope.
- **`get_scope`** — the current include/exclude scope rules (read-only).
- **`set_scope_rule`** — add/remove a URL prefix from scope. Gated on *Enable tools that can edit your
  config*, so an agent can't widen its own scope without your consent.

### Scope enforcement guardrail
New **Target scope enforcement** selector in the MCP tab, applied to every request/scan started through MCP,
*before* the per-host approval dialog and independently of it:

- `Off (host approval only)` — original upstream behaviour.
- `Block out-of-scope targets` (**default**) — out-of-scope targets are always denied; in-scope still prompts.
- `Block out-of-scope, auto-approve in-scope` — out-of-scope denied, in-scope sent without prompting.

Unknown/corrupted stored values fall back to `Block out-of-scope`, never to `Off`.

### Agent action log
Optional (on by default): every MCP request, denial and scope change is appended to
`~/.burp-mcp/logs/agent-actions-YYYY-MM-DD.jsonl` — one JSON object per line with timestamp, project, tool,
target, decision and reason. Request **line**, byte size and SHA-256 only; never headers or bodies, so it
proves what was sent without duplicating client credentials. Toggle in the MCP tab.

### Upstream bug fix
`set_project_options` / `set_user_options` descriptions had their required top-level object names swapped
(`user_options` vs `project_options`); corrected here.

## Verifying the guardrail (manual)

1. Set *Target scope enforcement* = *Block out-of-scope targets* and add one host to Target > Scope.
2. Ask the MCP client for `send_http1_request` to an in-scope host → approval dialog appears.
3. Ask for one to an out-of-scope host → denied with `outside the Burp Suite target scope`, no dialog,
   even with *Require approval for HTTP requests* unchecked.
4. Check `~/.burp-mcp/logs/agent-actions-<date>.jsonl`: both attempts logged, one `allowed:true`, one
   `false`, neither carrying headers or bodies.

Load the built `build/libs/*.jar` in Burp (Extensions → Add). Unload the official Burp MCP extension first —
both use port 9876 and the "MCP" tab.

---

Upstream documentation follows.

# Burp Suite MCP Server Extension

## Overview

Integrate Burp Suite with AI Clients using the Model Context Protocol (MCP).

For more information about the protocol visit: [modelcontextprotocol.io](https://modelcontextprotocol.io/)

## Features

- Connect Burp Suite to AI clients through MCP
- Automatic installation for Claude Desktop
- Comes with packaged Stdio MCP proxy server

## Usage

- Install the extension in Burp Suite
- Configure your Burp MCP server in the extension settings
- Configure your MCP client to use the Burp SSE MCP server or stdio proxy
- Interact with Burp through your client!

## Installation

### Prerequisites

Ensure that the following prerequisites are met before building and installing the extension:

1. **Java**: Java must be installed and available in your system's PATH. You can verify this by running `java --version` in your terminal.
2. **jar Command**: The `jar` command must be executable and available in your system's PATH. You can verify this by running `jar --version` in your terminal. This is required for building and installing the extension.

### Building the Extension

1. **Clone the Repository**: Obtain the source code for the MCP Server Extension.
   ```
   git clone https://github.com/PortSwigger/mcp-server.git
   ```

2. **Navigate to the Project Directory**: Move into the project's root directory.
   ```
   cd mcp-server
   ```

3. **Build the JAR File**: Use Gradle to build the extension.
   ```
   ./gradlew embedProxyJar
   ```

   This command compiles the source code and packages it into a JAR file located in `build/libs/burp-mcp-all.jar`.

### Loading the Extension into Burp Suite

1. **Open Burp Suite**: Launch your Burp Suite application.
2. **Access the Extensions Tab**: Navigate to the `Extensions` tab.
3. **Add the Extension**:
    - Click on `Add`.
    - Set `Extension Type` to `Java`.
    - Click `Select file ...` and choose the JAR file built in the previous step.
    - Click `Next` to load the extension.

Upon successful loading, the MCP Server Extension will be active within Burp Suite.

## Configuration

### Configuring the Extension
Configuration for the extension is done through the Burp Suite UI in the `MCP` tab.
- **Toggle the MCP Server**: The `Enabled` checkbox controls whether the MCP server is active.
- **Enable config editing**: The `Enable tools that can edit your config` checkbox allows the MCP server to expose tools which can edit Burp configuration files.
- **Advanced options**: You can configure the port and host for the MCP server. By default, it listens on `http://127.0.0.1:9876`.

### Claude Desktop Client

To fully utilize the MCP Server Extension with Claude, you need to configure your Claude client settings appropriately.
The extension has an installer which will automatically configure the client settings for you.

1. Currently, Claude Desktop only support STDIO MCP Servers
   for the service it needs.
   This approach isn't ideal for desktop apps like Burp, so instead, Claude will start a proxy server that points to the
   Burp instance,  
   which hosts a web server at a known port (`localhost:9876`).

2. **Configure Claude to use the Burp MCP server**  
   You can do this in one of two ways:

    - **Option 1: Run the installer from the extension**
      This will add the Burp MCP server to the Claude Desktop config.

    - **Option 2: Manually edit the config file**  
      Open the file located at `~/Library/Application Support/Claude/claude_desktop_config.json`,
      and replace or update it with the following:
      ```json
      {
        "mcpServers": {
          "burp": {
            "command": "<path to Java executable packaged with Burp>",
            "args": [
                "-jar",
                "/path/to/mcp/proxy/jar/mcp-proxy-all.jar",
                "--sse-url",
                "<your Burp MCP server URL configured in the extension>"
            ]
          }
        }
      }
      ```

3. **Restart Claude Desktop** - assuming Burp is running with the extension loaded.

## Manual installations
If you want to install the MCP server manually you can either use the extension's SSE server directly or the packaged
Stdio proxy server.

### SSE MCP Server
To use the SSE server directly, provide the configured server URL to your MCP client:
```
http://127.0.0.1:9876
```

### Stdio MCP Proxy Server
The source code for the proxy server can be found here: [MCP Proxy Server](https://github.com/PortSwigger/mcp-proxy)

In order to support MCP Clients which only support Stdio MCP Servers, the extension comes packaged with a proxy server for
passing requests to the SSE MCP server extension.

If you want to use the Stdio proxy server you can use the extension's installer option to extract the proxy server jar.
Once you have the jar you can add the following command and args to your client configuration:
```
/path/to/packaged/burp/java -jar /path/to/proxy/jar/mcp-proxy-all.jar --sse-url http://127.0.0.1:9876
```

If you modify the proxy source, rebuild and copy it into this project before packaging the extension:
```bash
# From mcp-proxy
./gradlew shadowJar
cp build/libs/mcp-proxy-all.jar /path/to/mcp-server/libs/mcp-proxy-all.jar

# From mcp-server
./gradlew embedProxyJar
```

### Creating / modifying tools

Tools are defined in `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`. To define new tools, create a new serializable
data class with the required parameters which will come from the LLM.

The tool name is auto-derived from its parameters data class. A description is also needed for the LLM. You can return
a string or a `List<ContentBlock>` to provide data back to the LLM.

Extend the Paginated interface to add auto-pagination support.
