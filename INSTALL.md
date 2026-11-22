# Install

Placeholders used throughout: `<profile>` is your DSH profile directory,
`<node.exe>` is the DSH runtime node (the value of `$env:DSH_NODE_EXECUTABLE`), and
`<repo>` is this checkout.

Two routes. Both need one approval, because both write outside this workspace (into the
DSH profile at `%USERPROFILE%\.dsh\profiles\<profile>`).

## Route A — as a bundle (recommended, removable from the Plugins UI)

The bundle lives in this repo at [`dsh-bundle/`](dsh-bundle/). Add it to the profile's
bundle list, then let the plugin manager install it:

1. Add `"@local/fleet-geo-mcp": "file:C:/DEV/fleet-geo-mcp/dsh-bundle"` to
   `dsh.profile.bundles` in `%USERPROFILE%\.dsh\profiles\<profile>\package.json`.
2. Run `pnpm install` in that profile directory using DSH's bundled pnpm.
3. Install/enable the bundle (`plugin_manager` `install_bundle`, or the Plugins UI).

## Route B — direct patch row (fastest, one file)

Append this to `%USERPROFILE%\.dsh\profiles\<profile>\cordis.patch.yml`:

```yaml
# fleet-geo: passive provider geolocation MCP
- insert:
    - id: fleet-geo-mcp
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: fleetgeo
        transport: stdio
        command: '<absolute path to node.exe>'
        args:
          - 'C:/DEV/fleet-geo-mcp/server.mjs'
        cwd: 'C:/DEV/fleet-geo-mcp'
        failOnStartupError: false
```

`failOnStartupError: false` means a broken server degrades to "no MCP tools" instead of
taking the profile down. The backup of the pre-change file is
`cordis.patch.yml.bak-fleetgeo`.

## Optional: build the Rust N-API native core

`fleet-geo-mcp` works out of the box with pure Node.js (zero `node_modules`). If Rust (`cargo`) is
installed, you can optionally build the Encore-style native core for sub-millisecond kernel socket
snapshots (no `ss`/`lsof`/`netstat`/PowerShell subprocesses) and a dual-stack LPM radix trie:

```powershell
cd <repo>
npm run build:native   # writes native/fleet-geo-native.<platform>-<arch>.node
```

The server auto-loads the `.node` binary when present and falls back to pure JS otherwise (or when
`FLEET_GEO_NATIVE=0` is set). `mcp__fleetgeo__explain_rules` reports `runtime.engine` (`rust-napi`
vs `js-fallback`).

## Verify

After the row mounts, the tools appear as `mcp__fleetgeo__*`:

- `mcp__fleetgeo__explain_rules` — cheap, proves the connection and active runtime (`rust-napi` / `js-fallback`).
- `mcp__fleetgeo__inspect_connections` with `{"locate": false}` — passive live RFC 1792 TCP/UDP socket MIB check.
- `mcp__fleetgeo__fleet_status` with `{"limit": 4}` — the real test.

Without DSH, prove the server standalone:

```powershell
cd <repo>
npm test                                                     # selftest (44) + tcpip + observe + native
node server.mjs --list-tools
node server.mjs --tool locate_model --args '{"lane":"W7"}'
node server.mjs --tool inspect_connections --args '{"locate":false}'
node test/stdio-check.mjs                                    # protocol surface
```

Regenerate the stdio fixture with shell redirection (not a piped child process):

```powershell
cmd /c "node server.mjs < test\fixtures\stdio-requests.jsonl > test\fixtures\stdio-responses.jsonl"
```

## Uninstall

Delete the `fleet-geo-mcp` insert block (or the bundle), or restore
`cordis.patch.yml.bak-fleetgeo`. Nothing else in the profile was touched.

## If it fails to start

- Node path missing? `DSH_NODE_EXECUTABLE`, or a system `node` on PATH, both work as
  `command`; the bundled runtime path is just the most stable.
- Blank tools and a clean stderr usually means the profile needs a restart, not a fix.
- The server writes nothing to stdout except JSON-RPC, so anything readable on stderr is
  a real diagnostic.
