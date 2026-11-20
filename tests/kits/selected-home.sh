#!/bin/sh
set -eu

root=$(mktemp -d "${TMPDIR:-/tmp}/marsh-kit-home.XXXXXX")
probe_pid=
trap '[ -z "$probe_pid" ] || kill "$probe_pid" 2>/dev/null || :; rm -rf "$root"' EXIT HUP INT TERM
# The Claude entrypoint asks the stock proxy about a claude.ai login only when
# HTTPS_PROXY is set. Cases that test it name a local stand-in; no other case
# may reach a real proxy from the machine running this test.
unset HTTPS_PROXY HTTP_PROXY https_proxy http_proxy NODE_USE_ENV_PROXY
# Nor may a credential, endpoint or binding of the machine running this test.
unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN CLAUDE_CODE_OAUTH_TOKEN \
  ANTHROPIC_PROFILE ANTHROPIC_FEDERATION_RULE_ID ANTHROPIC_ORGANIZATION_ID \
  ANTHROPIC_BASE_URL CLAUDE_CONFIG_DIR CLAUDE_CODE_USE_BEDROCK \
  CLAUDE_CODE_USE_VERTEX CLAUDE_CODE_USE_FOUNDRY OPENAI_API_KEY \
  SBX_CRED_ANTHROPIC_MODE SBX_CRED_OPENAI_MODE MCP_GATEWAY_URL \
  MCP_SENTINEL_TOKEN_NAME MARSH_TEST_CLAUDE_OAUTH_PROBE
bin="$root/bin"
mkdir -p "$bin"

make_fake() {
  name=$1
  cat >"$bin/$name" <<'EOF'
#!/bin/sh
printf '%s\n' "$HOME" >"$MARSH_TEST_CAPTURE/home"
printf '%s\n' "$@" >"$MARSH_TEST_CAPTURE/args"
printf '%s\n' "${ANTHROPIC_API_KEY:-}" >"$MARSH_TEST_CAPTURE/anthropic-key"
printf '%s\n' "${CLAUDE_CODE_OAUTH_TOKEN:-}" >"$MARSH_TEST_CAPTURE/claude-oauth-token"
EOF
  chmod 755 "$bin/$name"
}

make_fake claude
make_fake codex
make_fake pi

# The Codex adapter execs its pinned /usr/local/bin/codex, never PATH. Test a
# copy whose pin names the fake; the adapter logic is otherwise byte-identical.
codex_entry="$root/codex-entrypoint.sh"
sed "s#/usr/local/bin/codex#$bin/codex#g" kits/marsh-codex/marsh-entrypoint.sh >"$codex_entry"
adapter() {
  if [ "$1" = codex ]; then printf "%s\n" "$codex_entry"; else printf "%s\n" "kits/marsh-$1/marsh-entrypoint.sh"; fi
}

run_kit() {
  kit=$1
  home="$root/$kit-home"
  capture="$root/$kit-capture"
  mkdir -p "$home" "$capture"
  status=0
  PATH="$bin:$PATH" \
    MARSH_TEST_CAPTURE="$capture" \
    MARSH_SELECTED_HOME="$home" \
    SBX_CRED_ANTHROPIC_MODE=apikey \
    SBX_CRED_OPENAI_MODE=oauth \
  sh "$(adapter "$kit")" --version || status=$?
  test "$status" -eq 0 || return "$status"
  test "$(cat "$capture/home")" = "$home"
  test "$(tail -n 1 "$capture/args")" = "--version"
}

run_kit claude
run_kit codex
run_kit pi

test -f "$root/claude-home/.claude/settings.json"
grep -q 'proxy-managed' "$root/claude-home/.claude/settings.json"
node -e '
  const config = require(process.argv[1]);
  if (config.projects?.[process.argv[2]]?.hasTrustDialogAccepted !== true) process.exit(1);
' "$root/claude-home/.claude.json" "$PWD"
test ! -e "$root/claude-home/.claude/.credentials.json"
test -f "$root/codex-home/.codex/config.toml"
grep -Fqx "[projects.\"$PWD\"]" "$root/codex-home/.codex/config.toml"
grep -Fqx 'trust_level = "trusted"' "$root/codex-home/.codex/config.toml"
test "$(cat "$root/codex-home/.codex/auth.json")" = \
  '{"OPENAI_API_KEY":"proxy-managed"}'
test -d "$root/pi-home/.pi"
test "$(head -n 1 "$root/pi-capture/args")" = --approve
test "$(cat "$root/pi-capture/anthropic-key")" = proxy-managed

# The stock Gateway registration belongs to the selected home, not the Kit
# lifecycle home. It is merged under the same lock as project trust. Repeated
# jobs refresh a stale stock endpoint without replacing other user settings.
MCP_GATEWAY_URL=http://mcp-gateway.docker.internal/mcp \
  MCP_SENTINEL_TOKEN_NAME=proxy-managed run_kit claude
MCP_GATEWAY_URL=http://mcp-gateway.docker.internal/mcp \
  MCP_SENTINEL_TOKEN_NAME=proxy-managed run_kit codex
node -e '
  const config = require(process.argv[1]);
  const gateway = config.mcpServers?.["mcp-gateway"];
  if (gateway?.type !== "http" || gateway.url !== process.argv[2] ||
      gateway.headers?.Authorization !== "Bearer proxy-managed") process.exit(1);
' "$root/claude-home/.claude.json" http://mcp-gateway.docker.internal/mcp
for file in "$root/codex-home/.codex/config.toml"; do
  grep -Fqx 'url = "http://mcp-gateway.docker.internal/mcp"' "$file"
  grep -Fqx '[mcp_servers.mcp-gateway.http_headers]' "$file"
  grep -Fqx 'Authorization = "Bearer proxy-managed"' "$file"
done
# The sentinel name is stock-provided, not fixed by the kit. A changed valid
# sentinel must refresh the previously generated entry on both clients.
MCP_GATEWAY_URL=http://mcp-gateway.docker.internal/mcp \
  MCP_SENTINEL_TOKEN_NAME=proxy-managed-2 run_kit claude
MCP_GATEWAY_URL=http://mcp-gateway.docker.internal/mcp \
  MCP_SENTINEL_TOKEN_NAME=proxy-managed-2 run_kit codex
node -e '
  const config = require(process.argv[1]);
  if (config.mcpServers?.["mcp-gateway"]?.headers?.Authorization !==
      "Bearer proxy-managed-2") process.exit(1);
' "$root/claude-home/.claude.json"
grep -Fqx 'Authorization = "Bearer proxy-managed-2"' \
  "$root/codex-home/.codex/config.toml"
MCP_GATEWAY_URL=http://mcp-gateway.docker.internal/mcp \
  MCP_SENTINEL_TOKEN_NAME=proxy-managed run_kit claude
MCP_GATEWAY_URL=http://mcp-gateway.docker.internal/mcp \
  MCP_SENTINEL_TOKEN_NAME=proxy-managed run_kit codex
node -e '
  const config = require(process.argv[1]);
  if (config.mcpServers?.["mcp-gateway"]?.headers?.Authorization !==
      "Bearer proxy-managed") process.exit(1);
' "$root/claude-home/.claude.json"
grep -Fqx 'Authorization = "Bearer proxy-managed"' \
  "$root/codex-home/.codex/config.toml"

# A same-destination stanza with an unrecognized shape may contain client-owned
# state. Fail closed and leave it byte-identical instead of launching with a
# stale or unauthenticated stock Gateway registration.
cp "$root/claude-home/.claude.json" "$root/claude-gateway.valid"
cp "$root/codex-home/.codex/config.toml" "$root/codex-gateway.valid"
node -e '
  const fs = require("fs");
  const file = process.argv[1];
  const config = require(file);
  config.mcpServers["mcp-gateway"].extra = true;
  fs.writeFileSync(file, JSON.stringify(config, null, 2) + "\n");
' "$root/claude-home/.claude.json"
sed -i.bak 's/\.http_headers]/.headers]/' "$root/codex-home/.codex/config.toml"
rm "$root/codex-home/.codex/config.toml.bak"
cp "$root/claude-home/.claude.json" "$root/claude-stale.before"
cp "$root/codex-home/.codex/config.toml" "$root/codex-stale.before"
if MCP_GATEWAY_URL=http://mcp-gateway.docker.internal/mcp \
  MCP_SENTINEL_TOKEN_NAME=proxy-managed run_kit claude; then
  echo 'stale Claude Gateway shape was accepted' >&2
  exit 1
fi
if MCP_GATEWAY_URL=http://mcp-gateway.docker.internal/mcp \
  MCP_SENTINEL_TOKEN_NAME=proxy-managed run_kit codex; then
  echo 'stale Codex Gateway shape was accepted' >&2
  exit 1
fi
cmp "$root/claude-stale.before" "$root/claude-home/.claude.json"
cmp "$root/codex-stale.before" "$root/codex-home/.codex/config.toml"
cp "$root/claude-gateway.valid" "$root/claude-home/.claude.json"
cp "$root/codex-gateway.valid" "$root/codex-home/.codex/config.toml"

# A manually configured server of the same name at another URL is user state,
# not a stock Gateway stanza to overwrite.
node -e '
  const fs = require("fs");
  const file = process.argv[1];
  const config = require(file);
  config.mcpServers["mcp-gateway"] = {type: "http", url: "https://mine.example/mcp",
    headers: {Authorization: "Bearer my-private-value"}};
  fs.writeFileSync(file, JSON.stringify(config, null, 2) + "\n");
' "$root/claude-home/.claude.json"
cp "$root/claude-home/.claude.json" "$root/claude-user-mcp.before"
node -e '
  const fs = require("fs");
  const file = process.argv[1];
  const config = fs.readFileSync(file, "utf8");
  fs.writeFileSync(file, config.replace("http://mcp-gateway.docker.internal/mcp",
    "https://mine.example/mcp"));
' "$root/codex-home/.codex/config.toml"
cp "$root/codex-home/.codex/config.toml" "$root/codex-user-mcp.before"
MCP_GATEWAY_URL=http://mcp-gateway.docker.internal/mcp \
  MCP_SENTINEL_TOKEN_NAME=proxy-managed run_kit claude
MCP_GATEWAY_URL=http://mcp-gateway.docker.internal/mcp \
  MCP_SENTINEL_TOKEN_NAME=proxy-managed run_kit codex
cmp "$root/claude-user-mcp.before" "$root/claude-home/.claude.json"
cmp "$root/codex-user-mcp.before" "$root/codex-home/.codex/config.toml"

# A dangling user-owned settings symlink is rejected without creating or
# overwriting its target outside the selected Claude directory.
claude_symlink_home="$root/claude-symlink-home"
claude_symlink_capture="$root/claude-symlink-capture"
claude_settings_target="$root/claude-settings-target"
mkdir -p "$claude_symlink_home/.claude" "$claude_symlink_capture"
ln -s "$claude_settings_target" "$claude_symlink_home/.claude/settings.json"
if PATH="$bin:$PATH" \
  MARSH_TEST_CAPTURE="$claude_symlink_capture" \
  MARSH_SELECTED_HOME="$claude_symlink_home" \
  SBX_CRED_ANTHROPIC_MODE=apikey \
  sh kits/marsh-claude/marsh-entrypoint.sh --version \
  >"$root/claude-symlink.out" 2>"$root/claude-symlink.err"; then
  echo 'Claude settings symlink unexpectedly accepted' >&2
  exit 1
fi
test -L "$claude_symlink_home/.claude/settings.json"
test ! -e "$claude_settings_target"
grep -Fq 'must be a regular file; preserved unchanged' "$root/claude-symlink.err"

# Existing valid settings retain unrelated fields and explicit user choices,
# while a resolved SBX credential installs the exact proxy helper needed by
# Claude Code.
cat >"$root/claude-home/.claude/settings.json" <<'EOF'
{
  "userValue": "preserved",
  "themeId": 7,
  "permissions": { "defaultMode": "plan", "extra": true },
  "skipDangerousModePermissionPrompt": false
}
EOF
printf '%s\n' '{"userValue":"preserved"}' >"$root/claude-home/.claude.json"
printf '%s\n' 'user_value = "preserved"' >"$root/codex-home/.codex/config.toml"
printf '%s\n' user-auth >"$root/codex-home/.codex/auth.json"
run_kit claude
run_kit codex
node -e '
  const settings = require(process.argv[1]);
  if (settings.userValue !== "preserved" || settings.themeId !== 7 ||
      settings.permissions?.defaultMode !== "plan" ||
      settings.permissions?.extra !== true ||
      settings.skipDangerousModePermissionPrompt !== false ||
      settings.apiKeyHelper !== "echo proxy-managed") process.exit(1);
' "$root/claude-home/.claude/settings.json"
node -e '
  const config = require(process.argv[1]);
  if (config.userValue !== "preserved" ||
      config.projects?.[process.argv[2]]?.hasTrustDialogAccepted !== true) process.exit(1);
' "$root/claude-home/.claude.json" "$PWD"
test "$(head -n 1 "$root/codex-home/.codex/config.toml")" = 'user_value = "preserved"'
test "$(grep -Fxc "[projects.\"$PWD\"]" "$root/codex-home/.codex/config.toml")" = 1
test "$(cat "$root/codex-home/.codex/auth.json")" = user-auth

# Credential mode none must not synthesize apiKeyHelper. Other defaults still
# make a fresh selected home noninteractive.
claude_none_home="$root/claude-none-home"
claude_none_capture="$root/claude-none-capture"
mkdir -p "$claude_none_home" "$claude_none_capture"
PATH="$bin:$PATH" \
  MARSH_TEST_CAPTURE="$claude_none_capture" \
  MARSH_SELECTED_HOME="$claude_none_home" \
  SBX_CRED_ANTHROPIC_MODE=none \
  sh kits/marsh-claude/marsh-entrypoint.sh --version
node -e '
  const settings = require(process.argv[1]);
  if (Object.hasOwn(settings, "apiKeyHelper") ||
      settings.permissions?.defaultMode !== "bypassPermissions") process.exit(1);
' "$claude_none_home/.claude/settings.json"

# Docker Sandboxes reports a claude.ai login as mode none. The entrypoint then
# asks the proxy, here a stand-in that answers 200 only for the access-token
# sentinel, and passes the placeholder as CLAUDE_CODE_OAUTH_TOKEN. Nothing is
# written to the selected home: no helper and no credentials file. The
# stand-in logs every request with the case that made it, so a case can show
# that the proxy was not asked.
probe_log="$root/probe.log"
: >"$probe_log"
# shellcheck disable=SC2016 # JavaScript, not shell
node -e '
  const fs = require("node:fs");
  const [portFile, log] = process.argv.slice(1);
  let busy = 0, slow = 0;
  const server = require("node:http").createServer((request, response) => {
    fs.appendFileSync(log, `${request.method} ${request.url}\n`);
    const held = request.headers.authorization === "Bearer sk-ant-oat01-proxy-managed";
    switch (new URL(request.url, "http://stand-in").pathname) {
      case "/held": response.writeHead(held ? 200 : 401).end(); break;
      case "/redirect": response.writeHead(302, {location: "/held"}).end(); break;
      case "/busy": response.writeHead(503).end(); break;
      case "/busy-once": response.writeHead(!held ? 401 : busy++ ? 200 : 429).end(); break;
      // Never answers; the connection closes long after the probe gives up.
      case "/hang": setTimeout(() => request.socket.destroy(), 8000); break;
      // Busy, slowly, then never answers: the retry stays within the bound.
      case "/slow-busy":
        if (slow++) setTimeout(() => request.socket.destroy(), 8000);
        else setTimeout(() => response.writeHead(503).end(), 2000);
        break;
      default: response.writeHead(401).end();
    }
  });
  // As the HTTPS proxy, record where the probe asks to go and refuse it.
  server.on("connect", (request, socket) => {
    fs.appendFileSync(log, `CONNECT ${request.url}\n`);
    socket.end("HTTP/1.1 403 Forbidden\r\n\r\n");
  });
  server.listen(0, "127.0.0.1", () =>
    fs.writeFileSync(portFile, String(server.address().port)));
' "$root/probe-port.tmp" "$probe_log" &
probe_pid=$!
probe_wait=0
until [ -s "$root/probe-port.tmp" ]; do
  probe_wait=$((probe_wait + 1))
  test "$probe_wait" -lt 100
  sleep 0.05
done
probe="http://127.0.0.1:$(cat "$root/probe-port.tmp")"
claude_entry="$PWD/kits/marsh-claude/marsh-entrypoint.sh"
# Each case starts from an empty environment, so a credential of the machine
# running this test never reaches it, and runs in a project of its own.
run_claude_probe() {
  name=$1; path=$2; shift 2
  mkdir -p "$root/$name-home" "$root/$name-capture" "$root/$name-project"
  (
    cd "$root/$name-project"
    env -i PATH="$bin:$PATH" TMPDIR="${TMPDIR:-/tmp}" \
      MARSH_TEST_CAPTURE="$root/$name-capture" \
      MARSH_SELECTED_HOME="$root/$name-home" \
      SBX_CRED_ANTHROPIC_MODE=none \
      HTTPS_PROXY=http://127.0.0.1:9 \
      MARSH_TEST_CLAUDE_OAUTH_PROBE="$probe$path?case=$name" \
      "$@" sh "$claude_entry" --version 2>"$root/$name.err"
  )
}
asked() {
  grep -c "?case=$1\$" "$probe_log" || :
}
oauth_token() {
  cat "$root/$1-capture/claude-oauth-token"
}
run_claude_probe claude-oauth /held
test "$(oauth_token claude-oauth)" = sk-ant-oat01-proxy-managed
test -z "$(cat "$root/claude-oauth-capture/anthropic-key")"
test ! -e "$root/claude-oauth-home/.claude/.credentials.json"
node -e '
  if (Object.hasOwn(require(process.argv[1]), "apiKeyHelper")) process.exit(1);
' "$root/claude-oauth-home/.claude/settings.json"
test ! -s "$root/claude-oauth.err"

# A proxy that holds no login leaves the job signed out, so /login still works.
# Only a direct 200 counts: a redirect that ends in one does not.
run_claude_probe claude-unbound /none
test -z "$(oauth_token claude-unbound)"
test ! -s "$root/claude-unbound.err"
run_claude_probe claude-redirect /redirect
test -z "$(oauth_token claude-redirect)"
test "$(asked claude-redirect)" = 1

# A busy proxy is asked once more. If it is still busy, the job starts signed
# out and says why; a proxy that never answers releases the launch within the
# bound.
run_claude_probe claude-busy-once /busy-once
test "$(oauth_token claude-busy-once)" = sk-ant-oat01-proxy-managed
test "$(asked claude-busy-once)" = 2
run_claude_probe claude-busy /busy
test -z "$(oauth_token claude-busy)"
test "$(asked claude-busy)" = 2
grep -Fq 'could not confirm' "$root/claude-busy.err"
for stall in hang slow-busy; do
  probe_start=$(date +%s)
  run_claude_probe "claude-$stall" "/$stall"
  test $(($(date +%s) - probe_start)) -le 4
  test -z "$(oauth_token "claude-$stall")"
  grep -Fq 'could not confirm' "$root/claude-$stall.err"
done
test "$(asked claude-slow-busy)" = 2

# The probe goes to the Anthropic API through the proxy and nowhere else. This
# needs a Node that honours NODE_USE_ENV_PROXY, as the Kit image's does; check
# with a name that cannot resolve, so an older Node reaches nothing.
env -i PATH="$PATH" HTTP_PROXY="$probe" NODE_USE_ENV_PROXY=1 node -e '
  fetch("http://marsh-proxy-check.invalid/").catch(() => {});
' 2>/dev/null || :
if grep -Fqx 'GET http://marsh-proxy-check.invalid/' "$probe_log"; then
  mkdir -p "$root/claude-route-home" "$root/claude-route-capture"
  env -i PATH="$bin:$PATH" TMPDIR="${TMPDIR:-/tmp}" \
    MARSH_TEST_CAPTURE="$root/claude-route-capture" \
    MARSH_SELECTED_HOME="$root/claude-route-home" \
    SBX_CRED_ANTHROPIC_MODE=none HTTPS_PROXY="$probe" NODE_USE_ENV_PROXY=1 \
    sh "$claude_entry" --version 2>/dev/null
  test "$(grep '^CONNECT ' "$probe_log")" = 'CONNECT api.anthropic.com:443'
  test -z "$(oauth_token claude-route)"
else
  echo "selected-home: skipped the probe route case: this Node ignores NODE_USE_ENV_PROXY" >&2
fi

# Without the stock proxy there is nothing to ask.
mkdir -p "$root/claude-noproxy-home" "$root/claude-noproxy-capture"
env -i PATH="$bin:$PATH" TMPDIR="${TMPDIR:-/tmp}" \
  MARSH_TEST_CAPTURE="$root/claude-noproxy-capture" \
  MARSH_SELECTED_HOME="$root/claude-noproxy-home" SBX_CRED_ANTHROPIC_MODE=none \
  MARSH_TEST_CLAUDE_OAUTH_PROBE="$probe/held?case=claude-noproxy" \
  sh "$claude_entry" --version
test -z "$(oauth_token claude-noproxy)"
test "$(asked claude-noproxy)" = 0

# The job's own credential or endpoint always wins over the login sbx holds:
# the proxy is not asked, and the caller's value reaches Claude unchanged.
for variable in ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN CLAUDE_CODE_OAUTH_TOKEN \
    ANTHROPIC_PROFILE ANTHROPIC_FEDERATION_RULE_ID ANTHROPIC_BASE_URL \
    CLAUDE_CODE_USE_BEDROCK CLAUDE_CODE_USE_VERTEX CLAUDE_CODE_USE_FOUNDRY; do
  run_claude_probe "claude-own-$variable" /held "$variable=caller-value"
  test "$(asked "claude-own-$variable")" = 0
  if [ "$variable" = CLAUDE_CODE_OAUTH_TOKEN ]; then
    test "$(oauth_token "claude-own-$variable")" = caller-value
  else
    test -z "$(oauth_token "claude-own-$variable")"
  fi
done
test "$(cat "$root/claude-own-ANTHROPIC_API_KEY-capture/anthropic-key")" = caller-value
# A saved login, in the selected home or in CLAUDE_CONFIG_DIR.
mkdir -p "$root/claude-login-home/.claude" "$root/claude-config-dir"
printf '%s\n' '{"claudeAiOauth":{}}' >"$root/claude-login-home/.claude/.credentials.json"
printf '%s\n' '{"claudeAiOauth":{}}' >"$root/claude-config-dir/.credentials.json"
run_claude_probe claude-login /held
run_claude_probe claude-config-dir /held CLAUDE_CONFIG_DIR="$root/claude-config-dir"
# A helper of the user's own, or a credential or endpoint in a settings env,
# in the user's or the project's settings.
mkdir -p "$root/claude-helper-home/.claude" "$root/claude-settings-env-home/.claude" \
  "$root/claude-project-helper-project/.claude"
printf '%s\n' '{"apiKeyHelper":"my-vault-helper"}' \
  >"$root/claude-helper-home/.claude/settings.json"
printf '%s\n' '{"env":{"ANTHROPIC_BASE_URL":"https://gateway.example"}}' \
  >"$root/claude-settings-env-home/.claude/settings.json"
printf '%s\n' '{"apiKeyHelper":"my-vault-helper"}' \
  >"$root/claude-project-helper-project/.claude/settings.local.json"
run_claude_probe claude-helper /held
run_claude_probe claude-settings-env /held
run_claude_probe claude-project-helper /held
for own in login config-dir helper settings-env project-helper; do
  test "$(asked "claude-$own")" = 0
  test -z "$(oauth_token "claude-$own")"
done
node -e '
  if (require(process.argv[1]).apiKeyHelper !== "my-vault-helper") process.exit(1);
' "$root/claude-helper-home/.claude/settings.json"

# A mode of oauth takes the token path without asking, and also leaves a
# caller's own token alone.
run_claude_probe claude-mode-oauth /held SBX_CRED_ANTHROPIC_MODE=oauth
test "$(oauth_token claude-mode-oauth)" = sk-ant-oat01-proxy-managed
test "$(asked claude-mode-oauth)" = 0
run_claude_probe claude-mode-oauth-own /held SBX_CRED_ANTHROPIC_MODE=oauth \
  CLAUDE_CODE_OAUTH_TOKEN=caller-token
test "$(oauth_token claude-mode-oauth-own)" = caller-token
run_claude_probe claude-mode-oauth-key /held SBX_CRED_ANTHROPIC_MODE=oauth \
  ANTHROPIC_API_KEY=caller-key
test -z "$(oauth_token claude-mode-oauth-key)"
test "$(cat "$root/claude-mode-oauth-key-capture/anthropic-key")" = caller-key

# ACP mode passes the login the same way, never as an API key.
real_node=$(command -v node)
mkdir -p "$root/acp-bin"
cat >"$root/acp-bin/node" <<NODE
#!/bin/sh
if [ "\${1:-}" = /opt/marsh/claude-acp/mcp-gateway-proxy.mjs ]; then
  printf '%s\n' "\${ANTHROPIC_API_KEY:-}" >"\$MARSH_TEST_CAPTURE/anthropic-key"
  printf '%s\n' "\${CLAUDE_CODE_OAUTH_TOKEN:-}" >"\$MARSH_TEST_CAPTURE/claude-oauth-token"
  exit 0
fi
exec "$real_node" "\$@"
NODE
chmod 755 "$root/acp-bin/node"
mkdir -p "$root/claude-acp-home" "$root/claude-acp-capture"
env -i PATH="$root/acp-bin:$bin:$PATH" TMPDIR="${TMPDIR:-/tmp}" \
  MARSH_TEST_CAPTURE="$root/claude-acp-capture" \
  MARSH_SELECTED_HOME="$root/claude-acp-home" SBX_CRED_ANTHROPIC_MODE=none \
  HTTPS_PROXY=http://127.0.0.1:9 \
  MARSH_TEST_CLAUDE_OAUTH_PROBE="$probe/held?case=claude-acp" \
  sh "$claude_entry" --acp 2>"$root/claude-acp.err"
test "$(oauth_token claude-acp)" = sk-ant-oat01-proxy-managed
test -z "$(cat "$root/claude-acp-capture/anthropic-key")"
grep -Fqx 'marsh-auth-mode=oauth' "$root/claude-acp.err"

# An API key binding keeps the helper and never the OAuth placeholder.
test -z "$(cat "$root/claude-capture/claude-oauth-token")"

# A selected home keeps no stale state when the binding changes: the helper an
# API key binding wrote goes once the binding is a login, or nothing.
run_claude_probe claude-switch /held SBX_CRED_ANTHROPIC_MODE=apikey
node -e '
  if (require(process.argv[1]).apiKeyHelper !== "echo proxy-managed") process.exit(1);
' "$root/claude-switch-home/.claude/settings.json"
run_claude_probe claude-switch /held
test "$(oauth_token claude-switch)" = sk-ant-oat01-proxy-managed
node -e '
  const settings = require(process.argv[1]);
  if (Object.hasOwn(settings, "apiKeyHelper") || settings.themeId !== 1) process.exit(1);
' "$root/claude-switch-home/.claude/settings.json"
run_claude_probe claude-switch /held SBX_CRED_ANTHROPIC_MODE=apikey
run_claude_probe claude-switch /none
test -z "$(oauth_token claude-switch)"
node -e '
  if (Object.hasOwn(require(process.argv[1]), "apiKeyHelper")) process.exit(1);
' "$root/claude-switch-home/.claude/settings.json"
kill "$probe_pid" 2>/dev/null || :
probe_pid=

# Malformed settings fail closed and remain byte-for-byte unchanged without
# leaking their contents in diagnostics.
printf '%s\n' '{private-malformed-settings' >"$claude_none_home/.claude/settings.json"
cp "$claude_none_home/.claude/settings.json" "$root/claude-settings.before"
if PATH="$bin:$PATH" \
  MARSH_TEST_CAPTURE="$claude_none_capture" \
  MARSH_SELECTED_HOME="$claude_none_home" \
  SBX_CRED_ANTHROPIC_MODE=apikey \
  sh kits/marsh-claude/marsh-entrypoint.sh --version \
  >"$root/claude-settings.out" 2>"$root/claude-settings.err"; then
  echo 'malformed Claude settings unexpectedly accepted' >&2
  exit 1
fi
cmp "$root/claude-settings.before" "$claude_none_home/.claude/settings.json"
grep -Fq 'is malformed JSON; preserved unchanged' "$root/claude-settings.err"
if grep -Fq private-malformed-settings "$root/claude-settings.err"; then
  echo 'malformed Claude settings content leaked in diagnostics' >&2
  exit 1
fi

printf '%s\n' '[]' >"$claude_none_home/.claude/settings.json"
if PATH="$bin:$PATH" \
  MARSH_TEST_CAPTURE="$claude_none_capture" \
  MARSH_SELECTED_HOME="$claude_none_home" \
  SBX_CRED_ANTHROPIC_MODE=apikey \
  sh kits/marsh-claude/marsh-entrypoint.sh --version \
  >"$root/claude-settings.out" 2>"$root/claude-settings.err"; then
  echo 'non-object Claude settings unexpectedly accepted' >&2
  exit 1
fi
test "$(cat "$claude_none_home/.claude/settings.json")" = '[]'
grep -Fq 'must contain a JSON object; preserved unchanged' \
  "$root/claude-settings.err"

# Repeated starts are byte-for-byte idempotent once this project is trusted.
cp "$root/codex-home/.codex/config.toml" "$root/codex-config.before"
run_kit codex
cmp "$root/codex-config.before" "$root/codex-home/.codex/config.toml"

# Reproduce Ubuntu 26.04 uutils mkdir's false success on an existing lock.
# Configuration exclusion must use an atomic create, even with this utility
# on PATH. Ordinary directory setup keeps the real mkdir behavior.
real_mkdir=$(command -v mkdir)
cat >"$bin/mkdir" <<EOF
#!/bin/sh
case "\${1:-}" in
  *.marsh-lock) "$real_mkdir" "\$@" 2>/dev/null || [ -d "\$1" ] ;;
  *) exec "$real_mkdir" "\$@" ;;
esac
EOF
chmod 755 "$bin/mkdir"

# Concurrent fresh containers sharing one home must retain every project trust
# entry exactly once. This also exercises concurrent first initialization.
rm -rf "$root/codex-home" "$root/codex-capture"
mkdir -p "$root/codex-home" "$root/codex-capture"
codex_pids=
codex_index=1
while [ "$codex_index" -le 8 ]; do
  project="$root/codex-project-$codex_index"
  capture="$root/codex-capture-$codex_index"
  mkdir -p "$project" "$capture"
  project=$(cd "$project" && pwd -P)
  (
    cd "$project"
    PATH="$bin:$PATH" \
      MARSH_TEST_CAPTURE="$capture" \
      MARSH_SELECTED_HOME="$root/codex-home" \
      SBX_CRED_OPENAI_MODE=oauth \
      sh "$codex_entry" --version
  ) &
  codex_pids="$codex_pids $!"
  codex_index=$((codex_index + 1))
done
for codex_pid in $codex_pids; do
  wait "$codex_pid"
done
codex_index=1
while [ "$codex_index" -le 8 ]; do
  project="$root/codex-project-$codex_index"
  project=$(cd "$project" && pwd -P)
  test "$(grep -Fxc "[projects.\"$project\"]" \
    "$root/codex-home/.codex/config.toml")" = 1
  codex_index=$((codex_index + 1))
done
test "$(grep -c '^\[projects\.' "$root/codex-home/.codex/config.toml")" = 8

# A crashed writer's old protocol-owned lock is reclaimed without disturbing
# the completed config beside it.
codex_stale_lock="$root/codex-home/.codex/config.toml.marsh-lock"
mkdir "$codex_stale_lock"
printf '%s\n' 1 >"$codex_stale_lock/created"
printf '%s\n' interrupted >"$codex_stale_lock/config"
run_kit codex
test ! -e "$codex_stale_lock"

# A malformed config path is user state: fail closed without following or
# replacing it, and do not expose its contents in the diagnostic.
rm -f "$root/codex-home/.codex/config.toml"
printf '%s\n' sensitive-user-config >"$root/codex-config-target"
ln -s "$root/codex-config-target" "$root/codex-home/.codex/config.toml"
if PATH="$bin:$PATH" \
  MARSH_TEST_CAPTURE="$root/codex-capture" \
  MARSH_SELECTED_HOME="$root/codex-home" \
  SBX_CRED_OPENAI_MODE=oauth \
  sh "$codex_entry" --version \
  >"$root/codex-malformed.out" 2>"$root/codex-malformed.err"; then
  echo 'malformed Codex config path unexpectedly accepted' >&2
  exit 1
fi
test "$(cat "$root/codex-config-target")" = sensitive-user-config
test -L "$root/codex-home/.codex/config.toml"
grep -Fq 'must be a regular file; preserved unchanged' "$root/codex-malformed.err"
if grep -Fq sensitive-user-config "$root/codex-malformed.err"; then
  echo 'Codex config content leaked in diagnostics' >&2
  exit 1
fi

# Invalid TOML bytes are likewise preserved byte-for-byte and never echoed.
rm "$root/codex-home/.codex/config.toml"
printf 'private\000value\n' >"$root/codex-home/.codex/config.toml"
cp "$root/codex-home/.codex/config.toml" "$root/codex-malformed.before"
if PATH="$bin:$PATH" \
  MARSH_TEST_CAPTURE="$root/codex-capture" \
  MARSH_SELECTED_HOME="$root/codex-home" \
  SBX_CRED_OPENAI_MODE=oauth \
  sh "$codex_entry" --version \
  >"$root/codex-malformed.out" 2>"$root/codex-malformed.err"; then
  echo 'malformed Codex TOML unexpectedly accepted' >&2
  exit 1
fi
cmp "$root/codex-malformed.before" "$root/codex-home/.codex/config.toml"
grep -Fq 'is malformed TOML; preserved unchanged' "$root/codex-malformed.err"
if grep -Fq private "$root/codex-malformed.err"; then
  echo 'malformed Codex TOML content leaked in diagnostics' >&2
  exit 1
fi

# Concurrent fresh containers may initialize the same selected home. Every
# read/merge/rename must survive, rather than losing a project trust entry to a
# last-writer-wins race.
claude_pids=
claude_index=1
while [ "$claude_index" -le 8 ]; do
  project="$root/claude-project-$claude_index"
  mkdir -p "$project"
  (
    cd "$project"
    PATH="$bin:$PATH" \
      MARSH_TEST_CAPTURE="$root/claude-capture" \
      MARSH_SELECTED_HOME="$root/claude-home" \
      SBX_CRED_ANTHROPIC_MODE=apikey \
      MCP_GATEWAY_URL=http://mcp-gateway.docker.internal/mcp \
      MCP_SENTINEL_TOKEN_NAME=proxy-managed \
      sh "$OLDPWD/kits/marsh-claude/marsh-entrypoint.sh" --version
  ) &
  claude_pids="$claude_pids $!"
  claude_index=$((claude_index + 1))
done
for claude_pid in $claude_pids; do
  wait "$claude_pid"
done
node -e '
  const config = require(process.argv[1]);
  for (let index = 1; index <= 8; index += 1) {
    const suffix = `/claude-project-${index}`;
    const project = Object.entries(config.projects || {}).find(
      ([path, value]) => path.endsWith(suffix) && value?.hasTrustDialogAccepted === true
    );
    if (!project) process.exit(1);
  }
  if (config.mcpServers?.["mcp-gateway"]?.headers?.Authorization !==
      "Bearer proxy-managed") process.exit(1);
' "$root/claude-home/.claude.json"

# A crashed lock and old randomized atomic-write directory are reclaimed. The
# lock cleanup removes only protocol-owned files, and stale-directory cleanup
# refuses symlinks, regular files, recent directories, or unexpected contents.
stale_lock="$root/claude-home/.claude.json.marsh-lock"
mkdir "$stale_lock"
printf '%s\n' 1 >"$stale_lock/created"
printf '%s\n' interrupted >"$stale_lock/config"
stale_directory="$root/claude-home/.claude.json.marsh-orphan"
mkdir "$stale_directory"
printf '%s\n' interrupted >"$stale_directory/config"
touch -t 200001010000 "$stale_directory" "$stale_directory/config"
run_kit claude
test ! -e "$stale_lock"
test ! -e "$stale_directory"

# A malformed user-owned Claude config fails with a bounded diagnostic and is
# never replaced by Kit defaults. A stale regular file with a similar name is
# user state and is not mistaken for a protocol-owned temporary directory.
printf '%s\n' '{malformed-user-config' >"$root/claude-home/.claude.json"
printf '%s\n' stale >"$root/claude-home/.claude.json.marsh-stale"
if PATH="$bin:$PATH" \
  MARSH_TEST_CAPTURE="$root/claude-capture" \
  MARSH_SELECTED_HOME="$root/claude-home" \
  SBX_CRED_ANTHROPIC_MODE=apikey \
  sh kits/marsh-claude/marsh-entrypoint.sh --version \
  >"$root/malformed.out" 2>"$root/malformed.err"; then
  echo 'malformed Claude config unexpectedly accepted' >&2
  exit 1
fi
test "$(cat "$root/claude-home/.claude.json")" = '{malformed-user-config'
test "$(cat "$root/claude-home/.claude.json.marsh-stale")" = stale
grep -Fq 'is malformed JSON; preserved unchanged' "$root/malformed.err"
if grep -Fq '{malformed-user-config' "$root/malformed.err"; then
  echo 'malformed Claude config content leaked in diagnostics' >&2
  exit 1
fi

if MARSH_SELECTED_HOME=relative sh kits/marsh-pi/marsh-entrypoint.sh >/dev/null 2>&1; then
  echo 'relative selected home unexpectedly accepted' >&2
  exit 1
fi

# Only documented proxy sentinels may be materialized.
if grep -R -E '(sk-ant-|sk-proj-|Bearer [A-Za-z0-9_-]{20,})' \
  "$root/claude-home" "$root/codex-home" "$root/pi-home" >/dev/null; then
  echo 'credential-like material appeared in a selected home' >&2
  exit 1
fi
