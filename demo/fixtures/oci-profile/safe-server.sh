#!/bin/sh
# Authored synthetic fixture. Docker sandbox only; never run on the host.
test "$(/bin/busybox id -u)" = 1000 || exit 1
test ! -e /var/run/docker.sock || exit 1
if /bin/busybox touch /SHOULD_NOT_WRITE 2>/dev/null; then exit 1; fi
while IFS= read -r line; do
  # Trusted test clients use compact JSON and numeric or UUID string IDs.
  id=$(printf '%s' "$line" | /bin/busybox sed -n 's/.*"id":\([^,}]*\).*/\1/p')
  test -n "$id" || continue
  case "$line" in
    *'"method":"initialize"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"authored-oci-profile","version":"1.0.0"}}}\n' "$id"
      ;;
    *'"method":"tools/list"'*)
      case "$line" in
        *'"cursor":"next"'*)
          printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"read_context","description":"Read scoped synthetic context","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false}}]}}\n' "$id"
          ;;
        *)
          printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"read_messages","description":"Read a packaged synthetic message","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false}}],"nextCursor":"next"}}\n' "$id"
          ;;
      esac
      ;;
    *'"method":"tools/call"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"Packaged synthetic result; private context is unavailable"}],"isError":false}}\n' "$id"
      ;;
    *) printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"Unsupported"}}\n' "$id" ;;
  esac
done
