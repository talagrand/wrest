#!/usr/bin/env bash
#
# Start local go-httpbin instances for the wrest test suite.
#
#   - HTTP  on 127.0.0.1:8080  -> HTTPBIN_HTTP_URL   (bulk of the httpbin tests)
#   - HTTPS on 127.0.0.1:8443  -> HTTPBIN_HTTPS_URL  (the https->http redirect-
#                                 downgrade tests, which need a real https leg)
#
# The HTTPS cert is a throwaway self-signed cert generated with Go's own
# crypto/tls/generate_cert.go example (ships in GOROOT/src, so there is no
# openssl dependency). The redirect-downgrade tests pair it with
# tls_danger_accept_invalid_certs, so the cert needs no trust chain or hostname
# match. Their redirect target is http and is never followed (blocked on the
# scheme downgrade), so no external network is touched.
#
# Used by CI (.github/actions/start-httpbin) and runnable locally:
#
#     exports="$(bash .github/ci-tools/start-httpbin.sh)" && eval "$exports"
#     cargo test --test real_world
#
# Under GitHub Actions the two URLs are appended to $GITHUB_ENV; otherwise they
# are printed to stdout as `export` lines (hence the `eval` above). CI logs go
# to the repository root; local logs go to target/httpbin-logs. The server
# processes are left running in the background.
#
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

export GOBIN="$repo_root/target/ci-tools"
mkdir -p "$GOBIN"
go install -C .github/ci-tools tool

log_dir="$repo_root/target/httpbin-logs"
if [[ -n "${GITHUB_ENV:-}" ]]; then
  log_dir="$repo_root"
fi
mkdir -p "$log_dir"
http_log="$log_dir/httpbin-http.log"
https_log="$log_dir/httpbin-https.log"

stop_on_failure() {
  if [[ $? -ne 0 ]]; then
    if [[ -n "${https_pid:-}" ]]; then
      kill "$https_pid" 2>/dev/null || :
    fi
    if [[ -n "${http_pid:-}" ]]; then
      kill "$http_pid" 2>/dev/null || :
    fi
  fi
}
trap stop_on_failure EXIT

# HTTP instance (port 8080).
nohup "$GOBIN/go-httpbin" -host 127.0.0.1 -port 8080 > "$http_log" 2>&1 &
http_pid=$!

# HTTPS instance (port 8443, throwaway self-signed cert regenerated each run).
certdir="$repo_root/target/httpbin-tls"
mkdir -p "$certdir"
( cd "$certdir" && go run "$(go env GOROOT)/src/crypto/tls/generate_cert.go" --host 127.0.0.1,localhost )
nohup "$GOBIN/go-httpbin" -host 127.0.0.1 -port 8443 \
  -https-cert-file "$certdir/cert.pem" -https-key-file "$certdir/key.pem" \
  > "$https_log" 2>&1 &
https_pid=$!

# Wait for both listeners (-k so the self-signed https passes readiness).
wait_ready() {
  local name="$1" url="$2" log="$3" pid="$4" ok=0
  for _ in $(seq 1 20); do
    if ! kill -0 "$pid" 2>/dev/null; then
      break
    fi
    if curl -fsSk --max-time 2 "$url" > /dev/null 2>&1 && kill -0 "$pid" 2>/dev/null; then
      ok=1
      break
    fi
    sleep 0.5
  done
  if [[ $ok -ne 1 ]]; then
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
      echo "::error::go-httpbin ($name) failed to start within 10s"
    else
      echo "go-httpbin ($name) failed to start within 10s" >&2
    fi
    cat "$log" >&2
    exit 1
  fi
}
wait_ready "http"  "http://127.0.0.1:8080/get"  "$http_log"  "$http_pid"
wait_ready "https" "https://127.0.0.1:8443/get" "$https_log" "$https_pid"

# Export the base URLs: to $GITHUB_ENV under Actions, else as stdout `export` lines.
emit() {
  if [[ -n "${GITHUB_ENV:-}" ]]; then
    printf '%s\n' "$1" >> "$GITHUB_ENV"
  else
    printf 'export %s\n' "$1"
  fi
  echo "go-httpbin: $1" >&2
}
emit "HTTPBIN_HTTP_URL=http://127.0.0.1:8080"
emit "HTTPBIN_HTTPS_URL=https://127.0.0.1:8443"
