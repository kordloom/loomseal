#!/usr/bin/env bash
#
# ship.sh - test, lint, and deploy loomseal.com from your terminal.
#
# Mirrors .github/workflows/ship.yml: same gate, same wasm rebuild and selftest, same
# deploy, run locally. Every stage prints a timed pass/fail line and the full output of
# everything lands in one log file.
#
# Usage:
#   scripts/ship.sh               gate, rebuild the verifier, deploy loomseal.com (asks first)
#   scripts/ship.sh --gate-only   test and lint, deploy nothing
#   scripts/ship.sh --skip-gate   deploy without testing (emergencies only)
#   scripts/ship.sh --yes         no prompts
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO" || exit 1

SITE_URL="https://loomseal.com"
WRANGLER="wrangler@4.112.0"
LOG="${TMPDIR:-/tmp}/loomseal-ship-$(date +%Y%m%d-%H%M%S).log"

GATE=true
SITE=true
ASSUME_YES=false
while [ $# -gt 0 ]; do
	case "$1" in
	--gate-only) SITE=false ;;
	--skip-gate) GATE=false ;;
	--yes) ASSUME_YES=true ;;
	-h|--help) sed -n '2,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "unknown arg: $1 (try --help)" >&2; exit 2 ;;
	esac
	shift
done

bold=$'\033[1m'; dim=$'\033[2m'; red=$'\033[31m'; grn=$'\033[32m'
ylw=$'\033[33m'; blu=$'\033[34m'; cyn=$'\033[36m'; rst=$'\033[0m'

step() { printf '\n%s==>%s %s%s%s\n' "${blu}${bold}" "${rst}" "${bold}" "$*" "${rst}"; }
ok()   { printf '  %s✅ %s%s\n' "${grn}" "${rst}" "$*"; }
info() { printf '  %s•%s %s\n' "${cyn}" "${rst}" "$*"; }
warn() { printf '  %s⚠️  %s%s\n' "${ylw}" "$*" "${rst}"; }
die()  { printf '  %s❌ %s%s\n' "${red}" "$*" "${rst}" >&2; exit 1; }

# run prints a timed pass/fail line for one command, with all output captured in the log.
run() {
	local label="$1"; shift
	local t0=$SECONDS
	printf '  %s…%s %s' "${dim}" "${rst}" "$label"
	if { echo "----- $label -----"; "$@"; } >>"$LOG" 2>&1; then
		printf '\r  %s✅ %s%s %s(%ss)%s \n' "${grn}" "${rst}" "$label" "${dim}" "$((SECONDS - t0))" "${rst}"
	else
		printf '\r  %s❌ %s failed%s %s(%ss)%s \n' "${red}" "$label" "${rst}" "${dim}" "$((SECONDS - t0))" "${rst}" >&2
		printf '  %slast lines of %s:%s\n' "${dim}" "$LOG" "${rst}" >&2
		tail -15 "$LOG" | sed 's/^/    /' >&2
		exit 1
	fi
}

ask_yn() {
	$ASSUME_YES && return 0
	local a
	read -r -p "$(printf '  %s%s%s [y/N] ' "${cyn}" "$1" "${rst}")" a
	[[ "$a" == [yY] || "$a" == [yY][eE][sS] ]]
}

need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }

printf '%s🚢 LoomSeal ship%s %s(log: %s)%s\n' "${bold}" "${rst}" "${dim}" "$LOG" "${rst}"

step "🔎 Preflight"
need git; need go; need node; need npx; need curl
branch="$(git rev-parse --abbrev-ref HEAD)"
info "branch: ${bold}${branch}${rst}"
[ -n "$(git status --porcelain)" ] && warn "working tree is dirty; you are shipping what is on disk, not what is committed"
$GATE && need golangci-lint
if $SITE; then
	npx --yes "$WRANGLER" whoami >>"$LOG" 2>&1 || die "wrangler is not logged in; run: npx $WRANGLER login"
	ok "wrangler authenticated"
fi

if $GATE; then
	step "🧪 Gate (same checks as CI)"
	run "go build" go build ./...
	run "go vet" go vet ./...
	run "go test -race" go test -race ./...
	run "golangci-lint" golangci-lint run
else
	step "🧪 Gate"
	warn "skipped (--skip-gate)"
fi

if $SITE; then
	step "🧬 Browser verifier"
	mkdir -p site/public/verify
	run "build wasm verifier" env GOOS=js GOARCH=wasm go build -ldflags="-s -w" -o site/public/verify/loomseal.wasm ./wasm
	run "copy wasm_exec.js" cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" site/public/verify/
	run "selftest against the vectors" node wasm/selftest.mjs site/public/verify

	step "🚀 Deploy ${SITE_URL#https://}"
	if ask_yn "Deploy the site worker to Cloudflare now?"; then
		( cd site && run "wrangler deploy" npx --yes "$WRANGLER" deploy ) || exit 1
		run "verify ${SITE_URL#https://}" curl -fsS -o /dev/null "${SITE_URL}/?_=$(date +%s)"
	else
		warn "site deploy skipped"
	fi
fi

step "🎉 Done"
ok "everything requested is shipped ${dim}(full log: $LOG)${rst}"
