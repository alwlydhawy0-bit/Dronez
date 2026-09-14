#!/usr/bin/env bash
# Verify the Rego policy bundle.
#
# The Rego is the deterministic authorization gate, so it gets its own verification
# pass independent of the Python test suite:
#
#   opa check --strict   parse + type errors, unused/shadowed vars, unsafe references
#   opa fmt --list       formatting drift (a diff nobody reviewed is a diff nobody read)
#   opa test             the *_test.rego suites
#
# CI MUST run this. It is not optional: without it the gate ships unverified, and a
# Rego rule that fails to parse leaves the policy path undefined -- which the Python
# client correctly treats as a denial, so the failure mode is a hard outage rather
# than a silent bypass, but an outage of the dispatch path is still an outage.
#
# Usage: scripts/verify_policies.sh [--require-opa]
set -euo pipefail

POLICY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/src/policy_engine/policies"
REQUIRE_OPA=0
[[ "${1:-}" == "--require-opa" ]] && REQUIRE_OPA=1

if ! command -v opa >/dev/null 2>&1; then
	echo "opa binary not found on PATH."
	echo
	echo "  Install:  https://www.openpolicyagent.org/docs/latest/#running-opa"
	echo "            (or: brew install opa / apt-get install opa)"
	echo
	echo "  The policies in ${POLICY_DIR#"$PWD"/} are NOT verified without it."
	if [[ $REQUIRE_OPA -eq 1 ]]; then
		echo "  --require-opa was passed: failing." >&2
		exit 1
	fi
	echo "  Pass --require-opa to make this a hard failure (CI does)."
	exit 2
fi

echo "opa version: $(opa version | head -1)"
echo

echo "==> opa check --strict"
opa check --strict "$POLICY_DIR"
echo "    ok"
echo

echo "==> opa fmt --list"
UNFORMATTED="$(opa fmt --list "$POLICY_DIR" || true)"
if [[ -n "$UNFORMATTED" ]]; then
	echo "    formatting drift in:" >&2
	echo "$UNFORMATTED" >&2
	echo "    run: opa fmt --write $POLICY_DIR" >&2
	exit 1
fi
echo "    ok"
echo

echo "==> opa test"
opa test --verbose "$POLICY_DIR"
echo
echo "policy bundle verified."
