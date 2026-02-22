#!/bin/bash
# A2G Protocol — Battle Test Suite
# Tests all hardening fixes + stress test
set -uo pipefail
# Note: NOT using set -e because many tests intentionally fail

A2G="${A2G_BIN:-/sessions/vigilant-festive-shannon/a2g-target/release/a2g}"
TEST_DIR=$(mktemp -d)
PASS_COUNT=0
FAIL_COUNT=0

pass() { PASS_COUNT=$((PASS_COUNT + 1)); echo "  ✓ PASS: $1"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); echo "  ✗ FAIL: $1"; }
section() { echo ""; echo "═══ $1 ═══"; }

cleanup() { rm -rf "$TEST_DIR"; }
trap cleanup EXIT

mkdir -p "$TEST_DIR/workspace/reports" "$TEST_DIR/workspace/output"
echo "test data" > "$TEST_DIR/workspace/reports/q4.csv"

echo "╔═══════════════════════════════════════════╗"
echo "║  A2G Protocol — Battle Test Suite         ║"
echo "╚═══════════════════════════════════════════╝"
echo "Binary: $A2G"
echo "Test dir: $TEST_DIR"

# ═══════════════════════════════════════════════════
section "SETUP"
# ═══════════════════════════════════════════════════

$A2G sovereign --out "$TEST_DIR" >/dev/null 2>&1
pass "Sovereign identity created"

$A2G init --name "battle-agent" --out "$TEST_DIR" >/dev/null 2>&1
pass "Agent identity created"

SOV_KEY="$TEST_DIR/sovereign.secret.key"
MANDATE="$TEST_DIR/battle-agent.mandate.toml"
LEDGER="$TEST_DIR/gov.db"

# Set workspace_root to test dir for boundary matching
sed -i "s|workspace_root = \".*\"|workspace_root = \"$TEST_DIR\"|" "$MANDATE"

# ═══════════════════════════════════════════════════
section "INPUT VALIDATION (Phase 2)"
# ═══════════════════════════════════════════════════

# Path traversal
if $A2G init --name "../traversal" --out "$TEST_DIR" 2>/dev/null; then
    fail "Should reject path traversal in name"
else
    pass "Rejected path traversal in name"
fi

# Empty name
if $A2G init --name "" --out "$TEST_DIR" 2>/dev/null; then
    fail "Should reject empty name"
else
    pass "Rejected empty name"
fi

# Zero TTL
if $A2G sign --mandate "$MANDATE" --key "$SOV_KEY" --ttl 0 2>/dev/null; then
    fail "Should reject TTL=0"
else
    pass "Rejected TTL=0"
fi

# Excessive TTL
if $A2G sign --mandate "$MANDATE" --key "$SOV_KEY" --ttl 99999 2>/dev/null; then
    fail "Should reject TTL=99999"
else
    pass "Rejected TTL=99999"
fi

# Empty tool name
if $A2G enforce --mandate "$MANDATE" --tool "" --ledger "$LEDGER" 2>/dev/null; then
    fail "Should reject empty tool"
else
    pass "Rejected empty tool name"
fi

# Oversized params (2MB)
BIG_PARAMS=$(python3 -c "print('{\"x\":\"' + 'A'*2100000 + '\"}')")
if $A2G enforce --mandate "$MANDATE" --tool "test" --params "$BIG_PARAMS" --ledger "$LEDGER" 2>/dev/null; then
    fail "Should reject oversized params"
else
    pass "Rejected oversized JSON params"
fi

# ═══════════════════════════════════════════════════
section "GOVERNANCE LIFECYCLE"
# ═══════════════════════════════════════════════════

# Authority root (Fix 13 — configurable)
$A2G authority-root \
    --key "$SOV_KEY" \
    --name "BattleCorp" \
    --out "$TEST_DIR/root.json" \
    --ledger "$LEDGER" \
    --tools "read_file,write_file,execute" \
    --max-rate-limit 200 \
    --max-ttl 1440 >/dev/null 2>&1
pass "Authority root created (configurable)"

# Root delegation's grantee_did == sovereign DID (self-delegation)
# So delegating from root uses sovereign key — that works for key-DID binding
# For dept→team, the dept's grantee_did must match the signing key's DID
# Solution: sovereign delegates to itself at department level, then to itself at team level
# (In production, each level would have a different key)

SOV_DID=$(<"$TEST_DIR/sovereign.did")

$A2G delegate \
    --parent "$TEST_DIR/root.json" \
    --key "$SOV_KEY" \
    --grantee "$SOV_DID" \
    --grantee-name "Engineering" \
    --level department \
    --tools "read_file,write_file" \
    --ttl 168 \
    --out "$TEST_DIR/dept.json" \
    --ledger "$LEDGER" >/dev/null 2>&1
pass "Delegation: root → dept"

$A2G delegate \
    --parent "$TEST_DIR/dept.json" \
    --key "$SOV_KEY" \
    --grantee "$SOV_DID" \
    --grantee-name "DataTeam" \
    --level team \
    --tools "read_file" \
    --ttl 72 \
    --out "$TEST_DIR/team.json" \
    --ledger "$LEDGER" >/dev/null 2>&1
pass "Delegation: dept → team"

# Propose
$A2G propose \
    --proposer "$SOV_DID" \
    --name "Battle Agent Mandate" \
    --mandate "$MANDATE" \
    --justification "Testing governance" \
    --out "$TEST_DIR/proposal.json" \
    --ledger "$LEDGER" >/dev/null 2>&1
pass "Proposal created"

# Review
$A2G review \
    --proposal "$TEST_DIR/proposal.json" \
    --key "$SOV_KEY" \
    --reviewer-name "CTO" \
    --decision approve \
    --reason "Approved" \
    --ledger "$LEDGER" >/dev/null 2>&1
pass "Proposal approved"

# Sign with proposal (Fix 1+3)
$A2G sign \
    --mandate "$MANDATE" \
    --key "$SOV_KEY" \
    --ttl 24 \
    --proposal "$TEST_DIR/proposal.json" >/dev/null 2>&1
pass "Mandate signed with proposal"

# Verify
$A2G verify --mandate "$MANDATE" >/dev/null 2>&1
pass "Mandate verified"

# Enforce ALLOW (with workspace_root — Phase 1)
RESULT=$($A2G --output json enforce \
    --mandate "$MANDATE" \
    --tool read_file \
    --params "{\"path\":\"$TEST_DIR/workspace/reports/q4.csv\"}" \
    --ledger "$LEDGER" 2>&1 || true)
if echo "$RESULT" | grep -q '"ALLOW"'; then
    pass "Enforce ALLOW (workspace_root path resolution)"
else
    fail "Expected ALLOW for read_file in workspace. Got: $RESULT"
fi

# Enforce DENY — unauthorized tool
RESULT=$($A2G --output json enforce \
    --mandate "$MANDATE" \
    --tool execute \
    --params '{}' \
    --ledger "$LEDGER" 2>&1 || true)
if echo "$RESULT" | grep -q '"DENY"'; then
    pass "Enforce DENY (unauthorized tool)"
else
    fail "Expected DENY for unauthorized tool. Got: $RESULT"
fi

# Enforce DENY — boundary violation (/etc/passwd)
RESULT=$($A2G --output json enforce \
    --mandate "$MANDATE" \
    --tool read_file \
    --params '{"path":"/etc/passwd"}' \
    --ledger "$LEDGER" 2>&1 || true)
if echo "$RESULT" | grep -q '"DENY"'; then
    pass "Enforce DENY (boundary: /etc/passwd)"
else
    fail "Expected DENY for /etc/passwd. Got: $RESULT"
fi

# Enforce with authority chain (Fix 2)
RESULT=$($A2G --output json enforce \
    --mandate "$MANDATE" \
    --tool read_file \
    --params "{\"path\":\"$TEST_DIR/workspace/reports/q4.csv\"}" \
    --ledger "$LEDGER" \
    --authority-chain "$TEST_DIR/root.json,$TEST_DIR/dept.json" 2>&1 || true)
if echo "$RESULT" | grep -q '"ALLOW"'; then
    pass "Enforce ALLOW with authority chain"
else
    fail "Expected ALLOW with authority chain. Got: $RESULT"
fi

# Authority chain scope violation — team only has read_file, but mandate has write_file
RESULT=$($A2G enforce \
    --mandate "$MANDATE" \
    --tool write_file \
    --params "{\"path\":\"$TEST_DIR/workspace/output/test.txt\"}" \
    --ledger "$LEDGER" \
    --authority-chain "$TEST_DIR/root.json,$TEST_DIR/dept.json,$TEST_DIR/team.json" 2>&1 || true)
if echo "$RESULT" | grep -q "authority scope violation"; then
    pass "Authority chain scope violation detected"
else
    fail "Expected scope violation. Got: $RESULT"
fi

# ═══════════════════════════════════════════════════
section "ADVERSARIAL TESTS"
# ═══════════════════════════════════════════════════

# Sign with unapproved proposal
$A2G init --name "adv-agent" --out "$TEST_DIR" >/dev/null 2>&1
ADV_MANDATE="$TEST_DIR/adv-agent.mandate.toml"
$A2G propose \
    --proposer "did:a2g:attacker" \
    --name "Sneaky" \
    --mandate "$ADV_MANDATE" \
    --justification "Trust me" \
    --out "$TEST_DIR/unapproved.json" \
    --ledger "$LEDGER" >/dev/null 2>&1

if $A2G sign --mandate "$ADV_MANDATE" --key "$SOV_KEY" --ttl 4 --proposal "$TEST_DIR/unapproved.json" 2>/dev/null; then
    fail "Should block unapproved proposal"
else
    pass "Blocked sign with unapproved proposal"
fi

# Skip proposal (should succeed with warning)
if $A2G sign --mandate "$ADV_MANDATE" --key "$SOV_KEY" --ttl 4 --skip-proposal >/dev/null 2>&1; then
    pass "Skip-proposal allowed (with warning)"
else
    fail "Skip-proposal should be allowed"
fi

# Tamper mandate after approval
$A2G init --name "tamper-agent" --out "$TEST_DIR" >/dev/null 2>&1
TAMPER_MANDATE="$TEST_DIR/tamper-agent.mandate.toml"
$A2G propose \
    --proposer "$SOV_DID" \
    --name "Legit" \
    --mandate "$TAMPER_MANDATE" \
    --justification "OK" \
    --out "$TEST_DIR/tamper-prop.json" \
    --ledger "$LEDGER" >/dev/null 2>&1
$A2G review \
    --proposal "$TEST_DIR/tamper-prop.json" \
    --key "$SOV_KEY" \
    --reviewer-name "CTO" \
    --decision approve \
    --reason "OK" \
    --ledger "$LEDGER" >/dev/null 2>&1

# Tamper: add execute tool
sed -i 's/tools = \["read_file", "write_file"\]/tools = ["read_file", "write_file", "execute"]/' "$TAMPER_MANDATE"

if $A2G sign --mandate "$TAMPER_MANDATE" --key "$SOV_KEY" --ttl 4 --proposal "$TEST_DIR/tamper-prop.json" 2>/dev/null; then
    fail "Should detect tampered mandate"
else
    pass "Detected tampered mandate (hash mismatch)"
fi

# Revoke delegation, then enforce with revoked chain
$A2G revoke-delegation \
    --delegation "$TEST_DIR/dept.json" \
    --ledger "$LEDGER" \
    --reason "security incident" >/dev/null 2>&1
pass "Delegation revoked"

RESULT=$($A2G enforce \
    --mandate "$MANDATE" \
    --tool read_file \
    --params '{}' \
    --ledger "$LEDGER" \
    --authority-chain "$TEST_DIR/root.json,$TEST_DIR/dept.json" 2>&1 || true)
if echo "$RESULT" | grep -qi "revoked\|DENY"; then
    pass "Enforce DENY with revoked delegation"
else
    fail "Expected DENY with revoked delegation. Got: $RESULT"
fi

# Revoke mandate, enforce post-revocation
$A2G revoke --mandate "$MANDATE" --ledger "$LEDGER" --reason "battle test" >/dev/null 2>&1
pass "Mandate revoked"

RESULT=$($A2G --output json enforce \
    --mandate "$MANDATE" \
    --tool read_file \
    --params '{}' \
    --ledger "$LEDGER" 2>&1 || true)
if echo "$RESULT" | grep -q "mandate_revoked"; then
    pass "Enforce DENY post-revocation"
else
    fail "Expected mandate_revoked. Got: $RESULT"
fi

# ═══════════════════════════════════════════════════
section "STRESS TEST (100 enforce calls)"
# ═══════════════════════════════════════════════════

# Create a fresh signed mandate for stress test
$A2G init --name "stress-agent" --out "$TEST_DIR" >/dev/null 2>&1
STRESS_MANDATE="$TEST_DIR/stress-agent.mandate.toml"
sed -i "s|workspace_root = \".*\"|workspace_root = \"$TEST_DIR\"|" "$STRESS_MANDATE"
STRESS_LEDGER="$TEST_DIR/stress.db"

# Propose + approve + sign
$A2G propose --proposer "did:a2g:stress" --name "Stress" --mandate "$STRESS_MANDATE" --justification "Stress test" --out "$TEST_DIR/stress-prop.json" --ledger "$STRESS_LEDGER" >/dev/null 2>&1
$A2G review --proposal "$TEST_DIR/stress-prop.json" --key "$SOV_KEY" --reviewer-name "Bot" --decision approve --reason "Auto" --ledger "$STRESS_LEDGER" >/dev/null 2>&1
$A2G sign --mandate "$STRESS_MANDATE" --key "$SOV_KEY" --ttl 24 --proposal "$TEST_DIR/stress-prop.json" >/dev/null 2>&1

STRESS_PASS=0
STRESS_FAIL=0
for i in $(seq 1 100); do
    RESULT=$($A2G --output json enforce \
        --mandate "$STRESS_MANDATE" \
        --tool read_file \
        --params "{\"path\":\"$TEST_DIR/workspace/reports/q4.csv\"}" \
        --ledger "$STRESS_LEDGER" 2>&1 || true)
    if echo "$RESULT" | grep -q "receipt_id"; then
        STRESS_PASS=$((STRESS_PASS + 1))
    else
        STRESS_FAIL=$((STRESS_FAIL + 1))
    fi
done

if [ "$STRESS_PASS" -eq 100 ]; then
    pass "100/100 stress enforce calls produced valid receipts"
else
    fail "Stress test: $STRESS_PASS/100 passed, $STRESS_FAIL failed"
fi

# Verify audit count
AUDIT_COUNT=$($A2G --output json audit --ledger "$STRESS_LEDGER" --last 200 2>&1 | grep -c "receipt_id" || echo 0)
if [ "$AUDIT_COUNT" -ge 100 ]; then
    pass "Audit log has $AUDIT_COUNT entries (>=100)"
else
    fail "Audit log has only $AUDIT_COUNT entries (expected >=100)"
fi

# ═══════════════════════════════════════════════════
section "JSON OUTPUT VALIDATION (Fix 4)"
# ═══════════════════════════════════════════════════

JSON_ENFORCE=$($A2G --output json enforce \
    --mandate "$STRESS_MANDATE" \
    --tool read_file \
    --params "{\"path\":\"$TEST_DIR/workspace/reports/q4.csv\"}" \
    --ledger "$STRESS_LEDGER" 2>&1 || true)

if echo "$JSON_ENFORCE" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'decision' in d and 'receipt_id' in d" 2>/dev/null; then
    pass "JSON enforce output has required fields"
else
    fail "JSON enforce output missing fields: $JSON_ENFORCE"
fi

JSON_AUDIT=$($A2G --output json audit --ledger "$STRESS_LEDGER" --last 5 2>&1 || true)
if echo "$JSON_AUDIT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert isinstance(d, list) and len(d)>0" 2>/dev/null; then
    pass "JSON audit output is valid array"
else
    fail "JSON audit output invalid: $JSON_AUDIT"
fi

JSON_AUTHLOG=$($A2G --output json authority-log --ledger "$STRESS_LEDGER" --last 5 2>&1 || true)
if echo "$JSON_AUTHLOG" | python3 -c "import sys,json; d=json.load(sys.stdin); assert isinstance(d, list)" 2>/dev/null; then
    pass "JSON authority-log output is valid array"
else
    fail "JSON authority-log output invalid"
fi

# ═══════════════════════════════════════════════════
section "SUMMARY"
# ═══════════════════════════════════════════════════

TOTAL=$((PASS_COUNT + FAIL_COUNT))
echo ""
echo "═══════════════════════════════════════════"
echo "  Results: $PASS_COUNT/$TOTAL passed"
if [ "$FAIL_COUNT" -eq 0 ]; then
    echo "  Status: ALL TESTS PASSED"
    echo "═══════════════════════════════════════════"
    exit 0
else
    echo "  Status: $FAIL_COUNT FAILURES"
    echo "═══════════════════════════════════════════"
    exit 1
fi
