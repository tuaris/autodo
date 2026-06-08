#!/bin/sh
#
# mac_autodo test harness
#
# Must be run as a wheel-group member with doas/mdo access.
# The module must NOT be loaded before running (script handles load/unload).
#

set -e

PASS=0
FAIL=0
MODULE_PATH="${MODULE_PATH:-$(dirname "$0")/../src/mac_autodo.ko}"
TEST_FILE="/etc/master.passwd"

pass() {
	PASS=$((PASS + 1))
	printf "  PASS: %s\n" "$1"
}

fail() {
	FAIL=$((FAIL + 1))
	printf "  FAIL: %s\n" "$1"
}

assert_success() {
	if eval "$1" >/dev/null 2>&1; then
		pass "$2"
	else
		fail "$2 (command failed: $1)"
	fi
}

assert_fail() {
	if eval "$1" >/dev/null 2>&1; then
		fail "$2 (command succeeded unexpectedly: $1)"
	else
		pass "$2"
	fi
}

# Ensure module is not loaded
kldstat -q -m mac_autodo 2>/dev/null && {
	echo "ERROR: mac_autodo is already loaded. Unload it first."
	exit 1
}

# Verify we're in wheel group
id -Gn | grep -qw wheel || {
	echo "ERROR: Must be run as a wheel group member."
	exit 1
}

# Verify module exists
[ -f "$MODULE_PATH" ] || {
	echo "ERROR: Module not found at $MODULE_PATH (build it first)."
	exit 1
}

echo "=== mac_autodo test suite ==="
echo "Module: $MODULE_PATH"
echo ""

# --- Test: Access denied without module ---
echo "[1] Baseline: access denied without module"
assert_fail "cat $TEST_FILE" "read root file denied without module"

# --- Load module ---
echo ""
echo "[2] Module load"
doas kldload "$MODULE_PATH"
assert_success "kldstat -q -m mac_autodo" "module loaded successfully"

# --- Test: Access granted with module ---
echo ""
echo "[3] Host privileges with module loaded"
assert_success "cat $TEST_FILE" "read root file succeeds with module"
assert_success "jls" "jls (jail list) succeeds"

# --- Test: Sysctl interface ---
echo ""
echo "[4] Sysctl interface"
assert_success "sysctl security.mac.autodo.enabled" "enabled sysctl readable"
assert_success "sysctl security.mac.autodo.gid" "gid sysctl readable"
assert_success "sysctl security.mac.autodo.log_grants" "log_grants sysctl readable"
assert_success "sysctl security.mac.autodo.grant_count" "grant_count sysctl readable"

# --- Test: Disable via sysctl ---
echo ""
echo "[5] Disable via sysctl"
sysctl security.mac.autodo.enabled=0 >/dev/null
assert_fail "cat $TEST_FILE" "access denied when disabled"
doas sysctl security.mac.autodo.enabled=1 >/dev/null
assert_success "cat $TEST_FILE" "access restored when re-enabled"

# --- Test: GID change ---
echo ""
echo "[6] GID change"
sysctl security.mac.autodo.gid=9999 >/dev/null
assert_fail "cat $TEST_FILE" "access denied with wrong GID"
doas sysctl security.mac.autodo.gid=0 >/dev/null
assert_success "cat $TEST_FILE" "access restored with correct GID"

# --- Test: Grant counter ---
echo ""
echo "[7] Grant counter"
COUNT1=$(sysctl -n security.mac.autodo.grant_count)
cat $TEST_FILE >/dev/null
COUNT2=$(sysctl -n security.mac.autodo.grant_count)
if [ "$COUNT2" -gt "$COUNT1" ]; then
	pass "grant_count increments on access"
else
	fail "grant_count did not increment ($COUNT1 -> $COUNT2)"
fi

# --- Test: Jail isolation (if jails exist) ---
echo ""
echo "[8] Jail isolation"
FIRST_JAIL=$(jls -n name 2>/dev/null | head -1 | sed 's/name=//')
if [ -n "$FIRST_JAIL" ]; then
	# Jails default to disabled
	assert_fail "jexec $FIRST_JAIL cat /etc/master.passwd" \
	    "jail access denied by default (jail=$FIRST_JAIL)"

	# Enable via jail parameter
	jail -m name="$FIRST_JAIL" mac.autodo=new
	assert_success "jexec $FIRST_JAIL cat /etc/master.passwd" \
	    "jail access granted after mac.autodo=new"

	# Disable again
	jail -m name="$FIRST_JAIL" mac.autodo=disable
	assert_fail "jexec $FIRST_JAIL cat /etc/master.passwd" \
	    "jail access denied after mac.autodo=disable"

	# Test inheritance
	jail -m name="$FIRST_JAIL" mac.autodo=inherit
	assert_success "jexec $FIRST_JAIL cat /etc/master.passwd" \
	    "jail access via inheritance from host"
	jail -m name="$FIRST_JAIL" mac.autodo=disable
else
	echo "  SKIP: no jails running"
fi

# --- Test: Privilege scoping ---
echo ""
echo "[9] Privilege scoping"
assert_success "sysctl security.mac.autodo.scope" "scope sysctl readable"

# Restrict to VFS only
sysctl security.mac.autodo.scope=vfs >/dev/null
assert_success "cat $TEST_FILE" "VFS access works with scope=vfs"
assert_fail "jexec $FIRST_JAIL hostname" "jexec denied with scope=vfs (needs jail category)"

# Add jail category
doas sysctl security.mac.autodo.scope=vfs,jail >/dev/null
assert_success "jexec $FIRST_JAIL hostname" "jexec works with scope=vfs,jail"

# Invalid category rejected
if sysctl security.mac.autodo.scope=bogus >/dev/null 2>&1; then
	fail "invalid category 'bogus' should be rejected"
else
	pass "invalid category rejected with error"
fi

# Restore to all
doas sysctl security.mac.autodo.scope=all >/dev/null
assert_success "cat $TEST_FILE" "full access restored with scope=all"

# --- Test: Character device ---
echo ""
echo "[10] Character device (/dev/autodo)"
assert_success "test -c /dev/autodo" "/dev/autodo exists"
assert_success "test -r /dev/autodo" "/dev/autodo readable by wheel"

# --- Test: Module unload ---
echo ""
echo "[11] Module unload"
doas kldunload mac_autodo
assert_success "! kldstat -q -m mac_autodo" "module unloaded"
assert_fail "cat $TEST_FILE" "access denied after unload"

# --- Summary ---
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
