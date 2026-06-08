#!/usr/libexec/atf-sh
#
# Basic mac_autodo kernel module tests.
# Tests module load/unload, sysctl interface, and fundamental grant/deny.
#
# All tests run as root (required for kldload/sysctl).
# Privilege checks use "su -m admin" since root bypasses DAC entirely.
#

MODULE_DIR="$(atf_get_srcdir)/../src"
MODULE_PATH="${MODULE_DIR}/mac_autodo.ko"
TEST_FILE="/etc/master.passwd"
TEST_USER="admin"

load_module() {
	kldstat -q -m mac_autodo 2>/dev/null && return 0
	kldload "${MODULE_PATH}" || atf_fail "cannot load mac_autodo.ko"
}

unload_module() {
	kldstat -q -m mac_autodo 2>/dev/null && kldunload mac_autodo
	return 0
}

# Check access as non-root wheel user.  Returns 0 on success.
check_access() {
	su -m ${TEST_USER} -c "cat ${TEST_FILE}" >/dev/null 2>&1
}

# --- baseline: access denied without module ---

atf_test_case baseline_denied cleanup
baseline_denied_head() {
	atf_set "descr" "Root file unreadable by wheel user without module"
	atf_set "require.user" "root"
}
baseline_denied_body() {
	unload_module
	if check_access; then
		atf_fail "wheel user could read ${TEST_FILE} without module"
	fi
}
baseline_denied_cleanup() {
	unload_module
}

# --- module load ---

atf_test_case module_load cleanup
module_load_head() {
	atf_set "descr" "Module loads successfully"
	atf_set "require.user" "root"
}
module_load_body() {
	load_module
	atf_check -s exit:0 kldstat -q -m mac_autodo
}
module_load_cleanup() {
	unload_module
}

# --- module unload ---

atf_test_case module_unload cleanup
module_unload_head() {
	atf_set "descr" "Module unloads cleanly"
	atf_set "require.user" "root"
}
module_unload_body() {
	load_module
	atf_check -s exit:0 kldunload mac_autodo
	atf_check -s exit:1 kldstat -q -m mac_autodo
}
module_unload_cleanup() {
	unload_module
}

# --- sysctl interface ---

atf_test_case sysctl_readable cleanup
sysctl_readable_head() {
	atf_set "descr" "All mac_autodo sysctls are readable"
	atf_set "require.user" "root"
}
sysctl_readable_body() {
	load_module
	atf_check -s exit:0 -o match:"enabled" sysctl security.mac.autodo.enabled
	atf_check -s exit:0 -o match:"gid" sysctl security.mac.autodo.gid
	atf_check -s exit:0 -o match:"log_grants" sysctl security.mac.autodo.log_grants
	atf_check -s exit:0 -o match:"grant_count" sysctl security.mac.autodo.grant_count
	atf_check -s exit:0 -o match:"scope" sysctl security.mac.autodo.scope
}
sysctl_readable_cleanup() {
	unload_module
}

# --- grant with module loaded ---

atf_test_case grant_with_module cleanup
grant_with_module_head() {
	atf_set "descr" "Wheel user can read root file with module loaded"
	atf_set "require.user" "root"
}
grant_with_module_body() {
	load_module
	if ! check_access; then
		atf_fail "wheel user denied with module loaded"
	fi
}
grant_with_module_cleanup() {
	unload_module
}

# --- deny after unload ---

atf_test_case deny_after_unload cleanup
deny_after_unload_head() {
	atf_set "descr" "Access denied immediately after module unload"
	atf_set "require.user" "root"
}
deny_after_unload_body() {
	load_module
	if ! check_access; then
		atf_fail "wheel user denied with module loaded"
	fi
	kldunload mac_autodo
	if check_access; then
		atf_fail "wheel user could read ${TEST_FILE} after unload"
	fi
}
deny_after_unload_cleanup() {
	unload_module
}

# --- grant counter increments ---

atf_test_case grant_counter cleanup
grant_counter_head() {
	atf_set "descr" "Grant counter increments on privilege use"
	atf_set "require.user" "root"
}
grant_counter_body() {
	load_module
	count1=$(sysctl -n security.mac.autodo.grant_count)
	check_access || true
	count2=$(sysctl -n security.mac.autodo.grant_count)
	if [ "${count2}" -le "${count1}" ]; then
		atf_fail "grant_count did not increment (${count1} -> ${count2})"
	fi
}
grant_counter_cleanup() {
	unload_module
}

# --- enable/disable toggle ---

atf_test_case enable_disable cleanup
enable_disable_head() {
	atf_set "descr" "Disabling via sysctl denies access, re-enable restores"
	atf_set "require.user" "root"
}
enable_disable_body() {
	load_module
	sysctl security.mac.autodo.enabled=0
	if check_access; then
		atf_fail "access granted while disabled"
	fi
	sysctl security.mac.autodo.enabled=1
	if ! check_access; then
		atf_fail "access denied after re-enable"
	fi
}
enable_disable_cleanup() {
	sysctl security.mac.autodo.enabled=1 2>/dev/null
	unload_module
}

# --- GID change ---

atf_test_case gid_change cleanup
gid_change_head() {
	atf_set "descr" "Changing GID to non-matching value denies access"
	atf_set "require.user" "root"
}
gid_change_body() {
	load_module
	sysctl security.mac.autodo.gid=9999
	if check_access; then
		atf_fail "access granted with wrong GID"
	fi
	sysctl security.mac.autodo.gid=0
	if ! check_access; then
		atf_fail "access denied after restoring correct GID"
	fi
}
gid_change_cleanup() {
	sysctl security.mac.autodo.gid=0 2>/dev/null
	unload_module
}

# --- chardev exists ---

atf_test_case chardev_exists cleanup
chardev_exists_head() {
	atf_set "descr" "/dev/autodo character device is created on module load"
	atf_set "require.user" "root"
}
chardev_exists_body() {
	load_module
	atf_check -s exit:0 test -c /dev/autodo
}
chardev_exists_cleanup() {
	unload_module
}

atf_init_test_cases() {
	atf_add_test_case baseline_denied
	atf_add_test_case module_load
	atf_add_test_case module_unload
	atf_add_test_case sysctl_readable
	atf_add_test_case grant_with_module
	atf_add_test_case deny_after_unload
	atf_add_test_case grant_counter
	atf_add_test_case enable_disable
	atf_add_test_case gid_change
	atf_add_test_case chardev_exists
}
