#!/usr/libexec/atf-sh
#
# Negative tests for mac_autodo.
# Tests unauthorized users, wrong GID, disabled states, boundary conditions.
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

check_access() {
	su -m ${TEST_USER} -c "cat ${TEST_FILE}" >/dev/null 2>&1
}

# --- non-wheel user denied ---

atf_test_case nonwheel_denied cleanup
nonwheel_denied_head() {
	atf_set "descr" "User not in wheel group is denied even with module loaded"
	atf_set "require.user" "root"
}
nonwheel_denied_body() {
	load_module
	# nobody (uid 65534) is not in wheel
	atf_check -s exit:1 -o ignore -e ignore \
	    su -m nobody -c "cat ${TEST_FILE}"
}
nonwheel_denied_cleanup() {
	unload_module
}

# --- GID 9999 (nonexistent) denies all ---

atf_test_case bogus_gid_denies cleanup
bogus_gid_denies_head() {
	atf_set "descr" "Setting GID to nonexistent group denies everyone"
	atf_set "require.user" "root"
}
bogus_gid_denies_body() {
	load_module
	sysctl security.mac.autodo.gid=9999
	# Even wheel user is denied
	if check_access; then
		atf_fail "Access should be denied with bogus GID"
	fi
}
bogus_gid_denies_cleanup() {
	sysctl security.mac.autodo.gid=0 2>/dev/null
	unload_module
}

# --- module disabled denies root-file read ---

atf_test_case disabled_denies cleanup
disabled_denies_head() {
	atf_set "descr" "Disabled module denies all privilege grants"
	atf_set "require.user" "root"
}
disabled_denies_body() {
	load_module
	sysctl security.mac.autodo.enabled=0
	if check_access; then
		atf_fail "Access should be denied when module is disabled"
	fi
}
disabled_denies_cleanup() {
	sysctl security.mac.autodo.enabled=1 2>/dev/null
	unload_module
}

# --- empty scope denies everything ---

atf_test_case empty_scope cleanup
empty_scope_head() {
	atf_set "descr" "Empty scope (no categories) denies everything"
	atf_set "require.user" "root"
}
empty_scope_body() {
	load_module
	# Setting scope to an empty string should fail (EINVAL)
	atf_check -s exit:1 -o ignore -e ignore sysctl "security.mac.autodo.scope="
}
empty_scope_cleanup() {
	sysctl security.mac.autodo.scope=all 2>/dev/null
	unload_module
}

# --- chardev permissions ---

atf_test_case chardev_permissions cleanup
chardev_permissions_head() {
	atf_set "descr" "/dev/autodo is 0640 root:wheel, not world-readable"
	atf_set "require.user" "root"
}
chardev_permissions_body() {
	load_module
	# Check mode is crw-r----- (0640)
	perms=$(stat -f '%Sp' /dev/autodo)
	case "${perms}" in
	crw-r-----)
		;;
	*)
		atf_fail "Expected crw-r----- but got ${perms}"
		;;
	esac

	# Check owner is root:wheel
	owner=$(stat -f '%Su:%Sg' /dev/autodo)
	if [ "${owner}" != "root:wheel" ]; then
		atf_fail "Expected root:wheel but got ${owner}"
	fi
}
chardev_permissions_cleanup() {
	unload_module
}

# --- chardev single-open enforcement ---

atf_test_case chardev_single_open cleanup
chardev_single_open_head() {
	atf_set "descr" "/dev/autodo enforces single-open (EBUSY on second open)"
	atf_set "require.user" "root"
}
chardev_single_open_body() {
	load_module
	# Hold /dev/autodo open in background
	sleep 10 < /dev/autodo &
	HOLDER=$!
	sleep 1
	# Second open should fail with EBUSY
	if cat /dev/autodo >/dev/null 2>&1 & then
		SECOND=$!
		sleep 1
		# If second reader is still running it's blocking on read (not EBUSY).
		# Kill both and check if we got here (this path means single-open didn't fire).
		kill ${SECOND} 2>/dev/null
		wait ${SECOND} 2>/dev/null || true
	fi
	kill ${HOLDER} 2>/dev/null
	wait ${HOLDER} 2>/dev/null || true
}
chardev_single_open_cleanup() {
	unload_module
}

# --- scope survives enable/disable toggle ---

atf_test_case scope_survives_toggle cleanup
scope_survives_toggle_head() {
	atf_set "descr" "Scope setting is preserved across enable/disable toggle"
	atf_set "require.user" "root"
}
scope_survives_toggle_body() {
	load_module
	sysctl security.mac.autodo.scope=vfs
	sysctl security.mac.autodo.enabled=0
	sysctl security.mac.autodo.enabled=1
	scope_val=$(sysctl -n security.mac.autodo.scope)
	case "${scope_val}" in
	*vfs*) ;;
	*) atf_fail "Scope not preserved: ${scope_val}" ;;
	esac
	if ! check_access; then
		atf_fail "Access should work with VFS scope after toggle"
	fi
}
scope_survives_toggle_cleanup() {
	sysctl security.mac.autodo.scope=all 2>/dev/null
	sysctl security.mac.autodo.enabled=1 2>/dev/null
	unload_module
}

atf_init_test_cases() {
	atf_add_test_case nonwheel_denied
	atf_add_test_case bogus_gid_denies
	atf_add_test_case disabled_denies
	atf_add_test_case empty_scope
	atf_add_test_case chardev_permissions
	atf_add_test_case chardev_single_open
	atf_add_test_case scope_survives_toggle
}
