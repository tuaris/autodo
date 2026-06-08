#!/usr/libexec/atf-sh
#
# Privilege scoping tests for mac_autodo.
# Tests category-based bitmap, invalid categories, deny-by-scope.
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

check_jexec() {
	su -m ${TEST_USER} -c "jexec $1 hostname" >/dev/null 2>&1
}

get_jail() {
	jls -n name 2>/dev/null | head -1 | sed 's/name=//'
}

# --- scope defaults to all ---

atf_test_case scope_default cleanup
scope_default_head() {
	atf_set "descr" "Default scope is 'all'"
	atf_set "require.user" "root"
}
scope_default_body() {
	load_module
	atf_check -s exit:0 -o match:"all" sysctl security.mac.autodo.scope
}
scope_default_cleanup() {
	unload_module
}

# --- vfs scope grants file access ---

atf_test_case scope_vfs_grants cleanup
scope_vfs_grants_head() {
	atf_set "descr" "VFS scope grants file access"
	atf_set "require.user" "root"
}
scope_vfs_grants_body() {
	load_module
	sysctl security.mac.autodo.scope=vfs
	if ! check_access; then
		atf_fail "VFS scope should grant file access"
	fi
}
scope_vfs_grants_cleanup() {
	sysctl security.mac.autodo.scope=all 2>/dev/null
	unload_module
}

# --- vfs-only scope denies jail operations ---

atf_test_case scope_vfs_denies_jail cleanup
scope_vfs_denies_jail_head() {
	atf_set "descr" "VFS-only scope denies jail operations"
	atf_set "require.user" "root"
}
scope_vfs_denies_jail_body() {
	JAIL=$(get_jail)
	if [ -z "${JAIL}" ]; then
		atf_skip "No jails running"
	fi
	load_module
	jail -m name="${JAIL}" mac.autodo=new
	sysctl security.mac.autodo.scope=vfs
	if check_jexec ${JAIL}; then
		atf_fail "VFS-only scope should deny jail operations"
	fi
}
scope_vfs_denies_jail_cleanup() {
	JAIL=$(get_jail)
	[ -n "${JAIL}" ] && jail -m name="${JAIL}" mac.autodo=disable 2>/dev/null
	sysctl security.mac.autodo.scope=all 2>/dev/null
	unload_module
}

# --- adding jail category restores jexec ---

atf_test_case scope_vfs_jail cleanup
scope_vfs_jail_head() {
	atf_set "descr" "VFS+jail scope allows both file access and jexec"
	atf_set "require.user" "root"
}
scope_vfs_jail_body() {
	JAIL=$(get_jail)
	if [ -z "${JAIL}" ]; then
		atf_skip "No jails running"
	fi
	load_module
	jail -m name="${JAIL}" mac.autodo=new
	sysctl security.mac.autodo.scope=vfs,jail
	if ! check_access; then
		atf_fail "VFS+jail scope should grant file access"
	fi
	if ! check_jexec ${JAIL}; then
		atf_fail "VFS+jail scope should grant jail operations"
	fi
}
scope_vfs_jail_cleanup() {
	JAIL=$(get_jail)
	[ -n "${JAIL}" ] && jail -m name="${JAIL}" mac.autodo=disable 2>/dev/null
	sysctl security.mac.autodo.scope=all 2>/dev/null
	unload_module
}

# --- invalid category rejected ---

atf_test_case scope_invalid cleanup
scope_invalid_head() {
	atf_set "descr" "Invalid scope category is rejected with EINVAL"
	atf_set "require.user" "root"
}
scope_invalid_body() {
	load_module
	atf_check -s exit:1 -o ignore -e ignore sysctl security.mac.autodo.scope=bogus
	# Verify scope didn't change
	scope_val=$(sysctl -n security.mac.autodo.scope)
	case "${scope_val}" in
	*all*) ;;
	*) atf_fail "Scope changed after invalid input: ${scope_val}" ;;
	esac
}
scope_invalid_cleanup() {
	sysctl security.mac.autodo.scope=all 2>/dev/null
	unload_module
}

# --- all individual categories accepted ---

atf_test_case scope_all_categories cleanup
scope_all_categories_head() {
	atf_set "descr" "All 12 category names are accepted individually"
	atf_set "require.user" "root"
}
scope_all_categories_body() {
	load_module
	for cat in system audit cred debug jail kld proc vfs vm dev net misc; do
		atf_check -s exit:0 -o ignore sysctl security.mac.autodo.scope=${cat}
	done
}
scope_all_categories_cleanup() {
	sysctl security.mac.autodo.scope=all 2>/dev/null
	unload_module
}

# --- scope restore to all ---

atf_test_case scope_restore cleanup
scope_restore_head() {
	atf_set "descr" "Restoring scope to 'all' re-grants full access"
	atf_set "require.user" "root"
}
scope_restore_body() {
	load_module
	sysctl security.mac.autodo.scope=vfs
	sysctl security.mac.autodo.scope=all
	if ! check_access; then
		atf_fail "Restoring scope to all should grant access"
	fi
}
scope_restore_cleanup() {
	sysctl security.mac.autodo.scope=all 2>/dev/null
	unload_module
}

atf_init_test_cases() {
	atf_add_test_case scope_default
	atf_add_test_case scope_vfs_grants
	atf_add_test_case scope_vfs_denies_jail
	atf_add_test_case scope_vfs_jail
	atf_add_test_case scope_invalid
	atf_add_test_case scope_all_categories
	atf_add_test_case scope_restore
}
