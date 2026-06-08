#!/usr/libexec/atf-sh
#
# Per-jail mac_autodo tests.
# Tests enable/disable/inherit jail parameters.
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

check_jexec_file() {
	su -m ${TEST_USER} -c "jexec $1 cat ${TEST_FILE}" >/dev/null 2>&1
}

get_jail() {
	jls -n name 2>/dev/null | head -1 | sed 's/name=//'
}

# --- jails default to disabled ---

atf_test_case jail_default_disabled cleanup
jail_default_disabled_head() {
	atf_set "descr" "Jails default to mac.autodo=disable"
	atf_set "require.user" "root"
}
jail_default_disabled_body() {
	JAIL=$(get_jail)
	if [ -z "${JAIL}" ]; then
		atf_skip "No jails running"
	fi
	load_module
	if check_jexec_file ${JAIL}; then
		atf_fail "Jail should default to disabled"
	fi
}
jail_default_disabled_cleanup() {
	unload_module
}

# --- enable via mac.autodo=new ---

atf_test_case jail_enable cleanup
jail_enable_head() {
	atf_set "descr" "mac.autodo=new enables privileges in jail"
	atf_set "require.user" "root"
}
jail_enable_body() {
	JAIL=$(get_jail)
	if [ -z "${JAIL}" ]; then
		atf_skip "No jails running"
	fi
	load_module
	jail -m name="${JAIL}" mac.autodo=new
	if ! check_jexec_file ${JAIL}; then
		atf_fail "Jail access should be granted after mac.autodo=new"
	fi
}
jail_enable_cleanup() {
	JAIL=$(get_jail)
	[ -n "${JAIL}" ] && jail -m name="${JAIL}" mac.autodo=disable 2>/dev/null
	unload_module
}

# --- disable after enable ---

atf_test_case jail_disable cleanup
jail_disable_head() {
	atf_set "descr" "mac.autodo=disable revokes jail privileges"
	atf_set "require.user" "root"
}
jail_disable_body() {
	JAIL=$(get_jail)
	if [ -z "${JAIL}" ]; then
		atf_skip "No jails running"
	fi
	load_module
	jail -m name="${JAIL}" mac.autodo=new
	if ! check_jexec_file ${JAIL}; then
		atf_fail "Jail should be accessible after enable"
	fi
	jail -m name="${JAIL}" mac.autodo=disable
	if check_jexec_file ${JAIL}; then
		atf_fail "Jail should be denied after disable"
	fi
}
jail_disable_cleanup() {
	JAIL=$(get_jail)
	[ -n "${JAIL}" ] && jail -m name="${JAIL}" mac.autodo=disable 2>/dev/null
	unload_module
}

# --- inherit from host ---

atf_test_case jail_inherit cleanup
jail_inherit_head() {
	atf_set "descr" "mac.autodo=inherit inherits host policy"
	atf_set "require.user" "root"
}
jail_inherit_body() {
	JAIL=$(get_jail)
	if [ -z "${JAIL}" ]; then
		atf_skip "No jails running"
	fi
	load_module
	jail -m name="${JAIL}" mac.autodo=inherit
	if ! check_jexec_file ${JAIL}; then
		atf_fail "Jail should inherit host policy"
	fi
}
jail_inherit_cleanup() {
	JAIL=$(get_jail)
	[ -n "${JAIL}" ] && jail -m name="${JAIL}" mac.autodo=disable 2>/dev/null
	unload_module
}

# --- invalid jail parameter value ---

atf_test_case jail_invalid_value cleanup
jail_invalid_value_head() {
	atf_set "descr" "Invalid mac.autodo value is rejected"
	atf_set "require.user" "root"
}
jail_invalid_value_body() {
	JAIL=$(get_jail)
	if [ -z "${JAIL}" ]; then
		atf_skip "No jails running"
	fi
	load_module
	atf_check -s exit:1 -e ignore \
	    jail -m name="${JAIL}" mac.autodo=42
}
jail_invalid_value_cleanup() {
	unload_module
}

atf_init_test_cases() {
	atf_add_test_case jail_default_disabled
	atf_add_test_case jail_enable
	atf_add_test_case jail_disable
	atf_add_test_case jail_inherit
	atf_add_test_case jail_invalid_value
}
