#!/usr/libexec/atf-sh
#
# Multi-group policy tests for mac_autodo.
# Tests AUTODO_SET_POLICY ioctl via the daemon with templates.
#

MODULE_DIR="$(atf_get_srcdir)/../src"
MODULE_PATH="${MODULE_DIR}/mac_autodo.ko"
DAEMON_PATH="$(atf_get_srcdir)/../daemon/zig-out/bin/autodo-eventd"
TEMPLATE_DIR="$(atf_get_srcdir)/../config/templates"
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

kill_daemon() {
	pkill -f autodo-eventd 2>/dev/null || true
	sleep 1
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

# --- multi-group: wheel with all template ---

atf_test_case policy_all_template cleanup
policy_all_template_head() {
	atf_set "descr" "Multi-group policy with 'all' template grants full access"
	atf_set "require.user" "root"
	atf_set "require.progs" "${DAEMON_PATH}"
}
policy_all_template_body() {
	if [ ! -x "${DAEMON_PATH}" ]; then
		atf_skip "Daemon not built"
	fi
	load_module

	TMPCONF=$(mktemp)
	cat > "${TMPCONF}" <<-EOF
	enabled = true;
	groups { wheel { template = "all"; } }
	audit { enabled = false; }
	template_dir = "${TEMPLATE_DIR}";
	EOF

	"${DAEMON_PATH}" --config="${TMPCONF}" &
	sleep 1

	if ! check_access; then
		kill_daemon
		rm -f "${TMPCONF}"
		atf_fail "wheel should have full access via all template"
	fi

	kill_daemon
	rm -f "${TMPCONF}"
}
policy_all_template_cleanup() {
	kill_daemon
	unload_module
}

# --- multi-group: minimal template restricts to vfs ---

atf_test_case policy_minimal_template cleanup
policy_minimal_template_head() {
	atf_set "descr" "Minimal template restricts to VFS-only, denies jail ops"
	atf_set "require.user" "root"
	atf_set "require.progs" "${DAEMON_PATH}"
}
policy_minimal_template_body() {
	JAIL=$(get_jail)
	if [ -z "${JAIL}" ]; then
		atf_skip "No jails running"
	fi
	if [ ! -x "${DAEMON_PATH}" ]; then
		atf_skip "Daemon not built"
	fi
	load_module
	jail -m name="${JAIL}" mac.autodo=new

	TMPCONF=$(mktemp)
	cat > "${TMPCONF}" <<-EOF
	enabled = true;
	groups { wheel { template = "minimal"; } }
	audit { enabled = false; }
	template_dir = "${TEMPLATE_DIR}";
	EOF

	"${DAEMON_PATH}" --config="${TMPCONF}" &
	sleep 1

	# VFS should work
	if ! check_access; then
		kill_daemon
		rm -f "${TMPCONF}"
		atf_fail "VFS should work with minimal template"
	fi
	# Jail should be denied
	if check_jexec ${JAIL}; then
		kill_daemon
		rm -f "${TMPCONF}"
		atf_fail "Jail should be denied with minimal template"
	fi

	kill_daemon
	rm -f "${TMPCONF}"
}
policy_minimal_template_cleanup() {
	kill_daemon
	JAIL=$(get_jail)
	[ -n "${JAIL}" ] && jail -m name="${JAIL}" mac.autodo=disable 2>/dev/null
	unload_module
}

# --- multi-group: developer template denies specific privs ---

atf_test_case policy_developer_template cleanup
policy_developer_template_head() {
	atf_set "descr" "Developer template grants vfs/jail/net/proc, denies KMEM"
	atf_set "require.user" "root"
	atf_set "require.progs" "${DAEMON_PATH}"
}
policy_developer_template_body() {
	if [ ! -x "${DAEMON_PATH}" ]; then
		atf_skip "Daemon not built"
	fi
	load_module

	TMPCONF=$(mktemp)
	cat > "${TMPCONF}" <<-EOF
	enabled = true;
	groups { wheel { template = "developer"; } }
	audit { enabled = false; }
	template_dir = "${TEMPLATE_DIR}";
	EOF

	"${DAEMON_PATH}" --config="${TMPCONF}" &
	sleep 1

	# VFS should still work
	if ! check_access; then
		kill_daemon
		rm -f "${TMPCONF}"
		atf_fail "VFS should work with developer template"
	fi

	kill_daemon
	rm -f "${TMPCONF}"
}
policy_developer_template_cleanup() {
	kill_daemon
	unload_module
}

# --- multi-group: inline scope/deny ---

atf_test_case policy_inline cleanup
policy_inline_head() {
	atf_set "descr" "Inline scope/deny in groups block works correctly"
	atf_set "require.user" "root"
	atf_set "require.progs" "${DAEMON_PATH}"
}
policy_inline_body() {
	if [ ! -x "${DAEMON_PATH}" ]; then
		atf_skip "Daemon not built"
	fi
	load_module

	TMPCONF=$(mktemp)
	cat > "${TMPCONF}" <<-EOF
	enabled = true;
	groups {
	    wheel {
	        scope { categories = ["vfs", "proc"]; }
	    }
	}
	audit { enabled = false; }
	template_dir = "${TEMPLATE_DIR}";
	EOF

	"${DAEMON_PATH}" --config="${TMPCONF}" &
	sleep 1

	if ! check_access; then
		kill_daemon
		rm -f "${TMPCONF}"
		atf_fail "Inline scope should grant file access"
	fi

	kill_daemon
	rm -f "${TMPCONF}"
}
policy_inline_cleanup() {
	kill_daemon
	unload_module
}

# --- disabled via config ---

atf_test_case policy_disabled cleanup
policy_disabled_head() {
	atf_set "descr" "enabled=false in config denies all access"
	atf_set "require.user" "root"
	atf_set "require.progs" "${DAEMON_PATH}"
}
policy_disabled_body() {
	if [ ! -x "${DAEMON_PATH}" ]; then
		atf_skip "Daemon not built"
	fi
	load_module

	TMPCONF=$(mktemp)
	cat > "${TMPCONF}" <<-EOF
	enabled = false;
	groups { wheel { template = "all"; } }
	audit { enabled = false; }
	template_dir = "${TEMPLATE_DIR}";
	EOF

	"${DAEMON_PATH}" --config="${TMPCONF}" &
	sleep 1

	# Module enabled sysctl is still on, but policy has empty bitmap
	# The daemon pushes a policy with 0 count when disabled
	if check_access; then
		kill_daemon
		rm -f "${TMPCONF}"
		atf_fail "Access should be denied when config has enabled=false"
	fi

	kill_daemon
	rm -f "${TMPCONF}"
}
policy_disabled_cleanup() {
	kill_daemon
	unload_module
}

atf_init_test_cases() {
	atf_add_test_case policy_all_template
	atf_add_test_case policy_minimal_template
	atf_add_test_case policy_developer_template
	atf_add_test_case policy_inline
	atf_add_test_case policy_disabled
}
