#!/usr/libexec/atf-sh
#
# Stress and regression tests for mac_autodo.
# Tests concurrent access, load/unload cycles, sysctl changes under load.
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

# --- concurrent privilege checks ---

atf_test_case concurrent_access cleanup
concurrent_access_head() {
	atf_set "descr" "Multiple concurrent processes can use privileges"
	atf_set "require.user" "root"
	atf_set "timeout" "30"
}
concurrent_access_body() {
	load_module

	# Spawn 20 parallel readers as non-root wheel user
	PIDS=""
	for i in $(seq 1 20); do
		(for j in $(seq 1 50); do su -m ${TEST_USER} -c "cat ${TEST_FILE}" >/dev/null; done) &
		PIDS="${PIDS} $!"
	done

	# Wait for all, collect failures
	FAILED=0
	for pid in ${PIDS}; do
		if ! wait ${pid}; then
			FAILED=$((FAILED + 1))
		fi
	done

	if [ ${FAILED} -ne 0 ]; then
		atf_fail "${FAILED} of 20 workers failed"
	fi
}
concurrent_access_cleanup() {
	unload_module
}

# --- load/unload cycles ---

atf_test_case load_unload_cycles cleanup
load_unload_cycles_head() {
	atf_set "descr" "Module survives 10 rapid load/unload cycles"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
}
load_unload_cycles_body() {
	for i in $(seq 1 10); do
		kldload "${MODULE_PATH}" || atf_fail "load failed on cycle ${i}"
		check_access || atf_fail "access failed on cycle ${i}"
		kldunload mac_autodo || atf_fail "unload failed on cycle ${i}"
	done
}
load_unload_cycles_cleanup() {
	unload_module
}

# --- sysctl toggle under load ---

atf_test_case sysctl_under_load cleanup
sysctl_under_load_head() {
	atf_set "descr" "Toggling sysctls while processes access files"
	atf_set "require.user" "root"
	atf_set "timeout" "30"
}
sysctl_under_load_body() {
	load_module

	# Background continuous reader as non-root wheel user
	(while true; do su -m ${TEST_USER} -c "cat ${TEST_FILE}" >/dev/null 2>&1; done) &
	READER_PID=$!

	# Toggle enable/disable rapidly
	for i in $(seq 1 20); do
		sysctl security.mac.autodo.enabled=0 >/dev/null 2>&1
		sysctl security.mac.autodo.enabled=1 >/dev/null 2>&1
	done

	# Toggle scope rapidly
	for i in $(seq 1 20); do
		sysctl security.mac.autodo.scope=vfs >/dev/null 2>&1
		sysctl security.mac.autodo.scope=all >/dev/null 2>&1
	done

	kill ${READER_PID} 2>/dev/null
	wait ${READER_PID} 2>/dev/null || true

	# Module should still be functional
	sysctl security.mac.autodo.enabled=1 >/dev/null
	sysctl security.mac.autodo.scope=all >/dev/null
	if ! check_access; then
		atf_fail "Module not functional after stress"
	fi
}
sysctl_under_load_cleanup() {
	sysctl security.mac.autodo.enabled=1 2>/dev/null
	sysctl security.mac.autodo.scope=all 2>/dev/null
	unload_module
}

# --- grant counter consistency ---

atf_test_case counter_consistency cleanup
counter_consistency_head() {
	atf_set "descr" "Grant counter is consistent after burst of privilege checks"
	atf_set "require.user" "root"
}
counter_consistency_body() {
	load_module
	count_before=$(sysctl -n security.mac.autodo.grant_count)
	for i in $(seq 1 100); do
		check_access || true
	done
	count_after=$(sysctl -n security.mac.autodo.grant_count)
	delta=$((count_after - count_before))
	# Each cat triggers multiple priv checks (VFS_READ, etc.)
	# so delta should be >> 100. Just verify it moved substantially.
	if [ ${delta} -lt 100 ]; then
		atf_fail "grant_count delta too small: ${delta} (expected >= 100)"
	fi
}
counter_consistency_cleanup() {
	unload_module
}

atf_init_test_cases() {
	atf_add_test_case concurrent_access
	atf_add_test_case load_unload_cycles
	atf_add_test_case sysctl_under_load
	atf_add_test_case counter_consistency
}
