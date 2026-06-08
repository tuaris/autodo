/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Daniel Morante
 *
 * Shared definitions for mac_autodo kernel module and autodo-eventd daemon.
 */

#ifndef _AUTODO_H_
#define	_AUTODO_H_

#include <sys/ioccom.h>

/*
 * Privilege scope bitmap dimensions.
 * _PRIV_HIGHEST is 703, so ceil(703/64) = 11 words covers all privileges.
 */
#define	AUTODO_BITMAP_WORDS	11
#define	AUTODO_BITMAP_BYTES	(AUTODO_BITMAP_WORDS * 8)

/*
 * Ring buffer size for audit events.
 */
#define	AUTODO_RING_SIZE	1024

/*
 * Audit event structure.
 * Emitted by the kernel on each privilege grant (when audit is enabled).
 * Fixed-size for simple ring buffer indexing.
 */
struct autodo_event {
	uint64_t	ae_timestamp;	/* nanoseconds since boot (nanouptime) */
	uint32_t	ae_pid;
	uint32_t	ae_uid;
	uint32_t	ae_gid;
	int32_t		ae_priv;	/* priv(9) constant */
	uint8_t		ae_granted;	/* 1 = granted, 0 = denied by scope */
	uint8_t		ae_pad[3];
	char		ae_comm[20];	/* MAXCOMLEN + 1 = 20 on FreeBSD */
};	/* 48 bytes total */

/*
 * Scope bitmap for ioctl (legacy single-group interface).
 */
struct autodo_scope {
	uint64_t	as_bitmap[AUTODO_BITMAP_WORDS];
};

/*
 * Multi-group policy.
 * Each entry maps a GID to a privilege bitmap.
 * The daemon resolves group names, compiles templates/deny lists
 * into bitmaps, and pushes the whole policy to the kernel.
 */
#define	AUTODO_MAX_GROUPS	16

struct autodo_policy_entry {
	uint32_t	ape_gid;
	uint32_t	ape_pad;
	uint64_t	ape_bitmap[AUTODO_BITMAP_WORDS];
};

struct autodo_policy {
	uint32_t	ap_count;		/* active entries (0..16) */
	uint32_t	ap_pad;
	struct autodo_policy_entry ap_entries[AUTODO_MAX_GROUPS];
};

/*
 * ioctl commands on /dev/autodo.
 *
 * AUTODO_SET_SCOPE  — push a compiled privilege bitmap (legacy single-group)
 * AUTODO_GET_SCOPE  — read the current privilege bitmap (legacy)
 * AUTODO_FLUSH      — discard all pending events in the ring buffer
 * AUTODO_SET_POLICY — push a multi-group policy from daemon to kernel
 * AUTODO_GET_POLICY — read the current multi-group policy
 */
#define	AUTODO_SET_SCOPE	_IOW('A', 1, struct autodo_scope)
#define	AUTODO_GET_SCOPE	_IOR('A', 2, struct autodo_scope)
#define	AUTODO_FLUSH		_IO('A', 3)
#define	AUTODO_SET_POLICY	_IOW('A', 4, struct autodo_policy)
#define	AUTODO_GET_POLICY	_IOR('A', 5, struct autodo_policy)

#endif /* _AUTODO_H_ */
