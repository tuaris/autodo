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
 * Scope bitmap for ioctl.
 */
struct autodo_scope {
	uint64_t	as_bitmap[AUTODO_BITMAP_WORDS];
};

/*
 * ioctl commands on /dev/autodo.
 *
 * AUTODO_SET_SCOPE  — push a compiled privilege bitmap from daemon to kernel
 * AUTODO_GET_SCOPE  — read the current privilege bitmap
 * AUTODO_FLUSH      — discard all pending events in the ring buffer
 */
#define	AUTODO_SET_SCOPE	_IOW('A', 1, struct autodo_scope)
#define	AUTODO_GET_SCOPE	_IOR('A', 2, struct autodo_scope)
#define	AUTODO_FLUSH		_IO('A', 3)

#endif /* _AUTODO_H_ */
