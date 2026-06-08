/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Daniel Morante
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * mac_autodo - Transparent privilege escalation for authorized users.
 *
 * This MAC policy module grants privileges to processes whose credentials
 * include membership in a configured group (default: wheel/GID 0), without
 * requiring explicit use of mdo(1), sudo(8), or doas(1).
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/jail.h>
#include <sys/osd.h>
#include <sys/mount.h>
#include <sys/sx.h>
#include <sys/conf.h>
#include <sys/ioccom.h>
#include <sys/malloc.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include <sys/selinfo.h>
#include <sys/filio.h>
#include <sys/event.h>

#include <security/mac/mac_policy.h>

#include "autodo.h"

/*
 * Privilege scope bitmap.
 *
 * _PRIV_HIGHEST is 703, so we need ceil(703/64) = 11 uint64_t words.
 * A set bit means the privilege IS granted.  Default: all bits set ("all").
 */
#define	AUTODO_BITMAP_BITS	(AUTODO_BITMAP_WORDS * 64)

static volatile uint64_t autodo_scope_bitmap[AUTODO_BITMAP_WORDS];

static inline int
autodo_priv_in_scope(int priv)
{
	unsigned word, bit;

	if (priv <= 0 || priv >= AUTODO_BITMAP_BITS)
		return (0);
	word = (unsigned)priv / 64;
	bit = (unsigned)priv % 64;
	return ((autodo_scope_bitmap[word] >> bit) & 1);
}

static inline void
autodo_bitmap_set(volatile uint64_t *bitmap, int priv)
{
	unsigned word, bit;

	if (priv <= 0 || priv >= AUTODO_BITMAP_BITS)
		return;
	word = (unsigned)priv / 64;
	bit = (unsigned)priv % 64;
	bitmap[word] |= (1UL << bit);
}

static inline void
autodo_bitmap_clear(volatile uint64_t *bitmap, int priv)
{
	unsigned word, bit;

	if (priv <= 0 || priv >= AUTODO_BITMAP_BITS)
		return;
	word = (unsigned)priv / 64;
	bit = (unsigned)priv % 64;
	bitmap[word] &= ~(1UL << bit);
}

static void
autodo_bitmap_fill(volatile uint64_t *bitmap)
{
	int i;

	for (i = 0; i < AUTODO_BITMAP_WORDS; i++)
		bitmap[i] = ~0UL;
}

/*
 * Privilege categories for the 'scope' sysctl.
 * Each category maps to a range of priv(9) constants.
 */
#define	AUTODO_CAT_SYSTEM	0x0001
#define	AUTODO_CAT_AUDIT	0x0002
#define	AUTODO_CAT_CRED		0x0004
#define	AUTODO_CAT_DEBUG	0x0008
#define	AUTODO_CAT_JAIL		0x0010
#define	AUTODO_CAT_KLD		0x0020
#define	AUTODO_CAT_PROC		0x0040
#define	AUTODO_CAT_VFS		0x0080
#define	AUTODO_CAT_VM		0x0100
#define	AUTODO_CAT_DEV		0x0200
#define	AUTODO_CAT_NET		0x0400
#define	AUTODO_CAT_MISC		0x0800
#define	AUTODO_CAT_ALL		0x0FFF

struct autodo_priv_range {
	int	start;
	int	end;	/* inclusive */
};

static const struct autodo_priv_range autodo_cat_ranges[] = {
	[0]  = { 2, 18 },	/* SYSTEM: ACCT..SETTIMEOFDAY */
	[1]  = { 40, 44 },	/* AUDIT */
	[2]  = { 50, 62 },	/* CRED */
	[3]  = { 80, 92 },	/* DEBUG + DTRACE */
	[4]  = { 110, 112 },	/* JAIL */
	[5]  = { 130, 141 },	/* KLD + MAC */
	[6]  = { 160, 242 },	/* PROC: PROC,IPC,MQ,PMC,SCHED,SEM,SIGNAL,SYSCTL */
	[7]  = { 310, 345 },	/* VFS */
	[8]  = { 360, 364 },	/* VM */
	[9]  = { 370, 380 },	/* DEV: DEVFS,RANDOM */
	[10] = { 390, 540 },	/* NET: all networking */
	[11] = { 550, 702 },	/* MISC: MODULE,KMEM,RCTL,VERIEXEC,etc */
};

#define	AUTODO_NUM_CATS	(sizeof(autodo_cat_ranges) / sizeof(autodo_cat_ranges[0]))

/*
 * Rebuild the scope bitmap from a category bitmask.
 */
static void
autodo_rebuild_bitmap(uint32_t cats)
{
	int i, p;

	/* Start with empty bitmap. */
	for (i = 0; i < AUTODO_BITMAP_WORDS; i++)
		autodo_scope_bitmap[i] = 0;

	if (cats == AUTODO_CAT_ALL) {
		autodo_bitmap_fill(autodo_scope_bitmap);
		return;
	}

	for (i = 0; i < (int)AUTODO_NUM_CATS; i++) {
		if (!(cats & (1U << i)))
			continue;
		for (p = autodo_cat_ranges[i].start;
		    p <= autodo_cat_ranges[i].end; p++)
			autodo_bitmap_set(autodo_scope_bitmap, p);
	}
}

static uint32_t	autodo_scope_cats = AUTODO_CAT_ALL;

/*
 * Sysctl handler for 'scope' — accepts comma-separated category names or "all".
 */
static int
autodo_sysctl_scope(SYSCTL_HANDLER_ARGS)
{
	char buf[128];
	uint32_t new_cats;
	int error;
	char *p, *token;

	/* Build current string representation for reading. */
	if (autodo_scope_cats == AUTODO_CAT_ALL)
		strlcpy(buf, "all", sizeof(buf));
	else {
		buf[0] = '\0';
		if (autodo_scope_cats & AUTODO_CAT_SYSTEM)
			strlcat(buf, "system,", sizeof(buf));
		if (autodo_scope_cats & AUTODO_CAT_AUDIT)
			strlcat(buf, "audit,", sizeof(buf));
		if (autodo_scope_cats & AUTODO_CAT_CRED)
			strlcat(buf, "cred,", sizeof(buf));
		if (autodo_scope_cats & AUTODO_CAT_DEBUG)
			strlcat(buf, "debug,", sizeof(buf));
		if (autodo_scope_cats & AUTODO_CAT_JAIL)
			strlcat(buf, "jail,", sizeof(buf));
		if (autodo_scope_cats & AUTODO_CAT_KLD)
			strlcat(buf, "kld,", sizeof(buf));
		if (autodo_scope_cats & AUTODO_CAT_PROC)
			strlcat(buf, "proc,", sizeof(buf));
		if (autodo_scope_cats & AUTODO_CAT_VFS)
			strlcat(buf, "vfs,", sizeof(buf));
		if (autodo_scope_cats & AUTODO_CAT_VM)
			strlcat(buf, "vm,", sizeof(buf));
		if (autodo_scope_cats & AUTODO_CAT_DEV)
			strlcat(buf, "dev,", sizeof(buf));
		if (autodo_scope_cats & AUTODO_CAT_NET)
			strlcat(buf, "net,", sizeof(buf));
		if (autodo_scope_cats & AUTODO_CAT_MISC)
			strlcat(buf, "misc,", sizeof(buf));
		/* Remove trailing comma. */
		p = buf + strlen(buf) - 1;
		if (p >= buf && *p == ',')
			*p = '\0';
	}

	error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
	if (error != 0 || req->newptr == NULL)
		return (error);

	/* Parse new value. */
	if (strcmp(buf, "all") == 0) {
		new_cats = AUTODO_CAT_ALL;
	} else {
		new_cats = 0;
		p = buf;
		while ((token = strsep(&p, ",")) != NULL) {
			if (*token == '\0')
				continue;
			if (strcmp(token, "system") == 0)
				new_cats |= AUTODO_CAT_SYSTEM;
			else if (strcmp(token, "audit") == 0)
				new_cats |= AUTODO_CAT_AUDIT;
			else if (strcmp(token, "cred") == 0)
				new_cats |= AUTODO_CAT_CRED;
			else if (strcmp(token, "debug") == 0)
				new_cats |= AUTODO_CAT_DEBUG;
			else if (strcmp(token, "jail") == 0)
				new_cats |= AUTODO_CAT_JAIL;
			else if (strcmp(token, "kld") == 0)
				new_cats |= AUTODO_CAT_KLD;
			else if (strcmp(token, "proc") == 0)
				new_cats |= AUTODO_CAT_PROC;
			else if (strcmp(token, "vfs") == 0)
				new_cats |= AUTODO_CAT_VFS;
			else if (strcmp(token, "vm") == 0)
				new_cats |= AUTODO_CAT_VM;
			else if (strcmp(token, "dev") == 0)
				new_cats |= AUTODO_CAT_DEV;
			else if (strcmp(token, "net") == 0)
				new_cats |= AUTODO_CAT_NET;
			else if (strcmp(token, "misc") == 0)
				new_cats |= AUTODO_CAT_MISC;
			else
				return (EINVAL);
		}
		if (new_cats == 0)
			return (EINVAL);
	}

	autodo_scope_cats = new_cats;
	autodo_rebuild_bitmap(new_cats);
	return (0);
}

static int	autodo_enabled = 1;
static int	autodo_gid = 0;
static int	autodo_log_grants = 0;
static unsigned long autodo_grant_count = 0;

static struct timeval autodo_log_lasttime;
static unsigned	autodo_osd_jail_slot;

SYSCTL_NODE(_security_mac, OID_AUTO, autodo, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "mac_autodo policy controls");

SYSCTL_INT(_security_mac_autodo, OID_AUTO, enabled,
    CTLFLAG_RW | CTLFLAG_MPSAFE, &autodo_enabled, 0,
    "Enable transparent privilege escalation for authorized group");

SYSCTL_INT(_security_mac_autodo, OID_AUTO, gid,
    CTLFLAG_RW | CTLFLAG_MPSAFE, &autodo_gid, 0,
    "GID whose members receive implicit privileges (default: 0/wheel)");

SYSCTL_INT(_security_mac_autodo, OID_AUTO, log_grants,
    CTLFLAG_RW | CTLFLAG_MPSAFE, &autodo_log_grants, 0,
    "Log privilege grants to kernel message buffer (rate-limited)");

SYSCTL_ULONG(_security_mac_autodo, OID_AUTO, grant_count,
    CTLFLAG_RD | CTLFLAG_MPSAFE, &autodo_grant_count, 0,
    "Total number of privileges granted (read-only)");

SYSCTL_PROC(_security_mac_autodo, OID_AUTO, scope,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    autodo_sysctl_scope, "A",
    "Privilege scope: comma-separated categories or 'all' (default: all)");

SYSCTL_JAIL_PARAM_SYS_SUBNODE(mac, autodo, CTLFLAG_RW,
    "Jail MAC/autodo parameters");

/* ----------------------------------------------------------------
 * /dev/autodo character device — ring buffer + ioctl interface
 * ---------------------------------------------------------------- */

MALLOC_DEFINE(M_AUTODO, "autodo", "mac_autodo ring buffer");

static struct mtx	autodo_ring_mtx;
static struct autodo_event *autodo_ring;
static unsigned		autodo_ring_head;	/* next write position */
static unsigned		autodo_ring_tail;	/* next read position */
static unsigned		autodo_ring_count;	/* events available */
static struct selinfo	autodo_sel;
static struct cdev	*autodo_cdev;
static int		autodo_dev_open;	/* single-open flag */

static void
autodo_ring_push(const struct autodo_event *ev)
{

	mtx_lock(&autodo_ring_mtx);
	if (autodo_ring == NULL) {
		mtx_unlock(&autodo_ring_mtx);
		return;
	}
	autodo_ring[autodo_ring_head] = *ev;
	autodo_ring_head = (autodo_ring_head + 1) % AUTODO_RING_SIZE;
	if (autodo_ring_count < AUTODO_RING_SIZE)
		autodo_ring_count++;
	else
		autodo_ring_tail = (autodo_ring_tail + 1) % AUTODO_RING_SIZE;
	wakeup(&autodo_ring_count);
	mtx_unlock(&autodo_ring_mtx);
	selwakeup(&autodo_sel);
	KNOTE_UNLOCKED(&autodo_sel.si_note, 0);
}

static void
autodo_emit_event(struct ucred *cred, int priv, int granted)
{
	struct autodo_event ev;
	struct timespec ts;

	nanouptime(&ts);
	ev.ae_timestamp = (uint64_t)ts.tv_sec * 1000000000ULL +
	    (uint64_t)ts.tv_nsec;
	ev.ae_pid = curproc->p_pid;
	ev.ae_uid = cred->cr_uid;
	ev.ae_gid = cred->cr_rgid;
	ev.ae_priv = priv;
	ev.ae_granted = granted ? 1 : 0;
	memset(ev.ae_pad, 0, sizeof(ev.ae_pad));
	strlcpy(ev.ae_comm, curproc->p_comm, sizeof(ev.ae_comm));

	autodo_ring_push(&ev);
}

static int
autodo_dev_open_f(struct cdev *dev __unused, int oflags __unused,
    int devtype __unused, struct thread *td __unused)
{

	if (atomic_cmpset_int(&autodo_dev_open, 0, 1) == 0)
		return (EBUSY);
	return (0);
}

static int
autodo_dev_close_f(struct cdev *dev __unused, int fflag __unused,
    int devtype __unused, struct thread *td __unused)
{

	autodo_dev_open = 0;
	return (0);
}

static int
autodo_dev_read(struct cdev *dev __unused, struct uio *uio,
    int ioflag __unused)
{
	struct autodo_event ev;
	int error;

	mtx_lock(&autodo_ring_mtx);
	while (autodo_ring_count == 0) {
		error = msleep(&autodo_ring_count, &autodo_ring_mtx,
		    PCATCH, "autodo", 0);
		if (error != 0) {
			mtx_unlock(&autodo_ring_mtx);
			return (error);
		}
	}

	while (uio->uio_resid >= (ssize_t)sizeof(ev) &&
	    autodo_ring_count > 0) {
		ev = autodo_ring[autodo_ring_tail];
		autodo_ring_tail = (autodo_ring_tail + 1) % AUTODO_RING_SIZE;
		autodo_ring_count--;
		mtx_unlock(&autodo_ring_mtx);

		error = uiomove(&ev, sizeof(ev), uio);
		if (error != 0)
			return (error);

		mtx_lock(&autodo_ring_mtx);
	}
	mtx_unlock(&autodo_ring_mtx);
	return (0);
}

static int
autodo_dev_poll(struct cdev *dev __unused, int events, struct thread *td)
{
	int revents = 0;

	mtx_lock(&autodo_ring_mtx);
	if (events & (POLLIN | POLLRDNORM)) {
		if (autodo_ring_count > 0)
			revents |= events & (POLLIN | POLLRDNORM);
		else
			selrecord(td, &autodo_sel);
	}
	mtx_unlock(&autodo_ring_mtx);
	return (revents);
}

static int
autodo_dev_ioctl(struct cdev *dev __unused, u_long cmd, caddr_t data,
    int fflag __unused, struct thread *td __unused)
{
	struct autodo_scope *scope;
	int i;

	switch (cmd) {
	case AUTODO_SET_SCOPE:
		scope = (struct autodo_scope *)data;
		for (i = 0; i < AUTODO_BITMAP_WORDS; i++)
			autodo_scope_bitmap[i] = scope->as_bitmap[i];
		return (0);

	case AUTODO_GET_SCOPE:
		scope = (struct autodo_scope *)data;
		for (i = 0; i < AUTODO_BITMAP_WORDS; i++)
			scope->as_bitmap[i] = autodo_scope_bitmap[i];
		return (0);

	case AUTODO_FLUSH:
		mtx_lock(&autodo_ring_mtx);
		autodo_ring_head = 0;
		autodo_ring_tail = 0;
		autodo_ring_count = 0;
		mtx_unlock(&autodo_ring_mtx);
		return (0);

	default:
		return (ENOTTY);
	}
}

static int	autodo_kqread(struct knote *kn, long hint);
static void	autodo_kqdetach(struct knote *kn);

static const struct filterops autodo_read_filterops = {
	.f_isfd = true,
	.f_attach = NULL,
	.f_detach = autodo_kqdetach,
	.f_event = autodo_kqread,
};

static int
autodo_dev_kqfilter(struct cdev *dev __unused, struct knote *kn)
{

	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &autodo_read_filterops;
		knlist_add(&autodo_sel.si_note, kn, 0);
		return (0);
	default:
		return (EINVAL);
	}
}

static int
autodo_kqread(struct knote *kn, long hint __unused)
{

	mtx_lock(&autodo_ring_mtx);
	kn->kn_data = autodo_ring_count * sizeof(struct autodo_event);
	mtx_unlock(&autodo_ring_mtx);
	return (kn->kn_data > 0);
}

static void
autodo_kqdetach(struct knote *kn)
{

	knlist_remove(&autodo_sel.si_note, kn, 0);
}

static struct cdevsw autodo_cdevsw = {
	.d_version = D_VERSION,
	.d_open = autodo_dev_open_f,
	.d_close = autodo_dev_close_f,
	.d_read = autodo_dev_read,
	.d_poll = autodo_dev_poll,
	.d_ioctl = autodo_dev_ioctl,
	.d_kqfilter = autodo_dev_kqfilter,
	.d_name = "autodo",
};

/*
 * Per-jail OSD stores the jail's autodo mode as an intptr_t:
 *   0 (JAIL_SYS_DISABLE) - disabled in this jail
 *   1 (JAIL_SYS_NEW)     - enabled in this jail
 *   2 (JAIL_SYS_INHERIT) - inherit from parent jail
 *
 * We encode the mode +1 in the OSD pointer to distinguish "no OSD set"
 * (NULL) from "explicitly disabled" (value 1).  Decoding: mode = ptr - 1.
 */
#define	AUTODO_OSD_ENCODE(mode)	((void *)((intptr_t)(mode) + 1))
#define	AUTODO_OSD_DECODE(ptr)	((int)((intptr_t)(ptr) - 1))

static void
autodo_osd_jail_destructor(void *value __unused)
{
	/* Nothing to free — we store encoded integers, not pointers. */
}

static int
autodo_jail_create(void *obj, void *data __unused)
{
	struct prison *pr = obj;

	/* New jails default to disabled. */
	osd_jail_set(pr, autodo_osd_jail_slot,
	    AUTODO_OSD_ENCODE(JAIL_SYS_DISABLE));
	return (0);
}

static int
autodo_jail_get(void *obj, void *data)
{
	struct prison *pr = obj;
	struct vfsoptlist *opts = data;
	void *osd_val;
	int jsys, error;

	osd_val = osd_jail_get(pr, autodo_osd_jail_slot);
	if (osd_val == NULL)
		jsys = JAIL_SYS_DISABLE;
	else
		jsys = AUTODO_OSD_DECODE(osd_val);

	error = vfs_setopt(opts, "mac.autodo", &jsys, sizeof(jsys));
	if (error != 0 && error != ENOENT)
		return (error);
	return (0);
}

static int
autodo_jail_check(void *obj __unused, void *data)
{
	struct vfsoptlist *opts = data;
	int error, jsys;

	error = vfs_copyopt(opts, "mac.autodo", &jsys, sizeof(jsys));
	if (error == ENOENT)
		return (0);
	if (error != 0)
		return (error);
	if (jsys != JAIL_SYS_DISABLE && jsys != JAIL_SYS_NEW &&
	    jsys != JAIL_SYS_INHERIT)
		return (EINVAL);
	return (0);
}

static int
autodo_jail_set(void *obj, void *data)
{
	struct prison *pr = obj;
	struct vfsoptlist *opts = data;
	int error, jsys;

	error = vfs_copyopt(opts, "mac.autodo", &jsys, sizeof(jsys));
	if (error == ENOENT)
		return (0);
	if (error != 0)
		return (error);

	osd_jail_set(pr, autodo_osd_jail_slot,
	    AUTODO_OSD_ENCODE(jsys));
	return (0);
}

static const osd_method_t autodo_osd_methods[PR_MAXMETHOD] = {
	[PR_METHOD_CREATE] = autodo_jail_create,
	[PR_METHOD_GET] = autodo_jail_get,
	[PR_METHOD_CHECK] = autodo_jail_check,
	[PR_METHOD_SET] = autodo_jail_set,
};

/*
 * Check if autodo is enabled for the given prison.
 * Walks up the jail hierarchy for JAIL_SYS_INHERIT.
 * Returns 1 if enabled, 0 if disabled.
 */
static int
autodo_jail_enabled(struct prison *pr)
{
	void *osd_val;
	int jsys;

	for (; pr != NULL; pr = pr->pr_parent) {
		osd_val = osd_jail_get(pr, autodo_osd_jail_slot);
		if (osd_val == NULL)
			return (0);
		jsys = AUTODO_OSD_DECODE(osd_val);
		switch (jsys) {
		case JAIL_SYS_NEW:
			return (1);
		case JAIL_SYS_DISABLE:
			return (0);
		case JAIL_SYS_INHERIT:
			continue;
		default:
			return (0);
		}
	}
	return (0);
}

/*
 * Check if the credential includes the authorized GID in any position:
 * real GID, effective GID (cr_groups[0]), or supplementary groups.
 */
static int
autodo_cred_has_gid(struct ucred *cred, gid_t gid)
{
	int i;

	if (cred->cr_rgid == gid)
		return (1);
	for (i = 0; i < cred->cr_ngroups; i++) {
		if (cred->cr_groups[i] == gid)
			return (1);
	}
	return (0);
}

/*
 * MAC hook: mac_priv_grant
 *
 * Called when the kernel is about to deny a privilege.  Returning 0 grants
 * the privilege.  Returning EPERM abstains (leaves the decision to other
 * policies or the default deny).
 */
static int
autodo_priv_grant(struct ucred *cred, int priv)
{
	struct prison *pr;

	if (!autodo_enabled)
		return (EPERM);

	if (!autodo_cred_has_gid(cred, (gid_t)autodo_gid))
		return (EPERM);

	/*
	 * Check privilege scope bitmap.  If the privilege is not in the
	 * configured scope, deny it regardless of group membership.
	 */
	if (!autodo_priv_in_scope(priv))
		return (EPERM);

	/*
	 * Check jail policy.  The host (prison0) is always governed by
	 * the global 'enabled' sysctl above.  For jails, check per-jail
	 * OSD configuration.
	 */
	pr = cred->cr_prison;
	if (pr != &prison0 && !autodo_jail_enabled(pr))
		return (EPERM);

	atomic_add_long(&autodo_grant_count, 1);

	if (autodo_log_grants) {
		autodo_emit_event(cred, priv, 1);
		if (ratecheck(&autodo_log_lasttime, &(struct timeval){1, 0}))
			printf("mac_autodo: grant priv %d to uid %u "
			    "(pid %d, %s)\n",
			    priv, cred->cr_uid, curproc->p_pid,
			    curproc->p_comm);
	}

	return (0);
}

static void
autodo_init(struct mac_policy_conf *mpc __unused)
{
	struct prison *pr;

	/* Initialize scope bitmap to "all" (default). */
	autodo_bitmap_fill(autodo_scope_bitmap);

	/* Initialize ring buffer and chardev. */
	mtx_init(&autodo_ring_mtx, "autodo ring", NULL, MTX_DEF);
	autodo_ring = malloc(sizeof(struct autodo_event) * AUTODO_RING_SIZE,
	    M_AUTODO, M_WAITOK | M_ZERO);
	autodo_ring_head = 0;
	autodo_ring_tail = 0;
	autodo_ring_count = 0;
	autodo_dev_open = 0;
	knlist_init_mtx(&autodo_sel.si_note, &autodo_ring_mtx);
	autodo_cdev = make_dev(&autodo_cdevsw, 0, UID_ROOT, GID_WHEEL,
	    0640, "autodo");

	autodo_osd_jail_slot = osd_jail_register(
	    autodo_osd_jail_destructor, autodo_osd_methods);

	/* Set host jail (prison0) to enabled. */
	osd_jail_set(&prison0, autodo_osd_jail_slot,
	    AUTODO_OSD_ENCODE(JAIL_SYS_NEW));

	/* Set all existing jails to disabled. */
	sx_slock(&allprison_lock);
	TAILQ_FOREACH(pr, &allprison, pr_list) {
		osd_jail_set(pr, autodo_osd_jail_slot,
		    AUTODO_OSD_ENCODE(JAIL_SYS_DISABLE));
	}
	sx_sunlock(&allprison_lock);
}

static void
autodo_destroy(struct mac_policy_conf *mpc __unused)
{

	osd_jail_deregister(autodo_osd_jail_slot);

	if (autodo_cdev != NULL) {
		destroy_dev(autodo_cdev);
		autodo_cdev = NULL;
	}
	seldrain(&autodo_sel);
	knlist_destroy(&autodo_sel.si_note);
	mtx_lock(&autodo_ring_mtx);
	if (autodo_ring != NULL) {
		free(autodo_ring, M_AUTODO);
		autodo_ring = NULL;
	}
	autodo_ring_count = 0;
	mtx_unlock(&autodo_ring_mtx);
	mtx_destroy(&autodo_ring_mtx);
}

static struct mac_policy_ops autodo_ops = {
	.mpo_init = autodo_init,
	.mpo_destroy = autodo_destroy,
	.mpo_priv_grant = autodo_priv_grant,
};

MAC_POLICY_SET(&autodo_ops, mac_autodo,
    "MAC/autodo: transparent privilege escalation",
    MPC_LOADTIME_FLAG_UNLOADOK, NULL);
