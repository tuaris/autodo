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

#include <security/mac/mac_policy.h>

static int	autodo_enabled = 1;
static int	autodo_gid = 0;
static int	autodo_log_grants = 0;
static unsigned long autodo_grant_count = 0;

static struct timeval autodo_log_lasttime;

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

	if (!autodo_enabled)
		return (EPERM);

	if (!autodo_cred_has_gid(cred, (gid_t)autodo_gid))
		return (EPERM);

	atomic_add_long(&autodo_grant_count, 1);

	if (autodo_log_grants &&
	    ratecheck(&autodo_log_lasttime, &(struct timeval){1, 0}))
		printf("mac_autodo: grant priv %d to uid %u (pid %d, %s)\n",
		    priv, cred->cr_uid, curproc->p_pid, curproc->p_comm);

	return (0);
}

static struct mac_policy_ops autodo_ops = {
	.mpo_priv_grant = autodo_priv_grant,
};

MAC_POLICY_SET(&autodo_ops, mac_autodo,
    "MAC/autodo: transparent privilege escalation",
    MPC_LOADTIME_FLAG_UNLOADOK, NULL);
