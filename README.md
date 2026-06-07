# mac_autodo

A FreeBSD MAC policy module that transparently grants privileges to authorized
users without requiring explicit privilege escalation tools (`mdo`, `sudo`,
`doas`).

## Philosophy

The system owner is not an adversary.  If the kernel knows you are authorized
to perform privileged operations (via group membership and configured policy),
it should not force you to ask permission every single time.

## Requirements

- FreeBSD 15.0 or later
- Kernel sources installed (for module build)

## Quick Start

```sh
cd src
make
doas kldload ./mac_autodo.ko
# You now have implicit root privileges as a wheel member
cat /etc/master.passwd   # works without mdo/doas/sudo
```

## Configuration

Once loaded, the module is controlled via sysctl:

```sh
# Check if enabled
sysctl security.mac.autodo.enabled

# Disable without unloading
sysctl security.mac.autodo.enabled=0

# Change authorized GID (default: 0 = wheel)
sysctl security.mac.autodo.gid=0
```

## Persistence

```sh
# /boot/loader.conf
mac_autodo_load="YES"

# /etc/sysctl.conf
security.mac.autodo.enabled=1
```

## How It Works

The module implements the `mac_priv_grant()` MAC framework hook.  When the
standard DAC (Unix permissions) denies an operation and the kernel checks
whether the process holds the required privilege, `mac_autodo` checks if the
calling process belongs to the authorized group.  If so, it grants the
privilege — the operation succeeds as if the process were running as root.

## License

BSD-2-Clause
