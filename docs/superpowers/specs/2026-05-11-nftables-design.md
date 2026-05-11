# ipscromp 3.0 — nftables backend

**Date:** 2026-05-11
**Branch:** claude-ipv6 (extending current PR)

## Context

ipscromp is a firewall port-knocking daemon. The client authenticates over a
challenge-response protocol; the daemon calls a firewall helper script to open
the client's IP. The firewall backend has always been fully abstracted behind
`scripts/ipscromp_dynfw` — the C code just calls `ipscromp_dynfw open <ip>`.

The previous backend used iptables with a spool directory
(`/var/spool/ipscromp`) and `ipscromp_gatekeeper` (a C binary run from cron
every minute) to expire authenticated IPs after 10 hours. nftables set element
timeouts make the entire spool/gatekeeper/cron mechanism redundant.

## Version

3.0. Matches the precedent of 2.0 (complete firewall backend rewrite).

## nftables structure

ipscromp owns a dedicated `inet ipscromp` table. This avoids injecting into
the user's existing ruleset and makes the ipscromp state self-contained.

```
table inet ipscromp {
    set allow4 { type ipv4_addr; flags timeout; timeout 10h; }
    set allow6 { type ipv6_addr; flags timeout; timeout 10h; }

    chain input {
        type filter hook input priority -10; policy accept;
        ip  saddr @allow4 tcp dport { 22, 1022, 2525 } accept
        ip6 saddr @allow6 tcp dport { 22, 1022, 2525 } accept
    }
}
```

Priority -10 ensures the ipscromp ACCEPT rules are evaluated before the
user's main filter chain (priority 0). The chain/set rules never change at
runtime — only set elements are added/removed.

Address family is detected by presence of `:` in the IP string. IPv4 addresses
go into `allow4`, IPv6 into `allow6`.

Default timeout: 10h (matches the previous crontab value of 600 minutes).
Configurable via variable at the top of both setup and dynfw scripts.

## Files

### New
- `scripts/ipscromp_nft_setup` — creates the table/sets/chain above. Idempotent:
  checks for existing table before creating; will not clobber set contents on
  re-run. Documents how to persist rules across reboots (distro-specific).

### Rewritten
- `scripts/ipscromp_dynfw` — nftables implementation.
  `open <ip>`: `nft add element inet ipscromp allow{4,6} { <ip> }`
  `close <ip>`: `nft delete element inet ipscromp allow{4,6} { <ip> }` (silent if not present)

### Renamed (kept for iptables deployments)
- `scripts/ipscromp_dynfw.iptables` — current iptables script, renamed.

### Simplified
- `fw_touch.c` — drops all spool file I/O (`ip_to_filename`, stat/fopen/fprintf,
  FW_DIRECTORY dependency). Becomes: resolve IP string, call dynfw, return 0.

### Retired (source kept, removed from build)
- `ipscromp_gatekeeper.c` — comment added noting retirement; removed from Makefile.
- `scripts/ipscromp_crontab` — comment added noting retirement.
- `FW_DIRECTORY` — removed from Makefile CFLAGS; `#error` guard removed from
  fw_touch.c.

### Updated
- `CHANGES` — 3.0 entry.
- `README` — note nftables requirement and setup script.
- `Makefile` — remove gatekeeper target and FW_DIRECTORY define.

### Untouched
All daemon/client C code (`in.ipscrompd.c`, `auth_proto_v2.c`, `ipscromp.c`,
`common.c`, `fw_test.c`, `ipscromp.py`). The `fw_add_ip` interface is unchanged.

## Ports opened

22, 1022, 2525 — carried over from existing dynfw. Configurable via variable
in the setup script.

## Expiry

nftables removes set elements automatically when their timeout expires. The
gatekeeper, crontab, and spool directory are no longer needed. `nft list set
inet ipscromp allow4` shows current authenticated IPv4 addresses.

## Setup / deployment

1. Run `ipscromp_nft_setup` once (or on each boot before the daemon starts).
2. Ensure the `inet ipscromp` table is persisted across reboots using the
   distro's nftables persistence mechanism (e.g., `nft list ruleset >
   /etc/nftables.conf` on systems using `/etc/nftables.conf`).
3. Remove the ipscromp_gatekeeper crontab entry if present.
4. No changes to xinetd/inetd configuration.

## Out of scope

- Per-user timeout configuration (future: pass timeout from C code via dynfw argv).
- Migrating existing spool directory contents to nftables on upgrade.
- nftables persistence automation (distro-specific, documented not scripted).
