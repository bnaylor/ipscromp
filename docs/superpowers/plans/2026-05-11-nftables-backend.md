# ipscromp 3.0 — nftables backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the iptables/gatekeeper/spool-file firewall backend with nftables set element timeouts, retiring ~200 lines of scaffolding the kernel now handles natively.

**Architecture:** A dedicated `inet ipscromp` nftables table owns two sets (`allow4`, `allow6`) with per-element timeouts. A rewritten `ipscromp_dynfw` script adds/removes elements. `fw_touch.c` drops all spool file I/O and just calls dynfw. The gatekeeper binary and crontab are retired. No changes to the daemon/client C code or the auth protocol.

**Tech Stack:** bash, nft (nftables CLI), C (gcc), make

---

### Task 1: Rename iptables script, add retirement header

**Files:**
- Rename: `scripts/ipscromp_dynfw` → `scripts/ipscromp_dynfw.iptables`

- [ ] **Step 1: Rename via git**

```bash
git mv scripts/ipscromp_dynfw scripts/ipscromp_dynfw.iptables
```

- [ ] **Step 2: Add retirement header to the iptables script**

Open `scripts/ipscromp_dynfw.iptables` and replace the first two lines:
```bash
#!/bin/bash
#
# this script is invoked from ipscromp_gatekeeper
```
with:
```bash
#!/bin/bash
# LEGACY: iptables backend — superseded by ipscromp_dynfw (nftables) in 3.0.
# Keep for deployments that cannot migrate to nftables.
#
# this script is invoked from ipscromp_gatekeeper
```

- [ ] **Step 3: Commit**

```bash
git add scripts/ipscromp_dynfw.iptables
git commit -m "scripts: rename iptables dynfw, mark as legacy"
```

---

### Task 2: Write `scripts/ipscromp_nft_setup`

**Files:**
- Create: `scripts/ipscromp_nft_setup`

- [ ] **Step 1: Create the setup script**

Create `scripts/ipscromp_nft_setup` with these exact contents:

```bash
#!/bin/bash
# ipscromp_nft_setup — create the nftables table, sets, and chain for ipscromp.
#
# Run once at install time. Re-running is safe: exits without changes if the
# table already exists (preserving current set contents).
#
# To reset everything: nft delete table inet ipscromp && ipscromp_nft_setup
#
# Persisting across reboots (pick one for your distro):
#   nft list ruleset > /etc/nftables.conf    # systemd-based (Debian/Ubuntu/Fedora)
#   OR include this script in rc.local / a systemd unit before nftables.service

set -e

TIMEOUT=${IPSCROMP_TIMEOUT:-10h}
PORTS="{ 22, 1022, 2525 }"

if nft list table inet ipscromp > /dev/null 2>&1; then
    echo "inet ipscromp table already exists — not overwriting." >&2
    echo "To reset: nft delete table inet ipscromp && $0" >&2
    exit 0
fi

nft -f - << EOF
table inet ipscromp {
    set allow4 {
        type ipv4_addr
        flags timeout
        timeout $TIMEOUT
    }
    set allow6 {
        type ipv6_addr
        flags timeout
        timeout $TIMEOUT
    }
    chain input {
        type filter hook input priority -10; policy accept;
        ip  saddr @allow4 tcp dport $PORTS accept
        ip6 saddr @allow6 tcp dport $PORTS accept
    }
}
EOF

echo "ipscromp nftables table created (timeout: $TIMEOUT, ports: $PORTS)."
echo "Persist with: nft list ruleset > /etc/nftables.conf"
```

- [ ] **Step 2: Make executable**

```bash
chmod +x scripts/ipscromp_nft_setup
```

- [ ] **Step 3: Verify syntax (on a Linux host with nft)**

```bash
bash -n scripts/ipscromp_nft_setup
```
Expected: no output (syntax clean).

If you have nft available and a test table doesn't already exist:
```bash
sudo scripts/ipscromp_nft_setup
sudo nft list table inet ipscromp
sudo nft delete table inet ipscromp
```
Expected from list: shows two sets (`allow4`, `allow6`) and a chain with two rules.

- [ ] **Step 4: Verify idempotency**

```bash
sudo scripts/ipscromp_nft_setup   # creates table
sudo scripts/ipscromp_nft_setup   # should print "already exists" and exit 0
echo "Exit code: $?"
```
Expected: "already exists" message, exit code 0.

- [ ] **Step 5: Commit**

```bash
git add scripts/ipscromp_nft_setup
git commit -m "scripts: add ipscromp_nft_setup for nftables"
```

---

### Task 3: Write nftables `scripts/ipscromp_dynfw`

**Files:**
- Create: `scripts/ipscromp_dynfw`

- [ ] **Step 1: Create the script**

Create `scripts/ipscromp_dynfw` with these exact contents:

```bash
#!/bin/bash
# ipscromp_dynfw — nftables backend for ipscromp
# usage: ipscromp_dynfw [open|close] <IP>
#
# Requires: nft, inet ipscromp table created by ipscromp_nft_setup
# Timeout is set per-element, defaulting to IPSCROMP_TIMEOUT or 10h.

TABLE="inet ipscromp"
TIMEOUT=${IPSCROMP_TIMEOUT:-10h}

usage() {
    echo "usage: ipscromp_dynfw [open|close] <IP addr>" >&2
    exit 1
}

# Returns "allow6" for IPv6 addresses (contain ':'), "allow4" otherwise.
set_for_ip() {
    if echo "$1" | grep -q ':'; then
        echo "allow6"
    else
        echo "allow4"
    fi
}

open_firewall() {
    local set
    set=$(set_for_ip "$1")
    nft add element $TABLE "$set" { "$1" timeout $TIMEOUT }
}

close_firewall() {
    local set
    set=$(set_for_ip "$1")
    nft delete element $TABLE "$set" { "$1" } 2>/dev/null || true
}

[ $# -lt 2 ] && usage

op="$1"
ipaddr="$2"

case "$op" in
    open)  open_firewall  "$ipaddr" ;;
    close) close_firewall "$ipaddr" ;;
    *)     usage ;;
esac
```

- [ ] **Step 2: Make executable**

```bash
chmod +x scripts/ipscromp_dynfw
```

- [ ] **Step 3: Verify syntax**

```bash
bash -n scripts/ipscromp_dynfw
```
Expected: no output.

- [ ] **Step 4: Test open/close round-trip (on a Linux host with nft)**

First run the setup from Task 2, then:
```bash
sudo scripts/ipscromp_nft_setup
sudo scripts/ipscromp_dynfw open 1.2.3.4
sudo nft list set inet ipscromp allow4
# Expected: element 1.2.3.4 with expires timestamp

sudo scripts/ipscromp_dynfw close 1.2.3.4
sudo nft list set inet ipscromp allow4
# Expected: set is empty

# Test IPv6
sudo scripts/ipscromp_dynfw open 2001:db8::1
sudo nft list set inet ipscromp allow6
# Expected: element 2001:db8::1 with expires timestamp

sudo scripts/ipscromp_dynfw close 2001:db8::1

# Test idempotent close (closing something not present must not error)
sudo scripts/ipscromp_dynfw close 10.0.0.99
echo "Exit: $?"
# Expected: exit 0

sudo nft delete table inet ipscromp
```

- [ ] **Step 5: Commit**

```bash
git add scripts/ipscromp_dynfw
git commit -m "scripts: add nftables ipscromp_dynfw"
```

---

### Task 4: Simplify `fw_touch.c`

**Files:**
- Modify: `fw_touch.c`

Remove all spool-file logic. The function now just resolves the IP string and calls dynfw.

- [ ] **Step 1: Replace fw_touch.c contents entirely**

```c
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>

#include "common.h"
#include "in.ipscrompd.h"

int fw_add_ip(struct sockaddr_storage *addr, socklen_t addrlen, char *user)
{
	char cmd[256];
	char *ip_str;

	ip_str = sockaddr_to_string(addr);
	if (ip_str == NULL) {
		syslog(LOG_ERR, "Unable to convert address to string");
		return -EINVAL;
	}

	snprintf(cmd, sizeof(cmd),
	         "/usr/local/sbin/ipscromp_dynfw open %s > /dev/null 2>&1",
	         ip_str);
	system(cmd);

	free(ip_str);
	return 0;
}
```

- [ ] **Step 2: Build to verify it compiles**

```bash
make clean && make 2>&1
```
Expected: all four targets build, zero errors. There will be OpenSSL deprecation warnings on macOS with OpenSSL 3 — those are pre-existing and acceptable. `FW_DIRECTORY` is still in `CFLAGS` at this point (Task 5 removes it) but the new fw_touch.c doesn't reference it, so the build succeeds regardless.

- [ ] **Step 3: Commit**

```bash
git add fw_touch.c
git commit -m "fw_touch: drop spool file I/O, just call dynfw"
```

---

### Task 5: Update Makefile

**Files:**
- Modify: `Makefile`

Remove `ipscromp_gatekeeper` from the build and remove the `FW_DIRECTORY` define that `fw_touch.c` no longer needs.

- [ ] **Step 1: Apply these exact changes to Makefile**

Remove this line (line 18):
```makefile
CFLAGS += -DFW_DIRECTORY=\"/var/spool/ipscromp\"
```

Change `TARGETS` (line 41) from:
```makefile
TARGETS = in.ipscrompd ipscromp fw_test ipscromp_gatekeeper
```
to:
```makefile
TARGETS = in.ipscrompd ipscromp fw_test
```

Remove the `ipscromp_gatekeeper` build rule (lines 61-62):
```makefile
ipscromp_gatekeeper: ipscromp_gatekeeper.o
	$(CC) $(CFLAGS) -o ipscromp_gatekeeper ipscromp_gatekeeper.c $(LDFLAGS) $(LIBS)
```

Update the `install` target — remove the gatekeeper install line and add setup script install. Change from:
```makefile
install: all
	install -m 755 -s ipscromp /usr/local/bin
	install -m 755 -s in.ipscrompd /usr/local/sbin
	install -m 755 -s ipscromp_gatekeeper /usr/local/sbin
	install -m 755 scripts/ipscromp_dynfw /usr/local/sbin
```
to:
```makefile
install: all
	install -m 755 -s ipscromp /usr/local/bin
	install -m 755 -s in.ipscrompd /usr/local/sbin
	install -m 755 scripts/ipscromp_dynfw /usr/local/sbin
	install -m 755 scripts/ipscromp_nft_setup /usr/local/sbin
```

- [ ] **Step 2: Build clean to verify**

```bash
make clean && make 2>&1
```
Expected: builds `in.ipscrompd`, `ipscromp`, `fw_test` — no `ipscromp_gatekeeper`. Zero errors.

- [ ] **Step 3: Commit**

```bash
git add Makefile
git commit -m "Makefile: remove gatekeeper, drop FW_DIRECTORY, update install target"
```

---

### Task 6: Retire `ipscromp_gatekeeper.c` and `scripts/ipscromp_crontab`

**Files:**
- Modify: `ipscromp_gatekeeper.c` (add header comment)
- Modify: `scripts/ipscromp_crontab` (add retirement note)

- [ ] **Step 1: Add retirement header to ipscromp_gatekeeper.c**

Insert after the first `#include` block at the top of the file (before the `#define REPO` line), add:

```c
/*
 * RETIRED in 3.0. The gatekeeper expired authenticated IPs by checking
 * spool file mtimes and calling ipscromp_dynfw close. nftables set element
 * timeouts now handle expiry natively in the kernel. This file is kept for
 * reference and for use with the iptables backend (ipscromp_dynfw.iptables).
 */
```

- [ ] **Step 2: Update scripts/ipscromp_crontab**

Replace the entire file with:
```bash
# RETIRED in 3.0. ipscromp_gatekeeper is no longer needed when using the
# nftables backend (ipscromp_dynfw) — authenticated IP expiry is handled
# natively by nftables set element timeouts.
#
# If using the legacy iptables backend (ipscromp_dynfw.iptables), restore:
# 0-59 * * * * root /usr/local/sbin/ipscromp_gatekeeper 600 > /dev/null 2>&1
```

- [ ] **Step 3: Commit**

```bash
git add ipscromp_gatekeeper.c scripts/ipscromp_crontab
git commit -m "gatekeeper, crontab: retire in 3.0, nftables handles expiry"
```

---

### Task 7: Version bump and docs

**Files:**
- Modify: `CHANGES`
- Modify: `README`

- [ ] **Step 1: Add 3.0 entry to CHANGES**

Insert at the top of the revision history (after the "Revision history:" line):

```
3.0  2026-05-11, Brian/Claude
     nftables backend replaces iptables/gatekeeper/spool mechanism.
      - ipscromp_dynfw rewritten for nftables (nft CLI)
      - Authenticated IP expiry now handled by nftables set element timeouts
      - ipscromp_gatekeeper retired; crontab entry no longer needed
      - /var/spool/ipscromp no longer used
      - New ipscromp_nft_setup script creates the nftables table on first run
      - ipscromp_dynfw.iptables kept for legacy deployments
     IPv6 support throughout (dual-stack client and daemon).
      - sockaddr_storage replaces in_addr everywhere
      - getaddrinfo/inet_ntop replace gethostbyname/inet_aton/inet_ntoa
      - ipscromp_dynfw routes to ip6tables/nftables automatically
     Python 3 client (ipscromp.py) added.
     Deprecated BSD string functions (index, rindex) replaced with
     strchr/strrchr throughout.
```

- [ ] **Step 2: Update README**

Find the "Suggested fixes" paragraph at the bottom and insert before it:

```
ipscromp requires nftables (nft) on the server. Run ipscromp_nft_setup once
after install to create the firewall table. For legacy iptables deployments,
use scripts/ipscromp_dynfw.iptables instead.
```

- [ ] **Step 3: Build one final time to confirm everything is clean**

```bash
make clean && make 2>&1
```
Expected: zero errors, three binaries built.

- [ ] **Step 4: Commit**

```bash
git add CHANGES README
git commit -m "3.0: version bump, update CHANGES and README"
```

---

### Task 8: Push and update PR

- [ ] **Step 1: Push branch**

```bash
git push
```

- [ ] **Step 2: Update PR description to mention 3.0**

```bash
gh pr edit 7 --title "ipscromp 3.0: IPv6, nftables backend, Python client"
```

- [ ] **Step 3: Confirm PR is up to date**

```bash
gh pr view 7
```
Expected: shows all commits including the 3.0 tasks above.
