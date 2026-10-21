#!/usr/bin/env bash
# Scenario 2: Privilege-related activity (read attempt + fake user record)
set -e

WORKDIR="/tmp/ft_scenario02"
rm -rf "$WORKDIR"; mkdir -p "$WORKDIR"; cd "$WORKDIR"

# Attempt to read a privileged file; will fail as non-root but still traced
cat /etc/shadow > /dev/null 2>&1 || true

# Simulated post-escalation activity
echo "newuser:x:1001:1001::/home/newuser:/bin/sh" > fake_passwd_entry
cat fake_passwd_entry
rm -f fake_passwd_entry
