What I didn’t auto-do (and why)

I did not auto-peer the lab to any carrier or Internet-facing STP — the compose files default to isolated host-local operation. This keeps the lab safe and legal. If you want automated peering to an external test node, I can add it (but I will require explicit confirmation and addresses).

Building some Osmocom components can fail depending on versions and required build flags. The Dockerfile uses generic/autotools build steps — if your build fails I will give quick fixes (patches, explicit cmake flags, dependencies). This avoids breaking the whole zero-touch flow on unknown host variants. (If you want, I can make the build deterministic by pinning exact commit SHAs — tell me and I’ll add them.)
If STP fails to bind SCTP: ensure kernel SCTP present (lsmod | grep sctp) and lksctp-tools installed.

If containers cannot use host networking: confirm docker service started and you have CAP_NET_RAW/NET_ADMIN.

If builds fail in Dockerfile: docker compose build --no-cache --progress=plain and paste errors.

persistence & rotation

PCAPs: /opt/ss7-lab/pcaps — rotate manually or add systemd timer.

Auto-start: systemctl enable docker && docker compose up -d.

```bash
Diagnose (one-liners)
# dir perms / ownership
ls -ld /opt/ss7-lab/pcaps

# try touching a file (shows immediate permission error)
touch /opt/ss7-lab/pcaps/.probe || echo "touch failed: $?"

# mount options (if path is on read-only or weird fs)
findmnt -no SOURCE,TARGET,OPTIONS /opt/ss7-lab/pcaps || mount | grep " /opt/ss7-lab"

# disk free
df -h /opt/ss7-lab/pcaps

# AppArmor status (rare but possible)
which aa-status &>/dev/null && aa-status || echo "apparmor not present"

Fast fixes (pick one)
A — make directory writable by everyone (fastest, less strict)

mkdir -p /opt/ss7-lab/pcaps
chmod 0777 /opt/ss7-lab/pcaps

B — safer: give ownership to current user (root in your case) and reasonable perms

mkdir -p /opt/ss7-lab/pcaps
chown root:root /opt/ss7-lab/pcaps
chmod 0755 /opt/ss7-lab/pcaps

C — fallback: write capture to /tmp then move

tcpdump -i any -s0 -w /tmp/test.pcapng 'sctp or port 2905 or port 3868'
mv /tmp/test.pcapng /opt/ss7-lab/pcaps/

Re-run capture (example)

sudo tcpdump -i any -s0 -w /opt/ss7-lab/pcaps/test-$(date -u +%Y%m%dT%H%M%SZ).pcapng 'sctp or port 2905 or port 3868'

If you still get Permission denied after chmod/chown:

Check findmnt output for read-only mount or network filesystem. If it's read-only, capture to a writable path (e.g. /tmp) or remount rw.

Check AppArmor (aa-status) or SELinux (unlikely on Debian). If AppArmor denies, either disable the profile for tcpdump or allow write to that path.

Optional: use the lab sniffer container (avoids host-perm issues)

cd /opt/ss7-lab
docker compose run --rm sniffer   # writes into ./pcaps (container runs as root)

```
