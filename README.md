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

```bash
# SS7 / SIGTRAN / SMS / SIP detection rules
# Made by Taylor Christian Newsome

# MT-ForwardSM with obvious subscription keyword
alert tcp any any -> any any (msg:"SS7: MT-ForwardSM SUBSCRIBE PREMIUM"; content:"SUBSCRIBE PREMIUM"; nocase; sid:10000010; rev:1; classtype:bad-unknown;)

# MT-ForwardSM generic: look for MT-ForwardSM text identifier or keyword
alert tcp any any -> any any (msg:"SS7: MT-ForwardSM payload"; content:"MT-ForwardSM"; nocase; sid:10000011; rev:1; classtype:bad-unknown;)

# Detect common MAP/TCAP opcodes (CancelLocation / UpdateLocation / SendRoutingInfo / SendAuthenticationInfo)
alert udp any any -> any any (msg:"SS7: TCAP/MAP operation - CancelLocation/UpdateLocation/SendRoutingInfo/SendAuthenticationInfo"; content:"CancelLocation"; nocase; sid:10000012; rev:1; classtype:attempted-admin;)
alert udp any any -> any any (msg:"SS7: TCAP/MAP - SendAuthenticationInfo"; content:"SendAuthenticationInfo"; nocase; sid:10000013; rev:1; classtype:attempted-admin;)

# IMSI-like pattern (approx): digits 10-16 inside SMS/TCAP payloads (false-positive prone)
alert tcp any any -> any any (msg:"SS7: Potential IMSI pattern"; pcre:"/[0-9]{10,16}/"; sid:10000014; rev:1; classtype:suspicious;)

# SIP monitoring: suspicious REGISTER or INVITE to premium shortcodes
alert udp any any -> any any (msg:"SIP: possible suspicious INVITE/REGISTER"; content:"INVITE"; nocase; sid:10000020; rev:1; classtype:bad-unknown;)
alert udp any any -> any any (msg:"SIP: possible suspicious REGISTER"; content:"REGISTER"; nocase; sid:10000021; rev:1; classtype:bad-unknown;)
```
```bash
# Add include if missing
grep -q "ss7-advanced.rules" /etc/suricata/suricata.yaml || sed -i '/rule-files:/a\  - ss7-advanced.rules' /etc/suricata/suricata.yaml
systemctl restart suricata
suricata-update && systemctl restart suricata || true

@load base/protocols/sip

module SS7Detect;

export {
    redef enum Log::ID += { LOG_SS7 };
}

type SS7Event: record {
    ts: time &log;
    src: addr &log;
    dst: addr &log;
    proto: string &log;
    note: string &log;
    raw: string &log;
};

global ss7_log: log_list = open_log_stream("ss7_events", [$columns=SS7Event,
                                           $path="ss7_events.log"]);

function log_event(c: connection, proto: string, note: string, raw: string)
{
    local rec: SS7Event = [$ts=network_time(), $src=c$id$resp_h, $dst=c$id$orig_h,
                           $proto=proto, $note=note, $raw=raw];
    write(ss7_log, rec);
}

# Simple payload checks for TCP/UDP data
event connection_state_remove(c: connection)
{
    if ( c$history !~ /D/ ) return;
    if ( c$resp$application_data == "" && c$orig$application_data == "" ) return;
    local payload = fmt("%s%s", c$orig$application_data, c$resp$application_data);
    if ( /SUBSCRIBE PREMIUM/i in payload ) {
        log_event(c, "TCP/UDP", "MT-ForwardSM SUBSCRIBE PREMIUM", payload);
    }
    if ( /MT-ForwardSM/i in payload ) {
        log_event(c, "TCP/UDP", "MT-ForwardSM", payload);
    }
    if ( /SendAuthenticationInfo/i in payload || /CancelLocation/i in payload || /SendRoutingInfo/i || /InsertSubscriberData/i ) {
        log_event(c, "TCAP/MAP", "MAP/TCAP operation", payload);
    }
}

# SIP-specific events (INVITE/REGISTER)
event sip_request(caller: connection, msg: Info) &priority=5
{
    local method = msg$method;
    if ( method == "INVITE" || method == "REGISTER" ) {
        log_event(caller, "SIP", fmt("SIP %s observed", method), msg$raw);
    }
}
# install zeek if not present (Debian repo)
apt update && apt install -y zeek
mkdir -p /opt/ss7-lab/zeek
cp ss7-detect.zeek /opt/ss7-lab/zeek/ss7-detect.zeek
# add to local.zeek or zeekctl config: include the script
echo '@load /opt/ss7-lab/zeek/ss7-detect.zeek' >> /usr/local/zeek/share/zeek/site/local.zeek || true
# reload or start zeek
systemctl restart zeek || zeekctl deploy || true

# Vagrantfile - spins Debian 12 and runs the zero-touch installer
Vagrant.configure("2") do |config|
  config.vm.box = "bento/debian-12"
  config.vm.hostname = "ss7-lab"
  config.vm.provider "virtualbox" do |vb|
    vb.memory = 4096
    vb.cpus = 2
  end

  # synced folder: local repo -> /opt/ss7-lab
  config.vm.synced_folder ".", "/opt/ss7-lab", type: "virtualbox"

  # Provision: run the installer (noninteractive)
  config.vm.provision "shell", privileged: true, inline: <<-SHELL
    set -e
    # ensure script exists
    if [ -f /opt/ss7-lab/ss7-full-lab.sh ]; then
      chmod +x /opt/ss7-lab/ss7-full-lab.sh
      nohup /opt/ss7-lab/ss7-full-lab.sh > /var/log/ss7-vagrant-install.log 2>&1 &
    else
      echo "Installer /opt/ss7-lab/ss7-full-lab.sh not found!"
      exit 1
    fi
  SHELL
end
# create zeek dir and copy script
mkdir -p /opt/ss7-lab/zeek
cat > /opt/ss7-lab/zeek/ss7-detect.zeek <<'EOF'
# (paste the Zeek script content above)
EOF

# install zeek and enable script (one-liner)
apt update && apt install -y zeek || true
echo '@load /opt/ss7-lab/zeek/ss7-detect.zeek' >> /usr/local/zeek/share/zeek/site/local.zeek || true
systemctl restart zeek || zeekctl deploy || true

# copy Suricata rules
cat > /etc/suricata/rules/ss7-advanced.rules <<'EOF'
# (paste the Suricata rules content above)
EOF
grep -q "ss7-advanced.rules" /etc/suricata/suricata.yaml || sed -i '/rule-files:/a\  - ss7-advanced.rules' /etc/suricata/suricata.yaml
systemctl restart suricata || true

```
