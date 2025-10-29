# Creating SS7 defense lab zip package for user to download.
import os, zipfile, textwrap, pathlib

out_dir = "/mnt/data/ss7_lab_package"
os.makedirs(out_dir, exist_ok=True)

# Main installer script (ss7-full-lab.sh) - compacted version from above
installer = textwrap.dedent("""\
    #!/usr/bin/env bash
    # Zero-touch SS7/SIP Defense Lab installer for Debian 12 (Bookworm)
    # Made by Taylor Christian Newsome
    set -euo pipefail
    LOG=/var/log/ss7-full-lab-install.log
    exec > >(tee -a "$LOG") 2>&1

    LAB=/opt/ss7-lab
    SRC=$LAB/src
    PCAPS=$LAB/pcaps
    BIN=$LAB/bin
    PYVENV=$LAB/venv

    if [ "$(id -u)" -ne 0 ]; then
      echo "ERROR: must run as root"; exit 1
    fi

    echo "=== SS7 + SIP defense lab installer started: $(date -Iseconds) ==="
    echo "This host will be modified. Ensure it's an isolated lab host."

    export DEBIAN_FRONTEND=noninteractive
    apt update -y
    apt upgrade -y

    apt install -y --no-install-recommends \\
      build-essential git curl wget ca-certificates gnupg lsb-release \\
      autoconf automake libtool pkgconf pkg-config cmake \\
      python3 python3-venv python3-pip python3-distutils \\
      tcpdump tshark wireshark-common wireshark \\
      lksctp-tools libsctp-dev libpcap-dev libssl-dev libxml2-dev \\
      libncurses5-dev libsqlite3-dev libedit-dev uuid-dev libjansson-dev sqlite3 \\
      iptables iproute2 net-tools unzip jq

    apt install -y suricata || true

    # Docker
    if ! command -v docker >/dev/null 2>&1; then
      curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
      apt update -y
      apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    fi

    rm -rf "$LAB"
    mkdir -p "$SRC" "$PCAPS" "$BIN"
    chmod 0775 "$LAB" "$SRC" "$PCAPS" "$BIN"

    if command -v setcap >/dev/null 2>&1; then
      setcap 'cap_net_raw,cap_net_admin+eip' /usr/bin/dumpcap || true
    fi

    python3 -m venv "$PYVENV"
    "$PYVENV/bin/pip" install --upgrade pip setuptools wheel
    "$PYVENV/bin/pip" install --break-system-packages scapy pyshark || true

    cd "$SRC"
    git clone --depth 1 https://gitea.osmocom.org/osmocom/libosmo-sigtran.git || true
    git clone --depth 1 https://github.com/orangecertcc/pwnss7.git || true
    git clone --depth 1 https://github.com/pjsip/pjproject.git || true
    git clone --depth 1 https://gerrit.asterisk.org/asterisk || git clone --depth 1 https://github.com/asterisk/asterisk.git || true

    # Build attempts (best-effort, continue on failures)
    if [ -d "$SRC/libosmo-sigtran" ]; then
      cd "$SRC/libosmo-sigtran"
      autoreconf -fi 2>/dev/null || true
      ./configure --prefix=/usr || true
      make -j"$(nproc)" || true
      make install || true
    fi

    if [ -d "$SRC/pjproject" ]; then
      cd "$SRC/pjproject"
      CFLAGS="-fPIC" ./configure --prefix=/usr --enable-shared=no --disable-srtp --disable-opencore-amr || true
      make dep -j"$(nproc)" || true
      make -j"$(nproc)" || true
      make install || true
      ldconfig || true
    fi

    if [ -d "$SRC/asterisk" ]; then
      cd "$SRC/asterisk"
      ./contrib/scripts/get_mp3_source.sh >/dev/null 2>&1 || true
      ./configure --with-pjproject=/usr || true
      make -j"$(nproc)" || true
      make install || true
      make samples || true
      make config || true
      systemctl enable asterisk || true
    fi

    AST_ETC=/etc/asterisk
    mkdir -p "$AST_ETC"
    cat > "$AST_ETC/pjsip_monitor.conf" <<'EOF'
    [transport-udp]
    type=transport
    protocol=udp
    bind=0.0.0.0

    [monitor]
    type=endpoint
    context=from-monitor
    disallow=all
    allow=ulaw
    EOF

    # Suricata rule
    SUR_RULE_DIR=/etc/suricata/rules
    mkdir -p "$SUR_RULE_DIR"
    cat > "$SUR_RULE_DIR/ss7-advanced.rules" <<'RULE'
    alert tcp any any -> any any (msg:"SS7: MT-ForwardSM SUBSCRIBE PREMIUM"; content:"SUBSCRIBE PREMIUM"; nocase; sid:10000010; rev:1; )
    alert tcp any any -> any any (msg:"SS7: MT-ForwardSM payload"; content:"MT-ForwardSM"; nocase; sid:10000011; rev:1; )
    alert udp any any -> any any (msg:"SS7: TCAP/MAP - SendAuthenticationInfo"; content:"SendAuthenticationInfo"; nocase; sid:10000013; rev:1; )
    RULE
    if ! grep -q "ss7-advanced.rules" /etc/suricata/suricata.yaml 2>/dev/null; then
      sed -i '/rule-files:/a\  - ss7-advanced.rules' /etc/suricata/suricata.yaml || true
    fi
    systemctl restart suricata || true

    # Docker-compose
    cat > "$LAB/docker-compose.yml" <<'YAML'
    version: "3.8"
    services:
      pwnss7:
        image: python:3.11-slim
        container_name: pwnss7
        network_mode: "host"
        volumes:
          - ./src/pwnss7:/root/pwnss7
        working_dir: /root/pwnss7
        tty: true
        stdin_open: true

      stp_build:
        build:
          context: ./src/libosmo-sigtran
        container_name: osmo-stp
        network_mode: "host"
        cap_add: [ "NET_ADMIN","NET_RAW" ]
        privileged: true

      sniffer:
        image: nicolaka/netshoot:latest
        container_name: ss7-sniffer
        network_mode: "host"
        volumes:
          - ./pcaps:/pcaps
        command: /bin/bash -c "mkdir -p /pcaps && tcpdump -i any -s0 -w /pcaps/ss7-$(date -u +%Y%m%dT%H%M%SZ).pcapng 'sctp or port 2905 or port 3868 or tcp or udp' "
    YAML

    # helpers
    mkdir -p "$BIN"
    cat > "$BIN/capture_now.sh" <<'SH'
    #!/usr/bin/env bash
    OUTDIR=/opt/ss7-lab/pcaps; mkdir -p "$OUTDIR"
    IF="${1:-any}"; DUR="${2:-300}"
    OUT="$OUTDIR/ss7-$(date -u +%Y%m%dT%H%M%SZ).pcapng"
    timeout "$DUR" tcpdump -i "$IF" -s0 -w "$OUT" 'sctp or port 2905 or port 3868 or tcp or udp' || true
    echo "$OUT"
    SH
    chmod +x "$BIN/capture_now.sh"

    cat > "$BIN/parse_latest.sh" <<'SH'
    #!/usr/bin/env bash
    F="${1:-$(ls -1t /opt/ss7-lab/pcaps | head -n1 2>/dev/null)}"
    [ -f "/opt/ss7-lab/pcaps/$F" ] || { echo "No captures"; exit 2; }
    tshark -r "/opt/ss7-lab/pcaps/$F" -Y 'm3ua || sccp || tcap || gsm_map || sms || sip' -T fields -e frame.time -e ip.src -e ip.dst -e sctp.srcport -e sctp.dstport -e sip.From -e sip.To -e sms.msg_text -E separator=' | ' -E quote=d || true
    SH
    chmod +x "$BIN/parse_latest.sh"

    cat > "$BIN/tether_nats.sh" <<'SH'
    #!/usr/bin/env bash
    M="${1:-usb0}"; L="${2:-eth0}"
    iptables -t nat -C POSTROUTING -o "$M" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$M" -j MASQUERADE
    iptables -C FORWARD -i "$L" -o "$M" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$L" -o "$M" -j ACCEPT
    echo "NAT: $L -> $M"
    SH
    chmod +x "$BIN/tether_nats.sh"

    # systemd units
    cat > /etc/systemd/system/ss7-pcap-capture.service <<'UNIT'
    [Unit]
    Description=SS7 continuous pcap capture
    After=network.target
    [Service]
    Type=simple
    ExecStart=/opt/ss7-lab/bin/capture_now.sh any 0
    Restart=always
    RestartSec=5
    User=root
    [Install]
    WantedBy=multi-user.target
    UNIT

    cat > /etc/systemd/system/ss7-docker-stack.service <<'UNIT'
    [Unit]
    Description=SS7 docker compose stack
    After=docker.service
    Requires=docker.service
    [Service]
    Type=oneshot
    RemainAfterExit=yes
    WorkingDirectory=/opt/ss7-lab
    ExecStart=/usr/bin/docker compose up -d
    ExecStop=/usr/bin/docker compose down
    [Install]
    WantedBy=multi-user.target
    UNIT

    systemctl daemon-reload || true
    systemctl enable --now ss7-pcap-capture.service || true
    systemctl enable --now ss7-docker-stack.service || true

    chmod -R 0775 "$LAB" || true
    echo "=== INSTALL COMPLETE ==="
    echo "Made by Taylor Christian Newsome"
    """)

# Suricata advanced rules file
sur_rules = textwrap.dedent("""\
    # SS7 / SIGTRAN / SMS / SIP detection rules
    # Made by Taylor Christian Newsome
    alert tcp any any -> any any (msg:"SS7: MT-ForwardSM SUBSCRIBE PREMIUM"; content:"SUBSCRIBE PREMIUM"; nocase; sid:10000010; rev:1; )
    alert tcp any any -> any any (msg:"SS7: MT-ForwardSM payload"; content:"MT-ForwardSM"; nocase; sid:10000011; rev:1; )
    alert udp any any -> any any (msg:"SS7: TCAP/MAP - SendAuthenticationInfo"; content:"SendAuthenticationInfo"; nocase; sid:10000013; rev:1; )
    """)

# Zeek script
zeek_script = textwrap.dedent("""\
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

    global ss7_log: log_list = open_log_stream("ss7_events", [$columns=SS7Event, $path="ss7_events.log"]);

    function log_event(c: connection, proto: string, note: string, raw: string)
    {
        local rec: SS7Event = [$ts=network_time(), $src=c$id$resp_h, $dst=c$id$orig_h, $proto=proto, $note=note, $raw=raw];
        write(ss7_log, rec);
    }

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

    event sip_request(caller: connection, msg: Info) &priority=5
    {
        local method = msg$method;
        if ( method == "INVITE" || method == "REGISTER" ) {
            log_event(caller, "SIP", fmt("SIP %s observed", method), msg$raw);
        }
    }
    """)

# Vagrantfile
vagrantfile = textwrap.dedent("""\
    Vagrant.configure("2") do |config|
      config.vm.box = "bento/debian-12"
      config.vm.hostname = "ss7-lab"
      config.vm.provider "virtualbox" do |vb|
        vb.memory = 4096
        vb.cpus = 2
      end
      config.vm.synced_folder ".", "/opt/ss7-lab", type: "virtualbox"
      config.vm.provision "shell", privileged: true, inline: <<-SHELL
        set -e
        if [ -f /opt/ss7-lab/ss7-full-lab.sh ]; then
          chmod +x /opt/ss7-lab/ss7-full-lab.sh
          nohup /opt/ss7-lab/ss7-full-lab.sh > /var/log/ss7-vagrant-install.log 2>&1 &
        else
          echo "Installer /opt/ss7-lab/ss7-full-lab.sh not found!"; exit 1
        fi
      SHELL
    end
    """)

# README
readme = textwrap.dedent("""\
    SS7 + SIP Defense Lab Package
    =============================
    Files included:
    - ss7-full-lab.sh         (main zero-touch installer)
    - /etc/suricata/rules/ss7-advanced.rules (Suricata rules)
    - /opt/ss7-lab/zeek/ss7-detect.zeek      (Zeek script)
    - Vagrantfile            (to spin a VM and auto-run installer)
    - README.txt             (this file)

    Usage:
    1) Copy 'ss7-full-lab.sh' to /root on a fresh Debian 12 VM and run:
       sudo bash /root/ss7-full-lab.sh
    2) To use Vagrant: put this entire package in a repo root with Vagrant installed and run 'vagrant up'.
    3) Suricata rules are included; the installer attempts to place them under /etc/suricata/rules.
    4) Zeek script is included; installer will not overwrite your Zeek install location -- copy to your Zeek site dir if installed.

    WARNING: Use only on isolated/test hosts you control. Made by Taylor Christian Newsome
    """)

# Write files
files = {
    "ss7-full-lab.sh": installer,
    "ss7-advanced.rules": sur_rules,
    "ss7-detect.zeek": zeek_script,
    "Vagrantfile": vagrantfile,
    "README.txt": readme
}

for fname, content in files.items():
    path = os.path.join(out_dir, fname)
    with open(path, "w", newline="\n") as f:
        f.write(content)
    os.chmod(path, 0o755 if fname.endswith(".sh") else 0o644)

# Create zip
zip_path = "/mnt/data/ss7-lab.zip"
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
    for root, dirs, filenames in os.walk(out_dir):
        for fn in filenames:
            full = os.path.join(root, fn)
            arc = os.path.relpath(full, out_dir)
            zf.write(full, arc)

zip_path

