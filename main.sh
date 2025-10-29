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
DOCKER_COMPOSE_VER="v2.21.0"   # packaged docker-compose plugin may vary

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: must run as root"; exit 1
fi

echo "=== SS7 + SIP defense lab installer started: $(date -Iseconds) ==="
echo "This host will be modified. Ensure it's an isolated lab host."

export DEBIAN_FRONTEND=noninteractive
apt update -y
apt upgrade -y

# Basic system packages & build deps
apt install -y --no-install-recommends \
  build-essential git curl wget ca-certificates gnupg lsb-release \
  autoconf automake libtool pkgconf pkg-config cmake \
  python3 python3-venv python3-pip python3-distutils \
  tcpdump tshark wireshark-common wireshark \
  lksctp-tools libsctp-dev libpcap-dev libssl-dev libxml2-dev \
  libncurses5-dev libsqlite3-dev libedit-dev uuid-dev libjansson-dev sqlite3 \
  iptables iproute2 net-tools unzip jq

# Suricata (APT)
apt install -y suricata

# Docker (official)
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
  https://download.docker.com/linux/debian $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
  apt update -y
  apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi

# create directory structure
rm -rf "$LAB"
mkdir -p "$SRC" "$PCAPS" "$BIN"
chmod 0775 "$LAB" "$SRC" "$PCAPS" "$BIN"

# grant dumpcap to non-root captures
if command -v setcap >/dev/null 2>&1; then
  setcap 'cap_net_raw,cap_net_admin+eip' /usr/bin/dumpcap || true
fi

# Python venv + tooling (use --break-system-packages)
python3 -m venv "$PYVENV"
"$PYVENV/bin/pip" install --upgrade pip setuptools wheel
"$PYVENV/bin/pip" install --break-system-packages scapy pyshark

# Clone sources (shallow)
cd "$SRC"
git clone --depth 1 https://gitea.osmocom.org/osmocom/libosmo-sigtran.git || true
git clone --depth 1 https://github.com/orangecertcc/pwnss7.git || true
git clone --depth 1 https://github.com/pjsip/pjproject.git || true
git clone --depth 1 https://gerrit.asterisk.org/asterisk || git clone --depth 1 https://github.com/asterisk/asterisk.git || true

# Build libosmo-sigtran (best-effort)
if [ -d "$SRC/libosmo-sigtran" ]; then
  cd "$SRC/libosmo-sigtran"
  autoreconf -fi 2>/dev/null || true
  ./configure --prefix=/usr || true
  make -j"$(nproc)" || true
  make install || true
fi

# Build pjproject (pjsip) - static-friendly build for Asterisk
if [ -d "$SRC/pjproject" ]; then
  cd "$SRC/pjproject"
  CFLAGS="-fPIC" ./configure --prefix=/usr --enable-shared=no --disable-srtp --disable-opencore-amr || true
  make dep -j"$(nproc)" || true
  make -j"$(nproc)" || true
  make install || true
  ldconfig || true
fi

# Build Asterisk (best-effort)
if [ -d "$SRC/asterisk" ]; then
  cd "$SRC/asterisk"
  ./contrib/scripts/get_mp3_source.sh || true
  ./configure --with-pjproject=/usr || true
  make -j"$(nproc)" || true
  make install || true
  make samples || true
  make config || true
  systemctl enable asterisk || true
fi

# Create a minimal Asterisk monitoring config (pjsip)
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

# Create Suricata rule to detect MT-ForwardSM / "SUBSCRIBE PREMIUM"
SUR_RULE_DIR=/etc/suricata/rules
mkdir -p "$SUR_RULE_DIR"
cat > "$SUR_RULE_DIR/ss7-subscribe.rules" <<'RULE'
alert tcp any any -> any any (msg:"SS7/SMS MT-ForwardSM Subscribe Premium"; content:"SUBSCRIBE PREMIUM"; sid:1000001; rev:1; classtype:bad-unknown; )
RULE
# include in suricata.yaml if not already; append include line
if ! grep -q "ss7-subscribe.rules" /etc/suricata/suricata.yaml 2>/dev/null; then
  sed -i '/rule-files:/a\  - ss7-subscribe.rules' /etc/suricata/suricata.yaml || true
fi
systemctl restart suricata || true

# Docker compose for pwnss7 & sniffer
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

# Helper scripts
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
tshark -r "/opt/ss7-lab/pcaps/$F" -Y 'm3ua || sccp || tcap || gsm_map || sms || sip' -T fields \
  -e frame.time -e ip.src -e ip.dst -e sctp.srcport -e sctp.dstport -e sip.From -e sip.To -e sms.msg_text -E separator=' | ' -E quote=d || true
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

# Systemd service - persistent pcap capture rotating by timestamp (runs at boot)
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

systemctl daemon-reload || true
systemctl enable --now ss7-pcap-capture.service || true

# Ensure pcaps dir writable and owned by root
chmod 0777 "$PCAPS" || true
chown root:root "$PCAPS" || true

# Auto-start docker compose on boot using systemd unit
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
systemctl enable --now ss7-docker-stack.service || true

# Final perms & info
chmod -R 0775 "$LAB"
echo "=== INSTALL COMPLETE ==="
echo "Lab dir: $LAB"
echo "PCAPs: $PCAPS"
echo "Helpers: $BIN (capture_now.sh parse_latest.sh tether_nats.sh)"
echo "Docker stack: systemd unit ss7-docker-stack.service (started)"
echo "Continuous capture: ss7-pcap-capture.service (started)"
echo "Suricata rule: /etc/suricata/rules/ss7-subscribe.rules (restarted)"
echo "Python venv: $PYVENV (activate to use scapy/pyshark)"
echo
echo "Quick use:"
echo "  docker logs -f osmo-stp || docker ps"
echo "  docker exec -it pwnss7 /bin/bash"
echo "  /opt/ss7-lab/bin/capture_now.sh any 120"
echo "  /opt/ss7-lab/bin/parse_latest.sh"
echo "  /opt/ss7-lab/bin/tether_nats.sh usb0 eth0"
echo
echo "Made by Taylor Christian Newsome"
echo "=== DONE: $(date -Iseconds) ==="
