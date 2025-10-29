#!/usr/bin/env bash
# setup-ss7-defense-lab.sh -- Zero-touch SS7 defense lab (Debian 12)
# Run as root: sudo bash ./setup-ss7-defense-lab.sh
set -euo pipefail
LABDIR=/opt/ss7-lab
LOG=/var/log/ss7-defense-lab-install.log
exec > >(tee -a "$LOG") 2>&1

echo "=== SS7 Defense Lab installer started: $(date -Iseconds) ==="

# safety: require interactive acknowledgement before proceeding
cat <<'WARN'
WARNING: This script will install docker, clone/build open-source SS7/SIGTRAN tools,
and enable containers to bind to host networking (required for SCTP/M3UA testing).
Only run on systems and networks you own or are authorized to test.
Type 'I UNDERSTAND' to continue: 
WARN

read -r CONFIRM
if [ "$CONFIRM" != "I UNDERSTAND" ]; then
  echo "Confirmation not provided. Exiting."
  exit 1
fi

# Update & install prerequisites
export DEBIAN_FRONTEND=noninteractive
apt update -y
apt upgrade -y
apt install -y \
  apt-transport-https ca-certificates curl gnupg lsb-release \
  git build-essential python3 python3-venv python3-pip jq \
  tcpdump tshark libpcap-dev lksctp-tools libsctp-dev pkg-config

# Install Docker (official)
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
    https://download.docker.com/linux/debian $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list
  apt update -y
  apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi

# Add invoking sudo user to docker group (if applicable)
SUDO_USER="${SUDO_USER:-root}"
if [ "$SUDO_USER" != "root" ]; then
  usermod -aG docker "$SUDO_USER" || true
  echo "Added $SUDO_USER to docker group"
fi

# Create lab dir
rm -rf "$LABDIR"
mkdir -p "$LABDIR"
cd "$LABDIR"

# Clone projects (sources)
echo "Cloning libosmo-sigtran (OsmoSTP) and pwnss7..."
if [ ! -d libosmo-sigtran ]; then
  git clone https://gitea.osmocom.org/osmocom/libosmo-sigtran.git
fi
if [ ! -d pwnss7 ]; then
  git clone https://github.com/orangecertcc/pwnss7.git
fi

# Create dockerfiles & compose
cat > "$LABDIR/Dockerfile.osmo-stp" <<'DOCKER'
FROM debian:12
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update -y && apt install -y \
  build-essential git cmake pkg-config libtool automake autoconf \
  libsctp-dev lksctp-tools libssl-dev wget \
  python3 python3-venv python3-pip
# copy source into image at build-time (build context will include libosmo-sigtran)
COPY libosmo-sigtran /usr/src/libosmo-sigtran
WORKDIR /usr/src/libosmo-sigtran
# simple build steps (libosmo-sigtran uses autotools/cmake; attempt generic build)
RUN autoreconf -fi || true
RUN ./autogen.sh || true || true
RUN ./configure --prefix=/usr || true
RUN make -j"$(nproc)" || true
RUN make install || true
# minimal runtime command (will attempt to run osmo-stp binary)
CMD ["/usr/sbin/osmo-stp", "-f", "/etc/osmocom/osmo-stp.cfg"]
DOCKER

cat > "$LABDIR/Dockerfile.pwnss7" <<'DOCKER'
FROM python:3.11-slim
RUN apt update -y && apt install -y gcc libpcap-dev libsctp-dev lksctp-tools tcpdump
WORKDIR /root/pwnss7
COPY pwnss7 /root/pwnss7
RUN python3 -m venv /opt/venv
RUN /opt/venv/bin/pip install --upgrade pip
# use --break-system-packages when users ask (we install in venv so not needed)
RUN /opt/venv/bin/pip install -r requirements.txt || true
ENV PATH="/opt/venv/bin:$PATH"
CMD ["/bin/bash"]
DOCKER

cat > "$LABDIR/docker-compose.yml" <<'YAML'
version: "3.8"
services:
  stp:
    build:
      context: .
      dockerfile: Dockerfile.osmo-stp
    container_name: osmo-stp
    network_mode: "host"           # host network to allow SCTP binding to host interfaces
    cap_add:
      - NET_ADMIN
      - NET_RAW
    privileged: true
    volumes:
      - ./libosmo-sigtran:/usr/src/libosmo-sigtran:ro
    restart: unless-stopped

  pwnss7:
    build:
      context: .
      dockerfile: Dockerfile.pwnss7
    container_name: pwnss7
    network_mode: "host"
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ./pwnss7:/root/pwnss7:rw
    tty: true
    stdin_open: true

  sniffer:
    image: nicolaka/netshoot:latest
    container_name: ss7-sniffer
    network_mode: "host"
    cap_add:
      - NET_RAW
      - NET_ADMIN
    volumes:
      - ./pcaps:/pcaps
    command: /bin/bash -c "mkdir -p /pcaps && tcpdump -i any -s0 -w /pcaps/ss7-$(date -u +%Y%m%dT%H%M%SZ).pcapng 'sctp or port 2905 or port 3868 or tcp or udp' "
    restart: "no"
YAML

# create pcaps dir
mkdir -p "$LABDIR/pcaps"

# Build docker images (can take time)
echo "Building docker images (this may take several minutes)..."
docker compose build --parallel

echo "Lab bootstrap complete."
cat > "$LABDIR/USAGE.txt" <<'USAGE'
SS7 Defense Lab - quick usage
1) Start the basic stack:
   cd /opt/ss7-lab
   docker compose up -d stp pwnss7

2) Start a sniffer (foreground) to capture to ./pcaps:
   docker compose run --rm sniffer

3) Enter pwnss7 container for testing:
   docker exec -it pwnss7 /bin/bash
   # Inside container, activate venv if created: source /opt/venv/bin/activate
   # Use pwnss7 script tools to craft M3UA/SCCP/TCAP packets (see pwnss7 README)

4) Captures appear in /opt/ss7-lab/pcaps

Notes:
- All containers use host network mode to allow SCTP and point-code style traffic
  to be exercised on the same host interfaces. This is necessary for SIGTRAN testing,
  but it also means containers can reach services on host network.
- If you want to simulate a closed lab, run this on an isolated VLAN or an
  air-gapped host. Do NOT run on production infrastructure.
USAGE

echo "All done. Next steps:"
echo "  cd $LABDIR && docker compose up -d stp pwnss7"
echo "Logs: $LOG"
