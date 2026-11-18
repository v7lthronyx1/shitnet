#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 python3-venv python3-pip \
    tshark wireshark-common mtr-tiny curl iproute2 iputils-ping \
    poppler-utils libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libffi-dev shared-mime-info
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y \
    python3 python3-pip \
    wireshark-cli mtr curl iproute iputils \
    poppler-utils cairo pango gdk-pixbuf2 libffi-devel
elif command -v pacman >/dev/null 2>&1; then
  sudo pacman -Sy --noconfirm \
    python python-pip \
    wireshark-cli mtr curl iproute2 iputils \
    poppler cairo pango gdk-pixbuf2 libffi
else
  echo "Unsupported package manager. Install tshark/dumpcap, mtr, curl, iproute2, poppler-utils, pango, cairo manually."
fi

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e .

if command -v dumpcap >/dev/null 2>&1; then
  echo "Setup complete. If running without sudo, grant non-root capture permissions once:"
  echo "  sudo setcap cap_net_raw,cap_net_admin=eip \$(which dumpcap)"
fi

echo "Run interactive wizard: .venv/bin/shitnet wizard"
