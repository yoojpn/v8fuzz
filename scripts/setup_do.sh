#!/bin/bash
# DigitalOcean g-2 Droplet 初期セットアップ
# Ubuntu 24.04 LTS 想定
set -euo pipefail

echo "=== v8fuzz setup ==="

# --- 基本パッケージ ---
apt-get update -qq
apt-get install -y \
  git curl wget build-essential python3 python3-pip python3-venv \
  libssl-dev libffi-dev pkg-config \
  lsb-release software-properties-common \
  ninja-build cmake gdb \
  libdbus-1-dev libglib2.0-dev \
  tmux htop jq

# --- tmpfs マウント（高速I/O）---
mkdir -p /tmp/fuzz
if ! mountpoint -q /tmp/fuzz; then
  mount -t tmpfs -o size=512m tmpfs /tmp/fuzz
  echo "tmpfs /tmp/fuzz tmpfs size=512m 0 0" >> /etc/fstab
fi
echo "✅ tmpfs mounted at /tmp/fuzz"

# --- 作業ディレクトリ ---
mkdir -p /opt/v8fuzz/{corpus,logs,db,reports}
mkdir -p /opt/v8
mkdir -p /opt/jsc

# --- Python仮想環境 ---
python3 -m venv /opt/v8fuzz/venv
source /opt/v8fuzz/venv/bin/activate
pip install --upgrade pip -q
pip install aiohttp pyyaml aiofiles -q
echo "✅ Python venv created"

# --- depot_tools（V8ビルドに必要）---
if [ ! -d /opt/depot_tools ]; then
  git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git \
    /opt/depot_tools --depth=1 -q
fi
export PATH="/opt/depot_tools:$PATH"
echo 'export PATH="/opt/depot_tools:$PATH"' >> /etc/profile.d/v8fuzz.sh
echo "✅ depot_tools installed"

# --- v8fuzz コードをデプロイ ---
if [ ! -d /opt/v8fuzz/app ]; then
  mkdir -p /opt/v8fuzz/app
fi
echo "✅ App directory ready"

# --- systemd サービス登録 ---
cat > /etc/systemd/system/v8fuzz.service << 'EOF'
[Unit]
Description=v8fuzz - AI-driven JS engine fuzzer
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/v8fuzz/app
Environment=PATH=/opt/v8fuzz/venv/bin:/opt/depot_tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/opt/v8fuzz/venv/bin/python controller/main.py
Restart=always
RestartSec=10
StandardOutput=append:/opt/v8fuzz/logs/service.log
StandardError=append:/opt/v8fuzz/logs/service.log

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable v8fuzz
echo "✅ systemd service registered"

echo ""
echo "=== Setup complete ==="
echo "Next steps:"
echo "  1. bash scripts/build_v8.sh"
echo "  2. bash scripts/build_jsc.sh  (Azure VM)"
echo "  3. Edit config/config.yaml"
echo "  4. systemctl start v8fuzz"
