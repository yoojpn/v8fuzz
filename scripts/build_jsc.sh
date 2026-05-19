#!/bin/bash
# JavaScriptCore (WebKit) をビルド（Azure F2s v2 Ubuntu 22.04）
set -euo pipefail

echo "=== JSC Build Setup ==="

# 依存パッケージ
apt-get update -qq
apt-get install -y \
  libicu-dev libxml2-dev libxslt1-dev \
  libsqlite3-dev libgcrypt20-dev \
  libpng-dev libjpeg-dev libwebp-dev \
  libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev \
  ruby ruby-dev \
  perl \
  gperf \
  cmake ninja-build \
  python3 python3-pip \
  clang llvm lld \
  libclang-dev -q

cd /opt/jsc

echo "=== Fetching WebKit ==="
if [ ! -d /opt/jsc/WebKit ]; then
  # JSCだけのfetch（WebKit全体は巨大なのでsparse checkout）
  git clone https://github.com/WebKit/WebKit.git \
    --filter=blob:none \
    --sparse \
    --depth=50 \
    -q
  cd WebKit
  git sparse-checkout add \
    Source/JavaScriptCore \
    Source/WTF \
    Source/bmalloc \
    Tools/Scripts \
    CMakeLists.txt \
    Source/CMakeLists.txt
else
  cd WebKit
  git pull -q
fi

echo "=== Building JSC Release ==="
Tools/Scripts/build-webkit \
  --jsc-only \
  --release \
  --cmakeargs="-DENABLE_STATIC_JSC=ON" \
  2>&1 | tail -20

JSC_RELEASE=$(find . -name "jsc" -path "*/Release/*" | head -1)
if [ -n "$JSC_RELEASE" ]; then
  cp "$JSC_RELEASE" /opt/jsc/jsc
  echo "✅ JSC Release: /opt/jsc/jsc ($(ls -lh /opt/jsc/jsc | awk '{print $5}'))"
fi

echo "=== Building JSC ASAN ==="
Tools/Scripts/build-webkit \
  --jsc-only \
  --debug \
  --asan \
  --cmakeargs="-DENABLE_STATIC_JSC=ON" \
  2>&1 | tail -20

JSC_ASAN=$(find . -name "jsc" -path "*/Debug/*" | head -1)
if [ -n "$JSC_ASAN" ]; then
  cp "$JSC_ASAN" /opt/jsc/jsc-asan
  echo "✅ JSC ASAN: /opt/jsc/jsc-asan"
fi

echo ""
echo "=== JSC Build Complete ==="
echo "  Release: /opt/jsc/jsc"
echo "  ASAN:    /opt/jsc/jsc-asan"
echo ""
echo "Update config/config.yaml:"
echo "  engines.jsc.binary: /opt/jsc/jsc"
echo "  engines.jsc.asan_binary: /opt/jsc/jsc-asan"
