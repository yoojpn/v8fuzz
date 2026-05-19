#!/bin/bash
# V8をビルドする（探索用Release + 検証用ASAN）
set -euo pipefail

export PATH="/opt/depot_tools:$PATH"
cd /opt/v8

echo "=== Fetching V8 source ==="
if [ ! -d /opt/v8/v8 ]; then
  fetch v8
fi

cd v8
git checkout main
gclient sync -q

echo "=== Building V8 Release (fast, for fuzzing) ==="
cat > out/x64.release/args.gn << 'EOF'
is_debug = false
is_component_build = false
use_custom_libcxx = false
v8_static_library = true
symbol_level = 0
v8_enable_sandbox = true
EOF

autoninja -C out/x64.release d8 -j$(nproc)
echo "✅ Release build: $(ls -lh out/x64.release/d8 | awk '{print $5}')"

echo "=== Building V8 ASAN (for crash verification) ==="
mkdir -p out/x64.asan
cat > out/x64.asan/args.gn << 'EOF'
is_debug = false
is_asan = true
is_component_build = false
use_custom_libcxx = false
v8_static_library = true
symbol_level = 1
v8_enable_sandbox = true
v8_enable_slow_dchecks = true
EOF

autoninja -C out/x64.asan d8 -j$(nproc)
echo "✅ ASAN build: $(ls -lh out/x64.asan/d8 | awk '{print $5}')"

echo "=== Generating snapshot ==="
./out/x64.release/d8 \
  --snapshot-blob=/opt/v8fuzz/snapshot_release.bin \
  --allow-natives-syntax \
  -e "// warmup"
echo "✅ Snapshot generated"

echo ""
echo "=== V8 Build Complete ==="
echo "  Release: /opt/v8/v8/out/x64.release/d8"
echo "  ASAN:    /opt/v8/v8/out/x64.asan/d8"
echo "  Snapshot:/opt/v8fuzz/snapshot_release.bin"
echo ""
echo "Update config/config.yaml:"
echo "  engines.v8.binary: /opt/v8/v8/out/x64.release/d8"
echo "  engines.v8.asan_binary: /opt/v8/v8/out/x64.asan/d8"
echo "  engines.v8.snapshot: /opt/v8fuzz/snapshot_release.bin"
