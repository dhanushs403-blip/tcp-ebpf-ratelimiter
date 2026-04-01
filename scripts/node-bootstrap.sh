#!/bin/bash
set -e

BPFFS="/sys/fs/bpf/vishanti"
NIC="bond0"
OBJ_DIR="/root/tenants/ebpfrl1/ebpf-phase1/obj"

echo ""
echo "============================================================"
echo "  VISHANTI eBPF — Node Bootstrap"
echo "  Node: $(hostname)"
echo "  Time: $(date)"
echo "============================================================"

if [ ! -f "$OBJ_DIR/xdp_vishanti_combined.o" ]; then
    echo "ERROR: Compiled eBPF objects not found at $OBJ_DIR"
    exit 1
fi

# Check if already running
if ip link show $NIC 2>/dev/null | grep -q xdp; then
    echo ""
    echo "  XDP already attached to $NIC"
    read -p "  Reload? (yes/no) [no]: " reload
    if [ "$reload" != "yes" ]; then
        echo "  Skipping. Already running."
        exit 0
    fi
    echo "  Cleaning existing programs..."
    ip link set dev $NIC xdpgeneric off 2>/dev/null || true
    ip link set dev $NIC xdp off 2>/dev/null || true
    tc filter del dev $NIC egress prio 49152 2>/dev/null || true
    rm -rf $BPFFS 2>/dev/null || true
    sleep 1
    echo "  Cleaned."
fi

echo ""
echo "[1/4] Loading XDP program..."
mkdir -p $BPFFS
bpftool prog load $OBJ_DIR/xdp_vishanti_combined.o $BPFFS/xdp_prog \
    type xdp pinmaps $BPFFS
bpftool net attach xdpgeneric pinned $BPFFS/xdp_prog dev $NIC
echo "  XDP attached."

echo ""
echo "[2/4] Loading TC egress..."
bpftool prog load $OBJ_DIR/tc_vishanti_egress.o $BPFFS/tc_egress_prog \
    map name conn_count pinned $BPFFS/conn_count \
    map name managed_lb_ips pinned $BPFFS/managed_lb_ips
EGRESS_MAP_IDS=$(bpftool prog show pinned $BPFFS/tc_egress_prog 2>/dev/null | grep -oP 'map_ids \K[0-9,]+')
for mid in $(echo $EGRESS_MAP_IDS | tr ',' ' '); do
    MAP_NAME=$(bpftool map show id $mid 2>/dev/null | grep -oP 'name \K\S+')
    if [ "$MAP_NAME" = "egress_debug" ]; then
        bpftool map pin id $mid $BPFFS/egress_debug 2>/dev/null || true
    fi
done
tc qdisc add dev $NIC clsact 2>/dev/null || true
tc filter add dev $NIC egress prio 49152 bpf da pinned $BPFFS/tc_egress_prog
echo "  TC egress attached."

echo ""
echo "[3/4] Starting cleanup service..."
systemctl restart vishanti-cleanup.service 2>/dev/null || echo "  (cleanup service not installed)"

echo ""
echo "[4/4] Verification..."
echo ""
echo "  XDP:"
ip link show $NIC | grep xdp
echo ""
echo "  TC egress:"
tc filter show dev $NIC egress | grep vishanti || echo "  (attached)"
echo ""
echo "  Pinned maps:"
ls $BPFFS/ | grep -v _prog
echo ""
echo "  Cleanup:"
systemctl is-active vishanti-cleanup.service 2>/dev/null || echo "  not running"

echo ""
echo "============================================================"
echo "  Node bootstrap COMPLETE"
echo "============================================================"
