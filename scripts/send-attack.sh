#!/bin/bash
BPFFS="/sys/fs/bpf/vishanti"

ip_hex() {
    IFS='.' read -r a b c d <<< "$1"
    printf '%02x %02x %02x %02x' "$a" "$b" "$c" "$d"
}

get_syn_drops() {
    local key="$1"
    local sd=0
    local sj=$(bpftool map lookup pinned $BPFFS/syn_drop_count key hex $key 2>/dev/null)
    [ -n "$sj" ] && sd=$(echo "$sj" | grep -oP '"value":\s*\K[0-9]+' | awk '{s+=$1}END{print s+0}')
    echo "$sd"
}

get_conn_drops() {
    local key="$1"
    local cd=0
    local cj=$(bpftool map lookup pinned $BPFFS/conn_drop_count key hex $key 2>/dev/null)
    [ -n "$cj" ] && cd=$(echo "$cj" | grep -oP '"value":\s*\K[0-9]+' | awk '{s+=$1}END{print s+0}')
    echo "$cd"
}

get_conn_count() {
    local key="$1"
    bpftool map lookup pinned $BPFFS/conn_count key hex $key 2>/dev/null | grep -oP '"value":\s*\K[0-9]+' | head -1
}

# Discover targets
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  VISHANTI eBPF — Attack Simulator                       ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

LB_DATA=$(kubectl get svc -A \
    -o jsonpath='{range .items[?(@.status.loadBalancer.ingress)]}{.metadata.labels.gateway\.envoyproxy\.io/owning-gateway-namespace}{"\t"}{.status.loadBalancer.ingress[0].ip}{"\n"}{end}' 2>/dev/null | grep -v '^$' | grep -v '^	')

declare -a T_NS=()
declare -a T_IP=()

idx=1
while IFS=$'\t' read -r ns ip; do
    [ -z "$ns" ] || [ -z "$ip" ] && continue
    hk=$(ip_hex "$ip")
    if ! bpftool map lookup pinned "$BPFFS/managed_lb_ips" key hex $hk 2>/dev/null | grep -q "value"; then
        continue
    fi
    T_NS+=("$ns")
    T_IP+=("$ip")
    hostname=$(kubectl get httproute -n "$ns" -o jsonpath='{.items[0].spec.hostnames[0]}' 2>/dev/null)
    printf "  %2d) %s (%s) — %s\n" "$idx" "$ns" "$ip" "${hostname:-unknown}"
    ((idx++))
done <<< "$LB_DATA"

echo ""
read -p "  Select target (1-${#T_NS[@]}): " sel
i=$((sel-1))
IP="${T_IP[$i]}"
NS="${T_NS[$i]}"
HK=$(ip_hex "$IP")

echo ""
echo "  Target: $NS ($IP)"
echo ""
echo "  1) SYN rate test      — Send raw SYNs (test rate limit)"
echo "  2) Connection test    — Lower max conn, watch real traffic drop"
echo "  3) Custom SYN test    — Choose count + rate"
echo "  4) Reset all counters"
echo "  5) Restore all limits — Set back to 1000 SYN/sec, 5000 conn"
echo "  6) Exit"
echo ""
read -p "  Select (1-6): " choice

case $choice in
1)
    echo ""
    echo "  [SYN RATE TEST]"
    echo ""

    # Read current limit
    CUR_SYN=$(bpftool map lookup pinned $BPFFS/syn_tenant_cfg key hex $HK 2>/dev/null | grep -oP '"rate_per_sec":\s*\K[0-9]+')
    echo "  Current tenant SYN limit: ${CUR_SYN:-unknown}/sec"
    echo ""
    read -p "  Temporarily set SYN limit to [10]: " NEW_LIMIT
    NEW_LIMIT=${NEW_LIMIT:-10}
    read -p "  SYNs to send [200]: " COUNT
    COUNT=${COUNT:-200}
    read -p "  Rate (packets/sec) [50]: " RATE
    RATE=${RATE:-50}

    # Save original
    ORIG_SYN=$CUR_SYN
    ORIG_BURST=$(bpftool map lookup pinned $BPFFS/syn_tenant_cfg key hex $HK 2>/dev/null | grep -oP '"burst":\s*\K[0-9]+')

    # Set new limit
    BURST=$((NEW_LIMIT * 2))
    LIM_HEX="$(printf '%02x %02x %02x %02x %02x %02x %02x %02x' \
        $((NEW_LIMIT&0xFF)) $(((NEW_LIMIT>>8)&0xFF)) $(((NEW_LIMIT>>16)&0xFF)) $(((NEW_LIMIT>>24)&0xFF)) 0 0 0 0) \
    $(printf '%02x %02x %02x %02x %02x %02x %02x %02x' \
        $((BURST&0xFF)) $(((BURST>>8)&0xFF)) $(((BURST>>16)&0xFF)) $(((BURST>>24)&0xFF)) 0 0 0 0)"
    bpftool map update pinned $BPFFS/syn_tenant_cfg key hex $HK value hex $LIM_HEX

    echo ""
    echo "  SYN limit set to $NEW_LIMIT/sec (burst $BURST)"
    echo ""

    # Record BEFORE
    SD_BEFORE=$(get_syn_drops "$HK")

    echo "  Sending $COUNT SYNs at ${RATE}/sec..."
    echo "  Watch Terminal 1!"
    echo ""

    nping --tcp -p 443 --flags SYN -c $COUNT --rate $RATE $IP 2>&1 | tail -3

    # Record AFTER
    SD_AFTER=$(get_syn_drops "$HK")
    DROPPED=$((SD_AFTER - SD_BEFORE))
    PASSED=$((COUNT - DROPPED))
    [ "$DROPPED" -lt 0 ] && DROPPED=0 && PASSED=$COUNT
    PCT=$((DROPPED * 100 / COUNT))

    echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║  RESULTS                                  ║"
    echo "  ╠══════════════════════════════════════════╣"
    echo "  ║  SYN limit:     $NEW_LIMIT/sec"
    echo "  ║  Sent:          $COUNT at ${RATE}/sec"
    echo "  ║  Dropped:       $DROPPED ($PCT%)"
    echo "  ║  Passed:        $PASSED"
    echo "  ╚══════════════════════════════════════════╝"

    # Restore
    RESTORE_HEX="$(printf '%02x %02x %02x %02x %02x %02x %02x %02x' \
        $((ORIG_SYN&0xFF)) $(((ORIG_SYN>>8)&0xFF)) $(((ORIG_SYN>>16)&0xFF)) $(((ORIG_SYN>>24)&0xFF)) 0 0 0 0) \
    $(printf '%02x %02x %02x %02x %02x %02x %02x %02x' \
        $((ORIG_BURST&0xFF)) $(((ORIG_BURST>>8)&0xFF)) $(((ORIG_BURST>>16)&0xFF)) $(((ORIG_BURST>>24)&0xFF)) 0 0 0 0)"
    bpftool map update pinned $BPFFS/syn_tenant_cfg key hex $HK value hex $RESTORE_HEX
    echo ""
    echo "  Restored SYN limit to $ORIG_SYN/sec"
    ;;

2)
    echo ""
    echo "  [CONNECTION LIMIT TEST]"
    echo ""

    CUR_CONN=$(bpftool map lookup pinned $BPFFS/conn_tenant_max key hex $HK 2>/dev/null | grep -oP '"value":\s*\K[0-9]+')
    echo "  Current tenant max connections: ${CUR_CONN:-unknown}"
    echo ""
    read -p "  Temporarily set max connections to [5]: " NEW_CONN
    NEW_CONN=${NEW_CONN:-5}

    # Save original
    ORIG_CONN=$CUR_CONN

    # Set new limit
    CONN_HEX=$(printf '%02x %02x %02x %02x %02x %02x %02x %02x' \
        $((NEW_CONN&0xFF)) $(((NEW_CONN>>8)&0xFF)) $(((NEW_CONN>>16)&0xFF)) $(((NEW_CONN>>24)&0xFF)) 0 0 0 0)
    bpftool map update pinned $BPFFS/conn_tenant_max key hex $HK value hex $CONN_HEX

    # Reset conn count
    bpftool map update pinned $BPFFS/conn_count key hex $HK value hex 00 00 00 00 00 00 00 00

    # Record BEFORE
    CD_BEFORE=$(get_conn_drops "$HK")

    echo ""
    echo "  Max connections = $NEW_CONN"
    echo "  Counter reset"
    echo ""
    echo "  Watch Terminal 1 — connections will cap at $NEW_CONN"
    echo "  Real external traffic will trigger drops"
    echo ""
    read -p "  Press ENTER when done watching..."

    # Record AFTER
    CD_AFTER=$(get_conn_drops "$HK")
    FINAL_CONN=$(get_conn_count "$HK")
    DROPPED=$((CD_AFTER - CD_BEFORE))
    [ "$DROPPED" -lt 0 ] && DROPPED=0

    echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║  RESULTS                                  ║"
    echo "  ╠══════════════════════════════════════════╣"
    echo "  ║  Max connections:  $NEW_CONN"
    echo "  ║  Final conn count: ${FINAL_CONN:-0}"
    echo "  ║  Conn drops:       $DROPPED"
    echo "  ╚══════════════════════════════════════════╝"

    # Restore
    RESTORE_HEX=$(printf '%02x %02x %02x %02x %02x %02x %02x %02x' \
        $((ORIG_CONN&0xFF)) $(((ORIG_CONN>>8)&0xFF)) $(((ORIG_CONN>>16)&0xFF)) $(((ORIG_CONN>>24)&0xFF)) 0 0 0 0)
    bpftool map update pinned $BPFFS/conn_tenant_max key hex $HK value hex $RESTORE_HEX
    echo ""
    echo "  Restored max connections to $ORIG_CONN"
    ;;

3)
    echo ""
    echo "  [CUSTOM SYN TEST]"
    echo ""

    CUR_SYN=$(bpftool map lookup pinned $BPFFS/syn_tenant_cfg key hex $HK 2>/dev/null | grep -oP '"rate_per_sec":\s*\K[0-9]+')
    echo "  Current tenant SYN limit: ${CUR_SYN:-unknown}/sec"
    echo ""
    read -p "  SYNs to send [500]: " COUNT
    COUNT=${COUNT:-500}
    read -p "  Rate (packets/sec) [100]: " RATE
    RATE=${RATE:-100}

    SD_BEFORE=$(get_syn_drops "$HK")

    echo ""
    echo "  Sending $COUNT SYNs at ${RATE}/sec (limit: ${CUR_SYN}/sec)..."
    echo ""

    nping --tcp -p 443 --flags SYN -c $COUNT --rate $RATE $IP 2>&1 | tail -3

    SD_AFTER=$(get_syn_drops "$HK")
    DROPPED=$((SD_AFTER - SD_BEFORE))
    PASSED=$((COUNT - DROPPED))
    [ "$DROPPED" -lt 0 ] && DROPPED=0 && PASSED=$COUNT
    PCT=0
    [ "$COUNT" -gt 0 ] && PCT=$((DROPPED * 100 / COUNT))

    echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║  RESULTS                                  ║"
    echo "  ╠══════════════════════════════════════════╣"
    echo "  ║  SYN limit:     ${CUR_SYN}/sec"
    echo "  ║  Sent:          $COUNT at ${RATE}/sec"
    echo "  ║  Dropped:       $DROPPED ($PCT%)"
    echo "  ║  Passed:        $PASSED"
    echo "  ╚══════════════════════════════════════════╝"
    ;;

4)
    bpftool map update pinned $BPFFS/conn_count key hex $HK value hex 00 00 00 00 00 00 00 00
    bpftool map delete pinned $BPFFS/syn_drop_count key hex $HK 2>/dev/null
    bpftool map delete pinned $BPFFS/conn_drop_count key hex $HK 2>/dev/null
    echo "  All counters reset for $IP"
    ;;

5)
    bpftool map update pinned $BPFFS/syn_tenant_cfg key hex $HK \
        value hex e8 03 00 00 00 00 00 00 b0 04 00 00 00 00 00 00
    bpftool map update pinned $BPFFS/conn_tenant_max key hex $HK \
        value hex 88 13 00 00 00 00 00 00
    echo "  Restored: 1000 SYN/sec, 5000 connections"
    ;;

6)
    echo "  Bye!"
    exit 0
    ;;
esac
