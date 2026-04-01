#!/bin/bash
BPFFS="/sys/fs/bpf/vishanti"

ip_hex() {
    IFS='.' read -r a b c d <<< "$1"
    printf '%02x %02x %02x %02x' "$a" "$b" "$c" "$d"
}

# Discover managed tenants
echo ""
echo "============================================================"
echo "  Select Tenant to Monitor"
echo "============================================================"
echo ""

LB_DATA=$(kubectl get svc -A \
    -o jsonpath='{range .items[?(@.status.loadBalancer.ingress)]}{.metadata.labels.gateway\.envoyproxy\.io/owning-gateway-namespace}{"\t"}{.status.loadBalancer.ingress[0].ip}{"\t"}{.metadata.name}{"\n"}{end}' 2>/dev/null | grep -v '^$' | grep -v '^	')

declare -a M_NS=()
declare -a M_IP=()
declare -a M_HOST=()

idx=1
while IFS=$'\t' read -r ns ip svc; do
    [ -z "$ns" ] || [ -z "$ip" ] && continue
    hex_key=$(ip_hex "$ip")
    if ! bpftool map lookup pinned "$BPFFS/managed_lb_ips" key hex $hex_key 2>/dev/null | grep -q "value"; then
        continue
    fi

    hostname=$(kubectl get httproute -n "$ns" -o jsonpath='{.items[0].spec.hostnames[0]}' 2>/dev/null)

    M_NS+=("$ns")
    M_IP+=("$ip")
    M_HOST+=("${hostname:-unknown}")

    printf "  %2d) %s\n" "$idx" "$ns"
    printf "      IP:       %s\n" "$ip"
    printf "      Hostname: %s\n" "${hostname:-unknown}"
    echo ""
    ((idx++))
done <<< "$LB_DATA"

if [ ${#M_NS[@]} -eq 0 ]; then
    echo "  No managed tenants found!"
    exit 1
fi

read -p "  Select tenant (1-${#M_NS[@]}): " sel

if ! [[ "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt ${#M_NS[@]} ]; then
    echo "Invalid"
    exit 1
fi

i=$((sel-1))
TENANT_NS="${M_NS[$i]}"
TENANT_IP="${M_IP[$i]}"
TENANT_HOST="${M_HOST[$i]}"
IP_KEY=$(ip_hex "$TENANT_IP")

# Read configuration ONCE (doesn't change during monitoring)
PROV_SYN=$(bpftool map lookup pinned $BPFFS/syn_provider_cfg key hex $IP_KEY 2>/dev/null | grep -oP '"rate_per_sec":\s*\K[0-9]+')
PROV_BURST=$(bpftool map lookup pinned $BPFFS/syn_provider_cfg key hex $IP_KEY 2>/dev/null | grep -oP '"burst":\s*\K[0-9]+')
PROV_CONN=$(bpftool map lookup pinned $BPFFS/conn_provider_max key hex $IP_KEY 2>/dev/null | grep -oP '"value":\s*\K[0-9]+')
TEN_SYN=$(bpftool map lookup pinned $BPFFS/syn_tenant_cfg key hex $IP_KEY 2>/dev/null | grep -oP '"rate_per_sec":\s*\K[0-9]+')
TEN_BURST=$(bpftool map lookup pinned $BPFFS/syn_tenant_cfg key hex $IP_KEY 2>/dev/null | grep -oP '"burst":\s*\K[0-9]+')
TEN_CONN=$(bpftool map lookup pinned $BPFFS/conn_tenant_max key hex $IP_KEY 2>/dev/null | grep -oP '"value":\s*\K[0-9]+')

echo ""
echo "  Monitoring: $TENANT_NS ($TENANT_IP)"
echo "  Press Ctrl+C to stop"
sleep 2

# Monitor loop
while true; do
    clear

    # Header
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║  VISHANTI eBPF LIVE MONITOR                             ║"
    echo "╠══════════════════════════════════════════════════════════╣"
    echo "║  Tenant:   $TENANT_NS"
    echo "║  IP:       $TENANT_IP"
    echo "║  Hostname: $TENANT_HOST"
    echo "║  Time:     $(date '+%Y-%m-%d %H:%M:%S')"
    echo "╠══════════════════════════════════════════════════════════╣"

    # Configuration section
    echo "║                                                          ║"
    echo "║  CONFIGURATION                                           ║"
    echo "║  ──────────────────────────────────────────────────────  ║"
    echo "║                     Provider        Tenant       Effective"
    printf "║  SYN/sec:           %-15s %-12s %s\n" "${PROV_SYN:-?}" "${TEN_SYN:-?}" "${TEN_SYN:-?}"
    printf "║  SYN burst:         %-15s %-12s %s\n" "${PROV_BURST:-?}" "${TEN_BURST:-?}" "${TEN_BURST:-?}"
    printf "║  Max connections:   %-15s %-12s %s\n" "${PROV_CONN:-?}" "${TEN_CONN:-?}" "${TEN_CONN:-?}"

    echo "║                                                          ║"
    echo "╠══════════════════════════════════════════════════════════╣"

    # Live counters
    echo "║                                                          ║"
    echo "║  LIVE COUNTERS                                           ║"
    echo "║  ──────────────────────────────────────────────────────  ║"

    # Connection count
    CONN=$(bpftool map lookup pinned $BPFFS/conn_count key hex $IP_KEY 2>/dev/null | grep -oP '"value":\s*\K[0-9]+')
    CONN=${CONN:-0}
    CONN_STATUS="OK"
    [ "$CONN" -ge "${TEN_CONN:-999999}" ] 2>/dev/null && CONN_STATUS="AT LIMIT!"
    printf "║  Active Connections: %-8s / %-8s %s\n" "$CONN" "${TEN_CONN:-?}" "$CONN_STATUS"

    # SYN drops
    SD=0
    SJ=$(bpftool map lookup pinned $BPFFS/syn_drop_count key hex $IP_KEY 2>/dev/null)
    if [ -n "$SJ" ]; then
        SD=$(echo "$SJ" | grep -oP '"value":\s*\K[0-9]+' | awk '{s+=$1}END{print s+0}')
    fi
    SYN_STATUS="none"
    [ "$SD" -gt 0 ] && SYN_STATUS="DROPPING!"
    printf "║  SYN Drops (rate):   %-8s                  %s\n" "$SD" "$SYN_STATUS"

    # Connection drops
    CD=0
    CJ=$(bpftool map lookup pinned $BPFFS/conn_drop_count key hex $IP_KEY 2>/dev/null)
    if [ -n "$CJ" ]; then
        CD=$(echo "$CJ" | grep -oP '"value":\s*\K[0-9]+' | awk '{s+=$1}END{print s+0}')
    fi
    CONN_D_STATUS="none"
    [ "$CD" -gt 0 ] && CONN_D_STATUS="DROPPING!"
    printf "║  Conn Drops (limit): %-8s                  %s\n" "$CD" "$CONN_D_STATUS"

    echo "║                                                          ║"
    echo "╠══════════════════════════════════════════════════════════╣"

    # Token bucket status
    echo "║                                                          ║"
    echo "║  TOKEN BUCKET STATUS                                     ║"
    echo "║  ──────────────────────────────────────────────────────  ║"

    TOK=$(bpftool map lookup pinned $BPFFS/syn_rate_state key hex $IP_KEY 2>/dev/null)
    if [ -n "$TOK" ]; then
        PT=$(echo "$TOK" | grep -oP '"provider_tokens":\s*\K[0-9]+')
        TT=$(echo "$TOK" | grep -oP '"tenant_tokens":\s*\K[0-9]+')
        PT=${PT:-0}
        TT=${TT:-0}

        # Calculate percentage
        PROV_MAX=$((${PROV_BURST:-1} * 1000))
        TEN_MAX=$((${TEN_BURST:-1} * 1000))
        PP=100; [ "$PROV_MAX" -gt 0 ] && PP=$((PT * 100 / PROV_MAX))
        TP=100; [ "$TEN_MAX" -gt 0 ] && TP=$((TT * 100 / TEN_MAX))

        P_BAR=""; for b in $(seq 1 20); do [ $b -le $((PP/5)) ] && P_BAR="${P_BAR}█" || P_BAR="${P_BAR}░"; done
        T_BAR=""; for b in $(seq 1 20); do [ $b -le $((TP/5)) ] && T_BAR="${T_BAR}█" || T_BAR="${T_BAR}░"; done

        printf "║  Provider: [%s] %3d%%\n" "$P_BAR" "$PP"
        printf "║  Tenant:   [%s] %3d%%\n" "$T_BAR" "$TP"

        P_STATUS="FULL"
        [ "$PP" -lt 50 ] && P_STATUS="DRAINING"
        [ "$PP" -lt 10 ] && P_STATUS="RATE LIMITING!"
        T_STATUS="FULL"
        [ "$TP" -lt 50 ] && T_STATUS="DRAINING"
        [ "$TP" -lt 10 ] && T_STATUS="RATE LIMITING!"

        echo "║"
        printf "║  Provider: %-10s  Tenant: %s\n" "$P_STATUS" "$T_STATUS"
    else
        echo "║  (no rate state yet)"
    fi

    echo "║                                                          ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo "  Ctrl+C to stop | Config updates: re-run monitor.sh"

    sleep 1
done
