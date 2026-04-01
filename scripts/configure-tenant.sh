#!/bin/bash
set -e

BPFFS="/sys/fs/bpf/vishanti"

ip_to_hex_key() {
    local ip="$1"
    IFS='.' read -r a b c d <<< "$ip"
    printf '%02x %02x %02x %02x' "$a" "$b" "$c" "$d"
}

int_to_hex_u64() {
    local val=$1
    printf '%02x %02x %02x %02x %02x %02x %02x %02x' \
        $((val & 0xFF)) \
        $(((val >> 8) & 0xFF)) \
        $(((val >> 16) & 0xFF)) \
        $(((val >> 24) & 0xFF)) \
        $(((val >> 32) & 0xFF)) \
        $(((val >> 40) & 0xFF)) \
        $(((val >> 48) & 0xFF)) \
        $(((val >> 56) & 0xFF))
}

rate_cfg_to_hex() {
    echo "$(int_to_hex_u64 $1) $(int_to_hex_u64 $2)"
}

read_map_u64() {
    bpftool map lookup pinned "$1" key hex $2 2>/dev/null | grep -oP '"value":\s*\K[0-9]+' | head -1
}

read_map_rate_cfg() {
    bpftool map lookup pinned "$1" key hex $2 2>/dev/null | grep -oP "\"$3\":\s*\K[0-9]+" | head -1
}

check_prerequisites() {
    if [ ! -d "$BPFFS" ]; then
        echo "ERROR: eBPF programs not loaded!"
        exit 1
    fi
    for map in syn_tenant_cfg conn_tenant_max syn_provider_cfg conn_provider_max managed_lb_ips; do
        if [ ! -e "$BPFFS/$map" ]; then
            echo "ERROR: Map $map not found"
            exit 1
        fi
    done
    echo "[OK] eBPF maps found"
}

show_configured_lbs() {
    echo ""
    echo "============================================================"
    echo "  LoadBalancer IPs with Provider Ceiling Configured"
    echo "============================================================"
    echo ""

    LB_RAW=$(kubectl get svc -A \
        -o jsonpath='{range .items[?(@.status.loadBalancer.ingress)]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.status.loadBalancer.ingress[0].ip}{"\t"}{.spec.ports[*].port}{"\t"}{.metadata.labels.gateway\.envoyproxy\.io/owning-gateway-namespace}{"\n"}{end}' 2>/dev/null | grep -v '^$')

    declare -g -a LB_IPS=()
    declare -g -a LB_NAMES=()
    declare -g -a LB_SVC_NS=()
    declare -g -a LB_TENANT_NS=()
    declare -g -a LB_PROV_SYN=()
    declare -g -a LB_PROV_BURST=()
    declare -g -a LB_PROV_CONN=()

    local display_idx=1

    while IFS=$'\t' read -r svc_ns name ip ports tenant_ns; do
        [ -z "$ip" ] && continue
        local hex_key=$(ip_to_hex_key "$ip")

        if ! bpftool map lookup pinned "$BPFFS/managed_lb_ips" key hex $hex_key 2>/dev/null | grep -q "value"; then
            continue
        fi

        local prov_syn=$(read_map_rate_cfg "$BPFFS/syn_provider_cfg" "$hex_key" "rate_per_sec")
        local prov_burst=$(read_map_rate_cfg "$BPFFS/syn_provider_cfg" "$hex_key" "burst")
        local prov_conn=$(read_map_u64 "$BPFFS/conn_provider_max" "$hex_key")

        local ten_syn=$(read_map_rate_cfg "$BPFFS/syn_tenant_cfg" "$hex_key" "rate_per_sec")
        local ten_conn=$(read_map_u64 "$BPFFS/conn_tenant_max" "$hex_key")

        LB_IPS+=("$ip")
        LB_NAMES+=("$name")
        LB_SVC_NS+=("$svc_ns")
        LB_TENANT_NS+=("${tenant_ns:-$svc_ns}")
        LB_PROV_SYN+=("${prov_syn:-0}")
        LB_PROV_BURST+=("${prov_burst:-0}")
        LB_PROV_CONN+=("${prov_conn:-0}")

        local tenant_status="[NO TENANT LIMIT]"
        if [ -n "$ten_syn" ] && [ "$ten_syn" != "" ]; then
            tenant_status="[TENANT: ${ten_syn} SYN/s, ${ten_conn} conn]"
        fi

        printf "  %2d) %-18s %s\n" "$display_idx" "$ip" "$tenant_status"
        printf "      Service:          %s\n" "$name"
        printf "      Tenant NS:        %s\n" "${tenant_ns:-$svc_ns}"
        printf "      Provider Ceiling: %s SYN/sec (burst %s), %s connections\n" \
            "${prov_syn:-?}" "${prov_burst:-?}" "${prov_conn:-?}"
        echo ""
        ((display_idx++))
    done <<< "$LB_RAW"

    if [ ${#LB_IPS[@]} -eq 0 ]; then
        echo "  No LB IPs have provider ceiling configured!"
        echo "  Run /root/configure-provider.sh first."
        exit 1
    fi
    echo "============================================================"
}

select_lb_ip() {
    local count=${#LB_IPS[@]}
    echo ""
    read -p "Select LoadBalancer (1-$count): " selection

    if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le "$count" ]; then
        local idx=$((selection-1))
        SELECTED_IP="${LB_IPS[$idx]}"
        SELECTED_NAME="${LB_NAMES[$idx]}"
        SELECTED_SVC_NS="${LB_SVC_NS[$idx]}"
        SELECTED_TENANT_NS="${LB_TENANT_NS[$idx]}"
        PROV_SYN="${LB_PROV_SYN[$idx]}"
        PROV_BURST="${LB_PROV_BURST[$idx]}"
        PROV_CONN="${LB_PROV_CONN[$idx]}"
    else
        echo "Invalid selection"
        exit 1
    fi

    echo ""
    echo "  Selected IP:        $SELECTED_IP"
    echo "  Service:            $SELECTED_NAME"
    echo "  Tenant NS:          $SELECTED_TENANT_NS"
    echo "  Provider Ceiling:   $PROV_SYN SYN/sec, $PROV_CONN connections"
    echo ""
}

configure_limits() {
    echo "============================================================"
    echo "  Tenant Limit for $SELECTED_IP"
    echo "  Tenant Namespace: $SELECTED_TENANT_NS"
    echo "============================================================"
    echo ""
    echo "  Provider ceiling (CANNOT exceed):"
    echo "    Max SYN/sec:        $PROV_SYN"
    echo "    Max SYN burst:      $PROV_BURST"
    echo "    Max connections:    $PROV_CONN"
    echo ""
    echo "  --------------------------------------------------------"
    echo ""

    local default_syn=$((PROV_SYN / 5))
    echo "  Enter tenant SYN rate (must be <= $PROV_SYN):"
    read -p "  Max SYN per second [$default_syn]: " TEN_SYN
    TEN_SYN=${TEN_SYN:-$default_syn}

    if [ "$TEN_SYN" -gt "$PROV_SYN" ]; then
        echo ""
        echo "  REJECTED: $TEN_SYN exceeds provider ceiling $PROV_SYN"
        exit 1
    fi

    local default_ten_burst=$((TEN_SYN + TEN_SYN / 5))
    if [ "$default_ten_burst" -gt "$PROV_BURST" ]; then
        default_ten_burst=$PROV_BURST
    fi
    read -p "  Max SYN burst (must be <= $PROV_BURST) [$default_ten_burst]: " TEN_BURST
    TEN_BURST=${TEN_BURST:-$default_ten_burst}

    if [ "$TEN_BURST" -gt "$PROV_BURST" ]; then
        echo ""
        echo "  REJECTED: Burst $TEN_BURST exceeds provider ceiling $PROV_BURST"
        exit 1
    fi

    echo ""
    local default_conn=$((PROV_CONN / 4))
    echo "  Enter tenant max connections (must be <= $PROV_CONN):"
    read -p "  Max concurrent connections [$default_conn]: " TEN_CONN
    TEN_CONN=${TEN_CONN:-$default_conn}

    if [ "$TEN_CONN" -gt "$PROV_CONN" ]; then
        echo ""
        echo "  REJECTED: $TEN_CONN exceeds provider ceiling $PROV_CONN"
        exit 1
    fi

    local eff_syn=$TEN_SYN
    local eff_burst=$TEN_BURST
    local eff_conn=$TEN_CONN
    [ "$PROV_SYN" -lt "$eff_syn" ] && eff_syn=$PROV_SYN
    [ "$PROV_BURST" -lt "$eff_burst" ] && eff_burst=$PROV_BURST
    [ "$PROV_CONN" -lt "$eff_conn" ] && eff_conn=$PROV_CONN

    echo ""
    echo "============================================================"
    echo "  SUMMARY — Tenant Limit"
    echo "============================================================"
    echo "  LB IP:              $SELECTED_IP"
    echo "  Service:            $SELECTED_NAME"
    echo "  Tenant Namespace:   $SELECTED_TENANT_NS"
    echo ""
    echo "  Provider Ceiling    Tenant Request    Effective (min)"
    echo "  ----------------    --------------    ----------------"
    printf "  SYN/sec:   %-10s %-17s %s\n" "$PROV_SYN" "$TEN_SYN" "$eff_syn"
    printf "  Burst:     %-10s %-17s %s\n" "$PROV_BURST" "$TEN_BURST" "$eff_burst"
    printf "  Max Conn:  %-10s %-17s %s\n" "$PROV_CONN" "$TEN_CONN" "$eff_conn"
    echo ""
    echo "  VALIDATION: PASSED (all values within ceiling)"
    echo "============================================================"
    echo ""
    read -p "Apply this configuration? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        echo "Aborted."
        exit 0
    fi
}

apply_configuration() {
    local hex_key=$(ip_to_hex_key "$SELECTED_IP")
    local rate_hex=$(rate_cfg_to_hex $TEN_SYN $TEN_BURST)
    local conn_hex=$(int_to_hex_u64 $TEN_CONN)

    echo ""
    echo "Applying tenant configuration..."

    echo -n "  Setting syn_tenant_cfg... "
    bpftool map update pinned "$BPFFS/syn_tenant_cfg" key hex $hex_key value hex $rate_hex
    echo "OK"

    echo -n "  Setting conn_tenant_max... "
    bpftool map update pinned "$BPFFS/conn_tenant_max" key hex $hex_key value hex $conn_hex
    echo "OK"

    echo ""
    echo "============================================================"
    echo "  Tenant limit applied for $SELECTED_IP"
    echo "============================================================"

    echo ""
    echo "Verification:"
    echo "  Tenant SYN config:"
    bpftool map lookup pinned "$BPFFS/syn_tenant_cfg" key hex $hex_key 2>/dev/null
    echo ""
    echo "  Tenant max connections:"
    bpftool map lookup pinned "$BPFFS/conn_tenant_max" key hex $hex_key 2>/dev/null
    echo ""
    echo "  Current connection count:"
    bpftool map lookup pinned "$BPFFS/conn_count" key hex $hex_key 2>/dev/null || echo "    (no connections yet)"

    # Dynamic config directory based on tenant namespace
    local TENANT_SHORT="${SELECTED_TENANT_NS#vishanti-}"
    local CONFIG_DIR="/root/tenants/${TENANT_SHORT}/ebpf-phase1/configs"
    mkdir -p "$CONFIG_DIR"

    cat > "$CONFIG_DIR/tenant-${SELECTED_IP}.conf" << CONF
# Tenant Limit Configuration
# Generated: $(date)
LB_IP=$SELECTED_IP
SERVICE_NAME=$SELECTED_NAME
SERVICE_NAMESPACE=$SELECTED_SVC_NS
TENANT_NAMESPACE=$SELECTED_TENANT_NS
TENANT_SYN_PER_SEC=$TEN_SYN
TENANT_SYN_BURST=$TEN_BURST
TENANT_MAX_CONNECTIONS=$TEN_CONN
PROVIDER_SYN_PER_SEC=$PROV_SYN
PROVIDER_SYN_BURST=$PROV_BURST
PROVIDER_MAX_CONNECTIONS=$PROV_CONN
HEX_KEY="$hex_key"
CONF
    echo ""
    echo "  Config saved to: $CONFIG_DIR/tenant-${SELECTED_IP}.conf"
}

echo ""
echo "============================================================"
echo "  VISHANTI eBPF Rate Limiter — Tenant Configuration"
echo "============================================================"

check_prerequisites
show_configured_lbs
select_lb_ip
configure_limits
apply_configuration
