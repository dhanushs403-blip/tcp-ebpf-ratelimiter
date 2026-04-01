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

check_prerequisites() {
    if [ ! -d "$BPFFS" ]; then
        echo "ERROR: eBPF programs not loaded!"
        echo "Run: /root/node-bootstrap.sh"
        exit 1
    fi
    for map in syn_provider_cfg conn_provider_max managed_lb_ips; do
        if [ ! -e "$BPFFS/$map" ]; then
            echo "ERROR: Map $map not found"
            exit 1
        fi
    done
    echo "[OK] eBPF maps found"
}

build_lb_list() {
    LB_RAW=$(kubectl get svc -A \
        -o jsonpath='{range .items[?(@.status.loadBalancer.ingress)]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.status.loadBalancer.ingress[0].ip}{"\t"}{.spec.ports[*].port}{"\t"}{.metadata.labels.gateway\.envoyproxy\.io/owning-gateway-namespace}{"\n"}{end}' 2>/dev/null | grep -v '^$')

    declare -g -a LB_IPS=()
    declare -g -a LB_NAMES=()
    declare -g -a LB_SVC_NS=()
    declare -g -a LB_TENANT_NS=()
    declare -g -a LB_PORTS=()

    while IFS=$'\t' read -r svc_ns name ip ports tenant_ns; do
        [ -z "$ip" ] && continue
        LB_IPS+=("$ip")
        LB_NAMES+=("$name")
        LB_SVC_NS+=("$svc_ns")
        LB_TENANT_NS+=("${tenant_ns:-$svc_ns}")
        LB_PORTS+=("$ports")
    done <<< "$LB_RAW"
}

show_lb_list() {
    echo ""
    echo "============================================================"
    echo "  Available LoadBalancer Services"
    echo "============================================================"
    echo ""
    local count=${#LB_IPS[@]}
    for ((i=0; i<count; i++)); do
        local hex_key=$(ip_to_hex_key "${LB_IPS[$i]}")
        local status="[NOT CONFIGURED]"
        if bpftool map lookup pinned "$BPFFS/managed_lb_ips" key hex $hex_key 2>/dev/null | grep -q "value"; then
            status="[CONFIGURED]"
        fi
        printf "  %2d) %-18s %s\n" "$((i+1))" "${LB_IPS[$i]}" "$status"
        printf "      Service:      %s\n" "${LB_NAMES[$i]}"
        printf "      Service NS:   %s\n" "${LB_SVC_NS[$i]}"
        printf "      Tenant NS:    %s\n" "${LB_TENANT_NS[$i]}"
        printf "      Ports:        %s\n" "${LB_PORTS[$i]}"
        echo ""
    done
    echo "============================================================"
}

select_lb_ip() {
    local count=${#LB_IPS[@]}
    if [ "$count" -eq 0 ]; then
        echo "ERROR: No LoadBalancer services found"
        exit 1
    fi
    echo ""
    read -p "Select LoadBalancer (1-$count) or enter IP manually: " selection

    if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le "$count" ]; then
        local idx=$((selection-1))
        SELECTED_IP="${LB_IPS[$idx]}"
        SELECTED_NAME="${LB_NAMES[$idx]}"
        SELECTED_SVC_NS="${LB_SVC_NS[$idx]}"
        SELECTED_TENANT_NS="${LB_TENANT_NS[$idx]}"
    elif [[ "$selection" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        SELECTED_IP="$selection"
        SELECTED_NAME="unknown"
        SELECTED_SVC_NS="unknown"
        SELECTED_TENANT_NS="unknown"
        for ((i=0; i<${#LB_IPS[@]}; i++)); do
            if [ "${LB_IPS[$i]}" = "$SELECTED_IP" ]; then
                SELECTED_NAME="${LB_NAMES[$i]}"
                SELECTED_SVC_NS="${LB_SVC_NS[$i]}"
                SELECTED_TENANT_NS="${LB_TENANT_NS[$i]}"
                break
            fi
        done
    else
        echo "Invalid selection"
        exit 1
    fi

    echo ""
    echo "  Selected IP:      $SELECTED_IP"
    echo "  Service:          $SELECTED_NAME"
    echo "  Service NS:       $SELECTED_SVC_NS"
    echo "  Tenant NS:        $SELECTED_TENANT_NS"
    echo ""
}

configure_limits() {
    echo "============================================================"
    echo "  Provider Ceiling for $SELECTED_IP"
    echo "  Tenant Namespace: $SELECTED_TENANT_NS"
    echo "============================================================"
    echo ""
    echo "  These are HARD CAPS. Tenants cannot exceed these values."
    echo ""
    echo "  SYN Rate Presets:"
    echo "    Small:      1000 SYN/sec"
    echo "    Medium:     5000 SYN/sec"
    echo "    Large:     10000 SYN/sec"
    echo "    Enterprise: 50000 SYN/sec"
    echo ""
    read -p "  Max SYN per second [5000]: " MAX_SYN
    MAX_SYN=${MAX_SYN:-5000}
    local default_burst=$((MAX_SYN + MAX_SYN / 5))
    read -p "  Max SYN burst [$default_burst]: " MAX_BURST
    MAX_BURST=${MAX_BURST:-$default_burst}
    echo ""
    echo "  Connection Presets:"
    echo "    Small:       5000 connections"
    echo "    Medium:     20000 connections"
    echo "    Large:      50000 connections"
    echo "    Enterprise: 200000 connections"
    echo ""
    read -p "  Max concurrent connections [20000]: " MAX_CONN
    MAX_CONN=${MAX_CONN:-20000}

    echo ""
    echo "============================================================"
    echo "  SUMMARY — Provider Ceiling"
    echo "============================================================"
    echo "  LB IP:              $SELECTED_IP"
    echo "  Service:            $SELECTED_NAME"
    echo "  Service Namespace:  $SELECTED_SVC_NS"
    echo "  Tenant Namespace:   $SELECTED_TENANT_NS"
    echo "  Max SYN/sec:        $MAX_SYN"
    echo "  Max SYN burst:      $MAX_BURST"
    echo "  Max connections:    $MAX_CONN"
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
    local rate_hex=$(rate_cfg_to_hex $MAX_SYN $MAX_BURST)
    local conn_hex=$(int_to_hex_u64 $MAX_CONN)

    echo ""
    echo "Applying configuration..."

    echo -n "  Setting syn_provider_cfg... "
    bpftool map update pinned "$BPFFS/syn_provider_cfg" key hex $hex_key value hex $rate_hex
    echo "OK"

    echo -n "  Setting conn_provider_max... "
    bpftool map update pinned "$BPFFS/conn_provider_max" key hex $hex_key value hex $conn_hex
    echo "OK"

    echo -n "  Registering managed_lb_ips... "
    bpftool map update pinned "$BPFFS/managed_lb_ips" key hex $hex_key value hex 01
    echo "OK"

    echo ""
    echo "============================================================"
    echo "  Provider ceiling applied for $SELECTED_IP"
    echo "============================================================"

    echo ""
    echo "Verification:"
    echo "  Provider SYN config:"
    bpftool map lookup pinned "$BPFFS/syn_provider_cfg" key hex $hex_key 2>/dev/null
    echo ""
    echo "  Provider max connections:"
    bpftool map lookup pinned "$BPFFS/conn_provider_max" key hex $hex_key 2>/dev/null
    echo ""
    echo "  Managed LB IPs:"
    bpftool map lookup pinned "$BPFFS/managed_lb_ips" key hex $hex_key 2>/dev/null

    # Dynamic config directory based on tenant namespace
    local TENANT_SHORT="${SELECTED_TENANT_NS#vishanti-}"
    local CONFIG_DIR="/root/tenants/${TENANT_SHORT}/ebpf-phase1/configs"
    mkdir -p "$CONFIG_DIR"

    cat > "$CONFIG_DIR/provider-${SELECTED_IP}.conf" << CONF
# Provider Ceiling Configuration
# Generated: $(date)
LB_IP=$SELECTED_IP
SERVICE_NAME=$SELECTED_NAME
SERVICE_NAMESPACE=$SELECTED_SVC_NS
TENANT_NAMESPACE=$SELECTED_TENANT_NS
MAX_SYN_PER_SEC=$MAX_SYN
MAX_SYN_BURST=$MAX_BURST
MAX_CONCURRENT_CONNECTIONS=$MAX_CONN
HEX_KEY="$hex_key"
CONF
    echo ""
    echo "  Config saved to: $CONFIG_DIR/provider-${SELECTED_IP}.conf"
}

echo ""
echo "============================================================"
echo "  VISHANTI eBPF Rate Limiter — Provider Configuration"
echo "============================================================"

check_prerequisites
build_lb_list
show_lb_list
select_lb_ip
configure_limits
apply_configuration
