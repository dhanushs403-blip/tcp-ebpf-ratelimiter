#!/bin/bash
export KUBECONFIG=/etc/kubernetes/admin.conf
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin:$PATH

BPFFS="/sys/fs/bpf/vishanti"
INTERVAL=30
LOG="/var/log/vishanti-cleanup.log"
MAX_DRIFT=20

ip_to_hex_key() {
    IFS='.' read -r a b c d <<< "$1"
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

get_cilium_conn_count() {
    local ip="$1"
    local ct_output
    ct_output=$(kubectl exec -n kube-system ds/cilium -- cilium-dbg bpf ct list global 2>/dev/null)

    # Count only entries for this IP that have actual packets, not stale SYN-only entries
    local count
    count=$(echo "$ct_output" | \
        grep -F "$ip" | \
        grep -v "Packets=0" | \
        wc -l)

    echo "${count:-0}"
}

echo "$(date) Vishanti cleanup v5 started (excluding Packets=0 CT entries)" >> "$LOG"

if ! kubectl get nodes > /dev/null 2>&1; then
    echo "$(date) FATAL: kubectl not working" >> "$LOG"
    exit 1
fi
echo "$(date) kubectl OK" >> "$LOG"

TEST_OUTPUT=$(kubectl exec -n kube-system ds/cilium -- cilium-dbg bpf ct list global 2>/dev/null | grep -F "23.111.176.46" | grep -v "Packets=0" | wc -l)
echo "$(date) Cilium test (real entries only): $TEST_OUTPUT entries for 23.111.176.46" >> "$LOG"

while true; do
    KEYS=$(bpftool map dump pinned "$BPFFS/managed_lb_ips" 2>/dev/null | grep -oP '"key":\s*\K[0-9]+')

    for key_decimal in $KEYS; do
        a=$(( (key_decimal >> 0) & 0xFF ))
        b=$(( (key_decimal >> 8) & 0xFF ))
        c=$(( (key_decimal >> 16) & 0xFF ))
        d=$(( (key_decimal >> 24) & 0xFF ))
        ip="$a.$b.$c.$d"
        hex_key=$(ip_to_hex_key "$ip")

        ebpf_count=$(bpftool map lookup pinned "$BPFFS/conn_count" \
            key hex $hex_key 2>/dev/null | grep -oP '"value":\s*\K[0-9]+' | head -1)
        ebpf_count=${ebpf_count:-0}

        real_count=$(get_cilium_conn_count "$ip")

        drift=$((ebpf_count - real_count))
        abs_drift=${drift#-}

        if [ "$abs_drift" -gt "$MAX_DRIFT" ]; then
            corrected=$real_count
            corrected_hex=$(int_to_hex_u64 $corrected)

            bpftool map update pinned "$BPFFS/conn_count" \
                key hex $hex_key \
                value hex $corrected_hex

            echo "$(date '+%H:%M:%S') CORRECTED $ip: ebpf=$ebpf_count real=$real_count drift=$drift" >> "$LOG"
        else
            echo "$(date '+%H:%M:%S') OK $ip: ebpf=$ebpf_count real=$real_count drift=$drift" >> "$LOG"
        fi
    done

    sleep $INTERVAL
done
