// SPDX-License-Identifier: GPL-2.0
// Combined XDP: SYN rate limiting + Connection counting
// Runs BEFORE Cilium TC (sees original daddr = LB VIP)
// Mode: XDP generic (bond0 doesn't support native XDP)

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TOKEN_SCALE 1000ULL

// ===== SYN RATE LIMITING MAPS =====

struct rate_cfg {
    __u64 rate_per_sec;
    __u64 burst;
};

struct rate_state {
    __u64 provider_tokens;
    __u64 tenant_tokens;
    __u64 last_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct rate_cfg);
} syn_provider_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct rate_cfg);
} syn_tenant_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct rate_state);
} syn_rate_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} syn_drop_count SEC(".maps");

// ===== CONNECTION COUNTING MAPS =====

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} conn_provider_max SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} conn_tenant_max SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} conn_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} conn_drop_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} managed_lb_ips SEC(".maps");

// ===== RATE LIMITER LOGIC =====

static __always_inline int refill_and_consume(
    struct rate_state *st, struct rate_cfg *p_cfg,
    struct rate_cfg *t_cfg, __u64 now)
{
    __u64 elapsed = now - st->last_ns;
    st->last_ns = now;

    __u64 p_add = (elapsed * p_cfg->rate_per_sec) / 1000000000ULL * TOKEN_SCALE;
    st->provider_tokens += p_add;
    if (st->provider_tokens > p_cfg->burst * TOKEN_SCALE)
        st->provider_tokens = p_cfg->burst * TOKEN_SCALE;

    __u64 t_add = (elapsed * t_cfg->rate_per_sec) / 1000000000ULL * TOKEN_SCALE;
    st->tenant_tokens += t_add;
    if (st->tenant_tokens > t_cfg->burst * TOKEN_SCALE)
        st->tenant_tokens = t_cfg->burst * TOKEN_SCALE;

    if (st->provider_tokens < TOKEN_SCALE || st->tenant_tokens < TOKEN_SCALE)
        return XDP_DROP;

    st->provider_tokens -= TOKEN_SCALE;
    st->tenant_tokens -= TOKEN_SCALE;
    return XDP_PASS;
}

// ===== CONNECTION COUNT HELPERS =====

static __always_inline __u64 get_effective_max(__u32 ip)
{
    __u64 *p = bpf_map_lookup_elem(&conn_provider_max, &ip);
    __u64 *t = bpf_map_lookup_elem(&conn_tenant_max, &ip);
    if (!p) return 0;
    __u64 effective = *p;
    if (t && *t < effective) effective = *t;
    return effective;
}

static __always_inline void increment_drop(__u32 ip,
    struct bpf_map_def *drop_map)
{
    __u64 *cnt = bpf_map_lookup_elem(drop_map, &ip);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
    else {
        __u64 one = 1;
        bpf_map_update_elem(drop_map, &ip, &one, BPF_ANY);
    }
}

// ===== MAIN XDP PROGRAM =====

SEC("xdp")
int vishanti_xdp_combined(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Parse TCP
    int ihl = ip->ihl * 4;
    if (ihl < 20)
        return XDP_PASS;
    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u32 dest_ip = ip->daddr;

    // Check if this is a managed LB IP
    __u8 *managed = bpf_map_lookup_elem(&managed_lb_ips, &dest_ip);
    if (!managed)
        return XDP_PASS;

    // ============================================================
    // HANDLE SYN (new connection)
    // ============================================================
    if (tcp->syn && !tcp->ack) {

        // --- TIER 1: SYN Rate Limiting (token bucket) ---
        struct rate_cfg *p_cfg = bpf_map_lookup_elem(&syn_provider_cfg, &dest_ip);
        if (p_cfg) {
            struct rate_cfg *t_cfg = bpf_map_lookup_elem(&syn_tenant_cfg, &dest_ip);
            struct rate_cfg default_tenant = *p_cfg;
            if (!t_cfg) t_cfg = &default_tenant;

            __u64 now = bpf_ktime_get_ns();
            struct rate_state *st = bpf_map_lookup_elem(&syn_rate_state, &dest_ip);

            if (!st) {
                struct rate_state new_st = {
                    .provider_tokens = p_cfg->burst * TOKEN_SCALE,
                    .tenant_tokens = t_cfg->burst * TOKEN_SCALE,
                    .last_ns = now,
                };
                bpf_map_update_elem(&syn_rate_state, &dest_ip, &new_st, BPF_ANY);
            } else {
                int rate_action = refill_and_consume(st, p_cfg, t_cfg, now);
                if (rate_action == XDP_DROP) {
                    // SYN rate exceeded
                    __u64 *sc = bpf_map_lookup_elem(&syn_drop_count, &dest_ip);
                    if (sc) __sync_fetch_and_add(sc, 1);
                    else {
                        __u64 one = 1;
                        bpf_map_update_elem(&syn_drop_count, &dest_ip, &one, BPF_ANY);
                    }
                    return XDP_DROP;
                }
            }
        }

        // --- TIER 2: Connection Count Limiting ---
        __u64 max_conn = get_effective_max(dest_ip);
        if (max_conn > 0) {
            __u64 *cnt = bpf_map_lookup_elem(&conn_count, &dest_ip);
            if (!cnt) {
                __u64 one = 1;
                bpf_map_update_elem(&conn_count, &dest_ip, &one, BPF_ANY);
            } else {
                __u64 prev = __sync_fetch_and_add(cnt, 1);
                if (prev >= max_conn) {
                    // Over connection limit - rollback and drop
                    __sync_fetch_and_add(cnt, -1);
                    __u64 *dc = bpf_map_lookup_elem(&conn_drop_count, &dest_ip);
                    if (dc) __sync_fetch_and_add(dc, 1);
                    else {
                        __u64 one = 1;
                        bpf_map_update_elem(&conn_drop_count, &dest_ip, &one, BPF_ANY);
                    }
                    return XDP_DROP;
                }
            }
        }

        return XDP_PASS;
    }

    // ============================================================
    // HANDLE FIN/RST (connection closing - client side)
    // ============================================================
    if (tcp->fin || tcp->rst) {
        __u64 *cnt = bpf_map_lookup_elem(&conn_count, &dest_ip);
        if (cnt && *cnt > 0)
            __sync_fetch_and_add(cnt, -1);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
