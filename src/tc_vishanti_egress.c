// SPDX-License-Identifier: GPL-2.0
// TC Egress: decrement conn_count on server-initiated FIN/RST
// INCLUDES debug counter to verify program executes

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} conn_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} managed_lb_ips SEC(".maps");

// DEBUG: counts how many packets TC egress actually processes
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} egress_debug SEC(".maps");

// key 0 = total packets seen
// key 1 = TCP packets with managed saddr
// key 2 = FIN/RST decrements performed
// key 3 = total TCP packets

SEC("classifier")
int vishanti_tc_egress(struct __sk_buff *skb)
{
    // DEBUG: count every packet
    __u32 idx0 = 0;
    __u64 *total = bpf_map_lookup_elem(&egress_debug, &idx0);
    if (total) __sync_fetch_and_add(total, 1);

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
    if (ip->protocol != IPPROTO_TCP) return TC_ACT_OK;

    // DEBUG: count TCP packets
    __u32 idx3 = 3;
    __u64 *tcp_cnt = bpf_map_lookup_elem(&egress_debug, &idx3);
    if (tcp_cnt) __sync_fetch_and_add(tcp_cnt, 1);

    __u32 src_ip = ip->saddr;
    __u8 *managed = bpf_map_lookup_elem(&managed_lb_ips, &src_ip);
    if (!managed) return TC_ACT_OK;

    // DEBUG: count managed IP matches
    __u32 idx1 = 1;
    __u64 *managed_cnt = bpf_map_lookup_elem(&egress_debug, &idx1);
    if (managed_cnt) __sync_fetch_and_add(managed_cnt, 1);

    int ihl = ip->ihl * 4;
    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;

    if (tcp->fin || tcp->rst) {
        __u64 *cnt = bpf_map_lookup_elem(&conn_count, &src_ip);
        if (cnt && *cnt > 0) {
            __sync_fetch_and_add(cnt, -1);

            // DEBUG: count decrements
            __u32 idx2 = 2;
            __u64 *dec_cnt = bpf_map_lookup_elem(&egress_debug, &idx2);
            if (dec_cnt) __sync_fetch_and_add(dec_cnt, 1);
        }
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
