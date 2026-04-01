# Vishanti eBPF Rate Limiter: Architecture

This document details the internal architecture, component interactions, and data structures of the Vishanti two-tier TCP rate limiter.

## 🌊 High-Level Packet Flow

The system operates strictly at the network layer, intercepting packets before they reach user-space applications like Envoy. 

1. **Ingress (Internet → Node):**
   * A packet arrives at the node's network interface (`bond0`).
   * The **XDP Hook** (`xdp_vishanti_combined.o`) is triggered immediately.
   * The XDP program parses the Ethernet, IP, and TCP headers.
   * If the destination IP is in the `managed_lb_ips` map:
     * **On SYN (New Connection):** Evaluates the Token Bucket (Rate Limit) and Connection Counter (Max Connections). Drops (`XDP_DROP`) if limits are exceeded. Allows (`XDP_PASS`) if within limits.
     * **On FIN/RST (Client Close):** Decrements the active connection counter.
   * Allowed packets continue to Cilium/Envoy.

2. **Egress (Node → Internet):**
   * A response packet leaves the node.
   * The **TC Egress Hook** (`tc_vishanti_egress.o`) is triggered.
   * If the packet is a TCP FIN or RST (Server Close) originating from a managed IP, it decrements the active connection counter.

---

## 🧩 Core Components

### 1. XDP Program (`src/xdp_vishanti_combined.c`)
The primary enforcement engine. It operates in XDP Generic mode (as `bond0` typically requires generic mode). It implements both the **Token Bucket** algorithm for SYN rate limiting and the **Atomic Counters** for max concurrent connections.

### 2. TC Program (`src/tc_vishanti_egress.c`)
Attached to the Traffic Control (TC) egress hook. Its primary responsibility is to catch server-initiated connection closures (FIN/RST flags) to accurately decrement the active connection count, preventing counter leaks.

### 3. User-Space Control Plane (`scripts/`)
Shell scripts that interact with the kernel-space eBPF programs via `bpftool`. They read and write to the pinned eBPF maps located at `/sys/fs/bpf/vishanti/`.
* `configure-provider.sh`: Sets the absolute ceiling limits.
* `configure-tenant.sh`: Sets tenant-specific limits (validated against the provider ceiling).
* `monitor.sh`: Reads counters and rate states to provide a live UI.

### 4. Background Drift Cleanup (`scripts/conn-cleanup.sh`)
Because TCP state machines are complex and packets can be dropped further up the stack (e.g., by Cilium or routing issues), the eBPF connection counter can slowly drift. The cleanup service runs periodically to reconcile the eBPF `conn_count` map with the actual Cilium Connection Tracking (`ct list global`) table.

---

## 🗺️ eBPF Maps (Data Structures)

State and configuration are shared between user space and kernel space using pinned eBPF maps.

### Control Maps
* **`managed_lb_ips`** (Hash): A simple boolean flag map. Key is the Target LoadBalancer IP. If an IP exists here, the XDP program enforces limits; otherwise, it ignores the traffic.

### Configuration Maps
* **`syn_provider_cfg`** & **`syn_tenant_cfg`** (Hash): 
  * **Key:** Target IP (`__u32`)
  * **Value:** `struct rate_cfg { __u64 rate_per_sec; __u64 burst; }`
* **`conn_provider_max`** & **`conn_tenant_max`** (Hash): 
  * **Key:** Target IP (`__u32`)
  * **Value:** Max concurrent connections (`__u64`)

### State Maps
* **`syn_rate_state`** (LRU Hash): Stores the current token bucket state.
  * **Key:** Target IP (`__u32`)
  * **Value:** `struct rate_state { __u64 provider_tokens; __u64 tenant_tokens; __u64 last_ns; }`
* **`conn_count`** (Hash): Tracks the live count of established connections.
  * **Key:** Target IP (`__u32`)
  * **Value:** Active connections (`__u64`)

### Telemetry Maps
* **`syn_drop_count`** & **`conn_drop_count`** (Per-CPU Hash): Highly efficient per-CPU counters tracking how many packets were dropped due to rate limiting or connection limits, respectively.

---

## ⚖️ The Two-Tier Logic

The architecture is built around a "Provider vs. Tenant" model to ensure platform stability even if a tenant misconfigures their limits.

1. **Effective Connection Limit:** When checking connection limits, the XDP program dynamically reads both `conn_provider_max` and `conn_tenant_max`. It enforces the *minimum* of the two values.
2. **Dual Token Buckets:** When a SYN packet arrives, it must consume a token from **both** the Provider Bucket and the Tenant Bucket. If either bucket is empty, the packet is dropped. Tokens refill based on elapsed time (`last_ns`) and the configured rates.
