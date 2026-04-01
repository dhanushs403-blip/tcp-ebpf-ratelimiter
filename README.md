# Vishanti: TCP eBPF Rate Limiter

Vishanti is a kernel-space TCP rate limiter built with eBPF. It is designed to protect Kubernetes Ingress and Envoy gateways from SYN floods and connection exhaustion attacks by dropping malicious or excessive traffic at the network interface level (`bond0`) before it reaches user space or the CPU.

## Key Features

* **XDP-Based Enforcement:** Operates at the eXpress Data Path (XDP) layer, processing and potentially dropping packets in ~100 nanoseconds.
* **Two-Tier Policy System:**
    * **Provider Ceiling:** A hard upper limit set by the platform administrator.
    * **Tenant Limit:** A tenant-specific limit configured by the tenant administrator, strictly validated against the Provider Ceiling.
* **Dual-Metric Limiting:**
    * **SYN Rate Limiting:** Utilizes a token bucket algorithm to limit new TCP connections per second (SYN packets).
    * **Max Concurrent Connections:** Tracks and caps the total number of active connections per LoadBalancer IP.
* **Zero-Downtime Updates:** Limits can be updated dynamically via eBPF maps without restarting the service or dropping existing valid connections.

## Architecture Overview

The system hooks into the node's network interface and intercepts traffic destined for LoadBalancer VIPs.

1.  **Incoming Traffic:** Packets hit the network card (`bond0`).
2.  **eBPF XDP Hook (`xdp_vishanti_combined.c`):** * Parses the packet to identify TCP SYN or FIN/RST flags.
    * Checks the destination IP against a map of `managed_lb_ips`.
    * Evaluates the token bucket for SYN rate limits.
    * Evaluates the active connection count.
    * **Action:** Returns `XDP_DROP` if limits are exceeded, or `XDP_PASS` to allow the packet through to Cilium and Envoy.
3.  **eBPF TC Hook (`tc_vishanti_egress.c`):** Tracks outbound FIN/RST packets to decrement the active connection counters.
4.  **Cleanup Service:** A background systemd service (`vishanti-cleanup.service`) periodically scrubs stale connection counts by comparing eBPF map data with Cilium's connection tracking table.

## 📁 Project Structure

* `src/`: Contains the eBPF C source code (`xdp_vishanti_combined.c`, `tc_vishanti_egress.c`).
* `obj/`: Compiled eBPF object files (`.o`).
* `scripts/`: Automation and management shell scripts.
* `systemd/`: Contains the `vishanti-cleanup.service` definition.

## Prerequisites

To compile and run this project, the node requires:
* Kernel 5.15+
* Cilium 1.18+
* `clang` 14+, `llvm`, `bpftool`, and `libbpf-dev`
* eBPF filesystem mounted at `/sys/fs/bpf`

## Quick Start & Usage

The project includes interactive scripts to bootstrap the node, configure limits, and monitor live traffic.

### 1. Bootstrap the Node
Load the eBPF programs into the kernel and attach them to the network interface.
```bash
/root/node-bootstrap.sh
