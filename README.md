# Bare-Metal Network Shield

A hybrid nftables + XDP/eBPF mitigation stack extracted from a game server orchestration platform after repeated issues with high-PPS UDP flood traffic affecting container performance.

The goal is not to replace enterprise DDoS mitigation services or dedicated hardware appliances, but to reduce kernel overhead during sustained flood conditions and help keep game server containers responsive in small-scale bare-metal environments.

---

## Why This Exists

During testing and production operation, I found that relying solely on traditional firewall rules and conntrack-based filtering could still introduce enough CPU and kernel networking overhead to impact running game servers under sustained high packet rates.

This project explores a layered approach:

* nftables for stateful filtering and rate limiting
* XDP/eBPF for early packet drop paths
* a small userspace daemon to synchronize state between them

---

## Docker, UFW, and nftables

Docker’s iptables-based networking and UFW can introduce complexity when combined, especially in environments with heavy custom firewalling.

Rather than continuing to layer rules on top of multiple abstractions, I opted to manage filtering directly with nftables.

The ruleset uses a custom chain at a high-priority prerouting hook (`-150`) so traffic can be evaluated early in the networking path before reaching later firewall stages or container networking rules.

```nft
chain raw_checks {
    type filter hook prerouting priority -150;
    policy accept;
}
```

---

## Architecture

### 1. Stateful Filtering (nftables)

nftables handles:

* Per-protocol rate limiting
* Connection tracking-based protections
* Dynamic blacklist with timeout

IPs that exceed extreme thresholds are added to a blacklist set with a time-based expiration.

```nft
set blacklist {
    type ipv4_addr;
    flags dynamic, timeout;
    size 65535;
    timeout 300s;
}

ip saddr @blacklist counter name ddos_blacklist_drops drop
```

---

### 2. Fast-path filtering (XDP/eBPF)

In testing, nftables alone still introduced measurable CPU overhead under sustained high packet rates.

To reduce this overhead, a userspace daemon monitors the nftables blacklist and synchronizes entries into an eBPF map used by an XDP program.

When enabled, XDP allows packets to be dropped very early in the kernel networking path (at the XDP hook in the driver or generic fallback mode depending on system support).

```bash
xdp-filter load eth0 -f ipv4,ipv6 --mode native
xdp-filter ip -m src "$ip"
```

> Note: XDP mode depends on driver support. Systems without native XDP support will fall back to a generic mode in the kernel networking stack.

---

## Implementation Notes

* C# is used for orchestration and remote management of rules
* nftables rules are generated per-port and deployed dynamically
* XDP synchronization runs as a systemd service with a 2-second polling interval

This introduces a small window where newly flagged IPs may still reach the kernel before being added to the XDP map.

---

## Kernel Tuning

### UDP buffer sizing

Increasing `rmem_max` and `wmem_max` improves resilience under bursty traffic patterns by reducing packet drops in the kernel receive buffers.

This is especially relevant for real-time game traffic where short bursts can otherwise cause visible desynchronization.

```conf
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
```

---

### TCP congestion control

This setup uses BBR instead of CUBIC:

* CUBIC can interpret packet loss as congestion
* BBR tends to behave more consistently under variable network conditions typical in game server traffic

```conf
net.ipv4.tcp_congestion_control = bbr
```

---

## Stress Testing

Tested on an AMD EPYC bare-metal node under synthetic UDP flood conditions reaching approximately 500,000 packets per second.

At peak load, the upstream provider eventually null-routed the box to protect their network.

This behavior is visible in the full 22-minute telemetry replay:

👉 Performance audit: https://ray-hosting.com/en-US/performance-audit

![Stress Test](./media/stress-test.gif)

**Observed behavior:**

* nftables handled initial filtering
* XDP reduced CPU and softirq pressure under sustained load
* system remained responsive until upstream provider rate-limited or null-routed traffic

> This is not a guarantee of performance under all conditions; results will vary depending on hardware, driver support, and traffic patterns.

---

## Known Limitations

* The XDP synchronization daemon uses polling (2s interval), which introduces a small propagation delay between detection and hardware map update
* Orphaned nftables chains may remain after unexpected node restarts and are cleaned up via a garbage collection script
* SSH-based orchestration introduces overhead compared to fully agent-based systems

---

## Contributing

PRs are welcome, especially in areas such as:

* Reducing or replacing polling-based XDP synchronization
* Improving nftables chain lifecycle management
* Reducing SSH overhead in orchestration flows

---

## License / Usage

This is not a reference implementation for DDoS mitigation and should not be considered a substitute for upstream protection services.

It reflects an operational setup that evolved from real-world game hosting workloads where high-PPS UDP traffic and connection spikes were impacting server stability.

The same mitigation stack is currently used in production on my own game hosting infrastructure (Ray Hosting), and is provided here as-is. It may require tuning depending on kernel version, NIC driver behavior, and workload characteristics.
