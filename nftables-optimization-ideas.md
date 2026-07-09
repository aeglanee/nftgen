# Optimizing nftables for bare-metal x86 data center routers

requires a architecture-level approach that maximizes Linux kernel
packet-per-second (PPS) throughput and eliminates CPU cache thrashing.

## 1. Leverage Kernel Flowtables (Fast Path)

The single most effective optimization is the use of flowtables.
Once a TCP or UDP connection is verified in the standard conntrack
stateful path, subsequent packets bypass the entire netfilter stack,
reducing CPU processing time per packet down to near-line rate. [1]

table inet filter {
flowtable fwd_fastpath {
hook ingress priority filter
devices = { eth0, eth1 } # Replace with your high-speed interfaces
}

    chain forward {
        type filter hook forward priority filter; policy accept;

        # Offload established traffic immediately
        ct state established, related flow add @fwd_fastpath
    }

}

## 2. Structuring Rules for O(1) Lookups

Data center routers handling vast amounts of BGP prefixes, ACLs,
or CGNAT pools must completely avoid sequential list scanning.

Use Concatenations: Instead of creating separate nested chains or
sequential evaluation rules, bundle multiple lookup variables
(e.g., source IP, destination IP, protocol, port)
into a single expression. [2, 3]
Utilize Named Sets and Maps: Force O(1) algorithmic lookups using
hash trees under the hood. Avoid matching on anonymous sets ip saddr
{ 1.1.1.1, 2.2.2.2 } dynamically inside chains.
Optimize Set Policies: If managing colossal IP sets (e.g.,
threat intelligence feeds >100k elements),
configure the set policy explicitly to balance memory consumption. [4]

### Example of O(1) Concatenated VMAP for policy routing/actions

table ip router_vmap {
map acl_matrix {
type ipv4_addr . inet_service : verdict
elements = {
10.0.0.5 . 443 : accept,
192.168.1.10 . 22 : drop
}
}

    chain prerouting {
        type filter hook prerouting priority filter; policy accept;
        ip saddr . tcp dport vmap @acl_matrix
    }

}

## 3. Connection Tracking Optimization (conntrack)

Data center core routers handling millions of parallel states will
bottleneck instantly on conntrack locking mechanisms if left unconfigured.

- Bypass conntrack (notrack): For pure transit routing without stateful
  firewalling requirements (like public BGP transit), explicitly disable
  connection tracking using the raw table equivalent (prerouting priority -300).
- Scale the Conntrack Hash Table via sysctl: If state tracking is required for
  CGNAT or stateful ACLs, expand the hash size to prevent hash collisions.

### Set hash bucket size and max tracked connections based on large RAM capacity

sysctl -w net.netfilter.nf_conntrack_buckets=1048576
sysctl -w net.netfilter.nf_conntrack_max=4194304

## 4. Hardware and Kernel Tuning for x86 Data Planes

Even the most streamlined nftables configurations will fail at 10Gbps+ scales
if the underlying Linux networking subsystem is stalling on hardware queues. [5]

- Multi-Queue Ring Buffers & RSS: Distribute the interrupt processing load evenly
  across CPU cores using Receive Side Scaling (RSS) on enterprise NICs
  (e.g., Intel X710/E810 or Mellanox ConnectX).

ethtool -G eth0 rx 4096 tx 4096

[5, 6, 7]

- Pin Interrupts via irqbalance: Disable global irqbalance daemon and manually
  bind network interface rx/tx queues directly to specific physical CPU cores
  (avoid crossing NUMA nodes).
- Mitigate C-State Latency: Router platforms must handle unexpected bursts immediately.
  Force the CPU into a sustained performance state to prevent the microsecond
  awakening latencies that drop line-rate traffic.

cpupower frequency-set -g performance# Grub parameter: intel_idle.max_cstate=0 processor.max_cstate=0

[5]

## 5. Architectural Anti-Patterns to Avoid

- Avoid String Matching: Do not use payload or text-matching parameters at high
  scale inside nftables rules; it destroys CPU cache performance.
- Avoid iifname / oifname: Use iif and oif (numeric interface index matches)
  instead of string-based name comparisons, which perform dynamic system calls
  on every packet.
- Avoid Inline Logging: Streaming logs from nftables via standard syslog triggers
  heavy context switching. Offload logging to nflog or netlink monitoring
  tools if auditing is mandatory. [8, 9]

If you are looking to squeeze maximum packet performance
out of these x86 servers, let me know:

- What throughput tier are you targeting (e.g., 10G, 40G, 100G)?
- What is your average packet size or traffic profile?
- Do you require stateful operations like CGNAT or Stateful Firewalls?

I can help you build custom sysctl templates or tailor
the rules for your specific hardware architecture.

[1] [https://oneuptime.com](https://oneuptime.com/blog/post/2026-03-20-nftables-flowtables-performance/view)
[2] [https://www.monotux.tech](https://www.monotux.tech/posts/2021/04/nftables-primer/)
[3] [https://thermalcircle.de](https://thermalcircle.de/doku.php?id=blog:linux:flowtables_1_a_netfilter_nftables_fastpath)
[4] [https://forum.openwrt.org](https://forum.openwrt.org/t/nftables-chokes-on-very-large-sets/172580?page=2)
[5] [https://forums.servethehome.com](https://forums.servethehome.com/index.php?threads/10gbps-x86-router-requirements.51348/)
[6] [https://www.6wind.com](https://www.6wind.com/6wind-vrouter-4-steps-to-build-a-100g-border-router-on-an-x86-server/)
[7] [https://eureka.patsnap.com](https://eureka.patsnap.com/article/bios-tuning-for-high-frequency-trading-systems)
[8] [https://wiki.nftables.org](https://wiki.nftables.org/wiki-nftables/index.php/Main_Page)
[9] [https://wiki.archlinux.org](https://wiki.archlinux.org/title/Nftables)
