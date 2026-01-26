# xdp-gtpu (XDP/eBPF uplink PoC)

Minimal GTP-U uplink data plane using XDP: decap on N3, TEID lookup, counters, and redirect to N6. This is a UPF subset only; no control plane, PFCP, or downlink. Maps are managed with `bpftool`.

## Design snapshot
- Scope: Uplink only (N3 -> N6), GTP-U Flags=0x30 T-PDU, drop on TEID miss.
- Maps: `teid_fwd` (out_ifindex, dst/src MAC, optional next-hop), `teid_stats` (pkts/bytes/lookup_miss), `ingress_if` (expected N3 ifindex).
- Env: PoC assumes a veth pair (N3 side attach, N6 side egress). No PFCP/SMF/QoS/PMTU handling.

## Prerequisites
- clang/LLVM with BPF target, bpftool, Linux kernel with XDP.
- Root privileges to load/attach programs and update maps.

## Build
```bash
# Build XDP object + test sender
make
```

## Attach (example)
```bash
# 1) Set ingress ifindex (N3 side)
N3=veth-n3
N6=veth-n6
IDX_N3=$(cat /sys/class/net/$N3/ifindex)
IDX_N6=$(cat /sys/class/net/$N6/ifindex)

# 2) Load and attach
bpftool prog load xdp/mini_upf.o /sys/fs/bpf/mini_upf
bpftool net attach xdp pinned /sys/fs/bpf/mini_upf dev $N3

# 3) Program maps (example TEID 0x1)
bpftool map update pinned /sys/fs/bpf/tc/globals/ingress_if key 0 0 0 0 value $IDX_N3 0 0 0
bpftool map update pinned /sys/fs/bpf/tc/globals/teid_fwd key 01 00 00 00 \
  value $(printf "%02x %02x %02x %02x" $(echo $IDX_N6 | sed 's/.*/& 0 0 0/')) \
  aa bb cc dd ee ff 11 22 33 44 55 66 \
  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

> Note: Update the `teid_fwd` value bytes to include proper `dst_mac`/`src_mac` (12 bytes) and optional next-hop. The above is illustrative only; prefer `bpftool map -f` with a hex blob.

## Send a test GTP-U packet (raw socket helper)
- `send_gtpu` crafts one GTP-U TPDU (TEID=1, Flags=0x30, MsgType=TPDU, payload=4 bytes) and sends it on a given interface using AF_PACKET.
- Example (assuming `teid_fwd` has TEID=1 pointing to `veth-n6`):
```bash
sudo ./send_gtpu veth-n3 $(cat /sys/class/net/veth-n6/address)
```
- Outer IP: 203.0.113.1 -> 203.0.113.2, UDP 12345 -> 2152
- Inner IP: 10.0.0.1 -> 8.8.8.8, UDP 5555 -> 6666, payload: 01 02 03 04
- Verify delivery: `tcpdump -i veth-n6 -n -e` or `bpftool map dump pinned /sys/fs/bpf/tc/globals/teid_stats`

## Stats
- Dump counters: `bpftool map dump pinned /sys/fs/bpf/tc/globals/teid_stats`
- `lookup_miss` increments on TEID miss.

## Note

This repo is largely unreviewed.
