# Open vSwitch & XDP Network Traffic Control

A hands-on networking project demonstrating container networking, traffic control, and packet filtering using Docker, Open vSwitch (OVS), OpenFlow, and XDP/eBPF.

## Project Overview

This project creates a virtual network between three Docker containers connected through an Open vSwitch bridge.

The network was used to experiment with:

- Container-to-container communication
- Virtual Ethernet (veth) interfaces
- Open vSwitch networking
- OpenFlow traffic rules
- HTTP traffic rate limiting
- XDP/eBPF packet filtering
- Network traffic analysis with Wireshark

## Network Topology

```text
Container 1              Container 2              Container 3
10.10.0.11               10.10.0.12               10.10.0.13
     |                         |                        |
     +-------------------- ovs-br0 --------------------+
                       Open vSwitch
```

Container connectivity was verified using ICMP ping tests.

## HTTP Traffic

An HTTP server was started on Container 3 using port `8080`.

Container 1 was used as the client to generate HTTP requests with `curl`.

Example:

```bash
curl http://10.10.0.13:8080/normal
```

## Traffic Rate Limiting

OpenFlow 1.3 meter rules were configured on the OVS bridge to limit HTTP traffic directed to port `8080`.

This demonstrated how Open vSwitch can be used to control traffic flow between containers.

## XDP/eBPF Packet Filtering

A custom XDP program written in C inspects TCP packet payloads.

The program searches for the keyword:

```text
BLOCKME
```

Normal traffic is allowed:

```text
/normal → XDP_PASS
```

Traffic containing the keyword is dropped:

```text
/BLOCKME → XDP_DROP
```

## Verification

The implementation was tested using:

- `ping` for container connectivity
- `curl` for HTTP requests
- `bpftool` for XDP/eBPF inspection
- Wireshark for packet analysis

During testing, a normal HTTP request reached the server successfully, while a request containing `BLOCKME` timed out.

The XDP trace confirmed the packet drop:

```text
DROP: BLOCKME detected
```

## Technologies

- Docker
- Open vSwitch (OVS)
- OpenFlow 1.3
- XDP
- eBPF
- C
- Clang
- bpftool
- Wireshark
- Linux Networking
