In this implementation of the port knocking firewall, we maintain a hash-based state table which takes in the `src_ip` and the `dst_port` to update the state of a given flow, and forwards the packet back to the traffic generator. 

Each lcore (thread) works on a synchronous run-to-completion model. The steps are
1. The lcore retreives a packet through the receive API.
2. Parses the headers to get the `src_ip` and `dst_port`.
3. Updates the local state table based on the previous state (if it exists) and the information obtained from the new packet.
4. Swaps the source and the destination MAC address.
5. Add the processed packet to the TX queue, which will be buffered and drained every `BURST_TX_DRAIN_US` micro seconds

In addition to this, the main thread prints the port statistics every `timer_period` seconds.

Each lcore will poll 1 RX queue and transmit over 1 TX queue.
To update the number of lcores to use (except for single core version), update the `NUM_LCORES_FOR_RSS` parameter in the code. Also ensure that sufficient number of cores are being passed as the EAL parameters.
> When passing the list of cores as the EAL parameter, it is better to give them starting from 0. For eg: 0-5. This is because, we got some unexplained errors while compiling them and using different lcores. Also ensure that you pass at least `NUM_LCORES_FOR_RSS` number of lcores.

> These implementations are based on the [DPDK L2 forwarding example](https://doc.dpdk.org/guides/sample_app_ug/l2_forward_real_virtual.html). In the default example, only a single core is used per NIC port (which is the way the single core version works). However, to enable the application to run on multiple lcores for a single port, the per-port data structures have been modified to per-lcore data structures. Hence, the support for running it on multiple ports is not yet tested.

To run the application, just go to the required folder and run the following command
```
make
sudo ./build/portKnockingSingleCore -l 0-1 -n 1 -a 41:00.0 -- -p 0x1
```
> To run the multi-core version just replace `portKnockingSingleCore` with `l2fwd`. And choose the apporopriate number of lcores.
```
make
sudo ./build/l2fwd -l 0-<NUM_LCORES_FOR_RSS - 1> -n 1 -a <iface_port_no> -- -p 0x1
```
### 1. Single Core 
- All flows are directed to a single queue and processed by a single lcore.  

### 2. RSS 
- All flows are directed to specific lcores based on the result of the RSS hash function. 
- As per the given implementation, the hashing is done based on the IP address `RTE_ETH_RSS_IP`. This can be modified to a number of different hash functions as long as it is supported by the NIC.

### 3. Flow API
- DPDK provides an API (`rte_flow`) which can be used to perform certain actions based on a set of rules.
- Since Ethernet based RSS hash functions were not supported by the NICs we used, and the trace that we tested on had a modified source mac address of `10:10:10:10:10:<core_number>`, we could use rules to direct packets to specific queues based on the `<core_number>` part of the MAC address.

### 4. SCR
- This is identical to the Flow API version except that it uses State Compute Replication (SCR), to update the states of the packet. 

# References
- https://doc.dpdk.org/api/rte__flow_8h.html
- https://doc.dpdk.org/guides/prog_guide/rte_flow.html
- https://doc.dpdk.org/guides/howto/rte_flow.html
- https://doc.dpdk.org/api/examples_2l2fwd-macsec_2main_8c-example.html
- https://doc.dpdk.org/api-23.07/examples_2l3fwd_2l3fwd_event_8c-example.html
- https://doc.dpdk.org/api/examples_2l3fwd-power_2main_8c-example.html
- https://doc.dpdk.org/api/examples_2ipv4_multicast_2main_8c-example.html
- https://github.com/smartnic/bpf-profile