from scapy.all import rdpcap, IP, TCP, UDP, ICMP

packets = rdpcap("capture.pcapng")   # change name if needed

pkt_no = 1

for pkt in packets:
    print(f"\nPacket {pkt_no}")

    if IP in pkt:
        ip = pkt[IP]
        original_ip_cksum = ip.chksum
        del ip.chksum
        recalculated_ip_cksum = IP(bytes(ip)).chksum
        print(f"IP Checksum  -> Original: {hex(original_ip_cksum)}, Calculated: {hex(recalculated_ip_cksum)}")

    if TCP in pkt:
        tcp = pkt[TCP]
        original_tcp_cksum = tcp.chksum
        del tcp.chksum
        recalculated_tcp_cksum = TCP(bytes(tcp)).chksum
        print(f"TCP Checksum -> Original: {hex(original_tcp_cksum)}, Calculated: {hex(recalculated_tcp_cksum)}")

    if UDP in pkt:
        udp = pkt[UDP]
        original_udp_cksum = udp.chksum
        del udp.chksum
        recalculated_udp_cksum = UDP(bytes(udp)).chksum
        print(f"UDP Checksum -> Original: {hex(original_udp_cksum)}, Calculated: {hex(recalculated_udp_cksum)}")

    if ICMP in pkt:
        icmp = pkt[ICMP]
        original_icmp_cksum = icmp.chksum
        del icmp.chksum
        recalculated_icmp_cksum = ICMP(bytes(icmp)).chksum
        print(f"ICMP Checksum -> Original: {hex(original_icmp_cksum)}, Calculated: {hex(recalculated_icmp_cksum)}")

    pkt_no += 1
