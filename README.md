# Network-Packet-Analyzer
This program is a simple packet sniffer that captures and displays network traffic. It shows key details like source and destination IP addresses, protocols, and packet data, helping users analyze network activity

# How it Work

1) Socket Creation:

- The socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP) creates a raw socket that listens for network packets at the IP layer. AF_INET indicates that it's using IPv4, SOCK_RAW means it's working with raw packets, and IPPROTO_IP means it's capturing all - - IP packets.

2) Binding the Socket:

- conn.bind(("127.0.0.1", 0)): Binds the socket to the IP address 127.0.0.1 (localhost). The second argument 0 specifies an arbitrary port since the packet sniffing doesn’t rely on a specific port number.

3) Setting Socket Options:

- conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1): This option tells the socket to include the IP header in the packet data (i.e., to capture the full IP packet including the header).

4) Enabling Packet Capture:

- conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON): This command is used to enable promiscuous mode on Windows systems. Promiscuous mode allows the network card to capture all packets, even those not addressed to the machine.

5) Packet Reception:

- raw_packet, addr = conn.recvfrom(65565): This function receives raw packets. The buffer size 65565 is large enough to capture the full packet size. The function returns the raw packet data and the address of the sender.

6) Extracting IP Header Information:

- ip_header = raw_packet[:20]: Extracts the first 20 bytes of the raw packet, which represents the IP header.
- iph = struct.unpack('!BBHHHBBH4s4s', ip_header): The struct.unpack() function is used to unpack the IP header using a specific format:
- !: Network byte order (big-endian).
- BBHHHBBH: The format for the fields in the IP header.
- 4s4s: The source and destination IP addresses (4 bytes each).

### After unpacking, iph contains a tuple of the following values:

- iph[8]: Source IP address (in binary format).
- iph[9]: Destination IP address (in binary format).
- iph[6]: Protocol used (e.g., TCP, UDP).

7) Converting IPs:

- src_ip = socket.inet_ntoa(iph[8]): Converts the source IP from binary to the dotted decimal format (e.g., 192.168.1.1).
- dest_ip = socket.inet_ntoa(iph[9]): Converts the destination IP in the same way.

8) Displaying the Information:

- print(f"Source IP: {src_ip}, Destination IP: {dest_ip}, Protocol: {protocol}"): Prints the source IP, destination IP, and the protocol used in the packet.

9) Main Function:

- The main() function simply calls sniff_packets() to start the packet sniffing process.
### Key Points:

- This script uses raw sockets to capture packets, which requires administrator privileges or root access.
- It only processes the IP header, so it doesn't analyze higher-layer protocols like TCP or UDP.
- Promiscuous mode is enabled to allow the system to capture all packets, not just those addressed to it.
- The script continuously listens for packets and outputs details about the source and destination IPs and the protocol used.
