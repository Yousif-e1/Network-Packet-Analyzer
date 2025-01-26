import socket
import struct

def sniff_packets():
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    conn.bind(("127.0.0.1", 0))
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while True:
        raw_packet, addr = conn.recvfrom(65565)
        ip_header = raw_packet[:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

        src_ip = socket.inet_ntoa(iph[8])
        dest_ip = socket.inet_ntoa(iph[9])
        protocol = iph[6]

        print(f"Source IP: {src_ip}, Destination IP: {dest_ip}, Protocol: {protocol}")

def main():
    sniff_packets()

if __name__ == "__main__":
    main()
