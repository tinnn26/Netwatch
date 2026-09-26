import socket

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NETBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    8080: "HTTP-ALT"
}

def scan_port(ip, port, timeout=0.5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    result = sock.connect_ex((ip, port))

    sock.close()
    return result == 0

def scan_ports(ip, ports):
    open_ports = []

    for port in ports:
        if scan_port(ip, port):
            open_ports.append(port)

    return open_ports

def get_service(port):
    return COMMON_SERVICES.get(port, "Unknown")


if __name__ == "__main__":
    ports = [21, 22, 23, 53, 80, 443, 8080, 3389]

    open_ports = scan_ports("192.168.1.1", ports)

    print("Puertos abiertos:", open_ports)
