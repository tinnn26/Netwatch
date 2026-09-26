import socket

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


if __name__ == "__main__":
    ports = [21, 22, 23, 53, 80, 443, 8080, 3389]

    open_ports = scan_ports("192.168.1.1", ports)

    print("Puertos abiertos:", open_ports)