from scapy.all import ARP, Ether, srp
import socket


def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return "Desconocido"


def discover_devices(network):
    arp_request = ARP(pdst=network)
    ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ethernet_frame / arp_request

    answered = srp(packet, timeout=2, verbose=False)[0]

    devices = []

    for sent, received in answered:
        ip = received.psrc
        mac = received.hwsrc
        hostname = get_hostname(ip)

        devices.append({
            "ip": ip,
            "mac": mac,
            "hostname": hostname
        })

    return devices