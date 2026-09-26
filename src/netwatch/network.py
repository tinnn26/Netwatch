from scapy.all import ARP, Ether, srp
import socket


def discover_devices(network):
    arp_request = ARP(pdst=network)
    ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ethernet_frame / arp_request

    answered = srp(packet, timeout=2, verbose=False)[0]

    devices = []

    for sent, received in answered:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return devices

def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return "Desconocido"

