from rich.table import Table
from rich.console import Console
from network import discover_devices, get_hostname
import socket

def main():
    console = Console()
    network = "192.168.1.0/24"

    console.print("\n[bold]Netwatch - Buscador de dispositivos en la red[/bold]\n")

    devices = discover_devices(network)

    table = Table()
    table.add_column("IP Address")
    table.add_column("MAC Address")
    table.add_column("Hostname")

    for device in devices:
        table.add_row(
            device["ip"],
            device["mac"],
            get_hostname(device["ip"])
        )

    console.print(table)
    console.print(f"\n{len(devices)} Dispositivos encontrados en la red.\n")


if __name__ == "__main__":
    main()


def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return "Desconocido"