from rich.console import Console
from rich.table import Table
from scanner import scan_ports, get_service
from network import discover_devices
from database import create_database, save_device

network = "192.168.1.0/24"

create_database()
devices = discover_devices(network)
for device in devices:
    save_device(
        device["ip"],
        device["mac"],
        device["hostname"]
    )


def main():
    console = Console()

    network = "192.168.1.0/24"

    console.print("\n[bold]NETWATCH Buscador de diispositivos\n")

    devices = discover_devices(network)

    table = Table()

    table.add_column("IP Address")
    table.add_column("MAC Address")
    table.add_column("Hostname")

    for device in devices:
        table.add_row(
            device["ip"],
            device["mac"],
            device["hostname"]
        )

    console.print(table)

    console.print(
        f"\n{len(devices)} Dispositivos encontrados en la red."
    )

    ports = [21, 22, 23, 53, 80, 443, 8080, 3389]

    for device in devices:
        ip = device["ip"]

        console.print(f"\n[bold]Escaneando {ip}...[/bold]")

        open_ports = scan_ports(ip, ports)

        if open_ports:
            port_table = Table()

            port_table.add_column("Puerto")
            port_table.add_column("Estado")
            port_table.add_column("Servicio")

            for port in open_ports:
                port_table.add_row(
                    str(port),
                    "ABIERTO",
                    get_service(port)
                )

            console.print(port_table)
        else:
            console.print("No se encontraron puertos abiertos.")


if __name__ == "__main__":
    main()