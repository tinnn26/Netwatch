from rich.console import Console
from rich.table import Table

from scanner import scan_ports, get_service
from network import discover_devices
from database import (
    create_database,
    save_device,
    get_devices,
    save_port_scan
)

def main():
    console = Console()

    network = "192.168.1.0/24"

    create_database()

    console.print("\n[bold]NETWATCH — Buscador de dispositivos[/bold]\n")

    devices = discover_devices(network)

    for device in devices:
        is_new = save_device(
            device["ip"],
            device["mac"],
            device["hostname"]
        )

        if is_new:
            console.print(
                f"[bold red]NUEVO DISPOSITIVO:[/bold red] "
                f"{device['ip']} - {device['mac']}"
            )

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

    history = get_devices()
    history_table = Table()

    history_table.add_column("IP")
    history_table.add_column("MAC")
    history_table.add_column("Hostname")
    history_table.add_column("First Seen")
    history_table.add_column("Last Seen")

    for device in history:
        history_table.add_row(
            device[0],
            device[1],
            device[2],
            device[3],
            device[4]
        )
    console.print("\n[bold]Historial de dispositivos:[/bold]\n")
    console.print(history_table)

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
                service = get_service(port)

                port_table.add_row(
                    str(port),
                    "ABIERTO",
                    service
                )

                save_port_scan(
                    ip,
                    port,
                    service
                )

            console.print(port_table)

        else:
            console.print("No se encontraron puertos abiertos.")


if __name__ == "__main__":
    main()