"""NetWatch command line scan, inventory and risk dashboard."""

from __future__ import annotations

import argparse

from rich.console import Console
from rich.table import Table

if __package__:
    from .database import (
        acknowledge_alert,
        create_database,
        finish_scan_run,
        get_alert_summary,
        get_alerts,
        save_device,
        save_port_scan,
        start_scan_run,
    )
    from .network import discover_devices
    from .risk import build_risk_report, evaluate_device, record_findings
    from .scanner import get_service, scan_ports
else:
    # Also support `python src/netwatch/main.py` from the repository root.
    from database import (
        acknowledge_alert,
        create_database,
        finish_scan_run,
        get_alert_summary,
        get_alerts,
        save_device,
        save_port_scan,
        start_scan_run,
    )
    from network import discover_devices
    from risk import build_risk_report, evaluate_device, record_findings
    from scanner import get_service, scan_ports


DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080]


def _severity_style(severity: str) -> str:
    return {"critical": "bold white on red", "high": "bold red", "medium": "yellow", "low": "cyan", "info": "dim"}.get(severity, "white")


def display_alerts(console: Console, *, limit=20, unacknowledged_only=False):
    summary = get_alert_summary()
    console.print("\n[bold]Alertas pendientes[/bold]  "
                  f"[bold red]Críticas: {summary.get('critical', 0)}[/bold red]  "
                  f"[red]Altas: {summary.get('high', 0)}[/red]  "
                  f"[yellow]Medias: {summary.get('medium', 0)}[/yellow]  "
                  f"[cyan]Bajas: {summary.get('low', 0)}[/cyan]")
    alerts = get_alerts(limit=limit, unacknowledged_only=unacknowledged_only)
    table = Table(title="Historial de alertas")
    table.add_column("Fecha", style="dim")
    table.add_column("Nivel")
    table.add_column("Equipo")
    table.add_column("Alerta")
    table.add_column("Detalle", max_width=68)
    for alert in alerts:
        table.add_row(
            alert["created_at"].replace("T", " "),
            f"[{_severity_style(alert['severity'])}]{alert['severity'].upper()}[/]",
            alert["device_ip"] or "—",
            alert["title"],
            alert["description"],
        )
    if alerts:
        console.print(table)
    else:
        console.print("[green]No hay alertas para mostrar.[/green]")


def run_scan(network: str, ports: list[int], console: Console):
    run_id = start_scan_run(network)
    try:
        console.print(f"\n[bold]NETWATCH[/bold] — descubrimiento en [cyan]{network}[/cyan]\n")
        devices = discover_devices(network)
        device_changes = {}
        for device in devices:
            change = save_device(device["ip"], device["mac"], device["hostname"])
            device_changes[device["mac"]] = change

        device_table = Table(title="Dispositivos detectados")
        for column in ("IP", "MAC", "Hostname"):
            device_table.add_column(column)
        for device in devices:
            device_table.add_row(device["ip"], device["mac"], device["hostname"])
        console.print(device_table)
        console.print(f"\n{len(devices)} dispositivos encontrados.")

        scanned_ports: dict[str, list[int]] = {}
        findings = []
        for device in devices:
            ip = device["ip"]
            console.print(f"\n[bold]Escaneando servicios de {ip}...[/bold]")
            open_ports = scan_ports(ip, ports)
            scanned_ports[ip] = open_ports
            services = {port: get_service(port) for port in open_ports}
            device["services"] = services
            for port in open_ports:
                save_port_scan(ip, port, services[port], run_id)
            if open_ports:
                port_table = Table()
                port_table.add_column("Puerto")
                port_table.add_column("Estado")
                port_table.add_column("Servicio")
                for port in open_ports:
                    port_table.add_row(str(port), "ABIERTO", services[port])
                console.print(port_table)
            else:
                console.print("No se encontraron puertos abiertos.")

            change = device_changes[device["mac"]]
            findings.extend(evaluate_device(
                device, open_ports,
                is_new=change["is_new"],
                previous_ip=change["previous_ip"],
            ))

        record_findings(run_id, findings)
        finish_scan_run(run_id, len(devices))
        console.print("\n[bold]Riesgo por dispositivo[/bold]")
        report = build_risk_report(devices, scanned_ports)
        risk_table = Table()
        risk_table.add_column("IP")
        risk_table.add_column("Hostname")
        risk_table.add_column("Puertos abiertos")
        risk_table.add_column("Puntaje")
        risk_table.add_column("Riesgo")
        for row in report:
            style = "red" if row["score"] >= 30 else "yellow" if row["score"] >= 10 else "green"
            risk_table.add_row(row["ip"], row["hostname"], ", ".join(map(str, row["open_ports"])) or "—", str(row["score"]), f"[{style}]{row['risk']}[/]")
        console.print(risk_table)
        if findings:
            console.print(f"\n[bold yellow]{len(findings)} hallazgo(s) nuevo(s) guardado(s).[/bold yellow]")
        else:
            console.print("\n[green]Este escaneo no generó hallazgos nuevos.[/green]")
        display_alerts(console, limit=10, unacknowledged_only=True)
    except Exception:
        finish_scan_run(run_id, 0, status="failed")
        raise


def main():
    parser = argparse.ArgumentParser(prog="netwatch", description="Descubrimiento de red, alertas y evaluación de riesgo.")
    commands = parser.add_subparsers(dest="command")
    scan_parser = commands.add_parser("scan", help="Descubrir equipos y evaluar servicios")
    scan_parser.add_argument("--network", default="192.168.1.0/24", help="Red CIDR autorizada para escanear")
    scan_parser.add_argument("--ports", help="Puertos separados por coma (por defecto, un conjunto común)")
    alerts_parser = commands.add_parser("alerts", help="Consultar alertas persistidas")
    alerts_parser.add_argument("--all", action="store_true", help="Incluir alertas reconocidas")
    alerts_parser.add_argument("--limit", type=int, default=100)
    ack_parser = commands.add_parser("ack", help="Reconocer una alerta por ID")
    ack_parser.add_argument("id", type=int)
    args = parser.parse_args()

    create_database()
    console = Console()
    if args.command == "alerts":
        display_alerts(console, limit=max(1, args.limit), unacknowledged_only=not args.all)
    elif args.command == "ack":
        if acknowledge_alert(args.id):
            console.print(f"Alerta #{args.id} reconocida.")
        else:
            console.print(f"No existe la alerta #{args.id}.", style="yellow")
    else:
        network = args.network if args.command == "scan" else "192.168.1.0/24"
        ports = [int(value.strip()) for value in args.ports.split(",") if value.strip()] if args.command == "scan" and args.ports else DEFAULT_PORTS
        if any(port < 1 or port > 65535 for port in ports):
            parser.error("Los puertos deben estar entre 1 y 65535.")
        run_scan(network, ports, console)


if __name__ == "__main__":
    main()
