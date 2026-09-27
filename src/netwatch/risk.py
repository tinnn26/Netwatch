"""Transparent, conservative network risk rules that produce persistent alerts."""

from __future__ import annotations

from datetime import datetime, timezone

if __package__:
    from .database import save_alert
else:
    from database import save_alert


# Severity is intentionally rule based and explainable; scores are per finding,
# not a claim that a host has been compromised.
PORT_RULES = {
    21: ("high", 25, "FTP expuesto", "FTP puede transmitir credenciales sin cifrado."),
    23: ("critical", 40, "Telnet expuesto", "Telnet no cifra credenciales ni sesiones."),
    445: ("high", 30, "SMB expuesto", "SMB accesible puede ampliar el impacto de fallos o credenciales débiles."),
    3389: ("high", 30, "Escritorio remoto expuesto", "RDP accesible requiere controles de acceso y autenticación robustos."),
    139: ("medium", 15, "NetBIOS expuesto", "NetBIOS puede revelar información y ampliar la superficie de ataque."),
    22: ("low", 5, "SSH detectado", "SSH es administración remota; confirma que el acceso esté restringido."),
}
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _alert(severity, category, title, description, device, evidence):
    return {
        "created_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "severity": severity,
        "category": category,
        "title": title,
        "description": description,
        "device_ip": device.get("ip"),
        "device_mac": device.get("mac"),
        "evidence": evidence,
    }


def evaluate_device(device: dict, open_ports: list[int], *, is_new=False, previous_ip=None):
    findings = []
    if is_new:
        findings.append(_alert(
            "medium", "new_device", "Nuevo dispositivo detectado",
            "Este equipo no aparecía antes en el inventario de NetWatch. Verifica que sea conocido.",
            device, {"hostname": device.get("hostname", "Desconocido")},
        ))
    if previous_ip:
        findings.append(_alert(
            "low", "ip_changed", "Cambió la dirección IP del dispositivo",
            f"El dispositivo pasó de {previous_ip} a {device['ip']}. Esto puede ser normal si usa DHCP.",
            device, {"previous_ip": previous_ip, "current_ip": device["ip"]},
        ))

    for port in sorted(set(open_ports)):
        rule = PORT_RULES.get(port)
        if not rule:
            continue
        severity, score, title, description = rule
        findings.append(_alert(
            severity, "exposed_service", title, description, device,
            {"port": port, "service": device.get("services", {}).get(port, "desconocido"), "score": score},
        ))
    return findings


def risk_score(open_ports: list[int]) -> int:
    points = sum(PORT_RULES[port][1] for port in set(open_ports) if port in PORT_RULES)
    return min(points, 100)


def risk_label(score: int) -> str:
    if score >= 60:
        return "CRÍTICO"
    if score >= 30:
        return "ALTO"
    if score >= 10:
        return "MEDIO"
    if score:
        return "BAJO"
    return "SIN HALLAZGOS"


def record_findings(run_id: int, findings: list[dict]):
    for finding in findings:
        save_alert(run_id, finding)


def build_risk_report(devices: list[dict], scanned_ports: dict[str, list[int]]):
    report = []
    for device in devices:
        ports = scanned_ports.get(device["ip"], [])
        score = risk_score(ports)
        report.append({**device, "open_ports": sorted(ports), "score": score, "risk": risk_label(score)})
    return sorted(report, key=lambda row: (-row["score"], row["ip"]))
