"""MITRE ATT&CK (Enterprise) technique names for the IDs OctoV emits.

Kept as a small local table so the workbench works fully offline. Extend it
whenever a rule or indicator introduces a new technique ID (a test enforces it).
"""

from __future__ import annotations

TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1003.001": ("LSASS Memory", "credential-access"),
    "T1027": ("Obfuscated Files or Information", "defense-evasion"),
    "T1027.002": ("Software Packing", "defense-evasion"),
    "T1027.007": ("Dynamic API Resolution", "defense-evasion"),
    "T1055": ("Process Injection", "defense-evasion"),
    "T1055.001": ("Dynamic-link Library Injection", "defense-evasion"),
    "T1055.003": ("Thread Execution Hijacking", "defense-evasion"),
    "T1055.004": ("Asynchronous Procedure Call", "defense-evasion"),
    "T1055.012": ("Process Hollowing", "defense-evasion"),
    "T1055.013": ("Process Doppelgänging", "defense-evasion"),
    "T1068": ("Exploitation for Privilege Escalation", "privilege-escalation"),
    "T1070.001": ("Clear Windows Event Logs", "defense-evasion"),
    "T1070.006": ("Timestomp", "defense-evasion"),
    "T1106": ("Native API", "execution"),
    "T1134": ("Access Token Manipulation", "privilege-escalation"),
    "T1497.001": ("System Checks", "defense-evasion"),
    "T1543.003": ("Windows Service", "persistence"),
    "T1562.001": ("Disable or Modify Tools", "defense-evasion"),
    "T1562.006": ("Indicator Blocking", "defense-evasion"),
    "T1620": ("Reflective Code Loading", "defense-evasion"),
    "T1622": ("Debugger Evasion", "defense-evasion"),
}


def technique_name(technique_id: str) -> str:
    entry = TECHNIQUES.get(technique_id)
    return entry[0] if entry else technique_id


def technique_tactic(technique_id: str) -> str:
    entry = TECHNIQUES.get(technique_id)
    return entry[1] if entry else ""
