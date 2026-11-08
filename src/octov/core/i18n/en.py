"""English UI strings (reference language)."""

STRINGS: dict[str, str] = {
    "app.title": "OctoV - Binary Analysis Workbench",
    "menu.file": "File",
    "menu.view": "View",
    "menu.language": "Language",
    "menu.help": "Help",
    "action.open_sample": "Open Sample...",
    "action.new_session": "New Session...",
    "action.open_session": "Open Session...",
    "action.exit": "Exit",
    "action.theme_dark": "Dark Theme",
    "action.theme_light": "Light Theme",
    "action.reset_layout": "Reset Layout",
    "action.about": "About OctoV",
    "dock.samples": "Samples",
    "dock.overview": "Overview",
    "dock.indicators": "Indicators",
    "dock.disassembly": "Disassembly",
    "dock.pseudocode": "Pseudocode",
    "dock.graph": "Graph",
    "dock.hex": "Hex",
    "dock.memory_map": "Memory Map",
    "dock.timeline": "Timeline",
    "dock.mitre": "MITRE ATT&CK",
    "dock.ai_chat": "AI Assistant",
    "dock.log": "Log",
    "status.ready": "Ready",
    "status.loaded": "Loaded {name}",
    "status.error": "Error: {message}",
    "placeholder.milestone": "{panel} - coming in {milestone}",
    "overview.empty": (
        "Open a sample to begin static triage. Files are analysed locally and never uploaded."
    ),
    "indicators.column.severity": "Severity",
    "indicators.column.id": "Indicator",
    "indicators.column.mitre": "MITRE",
    "indicators.column.description": "Description",
    "dialog.open_sample": "Open PE sample",
    "dialog.session_filter": "OctoV session (*.octov)",
    "about.text": (
        "OctoV {version}\nDefensive Windows binary analysis workbench.\n"
        "All analysis is local; samples are never uploaded."
    ),
    "mitre.column.technique": "Technique",
    "mitre.column.name": "Name",
    "mitre.column.tactic": "Tactic",
    "mitre.column.severity": "Severity",
    "mitre.column.hits": "Hits",
    "mitre.column.sources": "Sources",
    "graph.too_large": (
        "sub_{start}: {count} blocks - too large to draw; use the disassembly listing."
    ),
    "disasm.raw": "raw @ {rva}",
    "indicators.navigate_tip": "rva {rva} - double-click to navigate",
    "functions.entry": "entry",
}
