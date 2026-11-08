"""English UI strings (reference language)."""

STRINGS: dict[str, str] = {
    "app.title": "OctoV - Binary Analysis Workbench",
    "menu.file": "File",
    "menu.view": "View",
    "menu.language": "Language",
    "menu.help": "Help",
    "action.theme_dark": "Dark Theme",
    "action.theme_light": "Light Theme",
    "status.loaded": "Loaded {name}",
    "indicators.column.severity": "Severity",
    "indicators.column.id": "Indicator",
    "indicators.column.mitre": "MITRE",
    "indicators.column.description": "Description",
    "graph.too_large": (
        "sub_{start}: {count} blocks - too large to draw; use the disassembly listing."
    ),
    "disasm.raw": "raw @ {rva}",
    "functions.entry": "entry",
    "sev.high": "High",
    "sev.medium": "Medium",
    "sev.low": "Low",
    "sev.info": "Info",
    "ui.open_file": "Open file",
    "ui.open_raw": "Open shellcode",
    "ui.new_session": "New session",
    "ui.open_session": "Open session",
    "ui.back": "Back",
    "ui.forward": "Forward",
    "ui.command_palette": "Go to address, function or finding…",
    "ui.export": "Export",
    "ui.local": "Local",
    "ui.local_only": "All analysis is local - samples never leave this machine",
    "ui.samples": "Samples",
    "ui.functions": "Functions",
    "ui.no_samples": "No samples yet. Open a PE file or a shellcode blob to start.",
    "ui.close": "Close",
    "ui.discovering": "Discovering functions…",
    "ui.search_functions": "Filter functions",
    "ui.identity": "Identity",
    "ui.file": "File",
    "ui.size": "Size",
    "ui.binary": "Binary",
    "ui.format": "Format",
    "ui.raw_blob": "Raw code blob (x{bits})",
    "ui.entropy": "Entropy",
    "ui.top_findings": "Top findings",
    "ui.sections": "Sections",
    "ui.name": "Name",
    "ui.perm": "Perm",
    "ui.imports": "Imports",
    "ui.entry_point": "Entry point",
    "ui.image_base": "base",
    "ui.compiled": "Compiled",
    "ui.signature": "Signature",
    "ui.unsigned": "Not signed",
    "ui.signed_valid": "Signed, verified",
    "ui.signed_unverified": "Signed, not verified",
    "ui.overlay": "Overlay",
    "ui.no_findings": "No findings for this sample",
    "ui.location": "Location",
    "ui.evidence": "Evidence",
    "ui.no_techniques": "No ATT&CK techniques observed",
    "ui.hits": "{n} hits",
    "ui.no_function": "No function selected",
    "ui.no_function_body": "Pick a function in the sidebar, press Ctrl+K, or open a finding.",
    "ui.graph_hint": "The control-flow graph appears for addresses inside a discovered function.",
    "ui.goto_offset": "Go to offset",
    "ui.offset": "offset",
    "ui.palette_placeholder": "Address (0x1000, sub_19c0), function or finding…",
    "ui.no_results": "No results",
    "ui.goto": "Go to",
    "ui.goto_address": "Go to {addr}",
    "ui.actions": "Actions",
    "ui.show_graph": "Show control-flow graph",
    "ui.findings": "Findings",
    "ui.cancel": "Cancel",
    "ui.open": "Open",
    "ui.path_hint": "Full path of the file to analyse (it is read locally, never uploaded)",
    "ui.architecture": "Architecture",
    "ui.copied": "Copied",
    "ui.copy": "Copy",
    "ui.saved": "Saved to {path}",
    "ui.save": "Save…",
    "ui.sigma_needs_pe": "Sigma rules need a PE sample (process / image-load hashes).",
    "ui.session_hint": "Path of the .octov session file",
    "ui.session_created": "Session created: {path}",
    "ui.overview": "Overview",
    "ui.disassembly": "Disassembly",
    "ui.graph": "Graph",
    "ui.hex": "Hex",
    "ui.welcome_title": "Analyse a Windows binary",
    "ui.welcome_body": (
        "Open a PE file or a raw shellcode blob. OctoV parses it locally, maps findings "
        "to MITRE ATT&CK and generates YARA and Sigma rules. Nothing is uploaded."
    ),
    "ui.analysing": "Analysing…",
    "ui.discovery_failed": "Function discovery failed",
    "ui.functions_count": "{n} functions",
    "ui.language": "Language",
    "ui.display_mode": "Display mode",
    "ui.theme_night": "Night",
    "ui.theme_normal": "Normal",
    "fact.rule.explain": (
        "A detection rule matched concrete artifacts of an attacker technique (byte "
        "patterns, strings or imports). Matches are evidence, not proof: legitimate "
        "security tools and system components can contain the same artifacts."
    ),
    "fact.rule.next": (
        "Jump to the evidence address, read the surrounding function and check whether the "
        "code actually uses it."
    ),
    "fact.indicator.explain": (
        "A structural property of the file that is common in malware, such as packing, "
        "unusual sections or suspicious imports. On its own it is a weak signal."
    ),
    "fact.indicator.next": (
        "Combine it with other findings; several independent indicators together are far "
        "more meaningful than one."
    ),
    "fact.crypto_constant.explain": (
        "The file contains a constant table of a known cryptographic or checksum algorithm."
        " Ransomware and loaders use these to encrypt files or decrypt configuration; many "
        "legitimate programs use them too."
    ),
    "fact.crypto_constant.next": (
        "Open the cross-references of the table to find the function that uses it and what "
        "data it processes."
    ),
    "fact.embedded_payload.explain": (
        "Another executable or an opaque high-entropy blob is hidden inside this file. "
        "Droppers and loaders carry their real payload this way; installers do it "
        "legitimately."
    ),
    "fact.embedded_payload.next": (
        "Open the payload as a new sample to analyse it; export it only as the encrypted ZIP."
    ),
    "fact.packer.explain": (
        "Several signs show the file is packed or encrypted, so the code you see is mostly "
        "an unpacking stub and the real program appears only in memory at run time."
    ),
    "fact.packer.next": (
        "Expect few meaningful functions or strings. Note the packer, and plan dynamic "
        "analysis (M3) or unpacking to see the real code."
    ),
    "fact.ioc.explain": (
        "An indicator of compromise (address, domain, URL, mutex, wallet or command) found "
        "as a string in the file. Such values let defenders hunt for the same activity "
        "elsewhere."
    ),
    "fact.ioc.next": (
        "Check the value against threat intelligence and your logs, and look at which "
        "function references it."
    ),
    "ind.high_entropy_section.explain": (
        "This section looks random (entropy above 7.2), which usually means compressed or "
        "encrypted data. Packers and encrypted payloads cause this; images and compressed "
        "resources do too."
    ),
    "ind.rwx_section.explain": (
        "This section is writable and executable at the same time, so code can modify "
        "itself. Unpacking stubs and shellcode loaders need this; normal compilers rarely "
        "produce it."
    ),
    "ind.packer_section_name.explain": (
        "The section name is the default of a known packer or protector. It strongly "
        "suggests the file was packed, which hides the real code from static analysis."
    ),
    "ind.virtual_size_inflated.explain": (
        "The section reserves much more memory than it stores on disk, typical of a buffer "
        "that an unpacker fills at run time with the real program."
    ),
    "ind.entry_point_not_executable.explain": (
        "Execution starts in a section that is not marked executable, which normal programs"
        " never do. It points to manual tampering or a packer that fixes permissions at run"
        " time."
    ),
    "ind.entry_point_outside_sections.explain": (
        "The entry point lies outside every section, a sign of a hand-crafted or corrupted "
        "header used to confuse analysis tools."
    ),
    "ind.no_imports.explain": (
        "The executable imports no functions at all, so it must find Windows APIs itself at"
        " run time. This is common for packed files and shellcode-style loaders."
    ),
    "ind.dynamic_api_resolution.explain": (
        "Only a handful of imports, including a library loader and GetProcAddress-style "
        "resolver. The program resolves the APIs it really uses at run time, hiding them "
        "from the import table."
    ),
    "ind.process_injection_apis.explain": (
        "The file imports APIs that write into another process and start code there, the "
        "building blocks of process injection. Debuggers and some security tools use them "
        "legitimately."
    ),
    "ind.anti_debug_apis.explain": (
        "The file imports APIs that detect a debugger. Malware uses them to change "
        "behaviour under analysis; ordinary programs also call them for crash handling."
    ),
    "ind.overlay_present.explain": (
        "Data is appended after the last section. Installers and signed files often have "
        "overlays, but droppers also hide payloads or configuration there."
    ),
    "ind.suspicious_timestamp.explain": (
        "The compile timestamp is zero or in the future, which suggests it was forged "
        "(timestomping) or stripped by a build tool for reproducibility."
    ),
    "ui.triage": "Triage",
    "triage.risk": "Risk score",
    "triage.band.low": "low",
    "triage.band.medium": "medium",
    "triage.band.high": "high",
    "triage.why": "Why this score",
    "triage.nothing": "Nothing suspicious contributes to the score.",
    "triage.reviewed": "{n} of {total} findings reviewed",
    "triage.running": "still analysing: {jobs}",
    "triage.verdict.confirm": "Confirmed",
    "triage.verdict.fp": "False positive",
    "triage.verdict.benign": "Benign here",
    "triage.packed": "Packed or encrypted ({packer})",
    "triage.capabilities": "Capabilities and findings",
    "triage.iocs": "IOCs",
    "triage.copy_csv": "Copy CSV",
    "triage.no_iocs": "No indicators of compromise found in strings.",
    "triage.top_functions": "Most suspicious functions",
    "triage.payloads": "Embedded payloads",
    "triage.open_payload": "Open as sample",
    "triage.export_payload": "Export (encrypted ZIP)",
    "triage.payload_safety": (
        "Payloads are never written to disk as executables; export is an AES ZIP with "
        "password 'infected'."
    ),
    "triage.orphaned": (
        "{n} saved verdicts refer to findings that no longer appear (rules changed)."
    ),
    "ui.strings": "Strings",
    "ui.compact": "Compact",
    "ui.compact_hint": "Hide explanations for a denser view (for experienced analysts)",
    "triage.show_explanation": "Show explanation",
    "triage.hide_explanation": "Hide explanation",
    "triage.jump": "Go to location",
    "triage.jobs": "Analyzers",
    "triage.job.queued": "queued",
    "triage.job.running": "running",
    "triage.job.done": "done",
    "triage.job.failed": "failed",
    "triage.job.unavailable": "unavailable",
    "functions.suggested": "suggested",
    "functions.suggested_hint": (
        "Name suggested from the APIs this function calls; press N to rename"
    ),
    "annotate.rename": "Rename function",
    "annotate.comment": "Comment",
    "annotate.bookmark": "Bookmark",
    "annotate.unbookmark": "Remove bookmark",
    "annotate.bookmarked": "Bookmarked",
    "annotate.rename_hint": (
        "New name (letters, digits, _ . : @ ?). Leave empty to restore the automatic name."
    ),
    "annotate.comment_hint": "Comment shown next to this instruction. Leave empty to remove it.",
    "annotate.invalid_name": "Use a letter or _ first, no spaces, at most 128 characters.",
    "annotate.save": "Save",
    "xref.to_here": "References to here",
    "xref.title": "References to {addr}",
    "xref.none": "No code references found (data may be reached indirectly).",
    "xref.show_hex": "Show in hex",
    "strings.search": "Search strings",
    "strings.all": "All",
    "strings.count": "{n} strings",
    "strings.offset": "Offset",
    "strings.section": "Section",
    "strings.encoding": "Enc",
    "strings.category": "Category",
    "strings.value": "Value",
    "strings.none": "No strings match.",
    "strings.dblclick": "Double-click to see the code that uses this string",
    "strings.cat.url": "URL",
    "strings.cat.domain": "Domain",
    "strings.cat.ipv4": "IPv4",
    "strings.cat.ipv6": "IPv6",
    "strings.cat.email": "E-mail",
    "strings.cat.path": "Path",
    "strings.cat.registry": "Registry",
    "strings.cat.mutex": "Mutex",
    "strings.cat.command": "Command",
    "strings.cat.user_agent": "User-Agent",
    "strings.cat.wallet": "Wallet",
    "strings.cat.base64": "Base64",
    "triage.iocs_shown": "first {n} of {total}; Copy CSV exports all",
}
