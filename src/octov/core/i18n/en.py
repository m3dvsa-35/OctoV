"""English UI strings (reference language)."""

from octov.core.i18n.en_api import API_STRINGS

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
    "capa.ns.anti-analysis.explain": (
        "The code tries to notice or slow down analysis: debugger checks, virtual-machine "
        "detection, obfuscation or timing tricks. Malware uses this to hide its real behaviour "
        "from analysts and sandboxes; some legitimate software (DRM, anti-cheat) does it too. "
        "Check which check is made and what the code does when it fires."
    ),
    "capa.ns.collection.explain": (
        "The code gathers data from the computer: screenshots, keystrokes, clipboard, browser or "
        "system information. Info-stealers and spyware live on this; ordinary tools collect far "
        "less. Check what is collected and whether it is stored or sent somewhere."
    ),
    "capa.ns.communication.explain": (
        "The code talks over the network or between processes: HTTP, sockets, DNS, named pipes, "
        "or a command-and-control channel. Malware needs this to receive orders and send data; "
        "many normal programs also connect out. Look for the addresses it contacts in the IOC "
        "list and in recovered strings."
    ),
    "capa.ns.compiler.explain": (
        "capa recognised the compiler or runtime the program was built with (for example MSVC, "
        "Go, Rust or a .NET packer stub). This is context, not a sign of malice: it tells you "
        "which library code to skip and which tools fit best for deeper analysis."
    ),
    "capa.ns.data-manipulation.explain": (
        "The code transforms data: encryption, hashing, encoding (Base64, XOR), compression or "
        "string handling. Malware uses it to hide configuration, strings and traffic; normal "
        "programs use the same algorithms for legitimate reasons. Check what data goes in and "
        "where the result is used."
    ),
    "capa.ns.executable.explain": (
        "Findings about the file as an executable: embedded files, resources, unusual PE "
        "structure or installer/packer traits. An embedded executable often means a dropper or "
        "loader; installers have them legitimately. Open embedded payloads as new samples."
    ),
    "capa.ns.exploitation.explain": (
        "The code shows traits of exploiting a vulnerability, such as shellcode patterns or "
        "spraying memory. This is rare in legitimate software and deserves a close look at the "
        "matched function and what it feeds the target."
    ),
    "capa.ns.host-interaction.explain": (
        "The code works with the local system: files, registry, processes, threads, services, "
        "users or hardware. Almost every program does some of this, so a single match means "
        "little; combinations (create a service and write the registry, open another process and "
        "write into it) are what matter."
    ),
    "capa.ns.impact.explain": (
        "The code can damage or deny use of the system: wiping or encrypting files, stopping "
        "services, shutting down. Ransomware and wipers do this; outside backup or admin tools it"
        " is a strong warning sign. Check which files or services are targeted."
    ),
    "capa.ns.internal.explain": (
        "Helper matches capa uses internally (for example limits on how often a feature may "
        "appear). They describe analysis bookkeeping rather than program behaviour and can "
        "usually be ignored."
    ),
    "capa.ns.linking.explain": (
        "How the program finds the code it calls: imports resolved at run time, API hashing, or "
        "loading libraries manually. Resolving APIs by hash or by hand hides what a program calls"
        " from static tools; plain runtime linking is common. Check which APIs end up being "
        "resolved."
    ),
    "capa.ns.load-code.explain": (
        "The code loads or runs other code: DLLs, PE files from memory, shellcode or scripts. "
        "Loaders and droppers are built on this, especially when the code comes from memory "
        "instead of a file. Check where the loaded code comes from."
    ),
    "capa.ns.malware-family.explain": (
        "A rule written for a known malware family matched. Treat it as a strong lead, not a "
        "verdict: confirm it with the family's other traits (strings, configuration, network "
        "indicators) before reporting the sample as that family."
    ),
    "capa.ns.persistence.explain": (
        "The code makes sure it runs again after a reboot or logon: Run keys, services, scheduled"
        " tasks, startup folders. Malware almost always needs this; installers set up persistence"
        " too, but openly. Check what exactly is registered to start."
    ),
    "capa.ns.runtime.explain": (
        "Traits of the language runtime the program uses (for example .NET or Go internals). Like"
        " compiler matches, this is context that helps you pick the right tools, not a sign of "
        "malicious behaviour."
    ),
    "capa.ns.targeting.explain": (
        "The code checks where it runs: keyboard language, locale, country or a specific product "
        "before acting. Targeted malware uses this to stay quiet outside its target; localisation"
        " code does it legitimately. Check what the result of the check changes."
    ),
    "capa.ns.other.explain": (
        "A capa rule matched that does not belong to one of the usual categories. Read the rule "
        "name, jump to the matched function and judge it together with the other findings."
    ),
    "fact.capability.next": "Jump to the function to see the code behind the match.",
    "fact.obfuscated_strings.explain": (
        "FLOSS found strings that do not exist in the file as plain text: they are assembled on "
        "the stack or decoded at run time. Hiding strings this way is a common malware technique "
        "to defeat simple string scans; some protected software does it as well."
    ),
    "fact.obfuscated_strings.next": (
        "Filter the Strings tab by Obfuscated and read the recovered values."
    ),
    "fact.hidden_ioc.explain": (
        "Indicators of compromise (URLs, domains, IP addresses, mutexes, commands) appear only "
        "after deobfuscation. A program that hides where it connects or what it runs is much more"
        " suspicious than one that stores these openly."
    ),
    "fact.hidden_ioc.next": (
        "Add the hidden indicators to your blocklists and search for them in your logs."
    ),
    "ext.reason.not_installed": "not installed",
    "ext.reason.no_rules": "capa rules missing",
    "ext.reason.in_memory": "only for files on disk (carved payloads stay in memory)",
    "ext.reason.too_large": "file too large (raise max_size_mb in config.yaml)",
    "ext.reason.no_ghidra": "Ghidra not found (run: octov ext setup ghidra)",
    "ext.reason.ghidra_version": "unsupported Ghidra version (12.x is needed)",
    "ext.reason.no_jdk": "no JDK 21 or newer found",
    "ext.reason.no_signatures": "signature files missing (run: octov ext setup library)",
    "ext.library.adds": (
        "Library recognition gives known library functions (C runtime, MFC, zlib, OpenSSL...) "
        "their real names, so you can skip code the author did not write."
    ),
    "functions.library": "lib",
    "functions.library_hint": "Known library function (matched by signature); usually safe to skip",
    "functions.hide_library": "Hide library ({n})",
    "triage.library": (
        "Known library code: {n} of {m} functions. They are named and left out of the ranking."
    ),
    "ext.reason.pe_only": "PE files only",
    "ext.ghidra.adds": (
        "Ghidra turns each function's machine code into readable pseudo-C, in sync with the "
        "disassembly and the graph."
    ),
    "ui.relations": "Relations",
    "relations.callers": "Callers",
    "relations.callees": "Callees",
    "relations.path": "path",
    "relations.is_entry": "this is the entry point",
    "relations.entry_path": "{n} call(s) from the entry point (marked path)",
    "relations.is_export": "this is an exported function (callable from outside)",
    "relations.export_path": "{n} call(s) from the exported function {name} (marked path)",
    "relations.no_path": "not reached from the entry point by direct calls",
    "relations.truncated": "showing the nearest {n} functions",
    "relations.more_callers": "+{n} callers",
    "relations.more_callees": "+{n} callees",
    "relations.score": "score {n}",
    "relations.recursive": "recursive",
    "relations.export": "export",
    "relations.sensitive": "sensitive APIs",
    "relations.other_apis": "other APIs",
    "relations.hint": (
        "Callers are on the left, called functions on the right. Click a function to centre "
        "it, double-click to open its code."
    ),
    "ui.search": "Search",
    "search.kind.bytes": "Bytes",
    "search.kind.text": "Text",
    "search.kind.imm": "Value",
    "search.hint.bytes": "Hex bytes, ?? = any byte. Example: 4D 5A ?? 00",
    "search.hint.text": "Part of an instruction or API name. Example: xor eax or VirtualAlloc",
    "search.hint.imm": "A constant an instruction uses. Example: 0x5A4D or 23117",
    "search.run": "Search",
    "search.count": "{n} result(s)",
    "search.truncated": "first {n} results (narrow the search to see the rest)",
    "search.none": "Nothing found",
    "search.not_mapped": "not mapped",
    "search.bad_pattern": "Write hex bytes with ?? for any byte, for example 4D 5A ?? 00",
    "search.bad_number": "Write a number, for example 0x10, 10h or 16",
    "analysis.not_ready": "Functions are still being discovered. Try again in a moment.",
    "ui.symbols": "Symbols",
    "symbols.filter": "Filter imports and exports",
    "symbols.exports": "Exports",
    "symbols.refs": "{n} reference(s) in the code. Click to list them.",
    "symbols.none": "This sample has no imports or exports.",
    "map.title": "File layout",
    "map.hint": "The whole file ({size}) from first to last byte. Click a part to see its bytes.",
    "map.kind.headers": "headers",
    "map.kind.section": "section",
    "map.kind.overlay": "overlay",
    "map.kind.gap": "unused",
    "map.kind.raw": "code blob",
    "ui.ai": "AI analyst",
    "ai.setup.title": "The AI analyst is not set up",
    "ai.setup.body": (
        "Set the OCTOV_AI_KEY environment variable (the key is never stored in a file), or "
        "configure a local OpenAI-compatible server such as Ollama under ai.fallback_base_url "
        "in config.yaml, then restart OctoV."
    ),
    "ai.dest.remote": "This will be sent to {host} (model {model}). It leaves this machine.",
    "ai.dest.local": "This will be sent to {host} (model {model}). It stays on this machine.",
    "ai.preview.title": "What will be sent ({n} characters)",
    "ai.preview.what": (
        "Only the analysis results below are sent: findings, function names, API calls, "
        "strings and code of the most suspicious functions. Never the file itself."
    ),
    "ai.preview.omitted": (
        "Left out to stay within the size limit: {code} code block(s), {functions} "
        "function(s), {findings} finding(s)."
    ),
    "ai.send": "Send this to {host}",
    "ai.send_note": "Nothing is sent until you press the button. Each send asks again.",
    "ai.ask_again": "Ask again",
    "ai.running": "Waiting for the answer from {host}…",
    "ai.assessment.benign": "Looks benign",
    "ai.assessment.suspicious": "Suspicious",
    "ai.assessment.malicious": "Likely malicious",
    "ai.confidence": "confidence",
    "ai.conf.low": "low",
    "ai.conf.medium": "medium",
    "ai.conf.high": "high",
    "ai.story": "What it does, step by step",
    "ai.points": "Key points",
    "ai.dropped": (
        "{n} statement(s) were removed because the evidence they pointed at does not exist in "
        "this file."
    ),
    "ai.disclaimer": (
        "This is the AI's opinion, not an OctoV finding. Check the evidence it points at."
    ),
    "ai.stale": (
        "The evidence has changed since this report (new analysis results or your edits). "
        "Ask again for an up-to-date opinion."
    ),
    "ai.destination": "Send to",
    "ai.chat.title": "Follow-up questions",
    "ai.chat.empty": (
        "Ask about this sample in your own words, for example: why is this function "
        "suspicious, or what should I look at next?"
    ),
    "ai.chat.placeholder": "Your question (up to 1000 characters)",
    "ai.chat.preview": "Preview what will be sent",
    "ai.chat.preview_title": "What will be sent with this question ({n} characters)",
    "ai.chat.focus": "about the function I am looking at ({name})",
    "ai.chat.running": "Waiting for the answer…",
    "ai.chat.you": "You",
    "ai.chat.clear": "Clear conversation",
    "ai.chat.clear_confirm": "Delete all questions and answers of this sample?",
    "ai.error.bad_focus": "Open a function first to ask about it.",
    "ai.error.busy": "Another AI request for this sample is still running. Wait for its answer.",
    "ai.error.bad_question": "Write a question of up to 1000 characters.",
    "ai.overlay": "AI overlay",
    "ai.mark": "AI",
    "ai.mark_hint": "What the AI analyst said about this function:",
    "ai.triage": "AI analyst: {assessment}",
    "ai.error.no_endpoint": "No AI endpoint is configured.",
    "ai.error.insecure_endpoint": (
        "The AI endpoint must use https:// (http:// is allowed only on this machine)."
    ),
    "ai.error.auth": "The AI endpoint rejected the key.",
    "ai.error.rate_limit": "The AI endpoint is busy (rate limit). Try again in a minute.",
    "ai.error.timeout": "The AI endpoint did not answer in time.",
    "ai.error.network": "The AI endpoint could not be reached.",
    "ai.error.bad_response": "The model did not return a usable report. Ask again.",
    "ai.error.internal": "The AI report could not be processed.",
    "ai.error.preview_changed": (
        "The evidence changed after you looked at it. Check the new preview and send again."
    ),
    "ui.pseudo_c": "Pseudo-C",
    "decomp.help.title": "How to read this",
    "decomp.help.body": (
        "This is pseudo-C that Ghidra rebuilt from the machine code: it shows what the code "
        "does, it is not the original source. param_1, param_2… are the function's arguments; "
        "local_10, uVar1, iVar2… are local variables Ghidra named by itself; DAT_… is data at "
        "that address; FUN_… is a function nobody has named yet (press N to rename it). Types "
        "are guesses (undefined8 = 8 bytes of unknown type). Click a line to jump to its "
        "instructions. Marked lines are where OctoV found something worth a look."
    ),
    "decomp.no_function": (
        "Ghidra found no function at this address (data, padding, or code it did not recognise)."
    ),
    "decomp.analysing": "Ghidra is analysing this file in the background…",
    "decomp.not_ready": "The decompiler has not run for this file yet.",
    "decomp.timeout": (
        "Decompiling this function took too long and was stopped. Try again, or read the "
        "disassembly instead."
    ),
    "decomp.failed": "The decompiler failed",
    "decomp.octov_function": "this address is in OctoV function {name}",
    "decomp.warnings": "{n} decompiler note(s)",
    "decomp.mark.fact": "Finding",
    "decomp.mark.api": "Sensitive API call",
    "ext.capa.adds": (
        "capa names what each function does (for example 'inject thread', 'encrypt data using "
        "AES') with ATT&CK and MBC references."
    ),
    "ext.floss.adds": (
        "FLOSS recovers strings hidden on the stack or decoded at run time, including hidden URLs"
        " and commands."
    ),
    "ext.install": "Install",
    "ext.setup": "One-time setup",
    "ext.run": "Run",
    "ext.rerun": "Run again",
    "ext.auto_run": "Run automatically",
    "ext.cached": "cached",
    "ext.queued": "queued",
    "ext.idle": "not started",
    "triage.job.idle": "not started",
    "strings.origin": "Origin",
    "strings.origin.static": "in file",
    "strings.origin.stack": "stack",
    "strings.origin.tight": "tight",
    "strings.origin.decoded": "decoded",
    "strings.obfuscated": "Obfuscated",
    "triage.capa_group": "{ns} ({n})",
}
STRINGS.update(API_STRINGS)
