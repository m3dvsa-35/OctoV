"""Azərbaycan dilində UI sətirləri."""

STRINGS: dict[str, str] = {
    "app.title": "OctoV - Binar Analiz İş Masası",
    "menu.file": "Fayl",
    "menu.view": "Görünüş",
    "menu.language": "Dil",
    "menu.help": "Kömək",
    "action.open_sample": "Nümunə aç...",
    "action.new_session": "Yeni sessiya...",
    "action.open_session": "Sessiya aç...",
    "action.exit": "Çıxış",
    "action.theme_dark": "Tünd mövzu",
    "action.theme_light": "Açıq mövzu",
    "action.reset_layout": "Düzülüşü sıfırla",
    "action.about": "OctoV haqqında",
    "dock.samples": "Nümunələr",
    "dock.overview": "İcmal",
    "dock.indicators": "İndikatorlar",
    "dock.disassembly": "Disassembler",
    "dock.pseudocode": "Psevdokod",
    "dock.graph": "Qraf",
    "dock.hex": "Hex",
    "dock.memory_map": "Yaddaş xəritəsi",
    "dock.timeline": "Zaman xətti",
    "dock.mitre": "MITRE ATT&CK",
    "dock.ai_chat": "Sİ köməkçisi",
    "dock.log": "Jurnal",
    "status.ready": "Hazırdır",
    "status.loaded": "{name} yükləndi",
    "status.error": "Xəta: {message}",
    "placeholder.milestone": "{panel} - {milestone} mərhələsində gələcək",
    "overview.empty": (
        "Statik ilkin analizə başlamaq üçün nümunə açın. "
        "Fayllar lokal analiz olunur və heç vaxt yüklənmir."
    ),
    "indicators.column.severity": "Ciddilik",
    "indicators.column.id": "İndikator",
    "indicators.column.mitre": "MITRE",
    "indicators.column.description": "Təsvir",
    "dialog.open_sample": "PE nümunəsini aç",
    "dialog.session_filter": "OctoV sessiyası (*.octov)",
    "about.text": (
        "OctoV {version}\nMüdafiə yönümlü Windows binar analiz iş masası.\n"
        "Bütün analiz lokaldır; nümunələr heç vaxt yüklənmir."
    ),
    "mitre.column.technique": "Texnika",
    "mitre.column.name": "Ad",
    "mitre.column.tactic": "Taktika",
    "mitre.column.severity": "Ciddilik",
    "mitre.column.hits": "Say",
    "mitre.column.sources": "Mənbələr",
    "graph.too_large": (
        "sub_{start}: {count} blok - çəkmək üçün çox böyükdür; "
        "disassembler siyahısından istifadə edin."
    ),
    "disasm.raw": "xam @ {rva}",
    "indicators.navigate_tip": "rva {rva} - keçmək üçün iki dəfə klikləyin",
    "functions.entry": "giriş",
}
