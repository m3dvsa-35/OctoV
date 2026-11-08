"""Azərbaycan dilində UI sətirləri."""

STRINGS: dict[str, str] = {
    "app.title": "OctoV - Binar Analiz İş Masası",
    "menu.file": "Fayl",
    "menu.view": "Görünüş",
    "menu.language": "Dil",
    "menu.help": "Kömək",
    "action.theme_dark": "Tünd mövzu",
    "action.theme_light": "Açıq mövzu",
    "status.loaded": "{name} yükləndi",
    "indicators.column.severity": "Ciddilik",
    "indicators.column.id": "İndikator",
    "indicators.column.mitre": "MITRE",
    "indicators.column.description": "Təsvir",
    "graph.too_large": (
        "sub_{start}: {count} blok - çəkmək üçün çox böyükdür; "
        "disassembler siyahısından istifadə edin."
    ),
    "disasm.raw": "xam @ {rva}",
    "functions.entry": "giriş",
    "sev.high": "Yüksək",
    "sev.medium": "Orta",
    "sev.low": "Aşağı",
    "sev.info": "Məlumat",
    "ui.open_file": "Fayl aç",
    "ui.open_raw": "Shellcode aç",
    "ui.new_session": "Yeni sessiya",
    "ui.open_session": "Sessiya aç",
    "ui.back": "Geri",
    "ui.forward": "İrəli",
    "ui.command_palette": "Ünvana, funksiyaya və ya tapıntıya keç…",
    "ui.export": "Eksport",
    "ui.local": "Lokal",
    "ui.local_only": "Bütün analiz lokaldır - nümunələr bu kompüterdən çıxmır",
    "ui.samples": "Nümunələr",
    "ui.functions": "Funksiyalar",
    "ui.no_samples": "Hələ nümunə yoxdur. Başlamaq üçün PE faylı və ya shellcode açın.",
    "ui.close": "Bağla",
    "ui.discovering": "Funksiyalar axtarılır…",
    "ui.search_functions": "Funksiyaları süz",
    "ui.identity": "Kimlik",
    "ui.file": "Fayl",
    "ui.size": "Ölçü",
    "ui.binary": "Binar",
    "ui.format": "Format",
    "ui.raw_blob": "Xam kod bloku (x{bits})",
    "ui.entropy": "Entropiya",
    "ui.top_findings": "Əsas tapıntılar",
    "ui.sections": "Bölmələr",
    "ui.name": "Ad",
    "ui.perm": "İcazə",
    "ui.imports": "İmportlar",
    "ui.entry_point": "Giriş nöqtəsi",
    "ui.image_base": "baza",
    "ui.compiled": "Kompilyasiya",
    "ui.signature": "İmza",
    "ui.unsigned": "İmzasız",
    "ui.signed_valid": "İmzalı, təsdiqlənib",
    "ui.signed_unverified": "İmzalı, təsdiqlənməyib",
    "ui.overlay": "Overlay",
    "ui.no_findings": "Bu nümunə üçün tapıntı yoxdur",
    "ui.location": "Yer",
    "ui.evidence": "Sübut",
    "ui.no_techniques": "ATT&CK texnikası müşahidə olunmayıb",
    "ui.hits": "{n} rast",
    "ui.no_function": "Funksiya seçilməyib",
    "ui.no_function_body": "Yan paneldən funksiya seçin, Ctrl+K basın və ya tapıntını açın.",
    "ui.graph_hint": (
        "İdarəetmə axını qrafı tapılmış funksiyanın daxilindəki ünvanlar üçün görünür."
    ),
    "ui.goto_offset": "Ofsetə keç",
    "ui.offset": "ofset",
    "ui.palette_placeholder": "Ünvan (0x1000, sub_19c0), funksiya və ya tapıntı…",
    "ui.no_results": "Nəticə yoxdur",
    "ui.goto": "Keç",
    "ui.goto_address": "{addr} ünvanına keç",
    "ui.actions": "Əməliyyatlar",
    "ui.show_graph": "İdarəetmə axını qrafını göstər",
    "ui.findings": "Tapıntılar",
    "ui.cancel": "Ləğv et",
    "ui.open": "Aç",
    "ui.path_hint": "Analiz ediləcək faylın tam yolu (lokal oxunur, heç yerə yüklənmir)",
    "ui.architecture": "Arxitektura",
    "ui.copied": "Kopyalandı",
    "ui.copy": "Kopyala",
    "ui.saved": "Saxlanıldı: {path}",
    "ui.save": "Saxla…",
    "ui.sigma_needs_pe": (
        "Sigma qaydaları üçün PE nümunəsi lazımdır (proses / image-load hash-ləri)."
    ),
    "ui.session_hint": ".octov sessiya faylının yolu",
    "ui.session_created": "Sessiya yaradıldı: {path}",
    "ui.overview": "İcmal",
    "ui.disassembly": "Disassembler",
    "ui.graph": "Qraf",
    "ui.hex": "Hex",
    "ui.welcome_title": "Windows binar faylını analiz edin",
    "ui.welcome_body": (
        "PE faylı və ya xam shellcode bloku açın. OctoV onu lokal təhlil edir, "
        "tapıntıları MITRE ATT&CK-ə uyğunlaşdırır, YARA və Sigma qaydaları yaradır. Heç "
        "nə yüklənmir."
    ),
    "ui.analysing": "Analiz olunur…",
    "ui.discovery_failed": "Funksiya axtarışı uğursuz oldu",
    "ui.functions_count": "{n} funksiya",
    "ui.language": "Dil",
    "ui.display_mode": "Görünüş rejimi",
    "ui.theme_night": "Gecə",
    "ui.theme_normal": "Normal",
    "fact.rule.explain": (
        "Aşkarlama qaydası hücum texnikasının konkret izlərinə (bayt nümunələri, stringlər "
        "və ya importlar) uyğun gəldi. Bu, sübut deyil, dəlildir: qanuni təhlükəsizlik "
        "alətləri və sistem komponentləri də eyni izləri daşıya bilər."
    ),
    "fact.rule.next": (
        "Sübutun ünvanına keçin, ətrafdakı funksiyanı oxuyun və kodun bunu həqiqətən "
        "istifadə edib-etmədiyini yoxlayın."
    ),
    "fact.indicator.explain": (
        "Faylın zərərli proqramlarda tez-tez rast gəlinən struktur xüsusiyyəti: paketləmə, "
        "qeyri-adi bölmələr və ya şübhəli importlar. Tək başına zəif siqnaldır."
    ),
    "fact.indicator.next": (
        "Digər tapıntılarla birlikdə qiymətləndirin; bir neçə müstəqil indikator bir "
        "indikatordan qat-qat mənalıdır."
    ),
    "fact.crypto_constant.explain": (
        "Faylda tanınmış kriptoqrafik və ya yoxlama cəmi alqoritminin sabit cədvəli var. "
        "Ransomware və loader-lər bunu faylları şifrələmək və ya konfiqurasiyanı açmaq üçün"
        " istifadə edir; bir çox qanuni proqram da istifadə edir."
    ),
    "fact.crypto_constant.next": (
        "Cədvəlin xref-lərini açın: onu istifadə edən funksiyanı və hansı məlumatı emal "
        "etdiyini tapın."
    ),
    "fact.embedded_payload.explain": (
        "Bu faylın içində başqa icra edilə bilən fayl və ya yüksək entropiyalı qapalı blok "
        "gizlənib. Dropper və loader-lər əsl payload-u belə daşıyır; quraşdırıcılar bunu "
        "qanuni edir."
    ),
    "fact.embedded_payload.next": (
        "Payload-u yeni nümunə kimi açıb analiz edin; ixracı yalnız şifrəli ZIP ilə edin."
    ),
    "fact.packer.explain": (
        "Bir neçə əlamət faylın paketləndiyini və ya şifrələndiyini göstərir: gördüyünüz "
        "kod əsasən açma stub-ıdır, əsl proqram yalnız işləyərkən yaddaşda görünür."
    ),
    "fact.packer.next": (
        "Az sayda mənalı funksiya və string gözləyin. Packer-i qeyd edin və əsl kodu görmək"
        " üçün dinamik analiz (M3) və ya açmanı planlayın."
    ),
    "fact.ioc.explain": (
        "Faylda string kimi tapılan kompromis göstəricisi (ünvan, domen, URL, mutex, cüzdan"
        " və ya komanda). Müdafiəçilər bu dəyərlərlə eyni fəaliyyəti başqa yerlərdə axtara "
        "bilər."
    ),
    "fact.ioc.next": (
        "Dəyəri təhdid kəşfiyyatı və jurnallarınızla müqayisə edin, hansı funksiyanın ona "
        "istinad etdiyinə baxın."
    ),
    "ind.high_entropy_section.explain": (
        "Bu bölmə təsadüfi görünür (entropiya 7.2-dən yüksək), bu adətən sıxılmış və ya "
        "şifrələnmiş məlumat deməkdir. Packer-lər və şifrəli payload-lar buna səbəb olur; "
        "şəkillər və sıxılmış resurslar da."
    ),
    "ind.rwx_section.explain": (
        "Bu bölmə eyni anda həm yazıla, həm də icra edilə biləndir, yəni kod özünü dəyişə "
        "bilər. Açma stub-ları və shellcode loader-ləri buna ehtiyac duyur; adi "
        "kompilyatorlar nadir hallarda belə edir."
    ),
    "ind.packer_section_name.explain": (
        "Bölmə adı tanınmış packer və ya qoruyucunun standart adıdır. Bu, faylın "
        "paketləndiyini və əsl kodun statik analizdən gizləndiyini güclü şəkildə göstərir."
    ),
    "ind.virtual_size_inflated.explain": (
        "Bölmə diskdə saxladığından xeyli çox yaddaş ayırır; bu, açıcının işləyərkən əsl "
        "proqramla doldurduğu bufer üçün tipikdir."
    ),
    "ind.entry_point_not_executable.explain": (
        "İcra icra edilə bilən kimi işarələnməmiş bölmədə başlayır, adi proqramlar heç vaxt"
        " belə etmir. Bu, əl ilə müdaxiləyə və ya icazələri işləyərkən düzəldən packer-ə "
        "işarədir."
    ),
    "ind.entry_point_outside_sections.explain": (
        "Giriş nöqtəsi heç bir bölmənin daxilində deyil; bu, analiz alətlərini çaşdırmaq "
        "üçün əl ilə hazırlanmış və ya pozulmuş başlıq əlamətidir."
    ),
    "ind.no_imports.explain": (
        "İcra faylı heç bir funksiya import etmir, yəni Windows API-lərini işləyərkən özü "
        "tapmalıdır. Bu, paketlənmiş fayllar və shellcode tipli loader-lər üçün adidir."
    ),
    "ind.dynamic_api_resolution.explain": (
        "Cəmi bir neçə import var, onların arasında kitabxana yükləyicisi və GetProcAddress"
        " tipli həlledici. Proqram əsl istifadə etdiyi API-ləri işləyərkən tapır və onları "
        "import cədvəlindən gizlədir."
    ),
    "ind.process_injection_apis.explain": (
        "Fayl başqa prosesə yazan və orada kod başladan API-ləri import edir; bunlar proses"
        " inyeksiyasının tikinti bloklarıdır. Debugger-lər və bəzi təhlükəsizlik alətləri "
        "bunları qanuni istifadə edir."
    ),
    "ind.anti_debug_apis.explain": (
        "Fayl debugger-i aşkar edən API-ləri import edir. Zərərli proqramlar bunlarla "
        "analiz altında davranışını dəyişir; adi proqramlar da xəta emalı üçün çağırır."
    ),
    "ind.overlay_present.explain": (
        "Son bölmədən sonra məlumat əlavə olunub. Quraşdırıcılar və imzalı fayllarda "
        "overlay tez-tez olur, amma dropper-lər də payload və ya konfiqurasiyanı orada "
        "gizlədir."
    ),
    "ind.suspicious_timestamp.explain": (
        "Kompilyasiya vaxtı sıfırdır və ya gələcəkdədir; bu, onun saxtalaşdırıldığını "
        "(timestomping) və ya build aləti tərəfindən təkrarlanma üçün silindiyini göstərir."
    ),
    "ui.triage": "Triage",
    "triage.risk": "Risk xalı",
    "triage.band.low": "aşağı",
    "triage.band.medium": "orta",
    "triage.band.high": "yüksək",
    "triage.why": "Bu xal niyə belədir",
    "triage.nothing": "Xala təsir edən şübhəli heç nə yoxdur.",
    "triage.reviewed": "{total} tapıntıdan {n}-i yoxlanılıb",
    "triage.running": "hələ analiz olunur: {jobs}",
    "triage.verdict.confirm": "Təsdiqləndi",
    "triage.verdict.fp": "Yalançı pozitiv",
    "triage.verdict.benign": "Burada zərərsizdir",
    "triage.packed": "Paketlənib və ya şifrələnib ({packer})",
    "triage.capabilities": "İmkanlar və tapıntılar",
    "triage.iocs": "IOC-lər",
    "triage.copy_csv": "CSV kopyala",
    "triage.no_iocs": "Stringlərdə kompromis göstəricisi tapılmadı.",
    "triage.top_functions": "Ən şübhəli funksiyalar",
    "triage.payloads": "Gizli payload-lar",
    "triage.open_payload": "Nümunə kimi aç",
    "triage.export_payload": "Eksport (şifrəli ZIP)",
    "triage.payload_safety": (
        "Payload-lar heç vaxt diskə icra edilə bilən fayl kimi yazılmır; eksport 'infected'"
        " parollu AES ZIP-dir."
    ),
    "triage.orphaned": (
        "{n} saxlanmış verdikt artıq görünməyən tapıntılara aiddir (qaydalar dəyişib)."
    ),
}
