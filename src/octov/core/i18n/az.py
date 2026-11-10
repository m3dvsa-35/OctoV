"""Azərbaycan dilində UI sətirləri."""

from octov.core.i18n.az_api import API_STRINGS

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
    "ui.strings": "Sətirlər",
    "ui.compact": "Yığcam",
    "ui.compact_hint": "Daha sıx görünüş üçün izahları gizlət (təcrübəli analitiklər üçün)",
    "triage.show_explanation": "İzahı göstər",
    "triage.hide_explanation": "İzahı gizlət",
    "triage.jump": "Yerə keç",
    "triage.jobs": "Analizatorlar",
    "triage.job.queued": "növbədə",
    "triage.job.running": "işləyir",
    "triage.job.done": "hazır",
    "triage.job.failed": "xəta",
    "triage.job.unavailable": "əlçatan deyil",
    "functions.suggested": "təklif",
    "functions.suggested_hint": (
        "Ad funksiyanın çağırdığı API-lərə görə təklif olunub; dəyişmək üçün N basın"
    ),
    "annotate.rename": "Funksiyanın adını dəyiş",
    "annotate.comment": "Şərh",
    "annotate.bookmark": "Əlfəcin qoy",
    "annotate.unbookmark": "Əlfəcini sil",
    "annotate.bookmarked": "Əlfəcinli",
    "annotate.rename_hint": (
        "Yeni ad (hərf, rəqəm, _ . : @ ?). Avtomatik ada qaytarmaq üçün boş saxlayın."
    ),
    "annotate.comment_hint": "Bu instruksiyanın yanında göstərilən şərh. Silmək üçün boş saxlayın.",
    "annotate.invalid_name": "Hərf və ya _ ilə başlayın, boşluqsuz, ən çox 128 simvol.",
    "annotate.save": "Yadda saxla",
    "xref.to_here": "Bura istinadlar",
    "xref.title": "{addr} ünvanına istinadlar",
    "xref.none": "Kod istinadı tapılmadı (məlumata dolayı yolla müraciət oluna bilər).",
    "xref.show_hex": "Hex-də göstər",
    "strings.search": "Sətirlərdə axtar",
    "strings.all": "Hamısı",
    "strings.count": "{n} sətir",
    "strings.offset": "Ofset",
    "strings.section": "Bölmə",
    "strings.encoding": "Kod",
    "strings.category": "Kateqoriya",
    "strings.value": "Dəyər",
    "strings.none": "Uyğun sətir yoxdur.",
    "strings.dblclick": "Bu sətirdən istifadə edən kodu görmək üçün iki dəfə klikləyin",
    "strings.cat.url": "URL",
    "strings.cat.domain": "Domen",
    "strings.cat.ipv4": "IPv4",
    "strings.cat.ipv6": "IPv6",
    "strings.cat.email": "E-poçt",
    "strings.cat.path": "Yol",
    "strings.cat.registry": "Reyestr",
    "strings.cat.mutex": "Mutex",
    "strings.cat.command": "Əmr",
    "strings.cat.user_agent": "User-Agent",
    "strings.cat.wallet": "Pul kisəsi",
    "strings.cat.base64": "Base64",
    "triage.iocs_shown": "{total}-dən ilk {n}; CSV kopyası hamısını ixrac edir",
    "capa.ns.anti-analysis.explain": (
        "Kod analizi aşkar etməyə və ya çətinləşdirməyə çalışır: debugger yoxlamaları, virtual "
        "maşın aşkarlanması, obfuskasiya və ya vaxt hiylələri. Zərərli proqram bununla əsl "
        "davranışını analitiklərdən və sandbox-lardan gizlədir; bəzi qanuni proqramlar (DRM, "
        "anti-cheat) da bunu edir. Hansı yoxlamanın edildiyinə və tetiklənəndə kodun nə etdiyinə "
        "baxın."
    ),
    "capa.ns.collection.explain": (
        "Kod kompüterdən məlumat toplayır: ekran görüntüsü, klaviatura basışları, bufer, brauzer "
        "və ya sistem məlumatı. Məlumat oğurlayan və casus proqramlar bununla yaşayır; adi "
        "alətlər çox az şey toplayır. Nəyin toplandığını və saxlanıb-saxlanmadığını, ya da hara "
        "isə göndərilib-göndərilmədiyini yoxlayın."
    ),
    "capa.ns.communication.explain": (
        "Kod şəbəkə üzərindən və ya proseslər arasında əlaqə qurur: HTTP, soket, DNS, named pipe "
        "və ya idarəetmə (C2) kanalı. Zərərli proqram əmr almaq və məlumat göndərmək üçün buna "
        "ehtiyac duyur; bir çox adi proqram da xaricə qoşulur. Əlaqə qurduğu ünvanları IOC "
        "siyahısında və bərpa olunmuş sətirlərdə axtarın."
    ),
    "capa.ns.compiler.explain": (
        "capa proqramın hansı kompilyator və ya icra mühiti ilə qurulduğunu tanıdı (məsələn, "
        "MSVC, Go, Rust və ya .NET paketləyici). Bu, zərər əlaməti deyil, kontekstdir: hansı "
        "kitabxana kodunu ötürə biləcəyinizi və dərin analiz üçün hansı alətlərin uyğun olduğunu "
        "göstərir."
    ),
    "capa.ns.data-manipulation.explain": (
        "Kod məlumatı çevirir: şifrələmə, heş, kodlaşdırma (Base64, XOR), sıxılma və ya sətir "
        "emalı. Zərərli proqram bundan konfiqurasiyanı, sətirləri və trafiki gizlətmək üçün "
        "istifadə edir; adi proqramlar eyni alqoritmlərdən qanuni məqsədlə istifadə edir. Hansı "
        "məlumatın daxil olduğunu və nəticənin harada işləndiyini yoxlayın."
    ),
    "capa.ns.executable.explain": (
        "Faylın icra olunan fayl kimi xüsusiyyətləri: daxilə qoyulmuş fayllar, resurslar, qeyri-"
        "adi PE quruluşu və ya quraşdırıcı/paketləyici izləri. Daxilə qoyulmuş icra faylı çox "
        "vaxt dropper və ya loader deməkdir; quraşdırıcılarda bu qanunidir. Daxili payload-ları "
        "yeni nümunə kimi açın."
    ),
    "capa.ns.exploitation.explain": (
        "Kod zəiflikdən istifadə (exploit) izləri göstərir, məsələn, shellcode nümunələri və ya "
        "yaddaşın doldurulması. Qanuni proqramlarda bu nadirdir; uyğun gələn funksiyaya və hədəfə"
        " nə ötürdüyünə diqqətlə baxmaq lazımdır."
    ),
    "capa.ns.host-interaction.explain": (
        "Kod yerli sistemlə işləyir: fayllar, reyestr, proseslər, axınlar, servislər, "
        "istifadəçilər və ya avadanlıq. Demək olar ki, hər proqram bunun bir qismini edir, ona "
        "görə tək uyğunluq az şey deyir; vacib olan birləşmələrdir (servis yaratmaq və reyestrə "
        "yazmaq, başqa prosesi açıb ona yazmaq)."
    ),
    "capa.ns.impact.explain": (
        "Kod sistemə ziyan vura və ya istifadəni əngəlləyə bilər: faylları silmək və ya "
        "şifrələmək, servisləri dayandırmaq, sistemi söndürmək. Fidyə proqramları və silicilər "
        "bunu edir; ehtiyat nüsxə və ya admin alətlərindən kənarda bu güclü xəbərdarlıqdır. Hansı"
        " faylların və ya servislərin hədəfə alındığını yoxlayın."
    ),
    "capa.ns.internal.explain": (
        "capa-nın daxildə istifadə etdiyi köməkçi uyğunluqlar (məsələn, bir xüsusiyyətin neçə "
        "dəfə görünə biləcəyinə dair məhdudiyyətlər). Bunlar proqramın davranışını yox, analizin "
        "daxili hesabını təsvir edir və adətən nəzərə alınmaya bilər."
    ),
    "capa.ns.linking.explain": (
        "Proqramın çağırdığı kodu necə tapması: icra zamanı həll olunan importlar, API heşləmə və"
        " ya kitabxanaların əl ilə yüklənməsi. API-ləri heş ilə və ya əl ilə həll etmək proqramın"
        " nəyi çağırdığını statik alətlərdən gizlədir; adi runtime linking geniş yayılıb. Sonda "
        "hansı API-lərin həll olunduğuna baxın."
    ),
    "capa.ns.load-code.explain": (
        "Kod başqa kodu yükləyir və ya işə salır: DLL-lər, yaddaşdan PE faylları, shellcode və ya"
        " skriptlər. Loader və dropper-lər bunun üzərində qurulur, xüsusən kod fayldan yox, "
        "yaddaşdan gəlirsə. Yüklənən kodun haradan gəldiyini yoxlayın."
    ),
    "capa.ns.malware-family.explain": (
        "Məlum zərərli proqram ailəsi üçün yazılmış qayda uyğun gəldi. Bunu hökm yox, güclü ipucu"
        " kimi qəbul edin: nümunəni həmin ailə kimi bildirməzdən əvvəl ailənin digər əlamətləri "
        "(sətirlər, konfiqurasiya, şəbəkə indikatorları) ilə təsdiqləyin."
    ),
    "capa.ns.persistence.explain": (
        "Kod yenidən başladıldıqdan və ya sistemə girişdən sonra təkrar işə düşməsini təmin edir:"
        " Run açarları, servislər, planlaşdırılmış tapşırıqlar, avtoyükləmə qovluqları. Zərərli "
        "proqram demək olar ki, həmişə buna ehtiyac duyur; quraşdırıcılar da bunu edir, amma açıq"
        " şəkildə. Dəqiq nəyin işə düşmək üçün qeyd edildiyini yoxlayın."
    ),
    "capa.ns.runtime.explain": (
        "Proqramın istifadə etdiyi dil icra mühitinin xüsusiyyətləri (məsələn, .NET və ya Go "
        "daxili strukturları). Kompilyator uyğunluqları kimi, bu da düzgün alətləri seçməyə kömək"
        " edən kontekstdir, zərərli davranış əlaməti deyil."
    ),
    "capa.ns.targeting.explain": (
        "Kod harada işlədiyini yoxlayır: klaviatura dili, regional ayarlar, ölkə və ya müəyyən "
        "məhsul. Hədəfli zərərli proqram bundan hədəfindən kənarda səssiz qalmaq üçün istifadə "
        "edir; lokallaşdırma kodu bunu qanuni edir. Yoxlamanın nəticəsinin nəyi dəyişdiyinə "
        "baxın."
    ),
    "capa.ns.other.explain": (
        "Adi kateqoriyaların heç birinə aid olmayan capa qaydası uyğun gəldi. Qaydanın adını "
        "oxuyun, uyğun funksiyaya keçin və onu digər tapıntılarla birlikdə qiymətləndirin."
    ),
    "fact.capability.next": "Uyğunluğun arxasındakı kodu görmək üçün funksiyaya keçin.",
    "fact.obfuscated_strings.explain": (
        "FLOSS faylda açıq mətn kimi olmayan sətirlər tapdı: onlar icra zamanı stack-də yığılır "
        "və ya deşifrə olunur. Sətirləri bu cür gizlətmək sadə sətir axtarışlarını aldatmaq üçün "
        "geniş yayılmış zərərli proqram texnikasıdır; bəzi qorunan proqramlar da bunu edir."
    ),
    "fact.obfuscated_strings.next": (
        "Strings tabında Obfuskasiyalı filtrini seçin və bərpa olunmuş dəyərləri oxuyun."
    ),
    "fact.hidden_ioc.explain": (
        "Kompromis indikatorları (URL-lər, domenlər, IP ünvanları, mutex-lər, əmrlər) yalnız "
        "deobfuskasiyadan sonra görünür. Hara qoşulduğunu və ya nəyi işə saldığını gizlədən "
        "proqram bunları açıq saxlayan proqramdan xeyli daha şübhəlidir."
    ),
    "fact.hidden_ioc.next": (
        "Gizli indikatorları blok siyahılarınıza əlavə edin və onları jurnallarınızda axtarın."
    ),
    "ext.reason.not_installed": "quraşdırılmayıb",
    "ext.reason.no_rules": "capa qaydaları yoxdur",
    "ext.reason.in_memory": "yalnız diskdəki fayllar üçün (çıxarılan payload-lar yaddaşda qalır)",
    "ext.reason.too_large": "fayl çox böyükdür (config.yaml-da max_size_mb-ni artırın)",
    "ext.reason.no_ghidra": "Ghidra tapılmadı (işə salın: octov ext setup ghidra)",
    "ext.reason.ghidra_version": "dəstəklənməyən Ghidra versiyası (12.x lazımdır)",
    "ext.reason.no_jdk": "JDK 21 və ya daha yenisi tapılmadı",
    "ext.reason.pe_only": "yalnız PE faylları üçün",
    "ext.ghidra.adds": (
        "Ghidra hər funksiyanın maşın kodunu oxunaqlı psevdo-C-yə çevirir; disassembly və qrafla "
        "sinxron işləyir."
    ),
    "ui.relations": "Əlaqələr",
    "relations.callers": "Çağıranlar",
    "relations.callees": "Çağırılanlar",
    "relations.path": "yol",
    "relations.is_entry": "bu, giriş nöqtəsidir",
    "relations.entry_path": "giriş nöqtəsindən {n} çağırış (işarələnmiş yol)",
    "relations.no_path": "giriş nöqtəsindən birbaşa çağırışlarla çatılmır",
    "relations.truncated": "ən yaxın {n} funksiya göstərilir",
    "relations.more_callers": "+{n} çağıran",
    "relations.more_callees": "+{n} çağırılan",
    "relations.score": "bal {n}",
    "relations.recursive": "rekursiv",
    "relations.export": "eksport",
    "relations.sensitive": "həssas API-lər",
    "relations.other_apis": "digər API-lər",
    "relations.hint": (
        "Çağıranlar solda, çağırılan funksiyalar sağdadır. Funksiyanı mərkəzə gətirmək üçün "
        "klikləyin, kodunu açmaq üçün iki dəfə klikləyin."
    ),
    "ui.pseudo_c": "Psevdo-C",
    "decomp.help.title": "Bunu necə oxumalı",
    "decomp.help.body": (
        "Bu, Ghidra-nın maşın kodundan bərpa etdiyi psevdo-C-dir: kodun nə etdiyini göstərir, "
        "orijinal mənbə kodu deyil. param_1, param_2… funksiyanın arqumentləridir; local_10, "
        "uVar1, iVar2… Ghidra-nın özünün adlandırdığı lokal dəyişənlərdir; DAT_… həmin "
        "ünvandakı məlumatdır; FUN_… hələ heç kimin ad vermədiyi funksiyadır (adını dəyişmək "
        "üçün N düyməsini basın). Tiplər təxminidir (undefined8 = tipi məlum olmayan 8 bayt). "
        "Sətrin təlimatlarına keçmək üçün ona klikləyin. İşarələnmiş sətirlər OctoV-un diqqətə "
        "layiq nəsə tapdığı yerlərdir."
    ),
    "decomp.no_function": (
        "Ghidra bu ünvanda funksiya tapmadı (məlumat, boşluq və ya tanımadığı kod)."
    ),
    "decomp.analysing": "Ghidra bu faylı arxa fonda analiz edir…",
    "decomp.not_ready": "Dekompilyator bu fayl üçün hələ işə salınmayıb.",
    "decomp.timeout": (
        "Bu funksiyanın dekompilyasiyası çox uzun çəkdi və dayandırıldı. Yenidən cəhd edin və "
        "ya disassembly-ni oxuyun."
    ),
    "decomp.failed": "Dekompilyator xəta verdi",
    "decomp.octov_function": "bu ünvan OctoV-un {name} funksiyasındadır",
    "decomp.warnings": "{n} dekompilyator qeydi",
    "decomp.mark.fact": "Tapıntı",
    "decomp.mark.api": "Həssas API çağırışı",
    "ext.capa.adds": (
        "capa hər funksiyanın nə etdiyini adlandırır (məsələn, 'inject thread', 'encrypt data "
        "using AES') və ATT&CK, MBC istinadları verir."
    ),
    "ext.floss.adds": (
        "FLOSS stack-də gizlədilmiş və ya icra zamanı deşifrə olunan sətirləri, o cümlədən gizli "
        "URL və əmrləri bərpa edir."
    ),
    "ext.install": "Quraşdır",
    "ext.setup": "Birdəfəlik quraşdırma",
    "ext.run": "İşə sal",
    "ext.rerun": "Yenidən işə sal",
    "ext.auto_run": "Avtomatik işə sal",
    "ext.cached": "keşdən",
    "ext.queued": "növbədə",
    "ext.idle": "başlanmayıb",
    "triage.job.idle": "başlanmayıb",
    "strings.origin": "Mənbə",
    "strings.origin.static": "faylda",
    "strings.origin.stack": "stack",
    "strings.origin.tight": "tight",
    "strings.origin.decoded": "deşifrə",
    "strings.obfuscated": "Obfuskasiyalı",
    "triage.capa_group": "{ns} ({n})",
}
STRINGS.update(API_STRINGS)
