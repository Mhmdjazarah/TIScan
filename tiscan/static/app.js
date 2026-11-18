"use strict";
(() => {
  // ------------------------------------------------------------------ helpers
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const I18N = {
    en: {
      tagline: "Threat Intelligence Scanner",
      nav_scan: "Scan", nav_bulk: "Bulk & Extract", nav_darkweb: "Dark Web", nav_ransomware: "Ransomware", nav_history: "History", nav_sources: "Sources",
      scan_title: "Investigate an indicator",
      scan_hint: "IP, domain, URL, file hash (MD5 / SHA1 / SHA256) or email. Defanged input such as hxxp://evil[.]com is accepted.",
      scan_ph: "e.g. 185.220.101.1, evil[.]com, 44d88612fea8a8f36de82e1278abb02f",
      mode_full: "Full - all sources", mode_fast: "Fast - skip slow & dark-web", nocache: "Bypass cache", btn_scan: "Scan", examples: "Try:",
      scanning: "Querying intelligence sources…", answered: "{n}/{m} sources answered",
      risk_score: "Threat risk", exposure_score: "Dark-web exposure",
      sources_answered: "{n}/{m} sources answered", flagged_n: "{n} flagged",
      defanged: "Defanged", reg_domain: "Registered domain", scanned_at: "Scanned", duration: "Duration", coverage: "Coverage",
      export_misp: "MISP JSON", push_misp: "Push to MISP", export_json: "JSON report", copy_defanged: "Copy defanged", rescan: "Re-scan (live)",
      copied: "Copied to clipboard", why: "Why this score", source_results: "Source results",
      f_all: "All", f_flagged: "Flagged", f_clean: "Clean", f_info: "Context", f_error: "Errors / no key",
      details: "Details", open_in_source: "Open", cached: "cached", stale: "stale cache", pending: "Querying…",
      related_title: "Related indicators", pivot_hint: "Pivot: select related IPs / domains / hashes and scan them in one go (fast mode).",
      select_all: "Select all", pivot_selected: "Pivot-scan selected", scan: "Scan", type: "Type", value: "Value", relation: "Relation", source: "Source",
      pivot_results: "Pivot results", pivot_none: "Select at least one indicator.", open: "Open",
      private_ip: "Private / reserved address - external intelligence sources were not queried.",
      more: "+{n} more", yes: "yes", no: "no",
      bulk_title: "Bulk scan & IOC extraction",
      bulk_hint: "Paste a phishing email (with headers), firewall / proxy logs, or a threat report. Every IOC is extracted, refanged and de-duplicated.",
      bulk_ph: "Paste text here…", extract: "Extract IOCs", load_file: "Load file", found_n: "{n} indicator(s) found",
      include_private: "Include private IPs", select_none: "Select none", scan_selected: "Scan selected ({n})", stop: "Stop",
      progress: "{done}/{total} scanned", export_csv: "Export CSV", export_misp_all: "Export all to MISP", top_hits: "Flagged by", risk: "Risk",
      bulk_none: "No indicators found in this text.", bulk_results: "Bulk results",
      dw_title: "Dark-web exposure",
      dw_hint: "Domain, email or company name. Checks ransomware leak sites, infostealer logs, breach databases and Tor (.onion) search.",
      dw_ph: "e.g. company.com, user@company.com or \"Company Name\"", dw_search: "Check exposure",
      dw_note: "Only metadata is shown (victim posts, breach names, counts). TIScan never downloads leaked data.",
      rw_title: "Ransomware victims monitor", rw_hint: "Latest organisations posted on ransomware leak sites, via ransomware.live. Configured countries refresh in the background.",
      add_country: "Add", global_recent: "Include global latest", load: "Load",
      total_victims: "Victims", groups: "Groups", countries_n: "Countries", last30: "Last 30 days",
      top_groups: "Most active groups", top_sectors: "Most targeted sectors", by_month: "Victims per month", by_country: "By country",
      date: "Date", victim: "Victim", country: "Country", sector: "Sector", group: "Group", domain: "Domain", filter: "Filter…", check: "Check",
      rw_partial: "Some feeds are still loading or rate-limited by ransomware.live (free API). Cached data is shown; press Load again in a minute.",
      rw_empty: "No victims found for the selected countries.",
      history_title: "Scan history", search: "Search…", clear_all: "Clear history", export_selected: "Export selected to MISP",
      confirm_clear: "Delete all scan history?", when: "When", mode: "Mode", exposure: "Exposure", delete: "Delete", empty: "No scans yet.",
      sources_title: "Intelligence sources", keys_hint: "Paste your free API keys below to unlock more sources. They are saved in your local .env file and work immediately, no restart needed.",
      api_key: "API key", paste_key: "Paste API key", key_saved_ph: "saved - paste a new one to replace", no_key_needed: "No key needed",
      remove: "Remove", key_saved: "Key saved - the source is ready", key_removed: "Key removed", confirm_remove_key: "Remove this API key?",
      configured: "Ready", missing_key: "Needs API key", optional_key: "Works without key", get_key: "Get key", weight: "Weight", types: "IOC types",
      total_sources: "Sources", ready_sources: "Ready", need_keys: "Need a key", darkweb_sources: "Dark-web sources",
      cache: "Cache", cache_info: "{n} cached responses ({f} fresh). {s} scans in history.", clear_cache: "Clear cache", cache_cleared: "Cache cleared",
      misp_on: "Connected to {h}. Scan results can be pushed as MISP events.", misp_off: "Not configured. Set MISP_URL and MISP_KEY in .env to push events. JSON export works without it.",
      misp_pushed: "Event created in MISP", footer_note: "For defensive security & threat-intelligence use only.",
      t_ip: "IP", t_domain: "Domain", t_url: "URL", t_md5: "MD5", t_sha1: "SHA1", t_sha256: "SHA256", t_email: "Email", t_keyword: "Keyword",
      l_critical: "Critical", l_high: "High", l_medium: "Medium", l_low: "Low", l_clean: "Clean", l_unknown: "Unknown",
      v_malicious: "Malicious", v_suspicious: "Suspicious", v_clean: "Clean", v_info: "Info", v_unknown: "No data",
      d_malicious: "Exposed", d_suspicious: "Possible", d_clean: "Not found", d_info: "Info", d_unknown: "No data",
      s_no_key: "No API key", s_error: "Error", s_rate_limited: "Rate limited", s_auth_error: "Auth error", s_timeout: "Timeout",
      s_unsupported: "N/A", s_skipped: "Skipped", s_not_found: "Not found",
      c_reputation: "Reputation", c_feeds: "Blocklists & feeds", c_infrastructure: "Infrastructure", c_darkweb: "Dark web",
      m_full: "full", m_fast: "fast", m_darkweb: "dark web",
      nav_monitor: "Monitoring", mon_title: "Continuous monitoring",
      mon_hint: "Add your organisation's domains, key email addresses, public IPs or company name. TIScan re-checks them every {h} h and alerts you only when something NEW appears: a ransomware leak post, an infostealer infection, a data breach, a Tor mention or a blocklisting.",
      mon_ph: "company.com, ceo@company.com, 203.0.113.10 or Company Name", mon_label_ph: "Label (optional)",
      mon_add: "Add to watchlist", mon_added: "Added - first check (baseline) is running",
      watchlist: "Watchlist", mon_schedule: "Checked automatically every {h} h", check_all: "Check all now", check_now: "Check now",
      report: "Report", asset: "Asset", last_check: "Last check", never: "never", checking: "Checking…",
      known_findings: "Known findings", enabled: "On", next_check: "next {t}", mon_empty: "Nothing monitored yet - add your first domain above.",
      alerts: "Alerts", alerts_empty: "No alerts yet. The first check of each asset sends a baseline summary.", clear: "Clear",
      not_delivered: "Not emailed - email alerts are not set up", confirm_delete: "Remove {v} from the watchlist?",
      channels: "Email alerts", channels_none: "Not set up yet - alerts are only shown on this page.",
      channels_active: "Alerts are emailed to: {c}",
      channels_hint: "Alerts are delivered by email (Telegram is blocked in Jordan).",
      email_title: "Email (SMTP)", email_hint: "Gmail: click \"Gmail settings\", enter your Gmail address as the username, and paste the 16-character App Password from myaccount.google.com/apppasswords (not your normal password). A company mail server works too.",
      smtp_host: "SMTP server", smtp_port: "Port", smtp_security: "Security", smtp_user: "Username (your email)", smtp_password: "App Password",
      smtp_from: "From address (optional)", smtp_to: "Send alerts to (comma separated)", password_saved: "saved - leave empty to keep it",
      gmail_preset: "Gmail settings", save: "Save", saved: "Saved", send_test: "Send test email", test_sent: "Test email sent - check your inbox",
      daily_report: "Also email a daily status report, even when nothing new is found", k_report: "Daily report",
      k_baseline: "Baseline", k_change: "New findings", k_test: "Test",
    },
    ar: {
      tagline: "ماسح استخبارات التهديدات",
      nav_scan: "فحص", nav_bulk: "فحص جماعي", nav_darkweb: "الدارك ويب", nav_ransomware: "الرانسوموير", nav_history: "السجل", nav_sources: "المصادر",
      scan_title: "افحص مؤشر اختراق (IOC)",
      scan_hint: "عنوان IP أو دومين أو رابط أو Hash لملف (MD5 / SHA1 / SHA256) أو إيميل. الصيغة المعطّلة مثل hxxp://evil[.]com مقبولة.",
      scan_ph: "مثال: 185.220.101.1 أو evil[.]com أو 44d88612fea8a8f36de82e1278abb02f",
      mode_full: "كامل - كل المصادر", mode_fast: "سريع - بدون البطيئة والدارك ويب", nocache: "تجاهل الكاش", btn_scan: "افحص", examples: "جرّب:",
      scanning: "جاري الاستعلام من مصادر الاستخبارات…", answered: "ردّ {n} من {m} مصدر",
      risk_score: "درجة الخطورة", exposure_score: "الانكشاف على الدارك ويب",
      sources_answered: "ردّ {n} من {m} مصدر", flagged_n: "{n} أبلغت عنه",
      defanged: "صيغة معطّلة", reg_domain: "الدومين الأساسي", scanned_at: "وقت الفحص", duration: "المدة", coverage: "التغطية",
      export_misp: "تصدير MISP", push_misp: "إرسال إلى MISP", export_json: "تقرير JSON", copy_defanged: "نسخ بصيغة معطّلة", rescan: "إعادة فحص مباشر",
      copied: "تم النسخ", why: "سبب هذه الدرجة", source_results: "نتائج المصادر",
      f_all: "الكل", f_flagged: "المُبلَّغ عنها", f_clean: "نظيفة", f_info: "معلومات", f_error: "أخطاء / بدون مفتاح",
      details: "التفاصيل", open_in_source: "فتح", cached: "من الكاش", stale: "كاش قديم", pending: "جاري الاستعلام…",
      related_title: "مؤشرات مرتبطة", pivot_hint: "Pivot: اختر عناوين IP أو دومينات أو Hashes مرتبطة وافحصها دفعة واحدة (الوضع السريع).",
      select_all: "تحديد الكل", pivot_selected: "افحص المحدد", scan: "افحص", type: "النوع", value: "القيمة", relation: "العلاقة", source: "المصدر",
      pivot_results: "نتائج الـPivot", pivot_none: "اختر مؤشراً واحداً على الأقل.", open: "فتح",
      private_ip: "عنوان داخلي أو محجوز - لم يتم إرساله إلى أي مصدر خارجي.",
      more: "+{n} أخرى", yes: "نعم", no: "لا",
      bulk_title: "فحص جماعي واستخراج المؤشرات",
      bulk_hint: "الصق إيميل تصيّد (مع الـheaders) أو سجلات جدار ناري / بروكسي أو تقرير تهديد. سيتم استخراج كل المؤشرات وإزالة التكرار.",
      bulk_ph: "الصق النص هنا…", extract: "استخرج المؤشرات", load_file: "تحميل ملف", found_n: "تم العثور على {n} مؤشر",
      include_private: "ضمّن عناوين IP الداخلية", select_none: "إلغاء التحديد", scan_selected: "افحص المحدد ({n})", stop: "إيقاف",
      progress: "تم فحص {done} من {total}", export_csv: "تصدير CSV", export_misp_all: "تصدير الكل إلى MISP", top_hits: "أبلغ عنه", risk: "الخطورة",
      bulk_none: "لم يتم العثور على مؤشرات في هذا النص.", bulk_results: "نتائج الفحص الجماعي",
      dw_title: "الانكشاف على الدارك ويب",
      dw_hint: "دومين أو إيميل أو اسم شركة. نفحص مواقع تسريب الرانسوموير، سجلات الـinfostealer، قواعد بيانات التسريبات، والبحث في مواقع .onion.",
      dw_ph: "مثال: company.com أو user@company.com أو اسم الشركة", dw_search: "افحص الانكشاف",
      dw_note: "نعرض معلومات وصفية فقط (منشورات الضحايا، أسماء التسريبات، الأعداد). الأداة لا تنزّل أي بيانات مسرّبة.",
      rw_title: "مراقبة ضحايا الرانسوموير", rw_hint: "آخر الجهات التي نُشرت على مواقع تسريب الرانسوموير عبر ransomware.live. الدول المحددة في الإعدادات تتحدّث تلقائياً بالخلفية.",
      add_country: "إضافة", global_recent: "ضمّن آخر الضحايا عالمياً", load: "تحميل",
      total_victims: "الضحايا", groups: "المجموعات", countries_n: "الدول", last30: "آخر 30 يوم",
      top_groups: "أنشط المجموعات", top_sectors: "أكثر القطاعات استهدافاً", by_month: "الضحايا حسب الشهر", by_country: "حسب الدولة",
      date: "التاريخ", victim: "الضحية", country: "الدولة", sector: "القطاع", group: "المجموعة", domain: "الدومين", filter: "فلترة…", check: "افحص",
      rw_partial: "بعض البيانات ما زالت تُحمّل أو أوقفها حد الطلبات في ransomware.live (واجهة مجانية). نعرض الكاش؛ اضغط تحميل مرة أخرى بعد دقيقة.",
      rw_empty: "لا يوجد ضحايا للدول المحددة.",
      history_title: "سجل الفحوصات", search: "بحث…", clear_all: "مسح السجل", export_selected: "تصدير المحدد إلى MISP",
      confirm_clear: "هل تريد حذف كل سجل الفحوصات؟", when: "الوقت", mode: "الوضع", exposure: "الانكشاف", delete: "حذف", empty: "لا توجد فحوصات بعد.",
      sources_title: "مصادر الاستخبارات", keys_hint: "الصق مفاتيح الـAPI المجانية بالأسفل لتفعيل مصادر إضافية. تُحفظ في ملف .env على جهازك وتعمل فوراً بدون إعادة تشغيل.",
      api_key: "مفتاح API", paste_key: "الصق المفتاح هنا", key_saved_ph: "محفوظ - الصق مفتاحاً جديداً للاستبدال", no_key_needed: "لا يحتاج مفتاح",
      remove: "إزالة", key_saved: "تم حفظ المفتاح - المصدر جاهز", key_removed: "تمت إزالة المفتاح", confirm_remove_key: "إزالة هذا المفتاح؟",
      configured: "جاهز", missing_key: "يحتاج مفتاح API", optional_key: "يعمل بدون مفتاح", get_key: "احصل على مفتاح", weight: "الوزن", types: "أنواع المؤشرات",
      total_sources: "المصادر", ready_sources: "جاهزة", need_keys: "تحتاج مفتاح", darkweb_sources: "مصادر الدارك ويب",
      cache: "الكاش", cache_info: "{n} استجابة مخزّنة ({f} حديثة). {s} فحص في السجل.", clear_cache: "مسح الكاش", cache_cleared: "تم مسح الكاش",
      misp_on: "متصل بـ {h}. يمكن إرسال النتائج كأحداث MISP.", misp_off: "غير مضبوط. ضع MISP_URL و MISP_KEY في ملف .env للإرسال. التصدير كملف JSON يعمل بدونه.",
      misp_pushed: "تم إنشاء الحدث في MISP", footer_note: "للاستخدام الدفاعي واستخبارات التهديدات فقط.",
      t_ip: "IP", t_domain: "دومين", t_url: "رابط", t_md5: "MD5", t_sha1: "SHA1", t_sha256: "SHA256", t_email: "إيميل", t_keyword: "كلمة بحث",
      l_critical: "حرج", l_high: "عالٍ", l_medium: "متوسط", l_low: "منخفض", l_clean: "نظيف", l_unknown: "غير معروف",
      v_malicious: "خبيث", v_suspicious: "مشبوه", v_clean: "نظيف", v_info: "معلومات", v_unknown: "لا بيانات",
      d_malicious: "مكشوف", d_suspicious: "محتمل", d_clean: "غير موجود", d_info: "معلومات", d_unknown: "لا بيانات",
      s_no_key: "بدون مفتاح", s_error: "خطأ", s_rate_limited: "تجاوز الحد", s_auth_error: "خطأ مصادقة", s_timeout: "انتهت المهلة",
      s_unsupported: "غير مدعوم", s_skipped: "تم التخطي", s_not_found: "غير موجود",
      c_reputation: "السمعة", c_feeds: "قوائم الحظر", c_infrastructure: "البنية التحتية", c_darkweb: "الدارك ويب",
      m_full: "كامل", m_fast: "سريع", m_darkweb: "دارك ويب",
      nav_monitor: "المراقبة", mon_title: "المراقبة المستمرة",
      mon_hint: "أضف دومينات مؤسستك، الإيميلات المهمة، عناوين IP العامة أو اسم الشركة. TIScan يعيد فحصها كل {h} ساعة وينبّهك فقط عند ظهور شيء جديد: منشور على موقع تسريب رانسوموير، إصابة infostealer، تسريب بيانات، ذكر على مواقع Tor، أو إدراج في قوائم الحظر.",
      mon_ph: "company.com أو ceo@company.com أو 203.0.113.10 أو اسم الشركة", mon_label_ph: "وصف (اختياري)",
      mon_add: "أضف للمراقبة", mon_added: "تمت الإضافة - الفحص الأول (خط الأساس) يعمل الآن",
      watchlist: "قائمة المراقبة", mon_schedule: "يُفحص تلقائياً كل {h} ساعة", check_all: "افحص الكل الآن", check_now: "افحص الآن",
      report: "التقرير", asset: "الأصل", last_check: "آخر فحص", never: "أبداً", checking: "جاري الفحص…",
      known_findings: "النتائج المعروفة", enabled: "مفعّل", next_check: "التالي {t}", mon_empty: "لا يوجد شيء تحت المراقبة - أضف أول دومين من الأعلى.",
      alerts: "التنبيهات", alerts_empty: "لا توجد تنبيهات بعد. أول فحص لكل أصل يرسل ملخص خط الأساس.", clear: "مسح",
      not_delivered: "لم يُرسل - تنبيهات الإيميل غير مضبوطة", confirm_delete: "إزالة {v} من قائمة المراقبة؟",
      channels: "تنبيهات الإيميل", channels_none: "غير مضبوطة بعد - التنبيهات تظهر في هذه الصفحة فقط.",
      channels_active: "التنبيهات تُرسل إلى: {c}",
      channels_hint: "التنبيهات تُرسل عبر الإيميل (تيليجرام محجوب في الأردن).",
      email_title: "الإيميل (SMTP)", email_hint: "Gmail: اضغط \"إعدادات Gmail\"، اكتب إيميلك في اسم المستخدم، والصق كلمة مرور التطبيق (16 حرف) من myaccount.google.com/apppasswords - وليس كلمة المرور العادية. سيرفر إيميل الشركة يعمل أيضاً.",
      smtp_host: "سيرفر SMTP", smtp_port: "المنفذ", smtp_security: "الحماية", smtp_user: "اسم المستخدم (إيميلك)", smtp_password: "كلمة مرور التطبيق (App Password)",
      smtp_from: "عنوان المرسل (اختياري)", smtp_to: "أرسل التنبيهات إلى (افصل بفاصلة)", password_saved: "محفوظة - اتركها فارغة للإبقاء عليها",
      gmail_preset: "إعدادات Gmail", save: "حفظ", saved: "تم الحفظ", send_test: "أرسل إيميل تجريبي", test_sent: "تم إرسال الإيميل التجريبي - افحص بريدك",
      daily_report: "أرسل تقرير يومي بالحالة، حتى لو ما في شي جديد", k_report: "تقرير يومي",
      k_baseline: "خط الأساس", k_change: "نتائج جديدة", k_test: "تجربة",
    },
  };

  const REGIONS = ["JO", "PS", "LB", "SY", "IQ", "SA", "AE", "KW", "QA", "BH", "OM", "YE", "EG", "LY", "TN", "DZ", "MA", "SD", "TR"];
  const SAFE_LINK_HOSTS = ["virustotal.com", "abuseipdb.com", "urlscan.io", "ransomware.live", "hudsonrock.com", "abuse.ch",
    "shodan.io", "crt.sh", "alienvault.com", "pulsedive.com", "ipinfo.io", "spamhaus.org", "haveibeenpwned.com", "leakcheck.io",
    "xposedornot.com", "ahmia.fi", "greynoise.io", "bgp.he.net", "icann.org", "quad9.net", "dns.google", "torproject.org", "circl.lu"];

  const state = {
    lang: "en", config: null, ctl: {}, current: { scan: null, darkweb: null },
    bulk: { iocs: [], results: [], running: false, stop: false, includePrivate: false, mode: "fast" },
    rw: { selected: new Set(), data: null, filter: "" },
  };

  function t(key, vars) {
    let s = I18N[state.lang]?.[key] ?? I18N.en[key] ?? key;
    if (vars) for (const [k, v] of Object.entries(vars)) s = s.split(`{${k}}`).join(v);
    return s;
  }
  const typeLabel = (x) => t("t_" + x);
  const levelLabel = (x) => t("l_" + (x || "unknown"));
  const verdictLabel = (v, dark) => t((dark ? "d_" : "v_") + v);
  const statusLabel = (s) => t("s_" + s);
  const catLabel = (c) => t("c_" + c);
  const regionName = (cc) => { try { return new Intl.DisplayNames([state.lang], { type: "region" }).of(cc) || cc; } catch { return cc; } };
  const fmtDate = (v) => { const d = typeof v === "number" ? new Date(v * 1000) : new Date(v); return isNaN(d) ? "" : d.toLocaleString(state.lang === "ar" ? "ar" : "en-GB", { dateStyle: "medium", timeStyle: "short" }); };
  const store = { get(k) { try { return localStorage.getItem(k); } catch { return null; } }, set(k, v) { try { localStorage.setItem(k, v); } catch { /* ignore */ } } };

  function toast(msg, kind = "") {
    const el = document.createElement("div");
    el.className = `toast ${kind}`;
    el.textContent = msg;
    $("#toasts").append(el);
    setTimeout(() => el.remove(), kind === "err" ? 8000 : 4000);
  }

  function download(name, text, mime = "application/json") {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type: mime }));
    a.download = name;
    document.body.append(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  }

  function errText(d) {
    if (!d) return "";
    if (typeof d.detail === "string") return d.detail;
    if (Array.isArray(d.detail)) return d.detail.map((x) => x.msg).join("; ");
    return "";
  }

  async function api(path, { method = "GET", body, signal } = {}) {
    const opts = { method, headers: { "X-Requested-With": "tiscan" }, signal };
    if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
    const res = await fetch(path, opts);
    let data = null;
    try { data = await res.json(); } catch { /* empty */ }
    if (!res.ok) throw new Error(errText(data) || `HTTP ${res.status}`);
    return data;
  }

  async function streamScan(body, onEvent, signal) {
    const res = await fetch("/api/scan/stream", {
      method: "POST", signal, body: JSON.stringify(body),
      headers: { "Content-Type": "application/json", "X-Requested-With": "tiscan" },
    });
    if (!res.ok) { let d = null; try { d = await res.json(); } catch { /* empty */ } throw new Error(errText(d) || `HTTP ${res.status}`); }
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i).trim();
        buf = buf.slice(i + 1);
        if (line) onEvent(JSON.parse(line));
      }
    }
    if (buf.trim()) onEvent(JSON.parse(buf));
  }

  function refang(s) {
    return s.replace(/hxxp/gi, "http").replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, ".").replace(/\[:\]/g, ":").replace(/\[@\]|\[at\]|\(at\)/gi, "@");
  }
  function guessType(raw, allowKeyword = false) {
    const v = refang(raw.trim());
    if (!v) return "";
    if (/^[a-f0-9]{32}$/i.test(v)) return "md5";
    if (/^[a-f0-9]{40}$/i.test(v)) return "sha1";
    if (/^[a-f0-9]{64}$/i.test(v)) return "sha256";
    if (/^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(v) || (/^\[?[0-9a-f:]+\]?$/i.test(v) && (v.match(/:/g) || []).length >= 2)) return "ip";
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return "url";
    if (/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(v)) return "email";
    if (/^([a-z0-9_-]+\.)+[a-z]{2,63}\.?$/i.test(v) || /^([a-z0-9_-]+\.)+xn--[a-z0-9-]+$/i.test(v)) return "domain";
    if (/^([a-z0-9_-]+\.)+[a-z]{2,63}[/?#]/i.test(v)) return "url";
    return allowKeyword ? "keyword" : "";
  }

  // ------------------------------------------------------------------ generic rendering
  const isEmpty = (v) => v === null || v === undefined || v === "" || (Array.isArray(v) && !v.length) || (typeof v === "object" && !Array.isArray(v) && !Object.keys(v).length);

  function safeHref(url) {
    try {
      const u = new URL(url);
      if (u.protocol !== "https:" && u.protocol !== "http:") return null;
      const h = u.hostname.toLowerCase();
      return SAFE_LINK_HOSTS.some((d) => h === d || h.endsWith("." + d)) ? u.href : null;
    } catch { return null; }
  }
  // Links to intel platforms are clickable; anything else (possibly malicious URLs) is shown as inert text.
  function link(url, text = url) {
    const href = safeHref(url);
    if (!href) return `<code class="url" dir="ltr">${esc(text)}</code>`;
    return `<a href="${esc(href)}" target="_blank" rel="noopener noreferrer" dir="ltr">${esc(text)}</a>`;
  }
  const shorten = (s, n) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

  function chipList(arr, max = 40) {
    const shown = arr.slice(0, max);
    return `<div class="chips">${shown.map((x) => `<span class="chip" dir="auto">${esc(x)}</span>`).join("")}${arr.length > max ? `<span class="chip more">${t("more", { n: arr.length - max })}</span>` : ""}</div>`;
  }
  function cell(v) {
    if (isEmpty(v)) return `<span class="muted">-</span>`;
    if (typeof v === "string" && /^https?:\/\//i.test(v)) return link(v, shorten(v, 70));
    if (typeof v === "boolean") return v ? t("yes") : t("no");
    if (typeof v === "object") return `<code>${esc(JSON.stringify(v))}</code>`;
    return `<span dir="auto">${esc(v)}</span>`;
  }
  function table(rows, max = 25) {
    const cols = [...new Set(rows.slice(0, 10).flatMap((r) => Object.keys(r || {})))];
    return `<div class="table-wrap"><table class="tbl"><thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>${
      rows.slice(0, max).map((r) => `<tr>${cols.map((c) => `<td>${cell(r?.[c])}</td>`).join("")}</tr>`).join("")
    }</tbody></table>${rows.length > max ? `<div class="muted small">${t("more", { n: rows.length - max })}</div>` : ""}</div>`;
  }
  function renderValue(v) {
    if (typeof v === "boolean") return v ? `<span class="yes">● ${t("yes")}</span>` : `<span class="no">${t("no")}</span>`;
    if (typeof v === "number") return esc(v.toLocaleString("en"));
    if (typeof v === "string") return /^https?:\/\//i.test(v) ? link(v, shorten(v, 90)) : `<span dir="auto">${esc(v)}</span>`;
    if (Array.isArray(v)) return v.every((x) => x === null || typeof x !== "object") ? chipList(v) : table(v);
    if (typeof v === "object") {
      return `<dl class="kv nested">${Object.entries(v).filter(([, x]) => !isEmpty(x)).map(([k, x]) => `<dt>${esc(k)}</dt><dd>${renderValue(x)}</dd>`).join("")}</dl>`;
    }
    return esc(v);
  }
  function renderData(data) {
    const rows = Object.entries(data || {}).filter(([, v]) => !isEmpty(v));
    if (!rows.length) return "";
    return `<dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${renderValue(v)}</dd>`).join("")}</dl>`;
  }

  // ------------------------------------------------------------------ report rendering
  const okish = (r) => r.status === "ok" || r.status === "not_found";
  function cardGroup(r) {
    if (!okish(r)) return "error";
    if (r.verdict === "malicious" || r.verdict === "suspicious" || r.exposure > 0) return "flagged";
    return r.verdict === "clean" ? "clean" : "info";
  }

  function sourceCard(r) {
    const dark = r.category === "darkweb";
    const v = okish(r) ? r.verdict : "unknown";
    const pill = okish(r) ? verdictLabel(r.verdict, dark) : statusLabel(r.status);
    const bar = dark ? r.exposure : r.score;
    const meta = r.cached ? (r.stale ? t("stale") : t("cached")) : (r.elapsed_ms ? `${r.elapsed_ms} ms` : "");
    const data = renderData(r.data);
    return `<article class="card src-card v-${esc(v)}" data-group="${cardGroup(r)}" data-src="${esc(r.source)}">
      <header><div><div class="src-name">${esc(r.name)}</div><div class="src-cat">${esc(catLabel(r.category))}</div></div><span class="pill v-${esc(v)}">${esc(pill)}</span></header>
      ${bar > 0 ? `<div class="bar"><span style="width:${Math.min(100, bar)}%"></span></div>` : ""}
      <p class="summary-line" dir="auto">${esc(r.summary || r.error || "")}</p>
      ${data ? `<details><summary>${t("details")}</summary>${data}</details>` : ""}
      <footer><span class="muted">${esc(meta)}</span>${r.link && safeHref(r.link) ? link(r.link, t("open_in_source") + " ↗") : ""}</footer>
    </article>`;
  }

  function pendingCard(s) {
    return `<article class="card src-card pending" data-src="${esc(s.id)}" data-group="info">
      <header><div><div class="src-name">${esc(s.name)}</div><div class="src-cat">${esc(catLabel(s.category))}</div></div><span class="pill"><span class="spinner"></span>${t("pending")}</span></header>
      <div class="skeleton"></div></article>`;
  }

  function gaugeCard(title, s, dark) {
    const lvl = s.level || "unknown";
    const pct = Math.max(0, Math.min(100, s.score || 0));
    const L = 251.33;
    return `<div class="panel gauge-card lvl-${esc(lvl)}">
      <div class="gauge-title">${esc(title)}</div>
      <svg viewBox="0 0 200 118" class="gauge" role="img" aria-label="${esc(title)} ${pct}/100">
        <path d="M20 105 A80 80 0 0 1 180 105" class="g-bg"/>
        <path d="M20 105 A80 80 0 0 1 180 105" class="g-fg" stroke-dasharray="${(pct / 100) * L} ${L}"/>
        <text x="100" y="92" class="g-num">${lvl === "unknown" ? "?" : pct}</text><text x="100" y="112" class="g-sub">/ 100</text>
      </svg>
      <div class="level-pill">${esc(levelLabel(lvl))}</div>
      <div class="muted small">${t("sources_answered", { n: s.answered, m: s.total })} · ${t("flagged_n", { n: s.flagged })}</div>
    </div>`;
  }

  function reasonsPanel(rep) {
    const items = [...(rep.risk?.reasons || []), ...(rep.exposure?.reasons || [])];
    if (!items.length) return "";
    return `<div class="panel"><h2>${t("why")}</h2><ul class="reasons">${items.map((r) => `
      <li class="v-${esc(r.verdict)}"><span class="impact" dir="ltr">${r.impact ? "+" + r.impact : "−"}</span><b>${esc(r.source)}</b><span dir="auto">${esc(r.text)}</span></li>`).join("")}</ul></div>`;
  }

  function filterBar(results) {
    const counts = { all: results.length, flagged: 0, clean: 0, info: 0, error: 0 };
    results.forEach((r) => { counts[cardGroup(r)]++; });
    const keys = ["all", "flagged", "clean", "info", "error"];
    return `<div class="seg" role="group">${keys.filter((k) => k === "all" || counts[k]).map((k) =>
      `<button type="button" data-filter="${k}" class="${k === "all" ? "active" : ""}">${t("f_" + k)}<span class="n">${counts[k]}</span></button>`).join("")}</div>`;
  }

  function relatedPanel(rep) {
    const rel = rep.related || [];
    if (!rel.length) return "";
    return `<div class="panel related">
      <div class="row space"><h2>${t("related_title")} <span class="count">${rel.length}</span></h2>
        <div class="row"><button type="button" class="btn ghost sm" data-act="rel-all">${t("select_all")}</button>
        <button type="button" class="btn primary sm" data-act="pivot">${t("pivot_selected")}</button></div></div>
      <p class="muted small">${t("pivot_hint")}</p>
      <div class="table-wrap"><table class="tbl"><thead><tr><th></th><th>${t("type")}</th><th>${t("value")}</th><th>${t("relation")}</th><th>${t("source")}</th><th></th></tr></thead><tbody>
      ${rel.map((r, i) => `<tr><td><input type="checkbox" class="rel-cb" data-i="${i}"></td>
        <td><span class="type-badge on sm">${esc(typeLabel(r.type))}</span></td><td><code dir="ltr">${esc(r.value)}</code></td>
        <td dir="auto">${esc(r.rel)}</td><td class="muted">${esc(r.source)}</td>
        <td><button type="button" class="btn link sm" data-act="scan-one" data-i="${i}">${t("scan")}</button></td></tr>`).join("")}
      </tbody></table></div><div class="pivot-out"></div></div>`;
  }

  function riskCell(score, level) {
    if (score === null || score === undefined) return `<span class="muted">-</span>`;
    return `<div class="riskcell lvl-${esc(level)}"><div class="bar"><span style="width:${score}%"></span></div><b>${score}</b><span class="pill lvl-${esc(level)}">${esc(levelLabel(level))}</span></div>`;
  }

  function compactTable(rows, { withOpen = true } = {}) {
    return `<div class="table-wrap"><table class="tbl"><thead><tr><th>${t("value")}</th><th>${t("type")}</th><th>${t("risk")}</th><th>${t("top_hits")}</th><th></th></tr></thead><tbody>
      ${rows.map((r) => `<tr><td><code dir="ltr">${esc(r.value)}</code>${r.error ? `<div class="muted small">${esc(r.error)}</div>` : ""}</td>
        <td><span class="type-badge on sm">${esc(typeLabel(r.type || ""))}</span></td>
        <td>${r.private ? `<span class="muted small">${t("s_skipped")}</span>` : riskCell(r.risk, r.level)}</td>
        <td><div class="chips">${(r.flagged || []).map((f) => `<span class="chip">${esc(f)}</span>`).join("")}</div>${r.top ? `<div class="muted small" dir="auto">${esc(r.top)}</div>` : ""}</td>
        <td>${withOpen && r.id ? `<button type="button" class="btn link sm" data-open="${r.id}">${t("open")}</button>` : ""}</td></tr>`).join("")}
      </tbody></table></div>`;
  }

  function renderReport(container, rep, kind) {
    const dark = rep.mode === "darkweb";
    const risk = rep.risk, exp = rep.exposure;
    const answered = (risk?.answered || 0) + (exp?.answered || 0);
    const total = (risk?.total || 0) + (exp?.total || 0);
    container.innerHTML = `
      <div class="summary-grid">
        ${risk ? gaugeCard(t("risk_score"), risk, false) : ""}
        ${exp ? gaugeCard(t("exposure_score"), exp, true) : ""}
        <div class="panel ioc-card">
          <div class="ioc-head"><span class="type-badge on">${esc(typeLabel(rep.ioc.type))}</span><code class="ioc-value" dir="ltr">${esc(rep.ioc.value)}</code></div>
          <dl class="kv compact">
            ${rep.ioc.defanged !== rep.ioc.value ? `<dt>${t("defanged")}</dt><dd><code dir="ltr">${esc(rep.ioc.defanged)}</code></dd>` : ""}
            ${rep.ioc.domain && rep.ioc.domain !== rep.ioc.value ? `<dt>${t("reg_domain")}</dt><dd><code dir="ltr">${esc(rep.ioc.domain)}</code></dd>` : ""}
            <dt>${t("scanned_at")}</dt><dd>${esc(fmtDate(rep.scanned_at))}</dd>
            <dt>${t("duration")}</dt><dd><bdi dir="ltr">${(rep.duration_ms / 1000).toFixed(1)} s</bdi> · ${esc(t("m_" + rep.mode))}</dd>
            <dt>${t("coverage")}</dt><dd>${t("sources_answered", { n: answered, m: total })}</dd>
          </dl>
          ${rep.tags?.length ? `<div class="chips" style="margin-top:.6rem">${rep.tags.map((x) => `<span class="chip tag">${esc(x)}</span>`).join("")}</div>` : ""}
          <div class="actions">
            ${rep.id ? `<button type="button" class="btn ghost sm" data-act="misp">${t("export_misp")}</button>` : ""}
            ${rep.id && state.config?.misp?.configured ? `<button type="button" class="btn ghost sm" data-act="push">${t("push_misp")}</button>` : ""}
            <button type="button" class="btn ghost sm" data-act="json">${t("export_json")}</button>
            <button type="button" class="btn ghost sm" data-act="copy">${t("copy_defanged")}</button>
            <button type="button" class="btn ghost sm" data-act="rescan">${t("rescan")}</button>
          </div>
        </div>
      </div>
      ${rep.ioc.private ? `<div class="panel private-note">${t("private_ip")}</div>` : ""}
      ${reasonsPanel(rep)}
      <div class="panel">
        <div class="row space"><h2>${t("source_results")}</h2>${filterBar(rep.results)}</div>
        <div class="cards" data-filter="all">${rep.results.map(sourceCard).join("")}</div>
      </div>
      ${dark ? "" : relatedPanel(rep)}`;
    bindReport(container, rep, kind);
  }

  function bindReport(container, rep, kind) {
    container.onclick = async (e) => {
      const btn = e.target.closest("button");
      if (!btn) return;
      if (btn.dataset.filter) {
        $$(".seg button", container).forEach((b) => b.classList.toggle("active", b === btn));
        $(".cards", container).dataset.filter = btn.dataset.filter;
        return;
      }
      if (btn.dataset.open) return openReport(+btn.dataset.open);
      const act = btn.dataset.act;
      if (act === "misp") exportMisp([rep.id]);
      else if (act === "push") pushMisp([rep.id]);
      else if (act === "json") download(`tiscan-${rep.ioc.value.replace(/[^\w.-]+/g, "_").slice(0, 60)}.json`, JSON.stringify(rep, null, 2));
      else if (act === "copy") { try { await navigator.clipboard.writeText(rep.ioc.defanged); toast(t("copied"), "ok"); } catch (err) { toast(err.message, "err"); } }
      else if (act === "rescan") runScan(kind, rep.ioc.value, { nocache: true });
      else if (act === "rel-all") {
        const boxes = $$(".rel-cb", container);
        const on = !boxes.slice(0, 25).every((b) => b.checked);
        boxes.forEach((b, i) => { b.checked = on && i < 25; });
      } else if (act === "scan-one") {
        const r = rep.related[+btn.dataset.i];
        $("#scan-input").value = r.value;
        updateBadge($("#scan-input"), $("#scan-type"));
        showTab("scan");
        runScan("scan", r.value);
      } else if (act === "pivot") {
        const values = $$(".rel-cb", container).filter((b) => b.checked).map((b) => rep.related[+b.dataset.i].value).slice(0, 25);
        if (!values.length) return toast(t("pivot_none"));
        const out = $(".pivot-out", container);
        out.innerHTML = `<div class="loading" style="margin-top:1rem"><span class="spinner"></span>${t("scanning")}</div>`;
        btn.disabled = true;
        try {
          const res = await api("/api/pivot", { method: "POST", body: { items: values, mode: "fast" } });
          const rows = res.results.sort((a, b) => (b.risk ?? -1) - (a.risk ?? -1));
          out.innerHTML = `<h2 style="margin-top:1.2rem">${t("pivot_results")}</h2>${compactTable(rows)}`;
        } catch (err) { out.innerHTML = `<div class="panel error-box">${esc(err.message)}</div>`; }
        btn.disabled = false;
      }
    };
  }

  // ------------------------------------------------------------------ scanning
  async function runScan(kind, value, { nocache = false } = {}) {
    const dark = kind === "darkweb";
    const container = dark ? $("#dw-result") : $("#scan-result");
    const mode = dark ? "darkweb" : $("#scan-mode").value;
    state.ctl[kind]?.abort();
    const ctl = new AbortController();
    state.ctl[kind] = ctl;
    state.current[kind] = null;
    container.onclick = null;
    container.innerHTML = `<div class="panel loading"><span class="spinner"></span>${t("scanning")}</div>`;
    let total = 0, done = 0;
    try {
      await streamScan({ ioc: value, mode, nocache: nocache || $(dark ? "#dw-nocache" : "#scan-nocache").checked }, (ev) => {
        if (ev.event === "start") {
          total = ev.sources.length;
          container.innerHTML = `<div class="panel">
              <div class="row space"><div class="ioc-head"><span class="type-badge on">${esc(typeLabel(ev.ioc.type))}</span><code class="ioc-value" dir="ltr">${esc(ev.ioc.value)}</code></div>
              <span class="muted live-count">${t("answered", { n: 0, m: total })}</span></div>
              <div class="progress"><span style="width:0%"></span></div>
              <div class="cards" data-filter="all">${ev.sources.map(pendingCard).join("")}</div></div>`;
        } else if (ev.event === "result") {
          done++;
          const slot = $(`.src-card[data-src="${CSS.escape(ev.result.source)}"]`, container);
          if (slot) slot.outerHTML = sourceCard(ev.result);
          const cnt = $(".live-count", container);
          if (cnt) cnt.textContent = t("answered", { n: done, m: total });
          const bar = $(".progress span", container);
          if (bar) bar.style.width = `${total ? (done / total) * 100 : 100}%`;
        } else if (ev.event === "done") {
          state.current[kind] = ev.report;
          renderReport(container, ev.report, kind);
          if (ev.report.id) history.replaceState(null, "", `#report/${ev.report.id}`);
        } else if (ev.event === "error") {
          throw new Error(ev.message);
        }
      }, ctl.signal);
    } catch (err) {
      if (err.name === "AbortError") return;
      container.innerHTML = `<div class="panel error-box">${esc(err.message)}</div>`;
    }
  }

  async function openReport(id) {
    try {
      const rep = await api(`/api/history/${id}`);
      const kind = rep.mode === "darkweb" ? "darkweb" : "scan";
      showTab(kind, false);
      history.replaceState(null, "", `#report/${id}`);
      const input = kind === "darkweb" ? $("#dw-input") : $("#scan-input");
      input.value = rep.ioc.value;
      updateBadge(input, kind === "darkweb" ? $("#dw-type") : $("#scan-type"), kind === "darkweb");
      state.current[kind] = rep;
      renderReport(kind === "darkweb" ? $("#dw-result") : $("#scan-result"), rep, kind);
      window.scrollTo({ top: 0, behavior: "smooth" });
    } catch (err) { toast(err.message, "err"); }
  }

  function exportMisp(ids) {
    const a = document.createElement("a");
    a.href = `/api/export/misp?ids=${ids.join(",")}`;
    document.body.append(a);
    a.click();
    a.remove();
  }

  async function pushMisp(ids) {
    try {
      const res = await api("/api/misp/push", { method: "POST", body: { ids } });
      toast(`${t("misp_pushed")}: #${res.id ?? "?"}`, "ok");
    } catch (err) { toast(err.message, "err"); }
  }

  function updateBadge(input, badge, allowKeyword = false) {
    const type = guessType(input.value, allowKeyword);
    badge.textContent = type ? typeLabel(type) : "";
    badge.classList.toggle("on", !!type);
  }

  // ------------------------------------------------------------------ bulk
  function renderBulkIocs() {
    const box = $("#bulk-iocs");
    const items = state.bulk.iocs;
    if (!items.length) { box.innerHTML = ""; return; }
    const counts = {};
    items.forEach((i) => { counts[i.type] = (counts[i.type] || 0) + 1; });
    const selected = items.filter((i) => i.sel).length;
    box.innerHTML = `<div class="panel">
      <div class="row space">
        <div class="chips">${Object.entries(counts).map(([k, n]) => `<span class="chip tag">${esc(typeLabel(k))}: ${n}</span>`).join("")}</div>
        <div class="row">
          <label class="check"><input type="checkbox" id="bulk-private" ${state.bulk.includePrivate ? "checked" : ""}><span>${t("include_private")}</span></label>
          <button type="button" class="btn ghost sm" data-bulk="all">${t("select_all")}</button>
          <button type="button" class="btn ghost sm" data-bulk="none">${t("select_none")}</button>
          <select id="bulk-mode">${["fast", "full"].map((m) => `<option value="${m}" ${state.bulk.mode === m ? "selected" : ""}>${t("mode_" + m)}</option>`).join("")}</select>
          ${state.bulk.running ? `<button type="button" class="btn danger sm" data-bulk="stop">${t("stop")}</button>`
            : `<button type="button" class="btn primary sm" data-bulk="run" ${selected ? "" : "disabled"}>${t("scan_selected", { n: selected })}</button>`}
        </div>
      </div>
      <div class="table-wrap" style="max-height:340px;margin-top:.8rem"><table class="tbl"><thead><tr><th></th><th>${t("type")}</th><th>${t("value")}</th></tr></thead><tbody>
        ${items.map((i, idx) => `<tr><td><input type="checkbox" data-idx="${idx}" ${i.sel ? "checked" : ""} ${i.private && !state.bulk.includePrivate ? "disabled" : ""}></td>
          <td><span class="type-badge on sm">${esc(typeLabel(i.type))}</span></td>
          <td><code dir="ltr">${esc(i.value)}</code>${i.private ? ` <span class="muted small">(private)</span>` : ""}</td></tr>`).join("")}
      </tbody></table></div></div>`;
  }

  function renderBulkResults() {
    const box = $("#bulk-results");
    const res = state.bulk.results;
    if (!res.length) { box.innerHTML = ""; return; }
    const finished = res.filter((r) => r.done).length;
    const rows = [...res].filter((r) => r.done).sort((a, b) => (b.risk ?? -1) - (a.risk ?? -1));
    box.innerHTML = `<div class="panel">
      <div class="row space"><h2>${t("bulk_results")}</h2>
        <div class="row">
          <button type="button" class="btn ghost sm" data-bulk="csv" ${finished ? "" : "disabled"}>${t("export_csv")}</button>
          <button type="button" class="btn ghost sm" data-bulk="misp" ${rows.some((r) => r.id) ? "" : "disabled"}>${t("export_misp_all")}</button>
        </div></div>
      <div class="muted">${t("progress", { done: finished, total: res.length })}</div>
      <div class="progress"><span style="width:${(finished / res.length) * 100}%"></span></div>
      ${compactTable(rows)}</div>`;
  }

  async function runBulk() {
    const targets = state.bulk.iocs.filter((i) => i.sel && (!i.private || state.bulk.includePrivate));
    if (!targets.length) return;
    const mode = state.bulk.mode;
    state.bulk.running = true;
    state.bulk.stop = false;
    state.bulk.results = targets.map((i) => ({ value: i.value, type: i.type, done: false }));
    renderBulkIocs();
    renderBulkResults();
    let next = 0;
    const worker = async () => {
      while (!state.bulk.stop && next < targets.length) {
        const idx = next++;
        const slot = state.bulk.results[idx];
        try {
          const rep = await api("/api/scan", { method: "POST", body: { ioc: targets[idx].value, mode } });
          const flagged = rep.results.filter((r) => r.verdict === "malicious" || r.verdict === "suspicious");
          Object.assign(slot, { id: rep.id, type: rep.ioc.type, private: rep.ioc.private, risk: rep.risk?.score, level: rep.risk?.level,
            flagged: flagged.map((r) => r.name), top: flagged[0]?.summary || "", done: true });
        } catch (err) {
          Object.assign(slot, { error: err.message, done: true });
        }
        renderBulkResults();
      }
    };
    await Promise.all([worker(), worker(), worker()]);
    state.bulk.running = false;
    renderBulkIocs();
    renderBulkResults();
  }

  function bulkCsv() {
    const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const lines = [["ioc", "type", "risk_score", "risk_level", "flagged_by", "top_finding", "scan_id"].join(",")];
    state.bulk.results.filter((r) => r.done).forEach((r) => lines.push([r.value, r.type, r.risk, r.level, (r.flagged || []).join("; "), r.top || r.error, r.id].map(q).join(",")));
    download(`tiscan-bulk-${new Date().toISOString().slice(0, 10)}.csv`, lines.join("\r\n"), "text/csv");
  }

  async function doExtract() {
    const text = $("#bulk-text").value;
    if (!text.trim()) return;
    try {
      const res = await api("/api/extract", { method: "POST", body: { text } });
      state.bulk.iocs = res.iocs.map((i) => ({ ...i, sel: !i.private }));
      $("#bulk-found").textContent = res.iocs.length ? t("found_n", { n: res.iocs.length }) : t("bulk_none");
      renderBulkIocs();
    } catch (err) { toast(err.message, "err"); }
  }

  // ------------------------------------------------------------------ ransomware monitor
  function renderCountryChips() {
    const all = [...new Set([...REGIONS, ...state.rw.selected])];
    $("#rw-countries").innerHTML = all.map((cc) =>
      `<button type="button" class="chip ${state.rw.selected.has(cc) ? "on" : ""}" data-cc="${esc(cc)}">${esc(cc)} · ${esc(regionName(cc))}</button>`).join("");
  }

  async function loadRansomware() {
    const box = $("#rw-result");
    const countries = [...state.rw.selected];
    box.innerHTML = `<div class="panel loading"><span class="spinner"></span>${t("scanning")}</div>`;
    try {
      const recent = $("#rw-recent").checked ? "&recent=true" : "";
      state.rw.data = await api(`/api/ransomware?countries=${encodeURIComponent(countries.join(","))}${recent}`);
      renderRansomware();
    } catch (err) { box.innerHTML = `<div class="panel error-box">${esc(err.message)}</div>`; }
  }

  function hbars(pairs, labeler = (x) => x) {
    if (!pairs.length) return `<div class="muted">-</div>`;
    const max = Math.max(...pairs.map((p) => p[1]));
    return `<div class="hbars">${pairs.map(([k, n]) => `<div class="hbar"><span class="lbl" dir="auto" title="${esc(labeler(k))}">${esc(labeler(k))}</span><div class="track"><span style="width:${(n / max) * 100}%"></span></div><span class="val">${n}</span></div>`).join("")}</div>`;
  }

  function monthLabel(ym) {
    try { return new Date(`${ym}-15T00:00:00Z`).toLocaleDateString(state.lang === "ar" ? "ar" : "en-GB", { month: "short", timeZone: "UTC" }); }
    catch { return ym.slice(5); }
  }

  function renderRansomware() {
    const d = state.rw.data;
    if (!d) return;
    const box = $("#rw-result");
    const partial = Object.values(d.status || {}).some((s) => s !== "ok");
    const cutoff = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
    const last30 = d.victims.filter((v) => (v.date || "") >= cutoff).length;
    const maxMonth = Math.max(1, ...d.stats.months.map((m) => m[1]));
    const f = state.rw.filter.toLowerCase();
    const rows = d.victims.filter((v) => !f || [v.victim, v.group, v.sector, v.domain, v.country].join(" ").toLowerCase().includes(f));
    box.innerHTML = `
      ${partial ? `<div class="panel notice">${t("rw_partial")}<div class="muted small" style="margin-top:.3rem">${Object.entries(d.status).map(([k, v]) => `${esc(k)}: ${esc(v)}`).join(" · ")}</div></div>` : ""}
      <div class="stat-row">
        <div class="stat"><b>${d.total}</b><span>${t("total_victims")}</span></div>
        <div class="stat"><b>${last30}</b><span>${t("last30")}</span></div>
        <div class="stat"><b>${d.stats.groups_total ?? d.stats.groups.length}</b><span>${t("groups")}</span></div>
        <div class="stat"><b>${d.stats.countries.length}</b><span>${t("countries_n")}</span></div>
      </div>
      ${d.total ? `<div class="grid2">
        <div class="panel"><h2>${t("top_groups")}</h2>${hbars(d.stats.groups)}</div>
        <div class="panel"><h2>${t("top_sectors")}</h2>${hbars(d.stats.sectors)}</div>
        <div class="panel"><h2>${t("by_month")}</h2><div class="cols">${d.stats.months.map(([m, n]) => `<div class="col" title="${esc(m)}: ${n}"><b>${n}</b><span style="height:${(n / maxMonth) * 100}%"></span><small>${esc(monthLabel(m))}</small></div>`).join("")}</div></div>
        <div class="panel"><h2>${t("by_country")}</h2>${hbars(d.stats.countries, (cc) => `${cc} · ${regionName(cc)}`)}</div>
      </div>` : ""}
      <div class="panel">
        <div class="row space"><h2>${t("total_victims")} <span class="count">${rows.length}</span></h2><input type="search" id="rw-filter" dir="auto" placeholder="${esc(t("filter"))}" value="${esc(state.rw.filter)}"></div>
        ${d.total ? `<div class="table-wrap"><table class="tbl"><thead><tr><th>${t("date")}</th><th>${t("victim")}</th><th>${t("country")}</th><th>${t("sector")}</th><th>${t("group")}</th><th>${t("domain")}</th><th></th></tr></thead><tbody>
          ${rows.slice(0, 400).map((v) => `<tr><td class="num">${esc(v.date || "")}</td><td dir="auto"><b>${esc(v.victim)}</b>${v.description ? `<div class="muted small" dir="auto">${esc(shorten(v.description, 160))}</div>` : ""}</td>
            <td>${v.country ? `${esc(v.country)}` : "-"}</td><td dir="auto">${esc(v.sector || "-")}</td><td><span class="pill v-malicious">${esc(v.group)}</span></td>
            <td>${v.domain ? `<code dir="ltr">${esc(v.domain)}</code> <button type="button" class="btn link sm" data-check="${esc(v.domain)}">${t("check")}</button>` : "-"}</td>
            <td>${v.link ? link(v.link, "↗") : ""}</td></tr>`).join("")}
        </tbody></table></div>${rows.length > 400 ? `<div class="muted small">${t("more", { n: rows.length - 400 })}</div>` : ""}` : `<p class="muted">${t("rw_empty")}</p>`}
      </div>`;
    const filter = $("#rw-filter");
    filter.oninput = () => {
      state.rw.filter = filter.value;
      const pos = filter.selectionStart;
      renderRansomware();
      const again = $("#rw-filter");
      again.focus();
      again.setSelectionRange(pos, pos);
    };
  }

  // ------------------------------------------------------------------ history
  let histTimer = null;
  async function loadHistory() {
    const q = $("#hist-q").value.trim();
    try {
      const res = await api(`/api/history?limit=300&q=${encodeURIComponent(q)}`);
      const box = $("#hist-list");
      if (!res.items.length) { box.innerHTML = `<p class="muted">${t("empty")}</p>`; return; }
      box.innerHTML = `<div class="table-wrap"><table class="tbl"><thead><tr><th><input type="checkbox" id="hist-all"></th><th>${t("when")}</th><th>${t("value")}</th><th>${t("type")}</th><th>${t("mode")}</th><th>${t("risk")}</th><th>${t("exposure")}</th><th></th></tr></thead><tbody>
        ${res.items.map((r) => `<tr><td><input type="checkbox" class="hist-cb" value="${r.id}"></td><td class="num">${esc(fmtDate(r.created))}</td>
          <td><code dir="ltr">${esc(r.ioc)}</code></td><td><span class="type-badge on sm">${esc(typeLabel(r.type))}</span></td><td>${esc(t("m_" + r.mode))}</td>
          <td>${r.risk_level ? riskCell(r.risk, r.risk_level) : "-"}</td><td>${r.exposure_level ? riskCell(r.exposure, r.exposure_level) : "-"}</td>
          <td class="row"><button type="button" class="btn link sm" data-open="${r.id}">${t("open")}</button><button type="button" class="btn link sm danger" data-del="${r.id}">${t("delete")}</button></td></tr>`).join("")}
      </tbody></table></div>`;
    } catch (err) { toast(err.message, "err"); }
  }

  // ------------------------------------------------------------------ sources
  async function loadSources() {
    try {
      const [cfg, stats] = await Promise.all([api("/api/config"), api("/api/stats")]);
      state.config = cfg;
      const src = cfg.sources;
      const ready = src.filter((s) => s.configured).length;
      $("#src-summary").innerHTML = `
        <div class="stat"><b>${src.length}</b><span>${t("total_sources")}</span></div>
        <div class="stat"><b style="color:var(--clean)">${ready}</b><span>${t("ready_sources")}</span></div>
        <div class="stat"><b style="color:var(--medium)">${src.length - ready}</b><span>${t("need_keys")}</span></div>
        <div class="stat"><b style="color:var(--info)">${src.filter((s) => s.darkweb).length}</b><span>${t("darkweb_sources")}</span></div>`;
      const cats = ["reputation", "feeds", "infrastructure", "darkweb"];
      $("#src-list").innerHTML = cats.map((c) => {
        const list = src.filter((s) => s.category === c);
        if (!list.length) return "";
        return `<h2 style="margin-top:1.2rem">${esc(catLabel(c))}</h2><div class="src-rows">
          ${list.map((s) => {
            const status = !s.configured ? `<span class="pill v-suspicious">${t("missing_key")}</span>`
              : s.key_env && !s.has_key ? `<span class="pill v-clean">${t("optional_key")}</span>` : `<span class="pill v-clean">${t("configured")}</span>`;
            const keyCell = !s.key_env ? `<span class="muted small">${t("no_key_needed")}</span>` : `
              <form class="key-form" data-key="${esc(s.key_env)}" autocomplete="off">
                <input type="password" name="value" dir="ltr" autocomplete="off" spellcheck="false"
                  placeholder="${esc(s.has_key ? t("key_saved_ph") : t("paste_key"))}">
                <button class="btn primary sm" type="submit">${t("save")}</button>
                ${s.has_key ? `<button class="btn link sm danger" type="button" data-clear="${esc(s.key_env)}">${t("remove")}</button>` : ""}
              </form>
              ${s.signup ? `<a class="small" href="${esc(s.signup)}" target="_blank" rel="noopener noreferrer">${t("get_key")} ↗</a>` : ""}`;
            return `<div class="src-row">
              <div><div class="row"><b>${esc(s.name)}</b>${status}</div><div class="muted small" dir="auto">${esc(s.description)}</div>
                <div class="chips" style="margin-top:.35rem">${s.types.map((x) => `<span class="type-badge on sm">${esc(typeLabel(x))}</span>`).join("")}</div></div>
              <div class="key-cell">${keyCell}</div></div>`;
          }).join("")}</div>`;
      }).join("");
      $("#cache-info").textContent = t("cache_info", { n: stats.cache.entries, f: stats.cache.fresh, s: stats.scans });
      $("#misp-info").textContent = cfg.misp.configured ? t("misp_on", { h: cfg.misp.host }) : t("misp_off");
    } catch (err) { toast(err.message, "err"); }
  }

  // ------------------------------------------------------------------ monitoring
  const mon = { data: null, alerts: [], timer: null, channelsOpen: null };

  function ago(ts) {
    if (!ts) return t("never");
    const diff = ts - Date.now() / 1000;
    const abs = Math.abs(diff);
    const [v, unit] = abs < 60 ? [Math.round(diff), "second"] : abs < 3600 ? [Math.round(diff / 60), "minute"]
      : abs < 86400 ? [Math.round(diff / 3600), "hour"] : [Math.round(diff / 86400), "day"];
    try { return new Intl.RelativeTimeFormat(state.lang, { numeric: "auto" }).format(v, unit); } catch { return fmtDate(ts); }
  }

  async function loadMonitor(withChannels = false) {
    clearTimeout(mon.timer);
    try {
      const [d, a] = await Promise.all([api("/api/monitor"), api("/api/monitor/alerts?limit=50")]);
      mon.data = d;
      mon.alerts = a.items;
      renderMonitor();
      if (withChannels) renderChannels();
      if (!$("#tab-monitor").hidden) mon.timer = setTimeout(loadMonitor, d.items.some((i) => i.checking) ? 4000 : 30000);
    } catch (err) { toast(err.message, "err"); }
  }

  function alertItem(a) {
    const lvl = a.level === "info" ? "low" : a.level;
    const delivery = Object.entries(a.delivery || {});
    return `<div class="alert-item lvl-${esc(lvl)}">
      <div class="meta"><span class="pill lvl-${esc(lvl)}">${esc(a.level.toUpperCase())}</span><span>${esc(t("k_" + a.kind))}</span><span>${esc(fmtDate(a.created))}</span>
        ${a.scan_id ? `<button type="button" class="btn link sm" data-open="${a.scan_id}">${t("report")}</button>` : ""}</div>
      <div dir="auto"><b>${esc(a.title)}</b></div>
      ${a.findings.length ? `<ul>${a.findings.slice(0, 6).map((f) => `<li dir="auto"><span class="pill lvl-${esc(f.severity === "info" ? "low" : f.severity)}">${esc(f.severity)}</span> ${esc(f.text)}</li>`).join("")}${a.findings.length > 6 ? `<li class="muted">${t("more", { n: a.findings.length - 6 })}</li>` : ""}</ul>` : ""}
      <div class="meta">${delivery.length ? delivery.map(([ch, res]) => `<span class="${res === "ok" ? "ok-text" : "warn-text"}">${res === "ok" ? "✓" : "✗"} ${esc(ch)}${res === "ok" ? "" : `: ${esc(res)}`}</span>`).join(" · ")
        : `<span class="warn-text">${t("not_delivered")}</span>`}</div>
    </div>`;
  }

  function renderMonitor() {
    const d = mon.data;
    if (!d) return;
    const h = +d.interval_hours.toFixed(1);
    $("#mon-hint").textContent = t("mon_hint", { h });
    $("#mon-schedule").textContent = d.enabled ? t("mon_schedule", { h }) : "";
    $("#mon-count").textContent = d.items.length || "";
    $("#mon-list").innerHTML = d.items.length ? `<div class="table-wrap"><table class="tbl"><thead><tr><th>${t("asset")}</th><th>${t("last_check")}</th><th>${t("risk")}</th><th>${t("exposure")}</th><th class="num">${t("known_findings")}</th><th>${t("enabled")}</th><th></th></tr></thead><tbody>
      ${d.items.map((w) => `<tr>
        <td><div class="row"><span class="type-badge on sm">${esc(typeLabel(w.type))}</span><code dir="ltr">${esc(w.value)}</code></div>
          ${w.label ? `<div class="muted small" dir="auto">${esc(w.label)}</div>` : ""}${w.last_error ? `<div class="small warn-text">${esc(w.last_error)}</div>` : ""}</td>
        <td>${w.checking ? `<span class="row"><span class="spinner"></span>${t("checking")}</span>`
          : `${esc(ago(w.last_checked))}${w.next_check ? `<div class="muted small">${esc(t("next_check", { t: ago(w.next_check) }))}</div>` : ""}`}</td>
        <td>${w.risk_level ? riskCell(w.risk, w.risk_level) : "-"}</td>
        <td>${w.exposure_level ? riskCell(w.exposure, w.exposure_level) : "-"}</td>
        <td class="num">${w.known_findings}</td>
        <td><input type="checkbox" class="switch" data-toggle="${w.id}" ${w.enabled ? "checked" : ""} aria-label="${esc(t("enabled"))}"></td>
        <td><div class="row"><button type="button" class="btn link sm" data-check="${w.id}" ${w.checking ? "disabled" : ""}>${t("check_now")}</button>
          ${w.last_scan_id ? `<button type="button" class="btn link sm" data-open="${w.last_scan_id}">${t("report")}</button>` : ""}
          <button type="button" class="btn link sm danger" data-del="${w.id}" data-v="${esc(w.value)}">${t("delete")}</button></div></td></tr>`).join("")}
      </tbody></table></div>` : `<p class="muted">${t("mon_empty")}</p>`;
    $("#mon-alerts").innerHTML = mon.alerts.length ? mon.alerts.map(alertItem).join("") : `<p class="muted">${t("alerts_empty")}</p>`;
  }

  function renderChannels() {
    const e = mon.data?.notify;
    if (!e) return;
    const box = $("#mon-channels");
    if (mon.channelsOpen === null) mon.channelsOpen = !e.configured;
    box.open = mon.channelsOpen;
    box.innerHTML = `<summary>${t("channels")} <span class="${e.configured ? "ok-text" : "warn-text"} small" dir="auto">${esc(e.configured ? t("channels_active", { c: e.to.join(", ") }) : t("channels_none"))}</span></summary>
      <div class="channel-grid">
        <form class="card" id="email-form" autocomplete="off">
          <div class="row space"><b>${t("email_title")}</b><button type="button" class="btn ghost sm" data-preset="gmail">${t("gmail_preset")}</button></div>
          <p class="hint">${t("channels_hint")}</p>
          <p class="hint">${t("email_hint")}</p>
          <div class="form-grid">
            <label>${t("smtp_host")}<input name="host" dir="ltr" value="${esc(e.host)}" placeholder="smtp.gmail.com"></label>
            <label>${t("smtp_port")}<input name="port" type="number" min="1" max="65535" dir="ltr" value="${esc(e.port)}"></label>
            <label>${t("smtp_security")}<select name="security">${["starttls", "ssl", "none"].map((s) => `<option value="${s}" ${e.security === s ? "selected" : ""}>${s.toUpperCase()}</option>`).join("")}</select></label>
            <label>${t("smtp_user")}<input name="user" dir="ltr" value="${esc(e.user)}" placeholder="you@gmail.com" autocomplete="off"></label>
            <label class="wide">${t("smtp_password")}<input name="password" type="password" dir="ltr" autocomplete="new-password" placeholder="${esc(e.has_password ? t("password_saved") : "")}"></label>
            <label>${t("smtp_from")}<input name="sender" dir="ltr" value="${esc(e.from)}" placeholder="you@gmail.com"></label>
            <label>${t("smtp_to")}<input name="to" dir="ltr" value="${esc(e.to.join(", "))}" placeholder="soc@company.com"></label>
            <label class="check wide"><input type="checkbox" name="daily_report" ${e.daily_report ? "checked" : ""}><span>${t("daily_report")}</span></label>
          </div>
          <div class="row"><button class="btn primary sm" type="submit">${t("save")}</button>
            <button type="button" class="btn ghost sm" id="notify-test" ${e.configured ? "" : "disabled"}>${t("send_test")}</button></div>
        </form>
      </div>`;
  }

  function wireMonitor() {
    $("#mon-input").addEventListener("input", () => updateBadge($("#mon-input"), $("#mon-type"), true));
    $("#mon-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const value = $("#mon-input").value.trim();
      if (!value) return;
      try {
        await api("/api/monitor/watch", { method: "POST", body: { value, label: $("#mon-label").value.trim() || null } });
        $("#mon-input").value = "";
        $("#mon-label").value = "";
        updateBadge($("#mon-input"), $("#mon-type"), true);
        toast(t("mon_added"), "ok");
        loadMonitor();
      } catch (err) { toast(err.message, "err"); }
    });
    const listClick = async (e) => {
      const b = e.target.closest("button");
      if (!b) return;
      try {
        if (b.dataset.open) return openReport(+b.dataset.open);
        if (b.dataset.check) { b.disabled = true; await api(`/api/monitor/watch/${b.dataset.check}/check`, { method: "POST" }); }
        else if (b.dataset.del) {
          if (!confirm(t("confirm_delete", { v: b.dataset.v }))) return;
          await api(`/api/monitor/watch/${b.dataset.del}`, { method: "DELETE" });
        } else return;
        loadMonitor();
      } catch (err) { toast(err.message, "err"); }
    };
    $("#mon-list").addEventListener("click", listClick);
    $("#mon-alerts").addEventListener("click", listClick);
    $("#mon-list").addEventListener("change", async (e) => {
      if (!e.target.dataset.toggle) return;
      try { await api(`/api/monitor/watch/${e.target.dataset.toggle}`, { method: "PATCH", body: { enabled: e.target.checked } }); loadMonitor(); }
      catch (err) { toast(err.message, "err"); }
    });
    $("#mon-check-all").addEventListener("click", async () => {
      try { await api("/api/monitor/check-all", { method: "POST" }); loadMonitor(); } catch (err) { toast(err.message, "err"); }
    });
    $("#mon-alerts-clear").addEventListener("click", async () => {
      try { await api("/api/monitor/alerts", { method: "DELETE" }); loadMonitor(); } catch (err) { toast(err.message, "err"); }
    });

    const box = $("#mon-channels");
    box.addEventListener("toggle", () => { mon.channelsOpen = box.open; });
    box.addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = new FormData(e.target);
      try {
        const status = await api("/api/monitor/notify/email", { method: "POST", body: {
          host: f.get("host").trim(), port: +f.get("port") || 587, security: f.get("security"), user: f.get("user").trim(),
          password: f.get("password") ? f.get("password").replace(/\s+/g, "") : null, sender: f.get("sender").trim(),
          to: f.get("to").split(/[,;\s]+/).filter(Boolean), daily_report: f.get("daily_report") === "on",
        } });
        mon.data.notify = status;
        renderChannels();
        toast(t("saved"), "ok");
      } catch (err) { toast(err.message, "err"); }
    });
    box.addEventListener("click", async (e) => {
      const b = e.target.closest("button");
      if (!b) return;
      if (b.dataset.preset === "gmail") {
        const el = $("#email-form").elements;
        el.namedItem("host").value = "smtp.gmail.com";
        el.namedItem("port").value = 587;
        el.namedItem("security").value = "starttls";
        el.namedItem("user").focus();
      } else if (b.id === "notify-test") {
        b.disabled = true;
        try {
          const res = await api("/api/monitor/notify/test", { method: "POST" });
          const failed = Object.entries(res.delivery || {}).filter(([, v]) => v !== "ok");
          failed.length ? toast(failed.map(([k, v]) => `${k}: ${v}`).join("\n"), "err") : toast(t("test_sent"), "ok");
          loadMonitor();
        } catch (err) { toast(err.message, "err"); }
        b.disabled = false;
      }
    });
  }

  // ------------------------------------------------------------------ tabs, language, wiring
  const TABS = ["scan", "bulk", "darkweb", "ransomware", "monitor", "history", "sources"];
  let rwLoaded = false;
  function showTab(name, updateHash = true) {
    $$(".tab").forEach((s) => { s.hidden = s.id !== `tab-${name}`; });
    $$(".tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
    if (updateHash) history.replaceState(null, "", `#${name}`);
    if (name === "history") loadHistory();
    if (name === "sources") loadSources();
    if (name === "ransomware" && !rwLoaded) { rwLoaded = true; loadRansomware(); }
    if (name === "monitor") loadMonitor(true);
    else clearTimeout(mon.timer);
  }

  function route() {
    const h = location.hash.slice(1);
    const m = h.match(/^report\/(\d+)$/);
    if (m) return openReport(+m[1]);
    showTab(TABS.includes(h) ? h : "scan", false);
  }

  function applyLang() {
    const ar = state.lang === "ar";
    document.documentElement.lang = state.lang;
    document.documentElement.dir = ar ? "rtl" : "ltr";
    $$("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
    $$("[data-i18n-ph]").forEach((el) => { el.placeholder = t(el.dataset.i18nPh); });
    $("#lang-toggle").textContent = ar ? "English" : "عربي";
    updateBadge($("#scan-input"), $("#scan-type"));
    updateBadge($("#dw-input"), $("#dw-type"), true);
    updateBadge($("#mon-input"), $("#mon-type"), true);
    renderMonitor();
    renderChannels();
    if (state.current.scan) renderReport($("#scan-result"), state.current.scan, "scan");
    if (state.current.darkweb) renderReport($("#dw-result"), state.current.darkweb, "darkweb");
    renderBulkIocs();
    renderBulkResults();
    renderCountryChips();
    renderRansomware();
    const active = TABS.find((n) => !$(`#tab-${n}`).hidden);
    if (active === "history") loadHistory();
    if (active === "sources") loadSources();
  }

  function wire() {
    wireMonitor();
    $$(".tabs button").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));
    $("#lang-toggle").addEventListener("click", () => {
      state.lang = state.lang === "ar" ? "en" : "ar";
      store.set("tiscan.lang", state.lang);
      applyLang();
    });

    $("#scan-input").addEventListener("input", () => updateBadge($("#scan-input"), $("#scan-type")));
    $("#scan-form").addEventListener("submit", (e) => { e.preventDefault(); const v = $("#scan-input").value.trim(); if (v) runScan("scan", v); });
    $$("[data-example]").forEach((b) => b.addEventListener("click", () => {
      $("#scan-input").value = b.dataset.example;
      updateBadge($("#scan-input"), $("#scan-type"));
      runScan("scan", b.dataset.example);
    }));

    $("#dw-input").addEventListener("input", () => updateBadge($("#dw-input"), $("#dw-type"), true));
    $("#dw-form").addEventListener("submit", (e) => { e.preventDefault(); const v = $("#dw-input").value.trim(); if (v) runScan("darkweb", v); });

    $("#bulk-extract").addEventListener("click", doExtract);
    $("#bulk-file").addEventListener("change", async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      if (file.size > 3_000_000) { toast("File larger than 3 MB", "err"); return; }
      $("#bulk-text").value = await file.text();
      e.target.value = "";
      doExtract();
    });
    $("#bulk-iocs").addEventListener("change", (e) => {
      if (e.target.id === "bulk-mode") {
        state.bulk.mode = e.target.value;
      } else if (e.target.id === "bulk-private") {
        state.bulk.includePrivate = e.target.checked;
        state.bulk.iocs.forEach((i) => { if (i.private) i.sel = e.target.checked; });
        renderBulkIocs();
      } else if (e.target.dataset.idx !== undefined) {
        state.bulk.iocs[+e.target.dataset.idx].sel = e.target.checked;
        const btn = $('[data-bulk="run"]');
        const n = state.bulk.iocs.filter((i) => i.sel).length;
        if (btn) { btn.textContent = t("scan_selected", { n }); btn.disabled = !n; }
      }
    });
    const onBulkClick = (e) => {
      const b = e.target.closest("[data-bulk]");
      const open = e.target.closest("[data-open]");
      if (open) return openReport(+open.dataset.open);
      if (!b) return;
      const act = b.dataset.bulk;
      if (act === "all" || act === "none") {
        state.bulk.iocs.forEach((i) => { i.sel = act === "all" && (!i.private || state.bulk.includePrivate); });
        renderBulkIocs();
      } else if (act === "run") runBulk();
      else if (act === "stop") { state.bulk.stop = true; b.disabled = true; }
      else if (act === "csv") bulkCsv();
      else if (act === "misp") exportMisp(state.bulk.results.filter((r) => r.id).map((r) => r.id));
    };
    $("#bulk-iocs").addEventListener("click", onBulkClick);
    $("#bulk-results").addEventListener("click", onBulkClick);

    $("#rw-countries").addEventListener("click", (e) => {
      const b = e.target.closest("[data-cc]");
      if (!b) return;
      const cc = b.dataset.cc;
      state.rw.selected.has(cc) ? state.rw.selected.delete(cc) : state.rw.selected.add(cc);
      store.set("tiscan.rw", [...state.rw.selected].join(","));
      renderCountryChips();
    });
    $("#rw-add").addEventListener("click", () => {
      const cc = $("#rw-custom").value.trim().toUpperCase();
      if (!/^[A-Z]{2}$/.test(cc)) return;
      state.rw.selected.add(cc);
      $("#rw-custom").value = "";
      store.set("tiscan.rw", [...state.rw.selected].join(","));
      renderCountryChips();
    });
    $("#rw-load").addEventListener("click", loadRansomware);
    $("#rw-result").addEventListener("click", (e) => {
      const b = e.target.closest("[data-check]");
      if (!b) return;
      $("#dw-input").value = b.dataset.check;
      updateBadge($("#dw-input"), $("#dw-type"), true);
      showTab("darkweb");
      runScan("darkweb", b.dataset.check);
    });

    $("#hist-q").addEventListener("input", () => { clearTimeout(histTimer); histTimer = setTimeout(loadHistory, 250); });
    $("#hist-list").addEventListener("click", async (e) => {
      const open = e.target.closest("[data-open]");
      const del = e.target.closest("[data-del]");
      if (open) openReport(+open.dataset.open);
      if (del) { try { await api(`/api/history/${del.dataset.del}`, { method: "DELETE" }); loadHistory(); } catch (err) { toast(err.message, "err"); } }
    });
    $("#hist-list").addEventListener("change", (e) => {
      if (e.target.id === "hist-all") $$(".hist-cb").forEach((c) => { c.checked = e.target.checked; });
    });
    $("#hist-export").addEventListener("click", () => {
      const ids = $$(".hist-cb").filter((c) => c.checked).map((c) => c.value);
      if (!ids.length) return toast(t("pivot_none"));
      exportMisp(ids);
    });
    $("#hist-clear").addEventListener("click", async () => {
      if (!confirm(t("confirm_clear"))) return;
      try { await api("/api/history", { method: "DELETE" }); loadHistory(); } catch (err) { toast(err.message, "err"); }
    });
    const saveKey = async (name, value) => {
      try {
        const res = await api("/api/keys", { method: "POST", body: { name, value } });
        toast(res.configured ? t("key_saved") : t("key_removed"), "ok");
        loadSources();
      } catch (err) { toast(err.message, "err"); }
    };
    $("#src-list").addEventListener("submit", (e) => {
      const form = e.target.closest(".key-form");
      if (!form) return;
      e.preventDefault();
      const value = form.elements.namedItem("value").value.trim();
      if (value) saveKey(form.dataset.key, value);
    });
    $("#src-list").addEventListener("click", (e) => {
      const b = e.target.closest("[data-clear]");
      if (b && confirm(t("confirm_remove_key"))) saveKey(b.dataset.clear, "");
    });
    $("#cache-clear").addEventListener("click", async () => {
      try { await api("/api/cache", { method: "DELETE" }); toast(t("cache_cleared"), "ok"); loadSources(); } catch (err) { toast(err.message, "err"); }
    });
    window.addEventListener("hashchange", route);
  }

  async function init() {
    const saved = store.get("tiscan.lang");
    state.lang = saved || ((navigator.language || "").toLowerCase().startsWith("ar") ? "ar" : "en");
    wire();
    try {
      state.config = await api("/api/config");
      $("#version").textContent = `v${state.config.version}`;
      const savedRw = store.get("tiscan.rw");
      (savedRw ? savedRw.split(",").filter(Boolean) : state.config.ransomware_countries).forEach((cc) => state.rw.selected.add(cc));
    } catch (err) { toast(err.message, "err"); }
    applyLang();
    route();
  }

  init();
})();
