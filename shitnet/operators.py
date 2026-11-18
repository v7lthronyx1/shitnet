import re

OPERATORS = {
    "AS197207": {
        "asn": "AS197207",
        "short_en": "MCI",
        "name_en": "MCI (Hamrah-e-Avval)",
        "name_fa": "همراه اول",
        "legal_fa": "شرکت ارتباطات سیار ایران (همراه اول)",
        "service_type_fa": "اینترنت سیم‌کارت همراه اول",
        "support_tel": "9990 (از خط همراه اول) / 09129990",
        "support_code": "9990",
        "support_channel": "تماس با 9990 یا ایمیل 9990@mci.ir / پورتال همراه من",
        "hashtags_fa": ["#همراه_اول", "#اینترنت", "#فیلترینگ", "#اینترنت_بین_الملل", "#کیفیت_اینترنت", "#سامانه_۱۹۵"],
    },
    "AS44244": {
        "asn": "AS44244",
        "short_en": "Irancell",
        "name_en": "MTN Irancell",
        "name_fa": "ایرانسل",
        "legal_fa": "شرکت خدمات ارتباطی ایرانسل",
        "service_type_fa": "اینترنت سیم‌کارت / مودم ایرانسل",
        "support_tel": "700 (از خط ایرانسل) / 09377000000",
        "support_code": "700",
        "support_channel": "تماس با 700 یا اپلیکیشن ایرانسل من / پورتال رسمی ایرانسل",
        "hashtags_fa": ["#ایرانسل", "#اینترنت", "#فیلترینگ", "#اینترنت_بین_الملل", "#کیفیت_اینترنت", "#سامانه_۱۹۵"],
    },
    "AS57218": {
        "asn": "AS57218",
        "short_en": "Rightel",
        "name_en": "RighTel",
        "name_fa": "رایتل",
        "legal_fa": "شرکت خدمات ارتباطی رایتل",
        "service_type_fa": "اینترنت سیم‌کارت رایتل",
        "support_tel": "200 (از خط رایتل) / 09202000000",
        "support_code": "200",
        "support_channel": "تماس با 200 یا پورتال رسمی پشتیبانی رایتل",
        "hashtags_fa": ["#رایتل", "#اینترنت", "#فیلترینگ", "#اینترنت_بین_الملل", "#کیفیت_اینترنت", "#سامانه_۱۹۵"],
    },
    "AS58224": {
        "asn": "AS58224",
        "short_en": "TCI",
        "name_en": "TCI (Mokhaberat)",
        "name_fa": "مخابرات ایران",
        "legal_fa": "شرکت مخابرات ایران",
        "service_type_fa": "اینترنت ثابت / فیبر نوری مخابرات",
        "support_tel": "2020",
        "support_code": "2020",
        "support_channel": "تماس با 2020 یا پورتال مخابرات من",
        "hashtags_fa": ["#مخابرات", "#اینترنت_ثابت", "#فیلترینگ", "#اینترنت_بین_الملل", "#کیفیت_اینترنت", "#سامانه_۱۹۵"],
    },
    "AS31549": {
        "asn": "AS31549",
        "short_en": "Shatel",
        "name_en": "Aria Shatel",
        "name_fa": "شاتل",
        "legal_fa": "شرکت آریا شاتل",
        "service_type_fa": "اینترنت پرسرعت شاتل",
        "support_tel": "021-91000000",
        "support_code": "91000000",
        "support_channel": "تماس با 021-91000000 یا پنل مای‌شاتل",
        "hashtags_fa": ["#شاتل", "#اینترنت", "#فیلترینگ", "#اینترنت_بین_الملل", "#کیفیت_اینترنت", "#سامانه_۱۹۵"],
    },
    "AS43754": {
        "asn": "AS43754",
        "short_en": "Asiatech",
        "name_en": "Asiatech",
        "name_fa": "آسیاتک",
        "legal_fa": "شرکت انتقال داده‌های آسیاتک",
        "service_type_fa": "اینترنت آسیاتک",
        "support_tel": "1544",
        "support_code": "1544",
        "support_channel": "تماس با 1544 یا سامانه امور مشترکین آسیاتک",
        "hashtags_fa": ["#آسیاتک", "#اینترنت", "#فیلترینگ", "#اینترنت_بین_الملل", "#کیفیت_اینترنت", "#سامانه_۱۹۵"],
    },
    "AS56402": {
        "asn": "AS56402",
        "short_en": "HiWEB",
        "name_en": "HiWEB",
        "name_fa": "های‌وب",
        "legal_fa": "شرکت داده‌گستر عصر نوین (های‌وب)",
        "service_type_fa": "اینترنت های‌وب",
        "support_tel": "1565",
        "support_code": "1565",
        "support_channel": "تماس با 1565 یا پورتال پشتیبانی های‌وب",
        "hashtags_fa": ["#های_وب", "#اینترنت", "#فیلترینگ", "#اینترنت_بین_الملل", "#کیفیت_اینترنت", "#سامانه_۱۹۵"],
    },
    "AS50810": {
        "asn": "AS50810",
        "short_en": "MobinNet",
        "name_en": "MobinNet",
        "name_fa": "مبین‌نت",
        "legal_fa": "شرکت ارتباطات مبین‌نت",
        "service_type_fa": "اینترنت TD-LTE مبین‌نت",
        "support_tel": "1575",
        "support_code": "1575",
        "support_channel": "تماس با 1575 یا پنل مای‌مبین‌نت",
        "hashtags_fa": ["#مبین_نت", "#اینترنت", "#فیلترینگ", "#اینترنت_بین_الملل", "#کیفیت_اینترنت", "#سامانه_۱۹۵"],
    },
    "AS16322": {
        "asn": "AS16322",
        "short_en": "ParsOnline",
        "name_en": "ParsOnline",
        "name_fa": "پارس‌آنلاین",
        "legal_fa": "شرکت پارس‌آنلاین",
        "service_type_fa": "اینترنت پارس‌آنلاین",
        "support_tel": "پشتیبانی رسمی پارس‌آنلاین",
        "support_code": "پشتیبانی اپراتور",
        "support_channel": "تیکت در پورتال رسمی پارس‌آنلاین",
        "hashtags_fa": ["#پارس_آنلاین", "#اینترنت", "#فیلترینگ", "#اینترنت_بین_الملل", "#کیفیت_اینترنت", "#سامانه_۱۹۵"],
    },
    "AS206065": {
        "asn": "AS206065",
        "short_en": "Zitel",
        "name_en": "Zitel",
        "name_fa": "زیتل",
        "legal_fa": "شرکت فرابرد داده‌های ایرانیان (زیتل)",
        "service_type_fa": "اینترنت ثابت بی‌سیم زیتل",
        "support_tel": "پشتیبانی رسمی زیتل",
        "support_code": "پشتیبانی اپراتور",
        "support_channel": "تیکت یا تماس با پشتیبانی رسمی زیتل",
        "hashtags_fa": ["#زیتل", "#اینترنت", "#فیلترینگ", "#اینترنت_بین_الملل", "#کیفیت_اینترنت", "#سامانه_۱۹۵"],
    },
    "AS42337": {
        "asn": "AS42337",
        "short_en": "Respina",
        "name_en": "Respina",
        "name_fa": "رسپینا",
        "legal_fa": "شرکت شبکه‌های ارتباطی رسپینا",
        "service_type_fa": "اینترنت سازمانی/تجاری رسپینا",
        "support_tel": "پشتیبانی NOC رسپینا",
        "support_code": "NOC",
        "support_channel": "ثبت تیکت رسمی در پورتال مشتریان رسپینا",
        "hashtags_fa": ["#رسپینا", "#اینترنت", "#فیلترینگ", "#اینترنت_بین_الملل", "#کیفیت_اینترنت", "#سامانه_۱۹۵"],
    },
    "AS49100": {
        "asn": "AS49100",
        "short_en": "Pishgaman",
        "name_en": "Pishgaman",
        "name_fa": "پیشگامان",
        "legal_fa": "شرکت پیشگامان توسعه ارتباطات",
        "service_type_fa": "اینترنت پیشگامان",
        "support_tel": "پشتیبانی رسمی پیشگامان",
        "support_code": "پشتیبانی اپراتور",
        "support_channel": "ثبت تیکت در پورتال رسمی پیشگامان",
        "hashtags_fa": ["#پیشگامان", "#اینترنت", "#فیلترینگ", "#اینترنت_بین_الملل", "#کیفیت_اینترنت", "#سامانه_۱۹۵"],
    },
    "AS25184": {
        "asn": "AS25184",
        "short_en": "Afranet",
        "name_en": "Afranet",
        "name_fa": "افرانت",
        "legal_fa": "شرکت افرانت",
        "service_type_fa": "اینترنت / دیتاسنتر افرانت",
        "support_tel": "پشتیبانی NOC افرانت",
        "support_code": "NOC",
        "support_channel": "ثبت تیکت در پورتال رسمی افرانت",
        "hashtags_fa": ["#افرانت", "#اینترنت", "#فیلترینگ", "#اینترنت_بین_الملل", "#کیفیت_اینترنت", "#سامانه_۱۹۵"],
    },
    "AS12880": {
        "asn": "AS12880",
        "short_en": "ITC",
        "name_en": "ITC / DCI",
        "name_fa": "شرکت ارتباطات زیرساخت / مخابرات",
        "legal_fa": "شرکت فناوری اطلاعات ایران / ارتباطات زیرساخت",
        "service_type_fa": "شبکه بالادست زیرساخت",
        "support_tel": "سامانه ۱۹۵",
        "support_code": "195",
        "support_channel": "ثبت شکایت در سامانه 195.cra.ir",
        "hashtags_fa": ["#اینترنت", "#فیلترینگ", "#اینترنت_بین_الملل", "#کیفیت_اینترنت", "#زیرساخت", "#سامانه_۱۹۵"],
    },
    "AS49666": {
        "asn": "AS49666",
        "short_en": "TIC",
        "name_en": "TIC Iran",
        "name_fa": "شرکت ارتباطات زیرساخت",
        "legal_fa": "شرکت ارتباطات زیرساخت",
        "service_type_fa": "دروازه بین‌الملل زیرساخت",
        "support_tel": "سامانه ۱۹۵",
        "support_code": "195",
        "support_channel": "ثبت شکایت در سامانه 195.cra.ir",
        "hashtags_fa": ["#اینترنت", "#فیلترینگ", "#اینترنت_بین_الملل", "#کیفیت_اینترنت", "#زیرساخت", "#سامانه_۱۹۵"],
    },
}

COMMON_HASHTAGS_FA = [
    "#اینترنت",
    "#فیلترینگ",
    "#اینترنت_بین_الملل",
    "#کیفیت_اینترنت",
    "#حقوق_مصرف_کننده",
    "#برنامه_نویسی",
    "#دواپس",
    "#شبکه",
    "#اینترنت_آزاد",
    "#زیرساخت",
    "#سامانه_۱۹۵",
    "#رگولاتوری",
    "#داکر",
    "#لینوکس",
]


def normalize_asn(raw_asn):
    if not raw_asn:
        return ""
    m = re.search(r"AS(\d+)", str(raw_asn), re.IGNORECASE)
    if m:
        return f"AS{m.group(1)}"
    s = str(raw_asn).strip()
    if s.isdigit():
        return f"AS{s}"
    return s.upper()


def resolve_operator(raw_asn, org_name="", override_name=None):
    asn = normalize_asn(raw_asn)
    if asn in OPERATORS:
        info = dict(OPERATORS[asn])
    else:
        clean_org = re.sub(r"^AS\d+\s*", "", str(org_name or "")).strip()
        short_en = override_name or (clean_org.split()[0] if clean_org else (asn or "ISP"))
        name_en = override_name or (clean_org or asn or "Unknown ISP")
        name_fa = override_name or (clean_org or "اپراتور اینترنت")
        info = {
            "asn": asn or "UNKNOWN-ASN",
            "short_en": short_en,
            "name_en": name_en,
            "name_fa": name_fa,
            "legal_fa": f"شرکت ارائه‌دهنده خدمات اینترنت ({name_fa})",
            "service_type_fa": f"سرویس اینترنت {name_fa}",
            "support_tel": "پشتیبانی رسمی اپراتور",
            "support_code": "پشتیبانی اپراتور",
            "support_channel": "ثبت تیکت رسمی در پورتال پشتیبانی اپراتور",
            "hashtags_fa": ["#اینترنت", "#فیلترینگ", "#اینترنت_بین_الملل", "#کیفیت_اینترنت", "#سامانه_۱۹۵"],
        }
    if override_name:
        info["short_en"] = override_name
        info["name_en"] = override_name
        info["name_fa"] = override_name
    merged_tags = []
    for tag in list(info["hashtags_fa"]) + COMMON_HASHTAGS_FA:
        if tag not in merged_tags:
            merged_tags.append(tag)
    info["all_hashtags_fa"] = merged_tags[:15]
    return info
