import pathlib

APP_NAME = "ShitNet"
CLI_NAME = "shitnet"
BRAND = "V7lthronyx"
AUTHOR = "Aiden Azad"
REPO_URL = "https://github.com/v7lthronyx1/shitnet"
__version__ = "1.0.0"

PACKAGE_DIR = pathlib.Path(__file__).resolve().parent
FONTS_DIR = PACKAGE_DIR / "fonts"


def font_face_css(relative_prefix=None):
    mappings = [
        ("Vazirmatn FD", "Vazirmatn-FD-Regular.ttf", 400),
        ("Vazirmatn FD", "Vazirmatn-FD-Medium.ttf", 500),
        ("Vazirmatn FD", "Vazirmatn-FD-Bold.ttf", 700),
        ("Vazirmatn FD", "Vazirmatn-FD-ExtraBold.ttf", 800),
        ("Vazirmatn FD", "Vazirmatn-FD-Black.ttf", 900),
        ("Vazirmatn", "Vazirmatn-Regular.ttf", 400),
        ("Vazirmatn", "Vazirmatn-Bold.ttf", 700),
        ("JetBrains Mono", "JetBrainsMono-Regular.ttf", 400),
        ("JetBrains Mono", "JetBrainsMono-Bold.ttf", 700),
    ]
    rules = []
    for family, fname, weight in mappings:
        fpath = FONTS_DIR / fname
        if fpath.exists():
            src_url = f"{relative_prefix}{fname}" if relative_prefix is not None else fpath.as_uri()
            rules.append(
                f"@font-face {{\n"
                f"  font-family: '{family}';\n"
                f"  src: url('{src_url}') format('truetype');\n"
                f"  font-weight: {weight};\n"
                f"  font-style: normal;\n"
                f"}}"
            )
    return "\n".join(rules)
