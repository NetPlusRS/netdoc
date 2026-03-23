"""
take_final.py — Zrzuty ekranu NetDoc w jasnym motywie.
"""
import asyncio
import sys
from pathlib import Path
from playwright.async_api import async_playwright

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

FLASK = "http://localhost"
GRAFANA = "http://localhost/grafana"
import os as _os
OUT = Path(_os.getenv("SCREENSHOTS_DIR", Path(__file__).parent.parent.parent / "screenshots"))
OUT.mkdir(parents=True, exist_ok=True)
VIEWPORT = {"width": 1440, "height": 900}

FONT_BLOCK_CSS = """
* { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important; }
"""


async def block_fonts(route):
    url = route.request.url
    if any(x in url for x in ['.woff', '.ttf', '.otf', 'fonts.gstatic', 'fonts.googleapis']):
        await route.abort()
    else:
        await route.continue_()


async def go(page, url, wait_ms=2500):
    await page.goto(url, wait_until="commit", timeout=30000)
    await page.wait_for_timeout(wait_ms)
    await page.evaluate(f"""() => {{
        document.documentElement.setAttribute('data-theme','light');
        try {{ localStorage.setItem('theme','light'); }} catch(e) {{}}
        var s = document.createElement('style');
        s.textContent = {repr(FONT_BLOCK_CSS)};
        document.head.appendChild(s);
        // Ukryj banner beta
        var b = document.getElementById('betaBanner');
        if (b) b.remove();
        // Rozwij quick panel w AI chat
        var qb = document.getElementById('quick-btns');
        var qt = document.getElementById('quick-toggle');
        if (qb) {{ qb.style.display = 'flex'; }}
        if (qt) {{ qt.classList.add('open'); }}
    }}""")
    await page.wait_for_timeout(800)


async def shot(page, name, full=False):
    path = OUT / f"{name}.png"
    await page.screenshot(path=str(path), full_page=full, timeout=120000)
    size = path.stat().st_size // 1024
    print(f"  [OK] {name}.png ({size} KB)")


def make_browser_args():
    return [
        "--disable-remote-fonts",
        "--font-render-hinting=none",
        "--disable-font-subpixel-positioning",
        "--no-sandbox",
    ]


async def flask_pages():
    print("\n=== Panel Admin (Flask) ===")
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=make_browser_args())
        ctx = await browser.new_context(viewport=VIEWPORT)
        ctx.set_default_timeout(30000)
        page = await ctx.new_page()
        await page.route("**/*", block_fonts)

        pages_list = [
            ("devices",     f"{FLASK}/devices",     2500),
            ("security",    f"{FLASK}/security",    2500),
            ("inventory",   f"{FLASK}/inventory",   2500),
            ("networks",    f"{FLASK}/networks",    2500),
            ("internet",    f"{FLASK}/internet",    3500),
            ("syslog",      f"{FLASK}/syslog",      3500),
            ("chat",        f"{FLASK}/chat",        2000),
        ]
        try:
            await go(page, f"{FLASK}/credentials", 1000)
            pages_list.insert(6, ("credentials", f"{FLASK}/credentials", 2500))
        except Exception:
            pass

        for name, url, wait in pages_list:
            try:
                await go(page, url, wait)
                # Syslog: kliknij Warn+ zeby ukryc HTTP garbage (severity 5=NOTICE)
                if name == "syslog":
                    warn_btn = page.locator("#severityFilter button[data-sev='4']")
                    if await warn_btn.count() > 0:
                        await warn_btn.click()
                        await page.wait_for_timeout(2500)
                await shot(page, name)
            except Exception as e:
                print(f"  [SKIP] {name}: {e}")

        await ctx.close()
        await browser.close()


async def ai_chat():
    print("\n=== AI Chat ===")
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=make_browser_args())
        ctx = await browser.new_context(viewport=VIEWPORT)
        ctx.set_default_timeout(90000)
        page = await ctx.new_page()
        await page.route("**/*", block_fonts)

        input_selectors = ["#chatInput", "textarea.chat-input", "textarea", "input[type='text']"]

        async def find_input():
            for sel in input_selectors:
                el = page.locator(sel)
                if await el.count() > 0:
                    return el.first
            return None

        # Pytanie 1: podatności
        try:
            await go(page, f"{FLASK}/chat", 1500)
            inp = await find_input()
            if inp:
                print("  Pytanie o podatności wysłane (czekam 50s)...")
                await inp.fill("Podaj mi tabelę urządzeń z krytycznymi podatnościami: IP, model, opis podatności.")
                await page.keyboard.press("Enter")
                await page.wait_for_timeout(50000)
                await shot(page, "ai_chat_security")
            else:
                print("  [WARN] brak pola input")
        except Exception as e:
            print(f"  [ERROR] ai_chat_security: {e}")

        # Pytanie 2: MOXA
        try:
            await go(page, f"{FLASK}/chat", 1500)
            inp2 = await find_input()
            if inp2:
                print("  Pytanie o MOXA wysłane (czekam 50s)...")
                await inp2.fill(
                    "Opisz urządzenie 192.168.5.138 (MOXA NPort W2150A). "
                    "Co to za sprzęt, jakie ryzyko niesie jako konwerter RS-232 w sieci OT "
                    "i co powinienem zrobić?"
                )
                await page.keyboard.press("Enter")
                await page.wait_for_timeout(50000)
                await shot(page, "ai_device_moxa")
        except Exception as e:
            print(f"  [ERROR] ai_device_moxa: {e}")

        await ctx.close()
        await browser.close()


async def grafana():
    import base64
    print("\n=== Grafana ===")
    auth = "Basic " + base64.b64encode(b"admin:netdoc").decode()
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
        ctx = await browser.new_context(viewport=VIEWPORT)
        ctx.set_default_timeout(15000)
        page = await ctx.new_page()

        # Login przez formularz
        print("  Logowanie...")
        await page.goto(f"{GRAFANA}/login", wait_until="commit", timeout=15000)
        await page.wait_for_timeout(1500)
        await page.fill("input[name='user']", "admin")
        await page.fill("input[name='password']", "netdoc")
        await page.click("button[type='submit']")
        await page.wait_for_timeout(3000)

        # Lista dashboardow przez API (z auth header)
        resp = await page.request.get(
            f"{GRAFANA}/api/search?type=dash-db&limit=50",
            headers={"Accept": "application/json", "Authorization": auth},
            timeout=15000,
        )
        try:
            dashboards = await resp.json()
            if not isinstance(dashboards, list):
                dashboards = []
        except Exception:
            dashboards = []
        print(f"  Znaleziono {len(dashboards)} dashboardow")

        name_map = {
            "siec": "grafana_main", "network": "grafana_main",
            "przegl": "grafana_main", "overview": "grafana_main",
            "bezpiecze": "grafana_security", "security": "grafana_security",
            "worker": "grafana_workers",
            "internet": "grafana_internet", "wan": "grafana_internet",
            "syslog": "grafana_syslog", "logi": "grafana_syslog", "log": "grafana_syslog",
        }

        taken = set()
        for dash in dashboards:
            title = (dash.get("title") or "").lower()
            url_path = dash.get("url", "")
            fname = None
            for key, target in name_map.items():
                if key in title and target not in taken:
                    fname = target
                    taken.add(target)
                    break
            if not fname:
                continue
            url = f"{GRAFANA}{url_path}?kiosk=1"
            print(f"  '{dash.get('title')}' -> {fname}.png")
            try:
                await page.goto(url, wait_until="commit", timeout=15000)
                await page.wait_for_timeout(7000)
                path = str(OUT / f"{fname}.png")
                await page.screenshot(path=path, full_page=False, timeout=60000)
                size = Path(path).stat().st_size // 1024
                print(f"    [OK] {fname}.png ({size} KB)")
            except Exception as e:
                print(f"    [WARN] {fname}: {e}")

        await ctx.close()
        await browser.close()


async def main():
    await flask_pages()
    await ai_chat()
    await grafana()

    print(f"\n=== Gotowe! ===")
    for f in sorted(OUT.glob("*.png")):
        size = f.stat().st_size // 1024
        print(f"  {f.name} ({size} KB)")


if __name__ == "__main__":
    asyncio.run(main())
