"""Retake syslog.png z filtrem Warn+ (ukrywa HTTP garbage)."""
import asyncio, sys
from pathlib import Path
from playwright.async_api import async_playwright

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FLASK = "http://localhost"
OUT = Path("C:/Users/Yeszie/OneDrive/netdoc-www/screenshots")
VIEWPORT = {"width": 1440, "height": 900}

FONT_CSS = "* { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important; }"

async def block_fonts(route):
    url = route.request.url
    if any(x in url for x in ['.woff', '.ttf', '.otf', 'fonts.gstatic', 'fonts.googleapis']):
        await route.abort()
    else:
        await route.continue_()

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=[
            "--disable-remote-fonts", "--no-sandbox"
        ])
        ctx = await browser.new_context(viewport=VIEWPORT)
        ctx.set_default_timeout(15000)
        page = await ctx.new_page()
        await page.route("**/*", block_fonts)

        # Navigate to syslog
        await page.goto(f"{FLASK}/syslog", wait_until="commit", timeout=15000)
        await page.wait_for_timeout(2000)

        # Set light theme
        await page.evaluate(f"""() => {{
            document.documentElement.setAttribute('data-theme','light');
            try {{ localStorage.setItem('theme','light'); }} catch(e) {{}}
            var s = document.createElement('style');
            s.textContent = {repr(FONT_CSS)};
            document.head.appendChild(s);
        }}""")
        await page.wait_for_timeout(500)

        # Click "Warn+" filter (severity <= 4, hides NOTICE=5 HTTP garbage)
        warn_btn = page.locator("#severityFilter button[data-sev='4']")
        if await warn_btn.count() > 0:
            await warn_btn.click()
            print("  Kliknieto Warn+ (severity<=4)")
            await page.wait_for_timeout(3000)  # czekaj na refresh danych
        else:
            print("  [WARN] Nie znaleziono przycisku Warn+")

        path = str(OUT / "syslog.png")
        await page.screenshot(path=path, full_page=False, timeout=30000)
        size = Path(path).stat().st_size // 1024
        print(f"  [OK] syslog.png ({size} KB)")

        await ctx.close()
        await browser.close()

asyncio.run(main())
