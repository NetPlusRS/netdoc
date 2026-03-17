"""
take_grafana.py — Grafana screenshots z poprawnym logowaniem przez formularz.
"""
import asyncio
import base64
import sys
from pathlib import Path
from playwright.async_api import async_playwright

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

GRAFANA = "http://localhost:3000"
OUT = Path("C:/Users/Yeszie/OneDrive/netdoc-www/screenshots")
VIEWPORT = {"width": 1440, "height": 900}
AUTH = "Basic " + base64.b64encode(b"admin:netdoc").decode()


async def main():
    print("\n=== Grafana ===")
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
        ctx = await browser.new_context(viewport=VIEWPORT)
        ctx.set_default_timeout(15000)
        page = await ctx.new_page()

        # Logowanie przez formularz
        print("  Logowanie...")
        await page.goto(f"{GRAFANA}/login", wait_until="commit", timeout=15000)
        await page.wait_for_timeout(1500)

        await page.fill("input[name='user']", "admin")
        await page.fill("input[name='password']", "netdoc")
        await page.click("button[type='submit']")
        await page.wait_for_timeout(3000)

        # Sprawdz URL po logowaniu — jesli nadal /login, blad
        current = page.url
        print(f"  URL po logowaniu: {current}")

        # Kliknij Skip tylko jesli istnieje i nie jest poza viewport
        try:
            skip = page.locator("a[href*='skip'], button:text-matches('skip', 'i'), a:text-matches('skip', 'i')")
            if await skip.count() > 0:
                await skip.first.click(timeout=3000, force=True)
                await page.wait_for_timeout(1000)
        except Exception:
            pass

        # Pobierz liste dashboardow przez Grafana API (z session cookies)
        resp = await page.request.get(
            f"{GRAFANA}/api/search?type=dash-db&limit=50",
            headers={"Accept": "application/json"},
            timeout=15000,
        )
        status = resp.status
        print(f"  API /search status: {status}")
        raw = await resp.text()
        print(f"  API response (150 chars): {raw[:150]}")

        try:
            dashboards = await resp.json()
            if not isinstance(dashboards, list):
                print(f"  [WARN] Nieoczekiwany typ odpowiedzi API: {type(dashboards)}, wartosc: {dashboards!r}")
                dashboards = []
        except Exception as e:
            print(f"  [WARN] JSON parse error: {e}")
            dashboards = []

        print(f"  Znaleziono {len(dashboards)} dashboardow")
        for d in dashboards:
            print(f"    - {d.get('title')}")

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
                fname_fallback = "grafana_" + title.replace(" ", "_").replace("/", "_")[:30]
                print(f"  [SKIP] '{dash.get('title')}' — brak mapowania (byloby: {fname_fallback})")
                continue

            url = f"{GRAFANA}{url_path}?kiosk=1"
            print(f"  '{dash.get('title')}' -> {fname}.png")
            try:
                await page.goto(url, wait_until="commit", timeout=15000)
                await page.wait_for_timeout(7000)  # czekaj na panele
                path = str(OUT / f"{fname}.png")
                await page.screenshot(path=path, full_page=False, timeout=60000)
                size = Path(path).stat().st_size // 1024
                print(f"    [OK] {fname}.png ({size} KB)")
            except Exception as e:
                print(f"    [WARN] {fname}: {e}")

        await ctx.close()
        await browser.close()

    print("\nGotowe! Grafana screenshots:")
    for f in sorted(OUT.glob("grafana*.png")):
        size = f.stat().st_size // 1024
        print(f"  {f.name} ({size} KB)")


if __name__ == "__main__":
    asyncio.run(main())
