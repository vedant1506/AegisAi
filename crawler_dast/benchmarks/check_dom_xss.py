import asyncio
from playwright.async_api import async_playwright

async def check_dom_xss():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        test_payload = '<iframe src="javascript:alert(1)">'
        test_url = f'http://localhost:3000/#/search?q={test_payload}'
        await page.goto(test_url, wait_until='networkidle')
        await page.wait_for_timeout(1500)
        
        content = await page.content()
        print('Target URL:', page.url)
        print('Payload in DOM HTML:', test_payload in content)
        iframes = await page.locator('iframe').count()
        print('Iframes count in DOM:', iframes)
        
        # Check any elements showing the payload
        heading = await page.locator('.mat-headline, .heading, mat-card-title, #searchQuery').all_text_contents()
        print('Headings in page:', heading)

        # Also test with a safe probe marker like <span id="aegis-xss-probe">xss</span>
        probe_payload = '<span id="aegis-xss-marker">xss-verified</span>'
        test_url2 = f'http://localhost:3000/#/search?q={probe_payload}'
        await page.goto(test_url2, wait_until='networkidle')
        await page.wait_for_timeout(1500)
        marker_count = await page.locator('#aegis-xss-marker').count()
        print(f"Probe marker '#aegis-xss-marker' count in DOM: {marker_count}")
        
        await browser.close()

if __name__ == '__main__':
    asyncio.run(check_dom_xss())
