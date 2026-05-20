from fastapi import APIRouter
from fastapi.responses import FileResponse
from playwright.async_api import async_playwright

import os
import base64

router = APIRouter()

BADGE_DIR = "generated_badges"
os.makedirs(BADGE_DIR, exist_ok=True)


@router.get("/pqc/badge/{asset_id}")
async def generate_badge(
    asset_id: str,
    domain: str = "quantumsentinel.ai"
):

    # HTML TEMPLATE
    html_path = "templates/pqc_badge.html"

    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()

    # DOMAIN
    html = html.replace("{{DOMAIN}}", domain)

    # IMAGE TO BASE64
    image_path = "templates/badge_base.png"

    with open(image_path, "rb") as img:
        encoded = base64.b64encode(img.read()).decode()

    image_data = f"data:image/png;base64,{encoded}"

    # REPLACE IMAGE
    html = html.replace("{{BADGE_IMAGE}}", image_data)

    # OUTPUT
    output_path = f"{BADGE_DIR}/{asset_id}.png"

    async with async_playwright() as p:

        browser = await p.chromium.launch()

        page = await browser.new_page(
            viewport={
                "width": 340,
                "height": 340
            }
        )

        await page.set_content(
            html,
            wait_until="load"
        )

        await page.wait_for_timeout(1000)

        await page.screenshot(
            path=output_path,
            omit_background=True
        )

        await browser.close()

    return FileResponse(
        output_path,
        media_type="image/png",
        filename=f"{domain}_pqc_badge.png",
    )