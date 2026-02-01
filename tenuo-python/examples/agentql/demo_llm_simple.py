#!/usr/bin/env python3
"""
Simplified LLM demo that works around AgentQL Python 3.14 issues.
Uses Playwright directly for navigation, AgentQL only for element queries.
"""

import asyncio
import os
import sys
from tenuo import Warrant, SigningKey, OneOf, UrlPattern
import agentql
from playwright.async_api import async_playwright


async def demo():
    print("Using real LLM + real browser (workaround mode)")

    user_key = SigningKey.generate()
    agent_key = SigningKey.generate()

    # Create warrant for the agent (would be used in real integration)
    _warrant = (
        Warrant.mint_builder()
        .capability("navigate", url=UrlPattern("https://duckduckgo.com/*"))
        .capability("fill", element=OneOf(["search_box"]))
        .holder(agent_key.public_key)
        .ttl(3600)
        .mint(user_key)
    )

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        pw_page = await browser.new_page()

        # Wrap with AgentQL
        page = agentql.wrap(pw_page)

        # Navigate using Playwright (bypasses AgentQL's wait issues)
        await pw_page.goto("https://duckduckgo.com")
        await pw_page.wait_for_load_state("networkidle")

        print("✅ Page loaded")

        # Now use AgentQL query
        try:
            result = await page.query_elements("{search_box}")
            print(f"✅ Found element: {result}")

            if result and hasattr(result, "search_box"):
                await result.search_box.fill("AI security")
                print("✅ Filled search box")
        except Exception as e:
            print(f"❌ AgentQL error: {e}")

        await browser.close()


if __name__ == "__main__":
    if not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"):
        print("Error: Set OPENAI_API_KEY or ANTHROPIC_API_KEY")
        sys.exit(1)

    asyncio.run(demo())
