#!/usr/bin/env python3
"""
Test script to find what elements AgentQL actually detects on duckduckgo.com
Run this to see what element names to use in the demo.
"""

import asyncio
import agentql
from playwright.async_api import async_playwright

async def test_elements():
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=False)
        playwright_page = await browser.new_page()
        page = agentql.wrap(playwright_page)
        
        print("Navigating to duckduckgo.com...")
        await page.goto("https://duckduckgo.com")
        
        # Give page time to load
        await playwright_page.wait_for_load_state('networkidle')
        
        print("\nTrying AgentQL query syntax:\n")
        
        # AgentQL uses GraphQL-style queries
        query = """
        {
            search_box
            search_button
        }
        """
        
        try:
            print(f"Query: {query}")
            response = await page.query_elements(query)
            print(f"✅ Response: {response}")
            print(f"   search_box: {response.search_box if hasattr(response, 'search_box') else 'Not found'}")
            print(f"   search_button: {response.search_button if hasattr(response, 'search_button') else 'Not found'}")
        except Exception as e:
            print(f"❌ Error: {type(e).__name__}: {e}")
        
        # Try simpler query
        print("\nTrying simpler query:")
        try:
            element = await page.query_elements("{search_box}")
            print(f"✅ Found search_box: {element}")
        except Exception as e:
            print(f"❌ Error: {type(e).__name__}: {e}")
        
        await browser.close()

if __name__ == "__main__":
    asyncio.run(test_elements())
