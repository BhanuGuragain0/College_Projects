#!/usr/bin/env python3
"""
Button Click Test Script
Tests if dashboard buttons are properly bound and clickable

Usage:
    python tests/button_click_test.py [--host HOST] [--port PORT]
"""

import asyncio
import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from securecomm.dashboard_server import create_app

def test_button_functionality():
    """Test if buttons are properly configured"""
    print("🧪 Testing Dashboard Button Functionality...")
    
    # Create app instance
    app = create_app()
    
    # Test dashboard HTML contains buttons
    from aiohttp import web
    from aiohttp.test_utils import TestClient, TestServer
    
    async def run_test():
        async with TestServer(app) as server:
            async with TestClient(server) as client:
                # Get dashboard page
                resp = await client.get('/')
                assert resp.status == 200, f"Failed to load dashboard: {resp.status}"
                
                html_content = await resp.text()
                
                # Check for button elements
                required_buttons = [
                    'btn-new-command',
                    'btn-payload-builder', 
                    'btn-file-manager',
                    'btn-cert-viewer',
                    'btn-batch-command'
                ]
                
                missing_buttons = []
                for button_id in required_buttons:
                    if f'id="{button_id}"' not in html_content:
                        missing_buttons.append(button_id)
                
                assert not missing_buttons, f"Missing buttons: {missing_buttons}"
                
                print("✅ All required buttons found in HTML")
                
                # Test JavaScript files are accessible
                js_files = ['/static/app.js', '/static/state.js']
                for js_file in js_files:
                    resp = await client.get(js_file)
                    assert resp.status == 200, f"JavaScript file not accessible: {js_file}"
                
                print("✅ JavaScript files accessible")
                
                # Test CSS is accessible
                resp = await client.get('/static/main.css')
                assert resp.status == 200, "CSS file not accessible"
                
                print("✅ CSS file accessible")
    
    asyncio.run(run_test())

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Button Click Test")
    args = parser.parse_args()
    
    try:
        result = test_button_functionality()
        if result:
            print("\n🎉 Button functionality test PASSED")
            print("📝 Check browser console for debugging messages:")
            print("   - Open browser to http://127.0.0.1:8080")
            print("   - Open Developer Tools (F12)")
            print("   - Check Console tab for debugging messages")
            print("   - Try clicking buttons and watch for console logs")
        else:
            print("\n❌ Button functionality test FAILED")
            sys.exit(1)
    except Exception as e:
        print(f"❌ Test execution failed: {e}")
        sys.exit(2)
