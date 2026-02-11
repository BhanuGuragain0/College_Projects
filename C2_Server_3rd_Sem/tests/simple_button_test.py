#!/usr/bin/env python3
"""
Simple Button Test Script
Tests if dashboard buttons exist in HTML

Usage:
    python tests/simple_button_test.py
"""

import sys
from pathlib import Path

def test_button_html():
    """Test if buttons exist in HTML"""
    print("🧪 Testing Dashboard Button HTML...")
    
    # Read dashboard HTML
    html_path = Path(__file__).parent.parent / "dashboard" / "index.html"
    if not html_path.exists():
        print(f"❌ HTML file not found: {html_path}")
        assert False, f"HTML file not found: {html_path}"
    
    with open(html_path, 'r') as f:
        html_content = f.read()
    
    
    # Check for button elements
    required_buttons = [
        'btn-new-command',
        'btn-payload-builder', 
        'btn-file-manager',
        'btn-cert-viewer',
        'btn-batch-command'
    ]
    
    missing_buttons = []
    found_buttons = []
    
    for button_id in required_buttons:
        if f'id="{button_id}"' in html_content:
            found_buttons.append(button_id)
        else:
            missing_buttons.append(button_id)
    
    print(f"✅ Found buttons: {found_buttons}")
    
    if missing_buttons:
        print(f"❌ Missing buttons: {missing_buttons}")
        assert False, f"Missing buttons: {missing_buttons}"
    
    print("✅ All required buttons found in HTML")
    
    # Check if JavaScript files exist
    static_path = Path(__file__).parent.parent / "dashboard" / "static"
    js_files = ["app.js", "state.js", "main.css"]
    
    missing_files = []
    for js_file in js_files:
        file_path = static_path / js_file
        if not file_path.exists():
            missing_files.append(js_file)
    
    if missing_files:
        print(f"❌ Missing static files: {missing_files}")
        assert False, f"Missing static files: {missing_files}"
    
    print("✅ All static files exist")
    
    # Check if JavaScript contains event binding
    app_js_path = static_path / "app.js"
    with open(app_js_path, 'r') as f:
        js_content = f.read()
    
    # Check for event binding code
    event_binding_patterns = [
        "addEventListener('click'",
        "bindEvents()",
        "bindButtonEvent('btn-new-command'",
        "bindButtonEvent('btn-payload-builder'",
        "bindButtonEvent('btn-file-manager'",
        "bindButtonEvent('btn-cert-viewer'",
        "bindButtonEvent('btn-batch-command'"
    ]
    
    missing_patterns = []
    for pattern in event_binding_patterns:
        if pattern not in js_content:
            missing_patterns.append(pattern)
    
    if missing_patterns:
        print(f"❌ Missing JavaScript patterns: {missing_patterns}")
        assert False, f"Missing JavaScript patterns: {missing_patterns}"
    
    print("✅ JavaScript event binding code found")
    
if __name__ == "__main__":
    try:
        test_button_html()
        print("\n🎉 Button HTML test PASSED")
        print("\n📝 Next steps to debug button clicks:")
        print("   1. Start dashboard: python launcher.py dashboard --host 127.0.0.1 --port 8080 --token \"\"")
        print("   2. Open browser: http://127.0.0.1:8080")
        print("   3. Open Developer Tools (F12)")
        print("   4. Check Console tab for debugging messages")
        print("   5. Look for messages like:")
        print("      - '🔧 Binding events...'")
        print("      - '✅ [button] button bound'")
        print("      - '🔧 [button] button clicked!'")
        print("   6. Try clicking buttons and watch console output")
        sys.exit(0)
    except AssertionError as e:
        print(f"\n❌ Button HTML test FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Test execution failed: {e}")
        sys.exit(2)
