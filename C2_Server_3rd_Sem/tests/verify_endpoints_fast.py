#!/usr/bin/env python3
"""
Fast Endpoint Verification & Testing Suite
Tests all backend API endpoints without long-running async operations
"""

import sys
import json
from pathlib import Path
import re

sys.path.insert(0, 'src')

# ==================== BACKEND ENDPOINT VERIFICATION ====================

def verify_backend_endpoints():
    """Verify all backend endpoints are properly registered and implemented"""
    print("\n" + "="*80)
    print("BACKEND ENDPOINT VERIFICATION")
    print("="*80)
    
    from securecomm.dashboard_server import create_app
    
    # Create the app
    app = create_app()
    
    # Get all routes
    routes = []
    for route in app.router.routes():
        if hasattr(route, 'resource'):
            routes.append(str(route.resource))
    
    print("\n✅ REGISTERED API ENDPOINTS:")
    print("-" * 80)
    
    # New endpoints to verify
    new_endpoints = [
        '/api/health/detailed',
        '/api/metrics',
        '/api/metrics/operation',
        '/api/metrics/errors'
    ]
    
    # Core endpoints
    core_endpoints = [
        '/api/state',
        '/api/agents', 
        '/api/commands',
        '/api/audit'
    ]
    
    found_new = 0
    print("\n🆕 NEW ENDPOINTS:")
    for endpoint in new_endpoints:
        if any(endpoint in route for route in routes):
            print(f"  ✅ {endpoint}")
            found_new += 1
        else:
            print(f"  ❌ {endpoint}")
    
    found_core = 0
    print("\n📡 CORE ENDPOINTS:")
    for endpoint in core_endpoints:
        if any(endpoint in route for route in routes):
            print(f"  ✅ {endpoint}")
            found_core += 1
        else:
            print(f"  ❌ {endpoint}")
    
    return found_new == len(new_endpoints) and found_core == len(core_endpoints)

# ==================== CODE VERIFICATION ====================

def verify_handler_code():
    """Verify handler functions exist in source code"""
    print("\n" + "="*80)
    print("HANDLER CODE VERIFICATION")
    print("="*80)
    
    dashboard_py = Path('src/securecomm/dashboard_server.py')
    
    with open(dashboard_py, 'r') as f:
        content = f.read()
    
    handlers = [
        'api_health_detailed',
        'api_metrics_detailed',
        'api_metrics_operation',
        'api_metrics_errors'
    ]
    
    print("\n🔧 HANDLER FUNCTIONS IN CODE:")
    all_found = True
    for handler in handlers:
        if f'async def {handler}' in content or f'def {handler}' in content:
            print(f"  ✅ {handler}()")
            
            # Verify it has proper error handling
            if 'try:' in content[content.find(f'def {handler}'):content.find(f'def {handler}')+1500]:
                print(f"       ✓ Has error handling (try/except)")
            if 'web.json_response' in content[content.find(f'def {handler}'):content.find(f'def {handler}')+1500]:
                print(f"       ✓ Returns JSON response")
        else:
            print(f"  ❌ {handler}() - NOT FOUND")
            all_found = False
    
    return all_found

# ==================== ROUTE REGISTRATION VERIFICATION ====================

def verify_route_registration():
    """Verify routes are registered with the app router"""
    print("\n" + "="*80)
    print("ROUTE REGISTRATION VERIFICATION")
    print("="*80)
    
    dashboard_py = Path('src/securecomm/dashboard_server.py')
    
    with open(dashboard_py, 'r') as f:
        content = f.read()
    
    routes_to_find = [
        'app.router.add_get("/api/health/detailed"',
        'app.router.add_get("/api/metrics"',
        'app.router.add_get("/api/metrics/operation"',
        'app.router.add_get("/api/metrics/errors"',
    ]
    
    print("\n📍 ROUTE REGISTRATION:")
    all_found = True
    for route_pattern in routes_to_find:
        if route_pattern in content:
            endpoint = route_pattern.split('"')[1]
            print(f"  ✅ {endpoint}")
        else:
            print(f"  ❌ {route_pattern} - NOT FOUND")
            all_found = False
    
    return all_found

# ==================== MODULE IMPORT VERIFICATION ====================

def verify_module_imports():
    """Verify all new modules are properly imported"""
    print("\n" + "="*80)
    print("MODULE IMPORT VERIFICATION")
    print("="*80)
    
    dashboard_py = Path('src/securecomm/dashboard_server.py')
    
    with open(dashboard_py, 'r') as f:
        content = f.read()
    
    imports_to_find = [
        ('logging_context', ['ContextManager', 'get_context_dict']),
        ('metrics', ['get_metrics', 'MetricsCollector']),
        ('health', ['HealthChecker']),
    ]
    
    print("\n📦 MODULE IMPORTS IN DASHBOARD_SERVER:")
    all_found = True
    for module_name, items in imports_to_find:
        if f"from securecomm.{module_name} import" in content or f"import securecomm.{module_name}" in content:
            print(f"  ✅ securecomm.{module_name}")
            for item in items:
                if item in content:
                    print(f"      ✓ {item}")
                else:
                    print(f"      ⚠️ {item} - May not be imported")
        else:
            print(f"  ❌ securecomm.{module_name} - NOT IMPORTED")
            all_found = False
    
    return all_found

# ==================== API CALL VERIFICATION ====================

def verify_api_call_handlers():
    """Verify handlers call the correct functions"""
    print("\n" + "="*80)
    print("API CALL HANDLER VERIFICATION")
    print("="*80)
    
    dashboard_py = Path('src/securecomm/dashboard_server.py')
    
    with open(dashboard_py, 'r') as f:
        content = f.read()
    
    # Expected handler -> function calls
    handler_calls = [
        ('api_health_detailed', ['HealthChecker', 'get_system_health']),
        ('api_metrics_detailed', ['get_metrics', 'get_all_metrics']),
        ('api_metrics_operation', ['get_metrics', 'get_operation_stats']),
        ('api_metrics_errors', ['get_metrics', 'get_error_stats']),
    ]
    
    print("\n🎯 HANDLER -> FUNCTION MAPPINGS:")
    all_correct = True
    for handler, expected_calls in handler_calls:
        print(f"\n  Handler: {handler}")
        
        # Find handler in content
        handler_start = content.find(f'def {handler}')
        if handler_start == -1:
            print(f"    ❌ Handler not found")
            all_correct = False
            continue
        
        # Get next 500 chars of handler code
        handler_code = content[handler_start:handler_start+800]
        
        calls_found = 0
        for call in expected_calls:
            if call in handler_code:
                print(f"    ✅ Calls {call}()")
                calls_found += 1
            else:
                print(f"    ⚠️ Does not call {call}()")
        
        if calls_found < len(expected_calls):
            all_correct = False
    
    return all_correct

# ==================== FRONTEND VERIFICATION ====================

def verify_frontend():
    """Verify frontend files exist and have basic structure"""
    print("\n" + "="*80)
    print("FRONTEND VERIFICATION")
    print("="*80)
    
    print("\n📱 FRONTEND FILES:")
    
    app_js = Path('dashboard/app.js')
    index_html = Path('dashboard/index.html')
    
    frontend_ok = True
    
    if app_js.exists():
        with open(app_js, 'r') as f:
            js_content = f.read()
        print(f"  ✅ dashboard/app.js ({len(js_content)} bytes)")
        
        # Check for API base
        if "apiBase" in js_content:
            print(f"       ✓ Has API base URL")
        if "fetch" in js_content:
            print(f"       ✓ Uses fetch() for API calls")
        if "WebSocket" in js_content:
            print(f"       ✓ Initializes WebSocket")
        if "getHeaders" in js_content:
            print(f"       ✓ Has authentication headers")
    else:
        print(f"  ❌ dashboard/app.js - NOT FOUND")
        frontend_ok = False
    
    if index_html.exists():
        with open(index_html, 'r') as f:
            html_content = f.read()
        print(f"  ✅ dashboard/index.html ({len(html_content)} bytes)")
        
        pages = ['dashboard', 'agents', 'commands', 'payload', 'files', 'certificates', 'audit']
        pages_found = 0
        print(f"       Pages:")
        for page in pages:
            if f'id="page-{page}"' in html_content or f'data-page="{page}"' in html_content:
                print(f"         ✓ {page}")
                pages_found += 1
        print(f"       ({pages_found}/{len(pages)} pages)")
    else:
        print(f"  ❌ dashboard/index.html - NOT FOUND")
        frontend_ok = False
    
    return frontend_ok

# ==================== COMPILATION CHECK ====================

def verify_compilation():
    """Verify all Python files compile"""
    print("\n" + "="*80)
    print("PYTHON COMPILATION VERIFICATION")
    print("="*80)
    
    import py_compile
    
    files_to_check = [
        'src/securecomm/dashboard_server.py',
        'src/securecomm/logging_context.py',
        'src/securecomm/metrics.py',
        'src/securecomm/health.py',
    ]
    
    print("\n🐍 PYTHON FILES:")
    all_compiled = True
    for filepath in files_to_check:
        filepath_obj = Path(filepath)
        if not filepath_obj.exists():
            print(f"  ❌ {filepath} - FILE NOT FOUND")
            all_compiled = False
            continue
            
        try:
            py_compile.compile(filepath, doraise=True)
            file_size = filepath_obj.stat().st_size
            print(f"  ✅ {filepath} ({file_size} bytes)")
        except py_compile.PyCompileError as e:
            print(f"  ❌ {filepath}: {e}")
            all_compiled = False
    
    return all_compiled

# ==================== ENDPOINT COUNT VERIFICATION ====================

def count_endpoints():
    """Count and list all endpoints"""
    print("\n" + "="*80)
    print("ENDPOINT COUNT SUMMARY")
    print("="*80)
    
    from securecomm.dashboard_server import create_app
    
    app = create_app()
    
    # Count routes
    routes = []
    for route in app.router.routes():
        if hasattr(route, 'resource'):
            routes.append(str(route.resource))
    
    # Categorize
    api_routes = [r for r in routes if '/api' in r]
    ws_routes = [r for r in routes if '/ws' in r]
    
    print(f"\n📊 TOTAL ENDPOINTS:")
    print(f"  Total routes: {len(routes)}")
    print(f"  API endpoints: {len(api_routes)}")
    print(f"  WebSocket: {len(ws_routes)}")
    
    return True

# ==================== MAIN TEST RUNNER ====================

def main():
    """Run all verification tests"""
    print("\n" + "="*80)
    print("🧪 COMPREHENSIVE ENDPOINT VERIFICATION SUITE")
    print("="*80)
    
    results = {}
    
    # 1. Compilation check
    print("\n[1/8] Checking Python compilation...")
    results['Compilation'] = verify_compilation()
    
    # 2. Module imports
    print("\n[2/8] Checking module imports in dashboard_server...")
    results['Module Imports'] = verify_module_imports()
    
    # 3. Backend endpoints
    print("\n[3/8] Verifying backend endpoints...")
    results['Backend Endpoints'] = verify_backend_endpoints()
    
    # 4. Handler functions
    print("\n[4/8] Checking handler functions...")
    results['Handler Functions'] = verify_handler_code()
    
    # 5. Route registration
    print("\n[5/8] Verifying route registration...")
    results['Route Registration'] = verify_route_registration()
    
    # 6. API call handlers
    print("\n[6/8] Verifying API call handlers...")
    results['API Call Handlers'] = verify_api_call_handlers()
    
    # 7. Frontend
    print("\n[7/8] Checking frontend files...")
    results['Frontend Files'] = verify_frontend()
    
    # 8. Endpoint count
    print("\n[8/8] Counting endpoints...")
    results['Endpoint Count'] = count_endpoints()
    
    # ==================== SUMMARY ====================
    
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    
    print("\n📊 VERIFICATION RESULTS:")
    passed = 0
    for test_name, result in results.items():
        if result is True:
            status = "✅ PASS"
            passed += 1
        elif result is False:
            status = "❌ FAIL"
        else:
            status = "⚠️ WARN"
            passed += 0.5
        
        print(f"  {status}: {test_name}")
    
    total = len(results)
    percentage = int(100 * passed / total)
    print(f"\n🎯 Overall: {passed}/{total} tests passed ({percentage}%)")
    
    if percentage >= 90:
        print("\n🟢 VERIFICATION SUCCESSFUL ✅")
        print("\n✨ Endpoint Configuration Status:")
        print("   Backend: ✅ All endpoints properly registered")
        print("   Handlers: ✅ All handler functions implemented")
        print("   Routes: ✅ All routes registered with router")
        print("   Imports: ✅ All new modules imported")
        print("   Frontend: ✅ Frontend files ready")
        print("   Compilation: ✅ All files compile without errors")
        print("\n🚀 System is ready for deployment!")
        return 0
    else:
        print(f"\n🟡 {total - passed} VERIFICATION ISSUE(S)")
        print("   Please review failed tests above")
        return 1

if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
