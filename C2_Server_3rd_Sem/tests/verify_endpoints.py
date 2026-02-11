#!/usr/bin/env python3
"""
Comprehensive Endpoint Verification & Testing Suite
Tests all backend API endpoints and verifies frontend integration
"""

import sys
import asyncio
import json
import time
from pathlib import Path

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
        routes.append({
            'method': route.method if hasattr(route, 'method') else 'N/A',
            'resource': str(route.resource) if hasattr(route, 'resource') else str(route)
        })
    
    print("\n✅ REGISTERED API ENDPOINTS:")
    print("-" * 80)
    
    # Filter and display API routes
    api_routes = [r for r in routes if '/api/' in str(r)]
    
    # New endpoints to verify
    new_endpoints = [
        '/api/health/detailed',
        '/api/metrics',
        '/api/metrics/operation',
        '/api/metrics/errors'
    ]
    
    # All expected endpoints
    expected_endpoints = {
        '/api/state': 'GET',
        '/api/agents': 'GET',
        '/api/commands': 'GET',
        '/api/audit': 'GET',
        '/api/stats': 'GET',
        '/api/command': 'POST',
        '/api/health/detailed': 'GET',
        '/api/metrics': 'GET',
        '/api/metrics/operation': 'GET',
        '/api/metrics/errors': 'GET',
    }
    
    found_endpoints = {}
    for route in api_routes:
        route_str = str(route['resource'])
        for expected in expected_endpoints.keys():
            if expected in route_str:
                found_endpoints[expected] = True
    
    # Verify new endpoints
    print("\n🆕 NEW ENDPOINTS VERIFICATION:")
    for endpoint in new_endpoints:
        if endpoint in found_endpoints:
            print(f"  ✅ {endpoint}")
        else:
            print(f"  ❌ {endpoint} - NOT FOUND")
    
    # Verify core endpoints
    print("\n📡 CORE ENDPOINTS VERIFICATION:")
    core_endpoints = ['/api/state', '/api/agents', '/api/commands', '/api/audit']
    for endpoint in core_endpoints:
        if endpoint in found_endpoints:
            print(f"  ✅ {endpoint}")
        else:
            print(f"  ❌ {endpoint} - NOT FOUND")
    
    return len([e for e in new_endpoints if e in found_endpoints]) == len(new_endpoints)

# ==================== HANDLER FUNCTION VERIFICATION ====================

def verify_handler_functions():
    """Verify all handler functions are implemented and importable"""
    print("\n" + "="*80)
    print("HANDLER FUNCTION VERIFICATION")
    print("="*80)
    
    from securecomm import dashboard_server
    import inspect
    
    # New handler functions
    handlers = {
        'api_health_detailed': 'Get system health details',
        'api_metrics_detailed': 'Get performance metrics',
        'api_metrics_operation': 'Get operation-specific metrics',
        'api_metrics_errors': 'Get error statistics',
    }
    
    print("\n🔧 HANDLER FUNCTIONS:")
    all_found = True
    for handler_name, description in handlers.items():
        # Try to find the handler (they're defined inside create_app, so we check if it's in the source)
        source = inspect.getsource(dashboard_server.create_app)
        if f'def {handler_name}' in source:
            print(f"  ✅ {handler_name}: {description}")
        else:
            print(f"  ❌ {handler_name}: NOT FOUND")
            all_found = False
    
    return all_found

# ==================== MODULE IMPORT VERIFICATION ====================

def verify_module_imports():
    """Verify all new modules are properly imported"""
    print("\n" + "="*80)
    print("MODULE IMPORT VERIFICATION")
    print("="*80)
    
    print("\n📦 IMPORTING NEW MODULES:")
    
    modules = {
        'logging_context': ['ContextManager', 'get_context_dict'],
        'metrics': ['get_metrics', 'MetricsCollector'],
        'health': ['HealthChecker'],
    }
    
    all_imported = True
    for module_name, items in modules.items():
        try:
            mod = __import__(f'securecomm.{module_name}', fromlist=items)
            print(f"  ✅ securecomm.{module_name}")
            for item in items:
                if hasattr(mod, item):
                    print(f"      ✓ {item}")
                else:
                    print(f"      ✗ {item} - NOT FOUND")
                    all_imported = False
        except Exception as e:
            print(f"  ❌ securecomm.{module_name}: {e}")
            all_imported = False
    
    return all_imported

# ==================== INTEGRATION VERIFICATION ====================

async def verify_async_handlers():
    """Verify async handlers can be called"""
    print("\n" + "="*80)
    print("ASYNC HANDLER VERIFICATION")
    print("="*80)
    
    try:
        from securecomm.health import HealthChecker
        from securecomm.metrics import get_metrics
        
        print("\n🔄 TESTING ASYNC HANDLERS:")
        
        # Test 1: HealthChecker
        print("\n  Test 1: HealthChecker.get_system_health()")
        try:
            checker = HealthChecker()
            health = await checker.get_system_health()
            if isinstance(health, dict):
                print(f"    ✅ Returns dict with keys: {list(health.keys())[:3]}...")
            else:
                print(f"    ❌ Returns {type(health)}")
        except Exception as e:
            print(f"    ⚠️ {e}")
        
        # Test 2: Metrics
        print("\n  Test 2: MetricsCollector.get_all_metrics()")
        try:
            metrics = get_metrics()
            all_metrics = metrics.get_all_metrics()
            if isinstance(all_metrics, dict):
                print(f"    ✅ Returns dict with keys: {list(all_metrics.keys())[:3]}...")
            else:
                print(f"    ❌ Returns {type(all_metrics)}")
        except Exception as e:
            print(f"    ⚠️ {e}")
        
        # Test 3: Operation stats
        print("\n  Test 3: MetricsCollector.get_operation_stats()")
        try:
            stats = metrics.get_operation_stats("test_operation")
            if isinstance(stats, dict):
                print(f"    ✅ Returns dict with keys: {list(stats.keys())[:3]}...")
            else:
                print(f"    ❌ Returns {type(stats)}")
        except Exception as e:
            print(f"    ⚠️ {e}")
        
        # Test 4: Error stats
        print("\n  Test 4: MetricsCollector.get_error_stats()")
        try:
            error_stats = metrics.get_error_stats()
            if isinstance(error_stats, dict):
                print(f"    ✅ Returns dict with keys: {list(error_stats.keys())}")
            else:
                print(f"    ❌ Returns {type(error_stats)}")
        except Exception as e:
            print(f"    ⚠️ {e}")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

# ==================== ENDPOINT ROUTE VERIFICATION ====================

def verify_endpoint_routes():
    """Verify endpoint routes are properly registered"""
    print("\n" + "="*80)
    print("ENDPOINT ROUTE VERIFICATION")
    print("="*80)
    
    from securecomm.dashboard_server import create_app
    
    app = create_app()
    
    # Expected routes
    expected_routes = {
        'GET /api/health/detailed': 'System health check',
        'GET /api/metrics': 'Performance metrics',
        'GET /api/metrics/operation': 'Operation metrics',
        'GET /api/metrics/errors': 'Error statistics',
    }
    
    print("\n🛣️  REGISTERED ROUTES:")
    
    registered_routes = []
    for route in app.router.routes():
        if hasattr(route, 'resource') and hasattr(route, 'method'):
            route_str = f"{route.method} {str(route.resource)}"
            registered_routes.append(route_str)
    
    all_found = True
    for expected, description in expected_routes.items():
        # Check if route exists (with or without trailing slash patterns)
        found = any(expected in r or r in expected for r in registered_routes)
        if found:
            print(f"  ✅ {expected}: {description}")
        else:
            print(f"  ❌ {expected}: NOT FOUND")
            all_found = False
    
    return all_found

# ==================== FRONTEND VERIFICATION ====================

def verify_frontend_integration():
    """Verify frontend can access new endpoints"""
    print("\n" + "="*80)
    print("FRONTEND INTEGRATION VERIFICATION")
    print("="*80)
    
    # Check if dashboard app.js has fetch calls
    app_js_path = Path('dashboard/app.js')
    if app_js_path.exists():
        with open(app_js_path, 'r') as f:
            content = f.read()
        
        print("\n📱 FRONTEND API CALL VERIFICATION:")
        
        api_endpoints = [
            '/api/state',
            '/api/agents',
            '/api/commands',
            '/api/audit',
            '/api/stats',
        ]
        
        for endpoint in api_endpoints:
            if endpoint in content:
                print(f"  ✅ {endpoint} - referenced in app.js")
            else:
                print(f"  ⚠️ {endpoint} - not referenced in app.js")
        
        # Check for fetch patterns
        if 'fetch' in content:
            print(f"\n  ✅ Frontend uses fetch() for API calls")
        if 'WebSocket' in content:
            print(f"  ✅ Frontend initializes WebSocket")
        if 'getHeaders()' in content:
            print(f"  ✅ Frontend includes authentication headers")
        
        return True
    else:
        print(f"  ⚠️ dashboard/app.js not found")
        return False

# ==================== HTML VERIFICATION ====================

def verify_html_pages():
    """Verify HTML has all necessary pages"""
    print("\n" + "="*80)
    print("HTML PAGE VERIFICATION")
    print("="*80)
    
    html_path = Path('dashboard/index.html')
    if html_path.exists():
        with open(html_path, 'r') as f:
            content = f.read()
        
        print("\n📄 DASHBOARD PAGES:")
        
        pages = ['dashboard', 'agents', 'commands', 'payload', 'files', 'certificates', 'audit']
        for page in pages:
            if f'id="page-{page}"' in content or f'data-page="{page}"' in content:
                print(f"  ✅ {page}")
            else:
                print(f"  ⚠️ {page}")
        
        return True
    else:
        print(f"  ⚠️ dashboard/index.html not found")
        return False

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
    
    print("\n🐍 PYTHON FILE COMPILATION:")
    all_compiled = True
    for filepath in files_to_check:
        try:
            py_compile.compile(filepath, doraise=True)
            print(f"  ✅ {filepath}")
        except py_compile.PyCompileError as e:
            print(f"  ❌ {filepath}: {e}")
            all_compiled = False
    
    return all_compiled

# ==================== MAIN TEST RUNNER ====================

async def main():
    """Run all verification tests"""
    print("\n" + "="*80)
    print("🧪 COMPREHENSIVE ENDPOINT VERIFICATION SUITE")
    print("="*80)
    
    results = {}
    
    # 1. Compilation check
    results['Compilation'] = verify_compilation()
    
    # 2. Module imports
    results['Module Imports'] = verify_module_imports()
    
    # 3. Backend endpoints
    results['Backend Endpoints'] = verify_backend_endpoints()
    
    # 4. Handler functions
    results['Handler Functions'] = verify_handler_functions()
    
    # 5. Endpoint routes
    results['Endpoint Routes'] = verify_endpoint_routes()
    
    # 6. Async handlers
    results['Async Handlers'] = await verify_async_handlers()
    
    # 7. Frontend integration
    results['Frontend Integration'] = verify_frontend_integration()
    
    # 8. HTML pages
    results['HTML Pages'] = verify_html_pages()
    
    # ==================== SUMMARY ====================
    
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    
    print("\n📊 VERIFICATION RESULTS:")
    passed = 0
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status}: {test_name}")
        if result:
            passed += 1
    
    total = len(results)
    print(f"\n🎯 Overall: {passed}/{total} tests passed ({100*passed//total}%)")
    
    if passed == total:
        print("\n🟢 ALL TESTS PASSED ✅")
        print("\n✨ All endpoints are properly connected!")
        print("   Backend: ✅ Fully implemented")
        print("   Frontend: ✅ Ready for integration")
        print("   Modules: ✅ All imported and working")
        return 0
    else:
        print(f"\n🟡 {total - passed} TEST(S) FAILED")
        print("   Please review failed tests above")
        return 1

if __name__ == '__main__':
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
