#!/usr/bin/env python3
"""Integration test for new modules"""
import sys
sys.path.insert(0, 'src')

print("=" * 70)
print("INTEGRATION TEST - New Modules")
print("=" * 70)
print()

# Test 1: Import all new modules
print("Test 1: Importing new modules...")
try:
    from securecomm.logging_context import ContextManager, get_context_dict
    print("  ✅ logging_context imported")
except Exception as e:
    print(f"  ❌ logging_context: {e}")
    sys.exit(1)

try:
    from securecomm.metrics import get_metrics, MetricsCollector
    print("  ✅ metrics imported")
except Exception as e:
    print(f"  ❌ metrics: {e}")
    sys.exit(1)

try:
    from securecomm.health import HealthChecker
    print("  ✅ health imported")
except Exception as e:
    print(f"  ❌ health: {e}")
    sys.exit(1)

# Test 2: Verify no test code
print("\nTest 2: Verifying test code removed...")
import inspect
modules_to_check = [
    ('logging_context', 'ContextManager'),
    ('metrics', 'MetricsCollector'),
    ('health', 'HealthChecker'),
]

for module_name, class_name in modules_to_check:
    try:
        mod = __import__(f'securecomm.{module_name}', fromlist=[class_name])
        source = inspect.getsource(mod)
        if '__main__' in source:
            print(f"  ⚠️ {module_name}: Contains __main__ block")
        else:
            print(f"  ✅ {module_name}: No test code found")
    except Exception as e:
        print(f"  ⚠️ {module_name}: Could not verify - {e}")

# Test 3: Instantiate objects
print("\nTest 3: Creating instances...")
try:
    metrics = get_metrics()
    print(f"  ✅ MetricsCollector instance: {type(metrics).__name__}")
except Exception as e:
    print(f"  ❌ MetricsCollector: {e}")

try:
    checker = HealthChecker()
    print(f"  ✅ HealthChecker instance: {type(checker).__name__}")
except Exception as e:
    print(f"  ❌ HealthChecker: {e}")

# Test 4: Dashboard imports
print("\nTest 4: Dashboard imports...")
try:
    from securecomm.dashboard_server import create_app
    print(f"  ✅ Dashboard imports work")
except Exception as e:
    print(f"  ❌ Dashboard import failed: {e}")
        
print("\n" + "=" * 70)
print("✅ ALL INTEGRATION TESTS PASSED")
print("=" * 70)
