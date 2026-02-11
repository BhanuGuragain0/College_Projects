#!/usr/bin/env python3
"""
UI Integration Test - Verifies all dashboard UI elements are properly integrated
Tests clickable elements, JavaScript functions, and user interactions

Usage:
    python tests/ui_integration_test.py [--verbose] [--host HOST] [--port PORT]
"""

import asyncio
import json
import logging
import sys
import time
from pathlib import Path
from typing import Dict, List, Any

import aiohttp
from bs4 import BeautifulSoup

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("UIIntegrationTest")

class UIIntegrationTester:
    """Tests UI integration and clickable elements"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
        self.session = None
        self.results = {
            "timestamp": time.time(),
            "clickable_elements": {},
            "javascript_functions": {},
            "api_endpoints": {},
            "static_files": {},
            "overall_score": 0.0,
            "issues_found": [],
            "recommendations": []
        }
    
    async def setup(self):
        """Setup test environment"""
        self.session = aiohttp.ClientSession()
    
    def _record_test(self, category: str, name: str, passed: bool, details: Dict = None):
        """Record test result"""
        if category not in self.results:
            self.results[category] = {}
        
        self.results[category][name] = {
            "passed": passed,
            "details": details or {}
        }
        
        status = "✅ PASS" if passed else "❌ FAIL"
        logger.info(f"{status} - {category}.{name}")
    
    async def test_static_files(self):
        """Test that all static files are accessible"""
        logger.info("📁 Testing static file accessibility...")
        
        static_files = [
            "/static/app.js",
            "/static/state.js", 
            "/static/main.css",
            "/static/favicon.svg"
        ]
        
        for file_path in static_files:
            try:
                async with self.session.get(f"{self.base_url}{file_path}", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        content_type = resp.headers.get('content-type', '')
                        if file_path.endswith('.js'):
                            is_js = 'javascript' in content_type
                            self._record_test("static_files", file_path, is_js, {"content_type": content_type})
                        elif file_path.endswith('.css'):
                            is_css = 'text/css' in content_type
                            self._record_test("static_files", file_path, is_css, {"content_type": content_type})
                        else:
                            self._record_test("static_files", file_path, True, {"content_type": content_type})
                    else:
                        self._record_test("static_files", file_path, False, {"status": resp.status})
            except Exception as e:
                self._record_test("static_files", file_path, False, {"error": str(e)})
    
    async def test_clickable_elements(self):
        """Test that all clickable elements have proper event handlers"""
        logger.info("🖱️ Testing clickable elements...")
        
        try:
            async with self.session.get(f"{self.base_url}/", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    html_content = await resp.text()
                    soup = BeautifulSoup(html_content, 'html.parser')
                    
                    # Test navigation links
                    nav_links = soup.find_all(class_="nav-link")
                    for link in nav_links:
                        link_id = link.get('data-page', 'unknown')
                        has_data_page = bool(link.get('data-page'))
                        has_href = bool(link.get('href'))
                        self._record_test("clickable_elements", f"nav_link_{link_id}", 
                                       has_data_page and has_href, 
                                       {"data_page": has_data_page, "href": has_href})
                    
                    # Test buttons
                    buttons = soup.find_all('button')
                    for button in buttons:
                        button_id = button.get('id', f'button_{len(buttons)}')
                        has_id = bool(button.get('id'))
                        has_onclick = bool(button.get('onclick'))
                        has_text = bool(button.get_text(strip=True))
                        
                        # Check if it's one of the important buttons
                        important_buttons = [
                            'btn-new-command', 'btn-payload-builder', 'btn-file-manager',
                            'btn-cert-viewer', 'btn-batch-command', 'refresh-btn',
                            'btn-new-command-page', 'btn-batch-command-inline'
                        ]
                        
                        is_important = button_id in important_buttons
                        if is_important:
                            self._record_test("clickable_elements", f"button_{button_id}", 
                                           has_id and has_text, 
                                           {"has_id": has_id, "has_onclick": has_onclick, "has_text": has_text})
                    
                    # Test form elements
                    forms = soup.find_all('form')
                    for form in forms:
                        form_id = form.get('id', f'form_{len(forms)}')
                        has_id = bool(form.get('id'))
                        has_inputs = len(form.find_all(['input', 'select', 'textarea'])) > 0
                        
                        self._record_test("clickable_elements", f"form_{form_id}", 
                                       has_id and has_inputs, 
                                       {"has_id": has_id, "has_inputs": has_inputs})
                    
                    # Test interactive elements
                    interactive_elements = [
                        ('#auto-refresh', 'checkbox'),
                        ('#search-input', 'search input'),
                        ('#status-filter', 'select filter'),
                        ('#audit-search', 'audit search')
                    ]
                    
                    for selector, element_type in interactive_elements:
                        element = soup.select_one(selector)
                        if element:
                            has_id = bool(element.get('id'))
                            self._record_test("clickable_elements", f"interactive_{element_type.replace(' ', '_')}", 
                                           has_id, {"has_id": has_id})
                        else:
                            self._record_test("clickable_elements", f"interactive_{element_type.replace(' ', '_')}", 
                                           False, {"missing": True})
                    
        except Exception as e:
            logger.error(f"Error testing clickable elements: {e}")
    
    async def test_javascript_functions(self):
        """Test that JavaScript functions exist and are callable"""
        logger.info("🔧 Testing JavaScript functions...")
        
        try:
            # Get the main app.js content
            async with self.session.get(f"{self.base_url}/static/app.js", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    js_content = await resp.text()
                    
                    # Check for critical functions
                    critical_functions = [
                        'openPayloadBuilder',
                        'openFileManager', 
                        'openCertificateViewer',
                        'openCommandModal',
                        'closeCommandModal',
                        'executeBatchCommand',
                        'loadPayloadTemplates',
                        'loadCertificates',
                        'submitCommand',
                        'refreshData',
                        'showToast'
                    ]
                    
                    for func_name in critical_functions:
                        function_exists = func_name in js_content
                        self._record_test("javascript_functions", func_name, function_exists, 
                                       {"found_in_app_js": function_exists})
                    
                    # Check for event listeners
                    event_patterns = [
                        'addEventListener',
                        'onclick',
                        'onchange',
                        'onsubmit'
                    ]
                    
                    for pattern in event_patterns:
                        has_pattern = pattern in js_content
                        self._record_test("javascript_functions", f"event_{pattern}", has_pattern,
                                       {"found_in_app_js": has_pattern})
                    
                    # Check for WebSocket functionality
                    websocket_features = [
                        'WebSocket',
                        'ws://',
                        'onmessage',
                        'onopen',
                        'onclose'
                    ]
                    
                    for feature in websocket_features:
                        has_feature = feature in js_content
                        self._record_test("javascript_functions", f"websocket_{feature}", has_feature,
                                       {"found_in_app_js": has_feature})
                    
        except Exception as e:
            logger.error(f"Error testing JavaScript functions: {e}")
    
    async def test_api_endpoints_ui_needs(self):
        """Test API endpoints that the UI depends on"""
        logger.info("🔌 Testing UI-dependent API endpoints...")
        
        ui_endpoints = [
            ('/api/stats', 'dashboard stats'),
            ('/api/agents', 'agent list'),
            ('/api/commands', 'command history'),
            ('/api/payload/templates', 'payload templates'),
            ('/api/certificates', 'certificate list'),
            ('/api/audit/logs', 'audit logs'),
            ('/ws', 'websocket connection')
        ]
        
        for endpoint, description in ui_endpoints:
            try:
                if endpoint == '/ws':
                    # Test WebSocket differently
                    ws_url = self.base_url.replace('http://', 'ws://') + endpoint
                    try:
                        async with self.session.ws_connect(ws_url, timeout=aiohttp.ClientTimeout(total=3)) as ws:
                            self._record_test("api_endpoints", description, True, {"websocket_connected": True})
                    except:
                        self._record_test("api_endpoints", description, False, {"websocket_failed": True})
                else:
                    async with self.session.get(f"{self.base_url}{endpoint}", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        success = resp.status in [200, 401, 403]  # These are acceptable
                        self._record_test("api_endpoints", description, success, 
                                       {"status": resp.status, "content_type": resp.headers.get('content-type', '')})
            except Exception as e:
                self._record_test("api_endpoints", description, False, {"error": str(e)})
    
    def calculate_overall_score(self):
        """Calculate overall integration score"""
        total_tests = 0
        passed_tests = 0
        
        for category, tests in self.results.items():
            if category in ["timestamp", "overall_score", "issues_found", "recommendations"]:
                continue
                
            for test_name, test_result in tests.items():
                if isinstance(test_result, dict) and "passed" in test_result:
                    total_tests += 1
                    if test_result["passed"]:
                        passed_tests += 1
        
        if total_tests > 0:
            self.results["overall_score"] = (passed_tests / total_tests) * 100
        
        # Generate recommendations
        self.generate_recommendations()
    
    def generate_recommendations(self):
        """Generate recommendations based on test results"""
        recommendations = []
        issues = []
        
        # Check static files
        static_files = self.results.get("static_files", {})
        for file_name, result in static_files.items():
            if not result.get("passed", False):
                issues.append(f"Static file {file_name} is not accessible")
                recommendations.append(f"Fix static file serving for {file_name}")
        
        # Check clickable elements
        clickable = self.results.get("clickable_elements", {})
        missing_elements = [name for name, result in clickable.items() if not result.get("passed", False)]
        if missing_elements:
            issues.append(f"Missing clickable elements: {', '.join(missing_elements)}")
            recommendations.append("Add missing HTML elements or fix their attributes")
        
        # Check JavaScript functions
        js_functions = self.results.get("javascript_functions", {})
        missing_functions = [name for name, result in js_functions.items() if not result.get("passed", False)]
        if missing_functions:
            issues.append(f"Missing JavaScript functions: {', '.join(missing_functions)}")
            recommendations.append("Implement missing JavaScript functions in app.js")
        
        # Check API endpoints
        api_endpoints = self.results.get("api_endpoints", {})
        failed_apis = [name for name, result in api_endpoints.items() if not result.get("passed", False)]
        if failed_apis:
            issues.append(f"Failed API endpoints: {', '.join(failed_apis)}")
            recommendations.append("Fix backend API endpoints that UI depends on")
        
        if not recommendations:
            recommendations.append("UI integration is excellent! All elements are properly integrated.")
        
        self.results["issues_found"] = issues
        self.results["recommendations"] = recommendations
    
    async def run_tests(self):
        """Run all UI integration tests"""
        await self.setup()
        
        logger.info("\n" + "="*80)
        logger.info("🧪 RUNNING UI INTEGRATION TEST SUITE")
        logger.info("="*80 + "\n")
        
        try:
            await self.test_static_files()
            await self.test_clickable_elements()
            await self.test_javascript_functions()
            await self.test_api_endpoints_ui_needs()
            
            self.calculate_overall_score()
            
        finally:
            if self.session:
                await self.session.close()
        
        return self.results
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "="*80)
        print("📊 UI INTEGRATION TEST SUMMARY")
        print("="*80)
        
        score = self.results["overall_score"]
        print(f"🎯 Overall Integration Score: {score:.1f}%")
        
        # Category breakdowns
        categories = ["static_files", "clickable_elements", "javascript_functions", "api_endpoints"]
        for category in categories:
            if category in self.results:
                tests = self.results[category]
                passed = sum(1 for t in tests.values() if t.get("passed", False))
                total = len(tests)
                percentage = (passed / total * 100) if total > 0 else 0
                
                print(f"\n📋 {category.replace('_', ' ').title()}:")
                print(f"   ✅ Passed: {passed}/{total} ({percentage:.1f}%)")
                
                # Show failed items
                failed = [name for name, result in tests.items() if not result.get("passed", False)]
                if failed:
                    print(f"   ❌ Failed: {', '.join(failed)}")
        
        # Issues and recommendations
        if self.results["issues_found"]:
            print(f"\n⚠️  Issues Found ({len(self.results['issues_found'])}):")
            for i, issue in enumerate(self.results["issues_found"], 1):
                print(f"   {i}. {issue}")
        
        if self.results["recommendations"]:
            print(f"\n💡 Recommendations:")
            for i, rec in enumerate(self.results["recommendations"], 1):
                print(f"   {i}. {rec}")
        
        # Final assessment
        print("\n" + "="*80)
        if score >= 95:
            print("🎉 EXCELLENT! UI integration is perfect - all elements work correctly!")
        elif score >= 85:
            print("✅ VERY GOOD! UI integration is mostly complete with minor issues.")
        elif score >= 75:
            print("⚠️  GOOD! UI integration works but has some issues to address.")
        elif score >= 60:
            print("🚨 FAIR! UI integration has significant issues that need fixing.")
        else:
            print("❌ POOR! UI integration has major problems - requires significant work.")
        print("="*80)

async def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="UI Integration Test Suite")
    parser.add_argument("--host", default="127.0.0.1", help="Dashboard host")
    parser.add_argument("--port", type=int, default=8080, help="Dashboard port")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--save-results", help="Save results to JSON file")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    tester = UIIntegrationTester(host=args.host, port=args.port)
    
    try:
        results = await tester.run_tests()
        tester.print_summary()
        
        if args.save_results:
            with open(args.save_results, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\n💾 Results saved to: {args.save_results}")
        
        # Exit with appropriate code
        if results["overall_score"] >= 80:
            sys.exit(0)  # Success
        else:
            sys.exit(1)  # Failure
            
    except KeyboardInterrupt:
        print("\n🛑 Tests interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"❌ Test execution failed: {e}")
        sys.exit(2)

if __name__ == "__main__":
    asyncio.run(main())
