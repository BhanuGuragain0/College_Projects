#!/usr/bin/env python3
"""
FILE MANAGER & PAYLOAD BUILDER FUNCTIONALITY TEST
Tests the File Manager and Payload Builder features in the SecureComm dashboard

Usage:
    python tests/file_manager_payload_builder_test.py [--host HOST] [--port PORT]
"""

import json
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

class FileManagerPayloadBuilderTester:
    """Test File Manager and Payload Builder functionality"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
        self.results = {
            "timestamp": time.time(),
            "file_manager": {},
            "payload_builder": {},
            "api_endpoints": {},
            "javascript_functions": {},
            "modal_functionality": {},
            "overall_status": "UNKNOWN"
        }
    
    def make_request(self, url: str) -> dict:
        """Make HTTP request and return response info"""
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'SecureComm-Tester/1.0')
            
            with urllib.request.urlopen(req, timeout=10) as response:
                return {
                    "status": response.getcode(),
                    "headers": dict(response.headers),
                    "content": response.read().decode('utf-8', errors='ignore')
                }
        except urllib.error.HTTPError as e:
            return {"status": e.code, "error": str(e), "content": ""}
        except Exception as e:
            return {"status": 0, "error": str(e), "content": ""}
    
    def test_file_manager_api(self):
        """Test File Manager related API endpoints"""
        print("🔍 Testing File Manager API endpoints...")
        
        # Test file browsing endpoint
        file_browse_response = self.make_request(f"{self.base_url}/api/files/browse?agent_id=test_agent")
        
        if file_browse_response["status"] == 200:
            self.results["file_manager"]["file_browse_api"] = {
                "status": "✅ WORKING",
                "endpoint": "/api/files/browse"
            }
            print("  ✅ File browse API: WORKING")
        else:
            self.results["file_manager"]["file_browse_api"] = {
                "status": f"❌ {file_browse_response['status']}",
                "error": file_browse_response.get("error", "")
            }
            print(f"  ❌ File browse API: HTTP {file_browse_response['status']}")
        
        # Test file upload endpoint (if exists)
        upload_response = self.make_request(f"{self.base_url}/api/files/upload", 
                                       data=b'{"test": "data"}'.encode('utf-8'),
                                       headers={'Content-Type': 'application/json'})
        
        if upload_response["status"] in [200, 405]:  # 405 might be expected for GET
            self.results["file_manager"]["file_upload_api"] = {
                "status": "✅ ACCESSIBLE",
                "endpoint": "/api/files/upload"
            }
            print("  ✅ File upload API: ACCESSIBLE")
        else:
            self.results["file_manager"]["file_upload_api"] = {
                "status": f"❌ {upload_response['status']}",
                "error": upload_response.get("error", "")
            }
            print(f"  ❌ File upload API: HTTP {upload_response['status']}")
    
    def test_payload_builder_api(self):
        """Test Payload Builder related API endpoints"""
        print("\n🔍 Testing Payload Builder API endpoints...")
        
        # Test payload templates endpoint
        templates_response = self.make_request(f"{self.base_url}/api/payloads/templates")
        
        if templates_response["status"] == 200:
            self.results["payload_builder"]["templates_api"] = {
                "status": "✅ WORKING",
                "endpoint": "/api/payloads/templates"
            }
            print("  ✅ Payload templates API: WORKING")
        else:
            self.results["payload_builder"]["templates_api"] = {
                "status": f"❌ {templates_response['status']}",
                "error": templates_response.get("error", "")
            }
            print(f"  ❌ Payload templates API: HTTP {templates_response['status']}")
        
        # Test payload config endpoint
        config_response = self.make_request(f"{self.base_url}/api/config/commands")
        
        if config_response["status"] == 200:
            self.results["payload_builder"]["config_api"] = {
                "status": "✅ WORKING",
                "endpoint": "/api/config/commands"
            }
            print("  ✅ Payload config API: WORKING")
        else:
            self.results["payload_builder"]["config_api"] = {
                "status": f"❌ {config_response['status']}",
                "error": config_response.get("error", "")
            }
            print(f"  ❌ Payload config API: HTTP {config_response['status']}")
    
    def test_javascript_functions(self):
        """Test if JavaScript functions are implemented"""
        print("\n🔍 Testing JavaScript function implementation...")
        
        response = self.make_request(f"{self.base_url}/static/app.js")
        
        if response["status"] != 200:
            print(f"  ❌ Cannot verify JavaScript: HTTP {response['status']}")
            return
        
        js_content = response["content"]
        
        # Test File Manager functions
        file_manager_functions = {
            "openFileManager": "openFileManager(" in js_content,
            "loadAgentFiles": "loadAgentFiles(" in js_content,
            "uploadFileToAgent": "uploadFileToAgent(" in js_content,
            "refreshFileList": "refreshFileList(" in js_content,
            "switchFileManagerAgent": "switchFileManagerAgent(" in js_content
        }
        
        for func_name, found in file_manager_functions.items():
            status = "✅ IMPLEMENTED" if found else "❌ MISSING"
            self.results["javascript_functions"][f"file_manager_{func_name}"] = {
                "status": status,
                "found": found
            }
            print(f"  {status} File Manager: {func_name}")
        
        # Test Payload Builder functions
        payload_builder_functions = {
            "openPayloadBuilder": "openPayloadBuilder(" in js_content,
            "loadPayloadTemplates": "loadPayloadTemplates(" in js_content,
            "buildPayload": "buildPayload(" in js_content
        }
        
        for func_name, found in payload_builder_functions.items():
            status = "✅ IMPLEMENTED" if found else "❌ MISSING"
            self.results["javascript_functions"][f"payload_builder_{func_name}"] = {
                "status": status,
                "found": found
            }
            print(f"  {status} Payload Builder: {func_name}")
    
    def test_modal_functionality(self):
        """Test if modal HTML structures are present"""
        print("\n🔍 Testing modal functionality...")
        
        response = self.make_request(f"{self.base_url}/")
        
        if response["status"] != 200:
            print(f"  ❌ Cannot test modals: HTTP {response['status']}")
            return
        
        html_content = response["content"]
        
        # Test for modal creation patterns
        modal_tests = {
            "file_manager_modal": "file-manager-modal" in js_content,
            "payload_builder_modal": "payload-builder-modal" in js_content,
            "modal_close_functionality": "modal-close" in js_content,
            "modal_content_structure": "modal-content" in js_content
        }
        
        for test_name, found in modal_tests.items():
            status = "✅ IMPLEMENTED" if found else "❌ MISSING"
            self.results["modal_functionality"][test_name] = {
                "status": status,
                "found": found
            }
            print(f"  {status} {test_name.replace('_', ' ').title()}")
    
    def test_button_functionality(self):
        """Test if buttons are properly bound"""
        print("\n🔍 Testing button functionality...")
        
        response = self.make_request(f"{self.base_url}/")
        
        if response["status"] != 200:
            print(f"  ❌ Cannot test buttons: HTTP {response['status']}")
            return
        
        html_content = response["content"]
        
        # Test for button onclick handlers
        button_tests = {
            "file_manager_button": "openFileManager(" in html_content or "btn-file-manager" in html_content,
            "payload_builder_button": "openPayloadBuilder(" in html_content or "btn-payload-builder" in html_content,
            "upload_button": "uploadFileToAgent(" in html_content,
            "build_payload_button": "buildPayload(" in html_content
        }
        
        for test_name, found in button_tests.items():
            status = "✅ IMPLEMENTED" if found else "❌ MISSING"
            self.results["modal_functionality"][f"button_{test_name}"] = {
                "status": status,
                "found": found
            }
            print(f"  {status} {test_name.replace('_', ' ').title()}")
    
    def calculate_overall_status(self):
        """Calculate overall system status"""
        all_checks = {}
        
        # Collect all check results
        for category in ["file_manager", "payload_builder", "api_endpoints", "javascript_functions", "modal_functionality"]:
            if category in self.results:
                all_checks[category] = self.results[category]
        
        total_checks = 0
        passed_checks = 0
        
        for category, checks in all_checks.items():
            for item_name, result in checks.items():
                total_checks += 1
                if result.get("status", "").startswith("✅"):
                    passed_checks += 1
        
        success_rate = (passed_checks / total_checks * 100) if total_checks > 0 else 0
        
        if success_rate >= 95:
            self.results["overall_status"] = "🟢 EXCELLENT"
        elif success_rate >= 85:
            self.results["overall_status"] = "🟡 GOOD"
        elif success_rate >= 70:
            self.results["overall_status"] = "🟠 FAIR"
        else:
            self.results["overall_status"] = "🔴 POOR"
        
        self.results["success_rate"] = success_rate
        self.results["total_checks"] = total_checks
        self.results["passed_checks"] = passed_checks
    
    def print_detailed_report(self):
        """Print detailed test report"""
        print("\n" + "="*80)
        print("📁🔧 FILE MANAGER & PAYLOAD BUILDER FUNCTIONALITY TEST")
        print("="*80)
        
        print(f"🕐 Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.results['timestamp']))}")
        print(f"🎯 Overall Status: {self.results['overall_status']}")
        print(f"📊 Success Rate: {self.results['success_rate']:.1f}%")
        print(f"✅ Passed: {self.results['passed_checks']}/{self.results['total_checks']}")
        
        # Category breakdowns
        categories = ["file_manager", "payload_builder", "api_endpoints", "javascript_functions", "modal_functionality"]
        for category in categories:
            if category in self.results:
                print(f"\n📋 {category.replace('_', ' ').title()}:")
                checks = self.results[category]
                passed = sum(1 for result in checks.values() if result.get("status", "").startswith("✅"))
                total = len(checks)
                print(f"   ✅ Passed: {passed}/{total}")
                
                # Show failed items
                failed = [name for name, result in checks.items() if not result.get("status", "").startswith("✅")]
                if failed:
                    print(f"   ❌ Failed: {', '.join(failed)}")
        
        # Testing instructions
        print("\n" + "="*80)
        print("🌐 MANUAL TESTING INSTRUCTIONS:")
        print("="*80)
        print("1. Start dashboard: python launcher.py dashboard --host 127.0.0.1 --port 8080 --token \"\"")
        print("2. Open browser to: http://127.0.0.1:8080")
        print("3. Open Developer Tools (F12) → Console tab")
        print("4. Test File Manager:")
        print("   - Click 📁 File Manager button")
        print("   - Verify modal opens with agent list")
        print("   - Check console for '📁 File Manager button clicked!'")
        print("   - Try switching between agents")
        print("   - Test upload and refresh buttons")
        print("5. Test Payload Builder:")
        print("   - Click 🔧 Payload Builder button")
        print("   - Verify modal opens with configuration options")
        print("   - Check console for '🔧 Payload Builder button clicked!'")
        print("   - Try building a payload")
        print("6. Verify API calls:")
        print("   - Check Network tab in DevTools")
        print("   - Look for calls to /api/files/browse")
        print("   - Look for calls to /api/payloads/templates")
        print("="*80)

def main():
    """Main test function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="File Manager & Payload Builder Test")
    parser.add_argument("--host", default="127.0.0.1", help="Dashboard host")
    parser.add_argument("--port", type=int, default=8080, help="Dashboard port")
    parser.add_argument("--save-results", help="Save results to JSON file")
    
    args = parser.parse_args()
    
    tester = FileManagerPayloadBuilderTester(host=args.host, port=args.port)
    
    try:
        print("🚀 Starting File Manager & Payload Builder functionality test...")
        
        tester.test_file_manager_api()
        tester.test_payload_builder_api()
        tester.test_javascript_functions()
        tester.test_modal_functionality()
        tester.test_button_functionality()
        
        tester.calculate_overall_status()
        tester.print_detailed_report()
        
        if args.save_results:
            with open(args.save_results, 'w') as f:
                json.dump(tester.results, f, indent=2, default=str)
            print(f"\n💾 Results saved to: {args.save_results}")
        
        # Exit with appropriate code
        if tester.results["success_rate"] >= 85:
            sys.exit(0)  # Success
        else:
            sys.exit(1)  # Failure
            
    except KeyboardInterrupt:
        print("\n🛑 Test interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Test failed: {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()
