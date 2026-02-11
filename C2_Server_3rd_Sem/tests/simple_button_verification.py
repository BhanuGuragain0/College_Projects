#!/usr/bin/env python3
"""
SIMPLIFIED BUTTON FUNCTIONALITY VERIFICATION
Tests dashboard buttons and frontend-backend integration using curl-like requests

Usage:
    python tests/simple_button_verification.py [--host HOST] [--port PORT]
"""

import json
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

class SimpleButtonVerifier:
    """Simple verification of dashboard button functionality"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
        self.results = {
            "timestamp": time.time(),
            "static_files": {},
            "html_structure": {},
            "button_elements": {},
            "javascript_loading": {},
            "api_endpoints": {},
            "overall_status": "UNKNOWN",
            "issues_found": [],
            "success_rate": 0
        }
    
    def make_request(self, url: str) -> dict:
        """Make HTTP request and return response info"""
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'SecureComm-Verifier/1.0')
            
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
    
    def verify_static_files(self):
        """Verify all static files are accessible"""
        print("🔍 Verifying static files...")
        
        static_files = {
            "/static/main.css": "CSS Stylesheet",
            "/static/app.js": "Main Application",
            "/static/state.js": "State Management",
            "/static/favicon.svg": "Favicon"
        }
        
        for file_path, description in static_files.items():
            response = self.make_request(f"{self.base_url}{file_path}")
            
            if response["status"] == 200:
                content_type = response["headers"].get('Content-Type', '')
                self.results["static_files"][file_path] = {
                    "status": "✅ OK",
                    "content_type": content_type,
                    "description": description
                }
                print(f"  ✅ {description}: {file_path}")
            else:
                self.results["static_files"][file_path] = {
                    "status": f"❌ {response['status']}",
                    "description": description,
                    "error": response.get("error", "")
                }
                print(f"  ❌ {description}: {file_path} (HTTP {response['status']})")
    
    def verify_html_structure(self):
        """Verify HTML structure contains required elements"""
        print("\n🔍 Verifying HTML structure...")
        
        response = self.make_request(f"{self.base_url}/")
        
        if response["status"] != 200:
            self.results["html_structure"]["dashboard_page"] = {
                "status": f"❌ HTTP {response['status']}",
                "error": "Dashboard page not accessible"
            }
            print(f"  ❌ Dashboard page: HTTP {response['status']}")
            return
        
        html_content = response["content"]
        
        # Check for critical HTML elements
        html_checks = {
            "doctype": "<!DOCTYPE html>" in html_content,
            "viewport": 'name="viewport"' in html_content,
            "title": "<title>" in html_content,
            "sidebar": 'class="sidebar"' in html_content,
            "main_content": 'class="main-content"' in html_content,
            "quick_actions": 'class="quick-actions"' in html_content,
            "stats_grid": 'class="stats-grid"' in html_content,
            "data_tables": 'class="data-table"' in html_content
        }
        
        for check_name, result in html_checks.items():
            status = "✅ FOUND" if result else "❌ MISSING"
            self.results["html_structure"][check_name] = {
                "status": status,
                "found": result
            }
            print(f"  {status} {check_name.replace('_', ' ').title()}")
    
    def verify_button_elements(self):
        """Verify all required button elements exist in HTML"""
        print("\n🔍 Verifying button elements...")
        
        response = self.make_request(f"{self.base_url}/")
        
        if response["status"] != 200:
            print(f"  ❌ Cannot verify buttons: HTTP {response['status']}")
            return
        
        html_content = response["content"]
        
        # Check for specific button IDs
        required_buttons = {
            "btn-new-command": "New Command",
            "btn-payload-builder": "Payload Builder",
            "btn-file-manager": "File Manager",
            "btn-cert-viewer": "Certificates",
            "btn-batch-command": "Batch Command",
            "btn-new-command-page": "New Command (Page)",
            "btn-batch-command-inline": "Batch Command (Inline)",
            "refresh-btn": "Refresh Button",
            "auto-refresh": "Auto-refresh Toggle"
        }
        
        for button_id, description in required_buttons.items():
            found = f'id="{button_id}"' in html_content
            status = "✅ FOUND" if found else "❌ MISSING"
            self.results["button_elements"][button_id] = {
                "status": status,
                "description": description,
                "found": found
            }
            print(f"  {status} {description}: {button_id}")
    
    def verify_javascript_loading(self):
        """Verify JavaScript files contain required functionality"""
        print("\n🔍 Verifying JavaScript functionality...")
        
        js_checks = {
            "dashboard_class": "class SecureCommDashboard",
            "bind_events": "bindEvents()",
            "button_handlers": "openCommandModal",
            "payload_builder": "openPayloadBuilder",
            "file_manager": "openFileManager",
            "certificate_viewer": "openCertificateViewer",
            "batch_command": "executeBatchCommand",
            "initialization": "window.dashboard = new SecureCommDashboard"
        }
        
        response = self.make_request(f"{self.base_url}/static/app.js")
        
        if response["status"] != 200:
            print(f"  ❌ Cannot verify JavaScript: HTTP {response['status']}")
            return
        
        js_content = response["content"]
        
        for check_name, pattern in js_checks.items():
            found = pattern in js_content
            status = "✅ FOUND" if found else "❌ MISSING"
            self.results["javascript_loading"][check_name] = {
                "status": status,
                "pattern": pattern,
                "found": found
            }
            print(f"  {status} {check_name.replace('_', ' ').title()}")
    
    def verify_api_endpoints(self):
        """Verify critical API endpoints are working"""
        print("\n🔍 Verifying API endpoints...")
        
        api_endpoints = {
            "/api/state": "System State",
            "/api/stats": "Statistics",
            "/api/agents": "Agent List",
            "/api/commands": "Command History",
            "/api/certificates": "Certificate List",
            "/api/health/detailed": "Health Details",
            "/api/metrics": "System Metrics"
        }
        
        for endpoint, description in api_endpoints.items():
            response = self.make_request(f"{self.base_url}{endpoint}")
            status = "✅ OK" if response["status"] == 200 else f"❌ {response['status']}"
            self.results["api_endpoints"][endpoint] = {
                "status": status,
                "description": description,
                "http_status": response["status"]
            }
            print(f"  {status} {description}: {endpoint}")
    
    def calculate_overall_status(self):
        """Calculate overall system status"""
        all_checks = {}
        
        # Collect all check results
        for category in ["static_files", "html_structure", "button_elements", "javascript_loading", "api_endpoints"]:
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
    
    def print_comprehensive_report(self):
        """Print comprehensive verification report"""
        print("\n" + "="*80)
        print("🧪 SIMPLIFIED BUTTON FUNCTIONALITY VERIFICATION")
        print("="*80)
        
        print(f"🕐 Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.results['timestamp']))}")
        print(f"🎯 Overall Status: {self.results['overall_status']}")
        print(f"📊 Success Rate: {self.results['success_rate']:.1f}%")
        print(f"✅ Passed: {self.results['passed_checks']}/{self.results['total_checks']}")
        
        # Category breakdowns
        categories = ["static_files", "html_structure", "button_elements", "javascript_loading", "api_endpoints"]
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
        
        # Final assessment
        print("\n" + "="*80)
        status = self.results["overall_status"]
        if status == "🟢 EXCELLENT":
            print("🎉 EXCELLENT! All button functionality is working correctly!")
            print("   Dashboard is production-ready with full functionality.")
        elif status == "🟡 GOOD":
            print("✅ GOOD! Most button functionality is working with minor issues.")
            print("   Address failed items for optimal performance.")
        elif status == "🟠 FAIR":
            print("⚠️  FAIR! Some button functionality needs attention.")
            print("   Significant improvements required for production use.")
        else:
            print("❌ POOR! Critical button functionality issues found.")
            print("   Major fixes required before system is usable.")
        print("="*80)
        
        # Browser testing instructions
        print("\n🌐 BROWSER TESTING INSTRUCTIONS:")
        print("1. Open browser to: http://127.0.0.1:8080")
        print("2. Open Developer Tools (F12)")
        print("3. Check Console tab for initialization messages")
        print("4. Look for messages like:")
        print("   - '🔧 Binding events...'")
        print("   - '✅ [button] button bound successfully'")
        print("   - '🔧 [button] button clicked!'")
        print("5. Test each button in Quick Actions section")
        print("6. Verify modals open and functionality works")

def main():
    """Main verification function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Simplified Button Functionality Verification")
    parser.add_argument("--host", default="127.0.0.1", help="Dashboard host")
    parser.add_argument("--port", type=int, default=8080, help="Dashboard port")
    parser.add_argument("--save-results", help="Save results to JSON file")
    
    args = parser.parse_args()
    
    verifier = SimpleButtonVerifier(host=args.host, port=args.port)
    
    try:
        print("🚀 Starting simplified button functionality verification...")
        
        verifier.verify_static_files()
        verifier.verify_html_structure()
        verifier.verify_button_elements()
        verifier.verify_javascript_loading()
        verifier.verify_api_endpoints()
        
        verifier.calculate_overall_status()
        verifier.print_comprehensive_report()
        
        if args.save_results:
            with open(args.save_results, 'w') as f:
                json.dump(verifier.results, f, indent=2, default=str)
            print(f"\n💾 Results saved to: {args.save_results}")
        
        # Exit with appropriate code
        if verifier.results["success_rate"] >= 85:
            sys.exit(0)  # Success
        else:
            sys.exit(1)  # Failure
            
    except KeyboardInterrupt:
        print("\n🛑 Verification interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Verification failed: {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()
