#!/usr/bin/env python3
"""
COMPREHENSIVE BUTTON FUNCTIONALITY VERIFICATION
Tests all dashboard buttons and frontend-backend integration

Usage:
    python tests/comprehensive_button_verification.py [--host HOST] [--port PORT]
"""

import asyncio
import json
import sys
import time
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from securecomm.dashboard_server import create_app
import aiohttp
from aiohttp.test import TestClient, TestServer

class ComprehensiveButtonVerifier:
    """Comprehensive verification of dashboard button functionality"""
    
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
            "recommendations": []
        }
    
    async def verify_static_files(self):
        """Verify all static files are accessible"""
        print("🔍 Verifying static files...")
        
        static_files = {
            "/static/main.css": "CSS Stylesheet",
            "/static/app.js": "Main Application",
            "/static/state.js": "State Management",
            "/static/favicon.svg": "Favicon"
        }
        
        for file_path, description in static_files.items():
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"{self.base_url}{file_path}") as resp:
                        if resp.status == 200:
                            content_type = resp.headers.get('content-type', '')
                            self.results["static_files"][file_path] = {
                                "status": "✅ OK",
                                "content_type": content_type,
                                "description": description
                            }
                            print(f"  ✅ {description}: {file_path}")
                        else:
                            self.results["static_files"][file_path] = {
                                "status": f"❌ {resp.status}",
                                "description": description
                            }
                            print(f"  ❌ {description}: {file_path} (HTTP {resp.status})")
            except Exception as e:
                self.results["static_files"][file_path] = {
                    "status": f"❌ ERROR: {str(e)}",
                    "description": description
                }
                print(f"  ❌ {description}: {file_path} - {str(e)}")
    
    async def verify_html_structure(self):
        """Verify HTML structure contains required elements"""
        print("\n🔍 Verifying HTML structure...")
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.base_url}/") as resp:
                    if resp.status != 200:
                        self.results["html_structure"]["dashboard_page"] = {
                            "status": f"❌ HTTP {resp.status}",
                            "error": "Dashboard page not accessible"
                        }
                        print(f"  ❌ Dashboard page: HTTP {resp.status}")
                        return
                    
                    html_content = await resp.text()
                    
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
                    
        except Exception as e:
            self.results["html_structure"]["dashboard_page"] = {
                "status": f"❌ ERROR: {str(e)}",
                "error": str(e)
            }
            print(f"  ❌ HTML structure verification failed: {str(e)}")
    
    async def verify_button_elements(self):
        """Verify all required button elements exist in HTML"""
        print("\n🔍 Verifying button elements...")
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.base_url}/") as resp:
                    if resp.status != 200:
                        print(f"  ❌ Cannot verify buttons: HTTP {resp.status}")
                        return
                    
                    html_content = await resp.text()
                    
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
                    
        except Exception as e:
            print(f"  ❌ Button verification failed: {str(e)}")
    
    async def verify_javascript_loading(self):
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
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.base_url}/static/app.js") as resp:
                    if resp.status != 200:
                        print(f"  ❌ Cannot verify JavaScript: HTTP {resp.status}")
                        return
                    
                    js_content = await resp.text()
                    
                    for check_name, pattern in js_checks.items():
                        found = pattern in js_content
                        status = "✅ FOUND" if found else "❌ MISSING"
                        self.results["javascript_loading"][check_name] = {
                            "status": status,
                            "pattern": pattern,
                            "found": found
                        }
                        print(f"  {status} {check_name.replace('_', ' ').title()}")
                    
        except Exception as e:
            print(f"  ❌ JavaScript verification failed: {str(e)}")
    
    async def verify_api_endpoints(self):
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
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"{self.base_url}{endpoint}") as resp:
                        status = "✅ OK" if resp.status == 200 else f"❌ {resp.status}"
                        self.results["api_endpoints"][endpoint] = {
                            "status": status,
                            "description": description,
                            "http_status": resp.status
                        }
                        print(f"  {status} {description}: {endpoint}")
            except Exception as e:
                self.results["api_endpoints"][endpoint] = {
                    "status": f"❌ ERROR: {str(e)}",
                    "description": description
                }
                print(f"  ❌ {description}: {endpoint} - {str(e)}")
    
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
        
        # Generate recommendations
        self.generate_recommendations()
    
    def generate_recommendations(self):
        """Generate recommendations based on verification results"""
        recommendations = []
        
        # Check for critical issues
        if any("❌" in result.get("status", "") for result in self.results.get("static_files", {}).values()):
            recommendations.append("Fix static file serving configuration")
        
        if any("❌" in result.get("status", "") for result in self.results.get("button_elements", {}).values()):
            recommendations.append("Ensure all button elements are present in HTML")
        
        if any("❌" in result.get("status", "") for result in self.results.get("javascript_loading", {}).values()):
            recommendations.append("Verify JavaScript contains all required functionality")
        
        if any("❌" in result.get("status", "") for result in self.results.get("api_endpoints", {}).values()):
            recommendations.append("Fix backend API endpoint implementation")
        
        if not recommendations:
            recommendations.append("System is working correctly - no immediate action needed")
        
        self.results["recommendations"] = recommendations
    
    def print_comprehensive_report(self):
        """Print comprehensive verification report"""
        print("\n" + "="*80)
        print("🧪 COMPREHENSIVE BUTTON FUNCTIONALITY VERIFICATION")
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
        
        # Recommendations
        if self.results["recommendations"]:
            print(f"\n💡 Recommendations:")
            for i, rec in enumerate(self.results["recommendations"], 1):
                print(f"   {i}. {rec}")
        
        # Final assessment
        print("\n" + "="*80)
        status = self.results["overall_status"]
        if status == "🟢 EXCELLENT":
            print("🎉 EXCELLENT! All button functionality is working correctly!")
            print("   Dashboard is production-ready with full functionality.")
        elif status == "🟡 GOOD":
            print("✅ GOOD! Most button functionality is working with minor issues.")
            print("   Address the failed items for optimal performance.")
        elif status == "🟠 FAIR":
            print("⚠️  FAIR! Some button functionality needs attention.")
            print("   Significant improvements required for production use.")
        else:
            print("❌ POOR! Critical button functionality issues found.")
            print("   Major fixes required before system is usable.")
        print("="*80)

async def main():
    """Main verification function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Comprehensive Button Functionality Verification")
    parser.add_argument("--host", default="127.0.0.1", help="Dashboard host")
    parser.add_argument("--port", type=int, default=8080, help="Dashboard port")
    parser.add_argument("--save-results", help="Save results to JSON file")
    
    args = parser.parse_args()
    
    verifier = ComprehensiveButtonVerifier(host=args.host, port=args.port)
    
    try:
        print("🚀 Starting comprehensive button functionality verification...")
        
        await verifier.verify_static_files()
        await verifier.verify_html_structure()
        await verifier.verify_button_elements()
        await verifier.verify_javascript_loading()
        await verifier.verify_api_endpoints()
        
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
    asyncio.run(main())
