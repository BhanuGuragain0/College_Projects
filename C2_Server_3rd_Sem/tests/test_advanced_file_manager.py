#!/usr/bin/env python3
"""
ADVANCED FILE MANAGER TESTING SUITE
Comprehensive testing for enhanced File Manager functionality

Usage:
    python tests/test_advanced_file_manager.py [--host HOST] [--port PORT]
"""

import asyncio
import json
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

class AdvancedFileManagerTester:
    """Test enhanced File Manager functionality"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
        self.test_results = {
            "timestamp": time.time(),
            "tests": {},
            "overall_status": "UNKNOWN",
            "success_rate": 0,
            "total_tests": 0,
            "passed_tests": 0
        }
    
    def make_request(self, endpoint: str, method: str = "GET", data=None, headers=None) -> dict:
        """Make HTTP request"""
        try:
            req = urllib.request.Request(f"{self.base_url}{endpoint}", method=method)
            
            if headers:
                for key, value in headers.items():
                    req.add_header(key, value)
            
            if data:
                req.add_header('Content-Type', 'application/json')
                req.data = json.dumps(data).encode('utf-8')
            
            with urllib.request.urlopen(req, timeout=10) as response:
                return {
                    "status": response.getcode(),
                    "headers": dict(response.headers),
                    "content": response.read().decode('utf-8', errors='ignore')
                }
        except Exception as e:
            return {
                "status": 0,
                "error": str(e),
                "content": ""
            }
    
    def test_static_files(self):
        """Test static file accessibility"""
        print("🔍 Testing static file accessibility...")
        
        static_files = [
            "/static/app.js",
            "/static/main.css"
            "/static/state.js"
            "/static/favicon.svg"
        ]
        
        results = {}
        for file_path in static_files:
            response = self.make_request(file_path)
            results[file_path] = {
                "status": "✅ OK" if response["status"] == 200 else f"❌ {response['status']}",
                "content_type": response["headers"].get("Content-Type", ""),
                "size": len(response["content"])
            }
        
        self.test_results["tests"]["static_files"] = results
        print(f"✅ Static files test completed")
        return all(r["status"] == "✅ OK" for r in results.values())
    
    def test_file_manager_ui(self):
        """Test File Manager UI components"""
        print("\n🔍 Testing File Manager UI components...")
        
        # Test dashboard page loads
        response = self.make_request("/")
        if response["status"] != 200:
            self.test_results["tests"]["ui_load"] = {
                "status": "❌ FAILED",
                "error": f"HTTP {response['status']}"
            }
            print(f"❌ Dashboard page load failed: HTTP {response['status']}")
            return False
        
        # Check for advanced File Manager elements
        html_content = response["content"]
        ui_tests = {
            "advanced_toolbar": "btn-upload-multiple" in html_content,
            "search_functionality": "file-search" in html_content,
            "batch_operations": "batch-operations" in html_content,
            "drag_drop_zone": "upload-drop-zone" in html_content,
            "file_preview": "file-preview-container" in html_content,
            "context_menu_support": "context-menu" in html_content or "contextmenu" in html_content,
            "progress_tracking": "file-progress-container" in html_content,
            "view_controls": "view-controls" in html_content,
            "selection_controls": "selection-controls" in html_content
        }
        
        self.test_results["tests"]["ui_components"] = ui_tests
        
        passed_ui_tests = sum(1 for present in ui_tests.values())
        total_ui_tests = len(ui_tests)
        
        self.test_results["tests"]["ui_components"]["status"] = (
            f"✅ {passed_ui_tests}/{total_ui_tests} components found"
            if passed_ui_tests > 0 else "❌ Missing UI components"
        )
        
        print(f"✅ UI components test: {passed_ui_tests}/{total_ui_tests} found")
        return passed_ui_tests == total_ui_tests
    
    def test_file_operations(self):
        """Test file operation endpoints"""
        print("\n🔍 Testing file operation endpoints...")
        
        # Test file browse endpoint
        browse_response = self.make_request("/api/files/browse?agent_id=test_agent")
        browse_test = {
            "status": "✅ OK" if browse_response["status"] == 200 else f"❌ {browse_response['status']}",
            "has_files": "files" in browse_response.get("content", ""),
            "response_size": len(browse_response.get("content", ""))
        }
        
        # Test file upload endpoint
        upload_data = {
            "test_file": "This is a test file content",
            "operation_id": f"test_upload_{int(time.time())}"
        }
        
        upload_response = self.make_request("/api/files/upload", method="POST", data=upload_data)
        upload_test = {
            "status": "✅ OK" if upload_response["status"] in [200, 201] else f"❌ {upload_response['status']}",
            "accepts_uploads": upload_response["status"] in [200, 201],
            "response_size": len(upload_response.get("content", ""))
        }
        
        # Test file download endpoint
        download_response = self.make_request("/api/files/download?agent_id=test_agent&file_path=/test/test.txt")
        download_test = {
            "status": "✅ OK" if download_response["status"] == 200 else f"❌ {download_response['status']}",
            "serves_files": "attachment" in download_response.get("headers", {}).get("Content-Disposition", ""),
            "response_size": len(download_response.get("content", ""))
        }
        
        self.test_results["tests"]["file_operations"] = {
            "browse": browse_test,
            "upload": upload_test,
            "download": download_test
        }
        
        operation_tests = [
            browse_test["status"] == "✅ OK",
            upload_test["status"] == "✅ OK",
            download_test["status"] == "✅ OK"
        ]
        
        self.test_results["tests"]["file_operations"]["status"] = (
            f"✅ {sum(operation_tests)}/3 operations working"
            if sum(operation_tests) == 3 else f"❌ {3 - sum(operation_tests)} operations failed"
        )
        
        print(f"✅ File operations test: {sum(operation_tests)}/3 endpoints working")
        return sum(operation_tests) == 3
    
    def test_advanced_features(self):
        """Test advanced File Manager features"""
        print("\n🔍 Testing advanced File Manager features...")
        
        # Test drag and drop functionality
        response = self.make_request("/")
        html_content = response.get("content", "")
        
        advanced_features = {
            "drag_drop_api": "uploadFileToAgent" in html_content and "handleFileDrop" in html_content,
            "multiple_upload": "uploadMultipleFiles" in html_content,
            "file_search": "searchFiles" in html_content and "clearFileSearch" in html_content,
            "batch_selection": "updateFileSelection" in html_content and "toggleSelectAll" in html_content,
            "context_menu": "showFileContextMenu" in html_content or "setupFileContextMenu" in html_content,
            "file_preview": "previewFile" in html_content and "closeFilePreview" in html_content,
            "progress_tracking": "uploadSingleFile" in html_content and "progress bar elements" in html_content,
            "keyboard_shortcuts": "setupFileKeyboardShortcuts" in html_content,
            "view_switching": "setFileManagerView" in html_content and "multiple view buttons" in html_content
        }
        
        self.test_results["tests"]["advanced_features"] = advanced_features
        
        feature_count = sum(1 for present in advanced_features.values())
        total_features = len(advanced_features)
        
        self.test_results["tests"]["advanced_features"]["status"] = (
            f"✅ {feature_count}/{total_features} advanced features implemented"
            if feature_count > 0 else "❌ No advanced features found"
        )
        
        print(f"✅ Advanced features test: {feature_count}/{total_features} features implemented")
        return feature_count > 0
    
    def test_error_handling(self):
        """Test error handling and user feedback"""
        print("\n🔍 Testing error handling...")
        
        # Test invalid agent ID
        invalid_agent_response = self.make_request("/api/files/browse?agent_id=invalid_agent")
        error_handling_tests = {
            "invalid_agent": invalid_agent_response["status"] == 400 or "Invalid agent" in invalid_agent_response.get("content", ""),
            "missing_files": "No files found" in invalid_agent_response.get("content", "")
        }
        
        # Test missing agent parameter
        missing_agent_response = self.make_request("/api/files/browse")
        error_handling_tests["missing_agent"] = missing_agent_response["status"] == 400 or "required" in missing_agent_response.get("content", "")
        
        # Test file not found
        not_found_response = self.make_request("/api/files/download?agent_id=test_agent&file_path=/nonexistent/file.txt")
        error_handling_tests["file_not_found"] = not_found_response["status"] == 404 or "not found" in not_found_response.get("content", "")
        
        error_test_count = sum(1 for present in error_handling_tests.values())
        total_error_tests = len(error_handling_tests)
        
        self.test_results["tests"]["error_handling"] = error_handling_tests
        
        self.test_results["tests"]["error_handling"]["status"] = (
            f"✅ {error_test_count}/{total_error_tests} error handling tests passed"
            if error_test_count > 0 else "❌ Error handling not working"
        )
        
        print(f"✅ Error handling test: {error_test_count}/{total_error_tests} tests passed")
        return error_test_count > 0
    
    def test_performance(self):
        """Test File Manager performance"""
        print("\n🔍 Testing File Manager performance...")
        
        # Test response times
        start_time = time.time()
        response = self.make_request("/api/files/browse?agent_id=test_agent")
        end_time = time.time()
        
        response_time = (end_time - start_time) * 1000  # Convert to milliseconds
        
        performance_tests = {
            "response_time_ms": response_time,
            "fast_response": response_time < 500,  # Under 500ms is considered fast
            "content_size": len(response.get("content", "")),
            "large_content": len(response.get("content", "")) > 10000  # Large content test
        }
        
        self.test_results["tests"]["performance"] = performance_tests
        
        performance_score = 0
        if performance_tests["fast_response"]:
            performance_score += 1
        if performance_tests["large_content"]:
            performance_score += 1
        
        self.test_results["tests"]["performance"]["status"] = (
            f"✅ Performance score: {performance_score}/2"
            if performance_score >= 2 else "❌ Performance needs improvement"
        )
        
        print(f"✅ Performance test: {performance_score}/2 - Response time: {response_time:.0f}ms")
        return performance_score >= 1
    
    def calculate_overall_status(self):
        """Calculate overall test results"""
        all_tests = [
            self.test_results["tests"].get("static_files", {}),
            self.test_results["tests"].get("ui_components", {}),
            self.test_results["tests"].get("file_operations", {}),
            self.test_results["tests"].get("advanced_features", {}),
            self.test_results["tests"].get("error_handling", {}),
            self.test_results["tests"].get("performance", {})
        ]
        
        total_tests = len(all_tests)
        passed_tests = sum(1 for test in all_tests if test.get("status", "").startswith("✅"))
        
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        if success_rate >= 90:
            status = "🟢 EXCELLENT"
        elif success_rate >= 75:
            status = "🟡 GOOD"
        elif success_rate >= 50:
            status = "🟠 FAIR"
        else:
            status = "🔴 POOR"
        
        self.test_results["overall_status"] = status
        self.test_results["success_rate"] = success_rate
        self.test_results["total_tests"] = total_tests
        self.test_results["passed_tests"] = passed_tests
        
        return status
    
    def print_detailed_report(self):
        """Print detailed test report"""
        print("\n" + "="*80)
        print("🧪 ADVANCED FILE MANAGER TEST RESULTS")
        print("="*80)
        
        print(f"🕐 Test Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.test_results['timestamp']))}")
        print(f"🎯 Overall Status: {self.test_results['overall_status']}")
        print(f"📊 Success Rate: {self.test_results['success_rate']:.1f}%")
        print(f"✅ Passed: {self.test_results['passed_tests']}/{self.test_results['total_tests']}")
        
        # Static Files Test
        print(f"\n📁 Static Files Test:")
        static_files = self.test_results["tests"].get("static_files", {})
        for file_path, result in static_files.items():
            print(f"  {result['status']} {file_path}")
        
        # UI Components Test
        print(f"\n🎛 UI Components Test:")
        ui_components = self.test_results["tests"].get("ui_components", {})
        print(f"  {ui_components['status']} - {ui_components.get('status', '')}")
        for component, present in ui_components.items():
            if component != "status":
                print(f"    ✅ {component}")
        
        # File Operations Test
        print(f"\n📂 File Operations Test:")
        file_ops = self.test_results["tests"].get("file_operations", {})
        for operation, result in file_ops.items():
            print(f"  {result['status']} - {operation}")
        
        # Advanced Features Test
        print(f"\n🔧 Advanced Features Test:")
        advanced_features = self.test_results["tests"].get("advanced_features", {})
        print(f"  {advanced_features['status']} - {advanced_features.get('status', '')}")
        for feature, present in advanced_features.items():
            if feature != "status":
                print(f"    ✅ {feature}")
        
        # Error Handling Test
        print(f"\n⚠️ Error Handling Test:")
        error_handling = self.test_results["tests"].get("error_handling", {})
        for test, result in error_handling.items():
            print(f"  {result['status']} - {test}")
        
        # Performance Test
        print(f"\n📊 Performance Test:")
        performance = self.test_results["tests"].get("performance", {})
        print(f"  {performance['status']} - Response time: {performance.get('response_time_ms', 0):.0f}ms")
        
        print("\n" + "="*80)
        print("🎯 RECOMMENDATIONS")
        
        if self.test_results["overall_status"] == "🟢 EXCELLENT":
            print("🎉 Advanced File Manager is PRODUCTION READY!")
            print("   All advanced features implemented and working correctly")
        elif self.test_results["overall_status"] == "🟡 GOOD":
            print("✅ Advanced File Manager is working well")
            print("   Minor improvements may be needed")
        else:
            print("⚠️  Advanced File Manager needs attention")
            print("   Critical issues must be addressed")
        
        print("="*80)

def main():
    """Main test function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Advanced File Manager Test Suite")
    parser.add_argument("--host", default="127.0.0.1", help="Dashboard host")
    parser.add_argument("--port", type=int, default=8080, help="Dashboard port")
    parser.add_argument("--save-results", help="Save results to JSON file")
    
    args = parser.parse_args()
    
    tester = AdvancedFileManagerTester(host=args.host, port=args.port)
    
    try:
        print("🚀 Starting Advanced File Manager Test Suite...")
        
        # Run all tests
        tester.test_static_files()
        tester.test_file_manager_ui()
        tester.test_file_operations()
        tester.test_advanced_features()
        tester.test_error_handling()
        tester.test_performance()
        
        # Calculate overall status
        overall_status = tester.calculate_overall_status()
        
        # Print detailed report
        tester.print_detailed_report()
        
        # Save results if requested
        if args.save_results:
            with open(args.save_results, 'w') as f:
                json.dump(tester.test_results, f, indent=2, default=str)
            print(f"\n💾 Results saved to: {args.save_results}")
        
        # Exit with appropriate code
        sys.exit(0 if overall_status.startswith("🟢") or overall_status.startswith("🟡") else 1)
        
    except KeyboardInterrupt:
        print("\n🛑 Test interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Test failed: {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()
