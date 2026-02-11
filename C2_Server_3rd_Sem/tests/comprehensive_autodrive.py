#!/usr/bin/env python3
"""
Comprehensive Autodrive Test Suite
Combines enhanced_autodrive.py and autodrive.py with additional features

Usage:
    python tests/comprehensive_autodrive.py [--verbose] [--skip-server-start] [--host HOST] [--port PORT]
"""

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent))

from enhanced_autodrive import EnhancedAutodriveTestRunner
from autodrive import AutodriveTestRunner

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("ComprehensiveAutoDrive")

class ComprehensiveAutodriveTestRunner:
    """Comprehensive test runner that combines both autodrive suites"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8080, skip_server_start: bool = False):
        self.host = host
        self.port = port
        self.skip_server_start = skip_server_start
        self.results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "test_suites": {},
            "overall_passed": 0,
            "overall_failed": 0,
            "overall_total": 0,
            "success_rate": 0.0,
            "system_grade": "F",
            "recommendations": [],
        }
    
    async def run_comprehensive_tests(self):
        """Run both autodrive test suites"""
        logger.info("\n" + "="*80)
        logger.info("🧪 COMPREHENSIVE AUTODRIVE TEST SUITE")
        logger.info("="*80 + "\n")
        
        # Run Enhanced Autodrive Tests
        logger.info("🚀 Running Enhanced Autodrive Tests...")
        enhanced_runner = EnhancedAutodriveTestRunner(
            host=self.host, 
            port=self.port, 
            skip_server_start=self.skip_server_start
        )
        
        try:
            enhanced_results = await enhanced_runner.run_enhanced_tests()
            self.results["test_suites"]["enhanced_autodrive"] = enhanced_results
            logger.info("✅ Enhanced Autodrive Tests completed")
        except Exception as e:
            logger.error(f"❌ Enhanced Autodrive Tests failed: {e}")
            self.results["test_suites"]["enhanced_autodrive"] = {
                "error": str(e),
                "passed": 0,
                "failed": 1,
                "total": 1
            }
        
        # Skip server start for second suite since server is already running
        logger.info("🚀 Running Standard Autodrive Tests...")
        standard_runner = AutodriveTestRunner(
            host=self.host,
            port=self.port,
            skip_server_start=True  # Server already running
        )
        
        try:
            standard_results = await standard_runner.run_tests()
            self.results["test_suites"]["standard_autodrive"] = standard_results
            logger.info("✅ Standard Autodrive Tests completed")
        except Exception as e:
            logger.error(f"❌ Standard Autodrive Tests failed: {e}")
            self.results["test_suites"]["standard_autodrive"] = {
                "error": str(e),
                "passed": 0,
                "failed": 1,
                "total": 1
            }
        
        # Calculate overall results
        self._calculate_overall_results()
        
        # Generate recommendations
        self._generate_recommendations()
        
        return self.results
    
    def _calculate_overall_results(self):
        """Calculate overall test results"""
        total_passed = 0
        total_failed = 0
        total_tests = 0
        
        for suite_name, suite_results in self.results["test_suites"].items():
            if "error" in suite_results:
                total_failed += 1
                total_tests += 1
            else:
                total_passed += suite_results.get("passed", 0)
                total_failed += suite_results.get("failed", 0)
                total_tests += suite_results.get("total", 0)
        
        self.results["overall_passed"] = total_passed
        self.results["overall_failed"] = total_failed
        self.results["overall_total"] = total_tests
        
        if total_tests > 0:
            self.results["success_rate"] = (total_passed / total_tests) * 100
        
        # Calculate system grade
        success_rate = self.results["success_rate"]
        if success_rate >= 95:
            self.results["system_grade"] = "A+"
        elif success_rate >= 90:
            self.results["system_grade"] = "A"
        elif success_rate >= 85:
            self.results["system_grade"] = "B+"
        elif success_rate >= 80:
            self.results["system_grade"] = "B"
        elif success_rate >= 75:
            self.results["system_grade"] = "C+"
        elif success_rate >= 70:
            self.results["system_grade"] = "C"
        elif success_rate >= 65:
            self.results["system_grade"] = "D+"
        elif success_rate >= 60:
            self.results["system_grade"] = "D"
        else:
            self.results["system_grade"] = "F"
    
    def _generate_recommendations(self):
        """Generate system recommendations based on test results"""
        recommendations = []
        
        # Check enhanced suite results
        enhanced_results = self.results["test_suites"].get("enhanced_autodrive", {})
        if "missing_features" in enhanced_results:
            missing_features = enhanced_results["missing_features"]
            if missing_features:
                recommendations.append(f"Implement missing features: {', '.join(missing_features)}")
        
        # Check API endpoint failures
        if "api_endpoints" in enhanced_results:
            failed_endpoints = [name for name, result in enhanced_results["api_endpoints"].items() 
                              if not result.get("passed", False)]
            if failed_endpoints:
                recommendations.append(f"Fix failing API endpoints: {', '.join(failed_endpoints)}")
        
        # Check workflow failures
        if "workflows" in enhanced_results:
            failed_workflows = [name for name, result in enhanced_results["workflows"].items() 
                              if not result.get("complete", False)]
            if failed_workflows:
                recommendations.append(f"Fix workflow issues: {', '.join(failed_workflows)}")
        
        # Check security issues
        if "security_tests" in enhanced_results:
            security_issues = [name for name, result in enhanced_results["security_tests"].items() 
                             if not result.get("complete", False)]
            if security_issues:
                recommendations.append(f"Address security issues: {', '.join(security_issues)}")
        
        # Check success rate
        success_rate = self.results["success_rate"]
        if success_rate < 90:
            recommendations.append("System needs significant improvements to reach production quality")
        elif success_rate < 95:
            recommendations.append("System has minor issues that should be addressed for optimal performance")
        
        if not recommendations:
            recommendations.append("System is performing excellently! Ready for production deployment.")
        
        self.results["recommendations"] = recommendations
    
    def print_comprehensive_summary(self):
        """Print comprehensive test summary"""
        print("\n" + "="*80)
        print("📊 COMPREHENSIVE AUTODRIVE TEST SUMMARY")
        print("="*80)
        
        print(f"🕐 Timestamp: {self.results['timestamp']}")
        print(f"🎯 Overall Success Rate: {self.results['success_rate']:.1f}%")
        print(f"📈 System Grade: {self.results['system_grade']}")
        print(f"✅ Total Passed: {self.results['overall_passed']}")
        print(f"❌ Total Failed: {self.results['overall_failed']}")
        print(f"📊 Total Tests: {self.results['overall_total']}")
        
        # Suite breakdowns
        print("\n📋 TEST SUITE BREAKDOWN:")
        for suite_name, suite_results in self.results["test_suites"].items():
            print(f"\n🔸 {suite_name.replace('_', ' ').title()}:")
            if "error" in suite_results:
                print(f"   ❌ ERROR: {suite_results['error']}")
            else:
                success_rate = (suite_results.get("passed", 0) / max(suite_results.get("total", 1), 1)) * 100
                print(f"   ✅ Passed: {suite_results.get('passed', 0)}")
                print(f"   ❌ Failed: {suite_results.get('failed', 0)}")
                print(f"   📊 Success Rate: {success_rate:.1f}%")
                
                # Show key metrics for enhanced suite
                if suite_name == "enhanced_autodrive" and "api_endpoints" in suite_results:
                    endpoints = suite_results["api_endpoints"]
                    passed_endpoints = sum(1 for e in endpoints.values() if e.get("passed", False))
                    print(f"   🔗 API Endpoints: {passed_endpoints}/{len(endpoints)} working")
                
                if suite_name == "enhanced_autodrive" and "workflows" in suite_results:
                    workflows = suite_results["workflows"]
                    passed_workflows = sum(1 for w in workflows.values() if w.get("complete", False))
                    print(f"   🔄 Workflows: {passed_workflows}/{len(workflows)} working")
        
        # Recommendations
        print("\n💡 RECOMMENDATIONS:")
        for i, rec in enumerate(self.results["recommendations"], 1):
            print(f"   {i}. {rec}")
        
        # Final assessment
        print("\n" + "="*80)
        grade = self.results["system_grade"]
        if grade in ["A+", "A"]:
            print("🎉 EXCELLENT! System is production-ready with exceptional quality!")
        elif grade in ["B+", "B"]:
            print("✅ GOOD! System is mostly ready with minor improvements needed.")
        elif grade in ["C+", "C"]:
            print("⚠️  AVERAGE! System needs significant improvements before production.")
        elif grade in ["D+", "D"]:
            print("🚨 BELOW AVERAGE! System has major issues that must be addressed.")
        else:
            print("❌ CRITICAL! System is not ready and requires major fixes.")
        print("="*80)

async def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Comprehensive SecureComm Autodrive Test Suite")
    parser.add_argument("--host", default="127.0.0.1", help="Dashboard host")
    parser.add_argument("--port", type=int, default=8080, help="Dashboard port")
    parser.add_argument("--skip-server-start", action="store_true", help="Skip server startup")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--save-results", help="Save results to JSON file")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    runner = ComprehensiveAutodriveTestRunner(
        host=args.host,
        port=args.port,
        skip_server_start=args.skip_server_start
    )
    
    try:
        results = await runner.run_comprehensive_tests()
        runner.print_comprehensive_summary()
        
        if args.save_results:
            with open(args.save_results, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\n💾 Results saved to: {args.save_results}")
        
        # Exit with appropriate code
        if results["success_rate"] >= 90:
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
