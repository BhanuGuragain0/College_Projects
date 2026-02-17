#!/usr/bin/env python3
"""
Payload Template Audit & Validation Script
Pre-presentation checklist for 95+ mark assurance

Usage: python3 audit_templates.py
"""

import json
import sys
from pathlib import Path
from typing import List, Dict, Tuple

# Colors for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'
BOLD = '\033[1m'

TEMPLATES_DIR = Path(__file__).parent / "payload_templates"

def print_header(text: str):
    print(f"\n{BOLD}{BLUE}{'='*60}{RESET}")
    print(f"{BOLD}{BLUE}{text.center(60)}{RESET}")
    print(f"{BOLD}{BLUE}{'='*60}{RESET}\n")

def print_success(text: str):
    print(f"{GREEN}✓{RESET} {text}")

def print_error(text: str):
    print(f"{RED}✗{RESET} {text}")

def print_warning(text: str):
    print(f"{YELLOW}⚠{RESET} {text}")

def validate_json_structure(data: Dict, filename: str) -> Tuple[bool, List[str]]:
    """Validate template has all required fields"""
    errors = []
    required_fields = ['id', 'name', 'description', 'version', 'category', 'platform', 'risk_level', 'commands']
    
    for field in required_fields:
        if field not in data:
            errors.append(f"Missing required field: {field}")
    
    # Validate commands structure
    if 'commands' in data:
        if not isinstance(data['commands'], list):
            errors.append("'commands' must be a list")
        else:
            for i, cmd in enumerate(data['commands']):
                if 'type' not in cmd:
                    errors.append(f"Command {i+1}: missing 'type'")
                if 'payload' not in cmd:
                    errors.append(f"Command {i+1}: missing 'payload'")
    
    return len(errors) == 0, errors

def check_mitre_mapping(data: Dict) -> bool:
    """Check if template has MITRE ATT&CK mapping"""
    return 'mitre_techniques' in data and len(data.get('mitre_techniques', [])) > 0

def check_academic_completeness(data: Dict) -> Tuple[bool, List[str]]:
    """Check academic documentation completeness"""
    recommendations = []
    
    if 'tags' not in data or len(data.get('tags', [])) < 3:
        recommendations.append("Add more descriptive tags (aim for 3-5)")
    
    if 'created_at' not in data or 'updated_at' not in data:
        recommendations.append("Add created_at and updated_at timestamps")
    
    if 'author' not in data:
        recommendations.append("Add author attribution")
    
    if 'version' not in data:
        recommendations.append("Add version number")
    
    return len(recommendations) == 0, recommendations

def run_audit():
    print_header("PAYLOAD TEMPLATE AUDIT - ACADEMIC PRESENTATION READINESS")
    
    # Find all JSON templates
    template_files = list(TEMPLATES_DIR.glob("*.json"))
    print(f"Found {len(template_files)} template files:\n")
    
    total_score = 0
    max_score = len(template_files) * 100
    issues_found = []
    
    for template_file in sorted(template_files):
        filename = template_file.name
        print(f"{BOLD}Auditing: {filename}{RESET}")
        
        try:
            with open(template_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            print_success("Valid JSON syntax")
            
            # Validate structure
            is_valid, errors = validate_json_structure(data, filename)
            if is_valid:
                print_success("Required fields present")
                score = 70  # Base score for valid structure
            else:
                print_error("Structure validation failed:")
                for error in errors:
                    print(f"  - {error}")
                score = 30
                issues_found.append(f"{filename}: Structure errors")
            
            # Check MITRE mapping
            if check_mitre_mapping(data):
                print_success("MITRE ATT&CK mapping present")
                score += 15
            else:
                print_warning("Missing MITRE ATT&CK techniques")
                score -= 10
                issues_found.append(f"{filename}: No MITRE mapping")
            
            # Check academic completeness
            is_complete, recommendations = check_academic_completeness(data)
            if is_complete:
                print_success("Academic documentation complete")
                score += 15
            else:
                print_warning("Academic improvements recommended:")
                for rec in recommendations:
                    print(f"  - {rec}")
                score += 5
            
            # Special features check
            special_features = []
            if 'demo_phases' in data:
                special_features.append("Demo phases")
            if 'ai_capabilities' in data:
                special_features.append("AI/ML features")
            if 'cloud_targets' in data:
                special_features.append("Cloud targeting")
            if 'evasion_methods' in data:
                special_features.append("Evasion techniques")
            if 'defense_categories' in data:
                special_features.append("Defense framework")
            
            if special_features:
                print_success(f"Advanced features: {', '.join(special_features)}")
                score += 10
            
            total_score += min(score, 100)
            print(f"\n  Score: {min(score, 100)}/100\n")
            
        except json.JSONDecodeError as e:
            print_error(f"Invalid JSON: {e}")
            issues_found.append(f"{filename}: JSON parse error")
            total_score += 0
        except Exception as e:
            print_error(f"Error processing: {e}")
            issues_found.append(f"{filename}: Processing error")
            total_score += 0
    
    # Final summary
    print_header("AUDIT SUMMARY")
    
    average_score = total_score / len(template_files) if template_files else 0
    
    print(f"Total Templates: {len(template_files)}")
    print(f"Average Score: {average_score:.1f}/100")
    print(f"Grade Estimate: ", end="")
    
    if average_score >= 95:
        print(f"{GREEN}{BOLD}A+ (95-100) - EXCELLENT{RESET}")
        print("\n✅ Ready for presentation!")
    elif average_score >= 85:
        print(f"{GREEN}A (85-94) - VERY GOOD{RESET}")
        print("\n⚠️  Minor improvements needed")
    elif average_score >= 75:
        print(f"{YELLOW}B (75-84) - GOOD{RESET}")
        print("\n⚠️  Several improvements needed")
    else:
        print(f"{RED}C or below (<75) - NEEDS WORK{RESET}")
        print("\n❌ Significant issues must be fixed")
    
    if issues_found:
        print(f"\n{BOLD}Issues to Address:{RESET}")
        for issue in issues_found[:10]:  # Show first 10
            print(f"  - {issue}")
        if len(issues_found) > 10:
            print(f"  ... and {len(issues_found) - 10} more")
    
    # Pre-presentation checklist
    print_header("PRE-PRESENTATION CHECKLIST")
    
    checklist = [
        ("VM Environment Prepared", "Ensure VM has realistic data/credentials"),
        ("Demo Script Ready", "Test demo_orchestrator_2026 template"),
        ("Defense Points Ready", "Review detection_mitigation_framework"),
        ("Presentation Slides", "Include MITRE ATT&CK mappings"),
        ("Time Management", "15-min demo fits presentation slot"),
        ("Backup Plan", "Have screenshots in case live demo fails"),
        ("Network Isolated", "Ensure lab network doesn't touch production"),
        ("Legal/Ethical Statement", "Include 'for educational purposes only'"),
    ]
    
    for item, note in checklist:
        print(f"{YELLOW}□{RESET} {item}")
        print(f"      {BLUE}Note:{RESET} {note}")
    
    print_header("RECOMMENDATIONS FOR 95+ MARKS")
    
    recommendations = [
        "1. Open with defense-in-depth explanation",
        "2. Show attack, then show detection, then show mitigation",
        "3. Reference specific MITRE ATT&CK techniques (T1082, T1003, etc.)",
        "4. Demonstrate both Windows and Linux attacks",
        "5. Include cloud/container attack scenarios (modern context)",
        "6. Discuss real-world case studies (SolarWinds, Kaseya, etc.)",
        "7. Show how SecureComm C2 orchestrates the attacks",
        "8. End with 'lessons learned' and future work",
        "9. Handle Q&A professionally - show deep understanding",
        "10. Have clean, professional documentation ready",
    ]
    
    for rec in recommendations:
        print(f"{GREEN}★{RESET} {rec}")
    
    print(f"\n{BOLD}Final Grade Estimate: {average_score:.0f}/100{RESET}\n")
    
    return 0 if average_score >= 85 else 1

if __name__ == "__main__":
    sys.exit(run_audit())
