"""
Payload Template Loader Module for SecureComm C2

This module provides dynamic loading and management of payload templates
from external JSON files, enabling easy customization and extension
of payload capabilities without code modifications.

Author: SecureComm C2 Team
Version: 1.0.0
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)

# Template storage directory
TEMPLATES_DIR = Path(__file__).parent / "payload_templates"


@dataclass
class PayloadCommand:
    """Individual command within a payload template"""
    type: str
    payload: str
    description: str = ""
    timeout: int = 60
    alt_payload: Optional[str] = None
    alt_tools: List[str] = field(default_factory=list)
    max_size: Optional[str] = None


@dataclass
class PayloadTemplate:
    """Enhanced payload template with metadata"""
    id: str
    name: str
    description: str
    version: str
    author: str
    category: str
    platform: str
    risk_level: str
    requires_admin: bool
    commands: List[Dict[str, Any]]
    tags: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    
    # Optional advanced fields
    tools_required: List[str] = field(default_factory=list)
    detection_risk: str = "low"
    persistence_methods: Dict[str, List[str]] = field(default_factory=dict)
    enumeration_areas: List[str] = field(default_factory=list)
    exfiltration_methods: List[str] = field(default_factory=list)
    file_types: Dict[str, List[str]] = field(default_factory=dict)
    encryption: Dict[str, Any] = field(default_factory=dict)
    network_discovery: Dict[str, bool] = field(default_factory=dict)


class PayloadTemplateManager:
    """
    Manager for loading and organizing payload templates
    
    Features:
    - Dynamic template loading from JSON files
    - Template validation and caching
    - Category-based organization
    - Platform filtering
    - Risk level assessment
    """
    
    def __init__(self, templates_dir: Optional[Path] = None):
        self.templates_dir = templates_dir or TEMPLATES_DIR
        self._templates: Dict[str, PayloadTemplate] = {}
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._last_reload: Optional[datetime] = None
        
    def load_all_templates(self) -> Dict[str, PayloadTemplate]:
        """Load all payload templates from the templates directory"""
        self._templates.clear()
        
        if not self.templates_dir.exists():
            logger.warning(f"Templates directory not found: {self.templates_dir}")
            return self._templates
            
        for template_file in self.templates_dir.glob("*.json"):
            try:
                with open(template_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                template = self._parse_template(data)
                self._templates[template.id] = template
                logger.debug(f"Loaded template: {template.id}")
                
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in {template_file}: {e}")
            except Exception as e:
                logger.error(f"Failed to load template {template_file}: {e}")
                
        self._last_reload = datetime.utcnow()
        logger.info(f"Loaded {len(self._templates)} payload templates")
        return self._templates
    
    def _parse_template(self, data: Dict[str, Any]) -> PayloadTemplate:
        """Parse JSON data into PayloadTemplate dataclass"""
        return PayloadTemplate(
            id=data.get('id', 'unknown'),
            name=data.get('name', 'Unnamed Template'),
            description=data.get('description', ''),
            version=data.get('version', '1.0'),
            author=data.get('author', 'Unknown'),
            category=data.get('category', 'general'),
            platform=data.get('platform', 'cross-platform'),
            risk_level=data.get('risk_level', 'low'),
            requires_admin=data.get('requires_admin', False),
            commands=data.get('commands', []),
            tags=data.get('tags', []),
            mitre_techniques=data.get('mitre_techniques', []),
            created_at=data.get('created_at', ''),
            updated_at=data.get('updated_at', ''),
            
            # Optional fields
            tools_required=data.get('tools_required', []),
            detection_risk=data.get('detection_risk', 'low'),
            persistence_methods=data.get('persistence_methods', {}),
            enumeration_areas=data.get('enumeration_areas', []),
            exfiltration_methods=data.get('exfiltration_methods', []),
            file_types=data.get('file_types', {}),
            encryption=data.get('encryption', {}),
            network_discovery=data.get('network_discovery', {})
        )
    
    def get_template(self, template_id: str) -> Optional[PayloadTemplate]:
        """Get a specific template by ID"""
        return self._templates.get(template_id)
    
    def get_all_templates(self) -> Dict[str, PayloadTemplate]:
        """Get all loaded templates"""
        return self._templates.copy()
    
    def get_templates_by_category(self, category: str) -> List[PayloadTemplate]:
        """Get templates filtered by category"""
        return [t for t in self._templates.values() if t.category == category]
    
    def get_templates_by_platform(self, platform: str) -> List[PayloadTemplate]:
        """Get templates filtered by platform compatibility"""
        return [
            t for t in self._templates.values()
            if t.platform == platform or t.platform == 'cross-platform'
        ]
    
    def get_templates_by_risk(self, max_risk: str) -> List[PayloadTemplate]:
        """
        Get templates up to a maximum risk level
        Risk levels: low < medium < high < critical
        """
        risk_order = ['low', 'medium', 'high', 'critical']
        max_index = risk_order.index(max_risk) if max_risk in risk_order else 3
        
        return [
            t for t in self._templates.values()
            if risk_order.index(t.risk_level) <= max_index
        ]
    
    def get_template_summary(self) -> List[Dict[str, Any]]:
        """Get summary information for all templates (for dashboard)"""
        return [
            {
                "id": t.id,
                "name": t.name,
                "description": t.description,
                "category": t.category,
                "platform": t.platform,
                "risk_level": t.risk_level,
                "requires_admin": t.requires_admin,
                "command_count": len(t.commands),
                "tags": t.tags
            }
            for t in self._templates.values()
        ]
    
    def validate_template(self, template_id: str) -> tuple[bool, List[str]]:
        """
        Validate a template's structure and content
        Returns: (is_valid, list_of_errors)
        """
        template = self._templates.get(template_id)
        if not template:
            return False, ["Template not found"]
            
        errors = []
        
        # Check required fields
        if not template.name:
            errors.append("Template name is required")
        if not template.commands:
            errors.append("At least one command is required")
            
        # Validate commands
        for i, cmd in enumerate(template.commands):
            if 'type' not in cmd:
                errors.append(f"Command {i+1}: 'type' is required")
            if 'payload' not in cmd:
                errors.append(f"Command {i+1}: 'payload' is required")
            if cmd.get('type') not in ['exec', 'upload', 'download', 'persist', 'recon', 'sleep', 'exit']:
                errors.append(f"Command {i+1}: invalid type '{cmd.get('type')}'")
                
        return len(errors) == 0, errors
    
    def reload_templates(self) -> Dict[str, PayloadTemplate]:
        """Force reload all templates from disk"""
        logger.info("Reloading payload templates...")
        return self.load_all_templates()
    
    def to_legacy_format(self, template_id: str) -> Optional[Dict[str, Any]]:
        """
        Convert template to legacy format for backward compatibility
        with existing dashboard_server.py code
        """
        template = self._templates.get(template_id)
        if not template:
            return None
            
        # Legacy format only requires these fields
        legacy = {
            "name": template.name,
            "description": template.description,
            "commands": template.commands,
            "requires_admin": template.requires_admin,
            "risk_level": template.risk_level
        }
        
        # Add platform if specified
        if template.platform:
            legacy["platform"] = template.platform
            
        return legacy
    
    def get_legacy_templates_dict(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all templates in legacy format for direct replacement
        of the PAYLOAD_TEMPLATES constant in dashboard_server.py
        """
        return {
            tid: self.to_legacy_format(tid)
            for tid in self._templates.keys()
            if self.to_legacy_format(tid) is not None
        }


# Global template manager instance
template_manager = PayloadTemplateManager()


def load_payload_templates() -> Dict[str, Any]:
    """
    Convenience function to load all templates in legacy format
    Use this as direct replacement for PAYLOAD_TEMPLATES
    """
    manager = PayloadTemplateManager()
    manager.load_all_templates()
    return manager.get_legacy_templates_dict()


def get_enhanced_templates() -> Dict[str, PayloadTemplate]:
    """Get all templates with full metadata"""
    manager = PayloadTemplateManager()
    return manager.load_all_templates()


# Categories for organization
PAYLOAD_CATEGORIES = {
    "reconnaissance": "Information gathering and discovery",
    "credential-access": "Credential theft and harvesting",
    "persistence": "Maintaining access across reboots",
    "exfiltration": "Data theft and transmission",
    "discovery": "System and network enumeration",
    "lateral-movement": "Pivoting to other systems",
    "defense-evasion": "Avoiding detection",
    "general": "General purpose payloads"
}


if __name__ == "__main__":
    # Test loading
    logging.basicConfig(level=logging.INFO)
    manager = PayloadTemplateManager()
    templates = manager.load_all_templates()
    
    print(f"\nLoaded {len(templates)} templates:")
    for tid, template in templates.items():
        print(f"  - {tid}: {template.name} ({template.category}, {template.risk_level} risk)")
