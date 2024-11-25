"""
vectors/storage_validator.py - Vector storage security validation
"""

import numpy as np
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
from collections import defaultdict
from ..core.logger import SecurityLogger
from ..core.exceptions import SecurityError

class StorageRisk(Enum):
    """Types of vector storage risks"""
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_CORRUPTION = "data_corruption"
    INDEX_MANIPULATION = "index_manipulation"
    VERSION_MISMATCH = "version_mismatch"
    INTEGRITY_VIOLATION = "integrity_violation"
    ENCRYPTION_WEAKNESS = "encryption_weakness"
    BACKUP_FAILURE = "backup_failure"

@dataclass
class StorageMetadata:
    """Metadata for vector storage"""
    storage_type: str
    vector_count: int
    dimension: int
    created_at: datetime
    updated_at: datetime
    version: str
    checksum: str
    encryption_info: Optional[Dict[str, Any]] = None

@dataclass
class ValidationRule:
    """Validation rule definition"""
    name: str
    description: str
    severity: int  # 1-10
    check_function: str
    parameters: Dict[str, Any]

@dataclass
class ValidationResult:
    """Result of storage validation"""
    is_valid: bool
    risks: List[StorageRisk]
    violations: List[str]
    recommendations: List[str]
    metadata: Dict[str, Any]

class StorageValidator:
    """Validator for vector storage security"""
    
    def __init__(self, security_logger: Optional[SecurityLogger] = None):
        self.security_logger = security_logger
        self.validation_rules = self._initialize_validation_rules()
        self.security_checks = self._initialize_security_checks()
        self.validation_history: List[ValidationResult] = []

    def _initialize_validation_rules(self) -> Dict[str, ValidationRule]:
        """Initialize validation rules"""
        return {
            "access_control": ValidationRule(
                name="access_control",
                description="Validate access control mechanisms",
                severity=9,
                check_function="check_access_control",
                parameters={
                    "required_mechanisms": [
                        "authentication",
                        "authorization",
                        "encryption"
                    ]
                }
            ),
            "data_integrity": ValidationRule(
                name="data_integrity",
                description="Validate data integrity",
                severity=8,
                check_function="check_data_integrity",
                parameters={
                    "checksum_algorithm": "sha256",
                    "verify_frequency": 3600  # seconds
                }
            ),
            "index_security": ValidationRule(
                name="index_security",
                description="Validate index security",
                severity=7,
                check_function="check_index_security",
                parameters={
                    "max_index_age": 86400,  # seconds
                    "required_backups": 2
                }
            ),
            "version_control": ValidationRule(
                name="version_control",
                description="Validate version control",
                severity=6,
                check_function="check_version_control",
                parameters={
                    "version_format": r"\d+\.\d+\.\d+",
                    "max_versions": 5
                }
            ),
            "encryption_strength": ValidationRule(
                name="encryption_strength",
                description="Validate encryption mechanisms",
                severity=9,
                check_function="check_encryption_strength",
                parameters={
                    "min_key_size": 256,
                    "allowed_algorithms": [
                        "AES-256-GCM",
                        "ChaCha20-Poly1305"
                    ]
                }
            )
        }

    def _initialize_security_checks(self) -> Dict[str, Any]:
        """Initialize security checks"""
        return {
            "backup_validation": {
                "max_age": 86400,  # 24 hours in seconds
                "min_copies": 2,
                "verify_integrity": True
            },
            "corruption_detection": {
                "checksum_interval": 3600,  # 1 hour in seconds
                "dimension_check": True,
                "norm_check": True
            },
            "access_patterns": {
                "max_rate": 1000,  # requests per hour
                "concurrent_limit": 10,
                "require_auth": True
            }
        }

    def validate_storage(self, 
                        metadata: StorageMetadata,
                        vectors: Optional[np.ndarray] = None,
                        context: Optional[Dict[str, Any]] = None) -> ValidationResult:
        """Validate vector storage security"""
        try:
            violations = []
            risks = []
            recommendations = []

            # Check access control
            access_result = self._check_access_control(metadata, context)
            self._process_check_result(
                access_result, violations, risks, recommendations
            )

            # Check data integrity
            integrity_result = self._check_data_integrity(metadata, vectors)
            self._process_check_result(
                integrity_result, violations, risks, recommendations
            )

            # Check index security
            index_result = self._check_index_security(metadata, context)
            self._process_check_result(
                index_result, violations, risks, recommendations
            )

            # Check version control
            version_result = self._check_version_control(metadata)
            self._process_check_result(
                version_result, violations, risks, recommendations
            )

            # Check encryption
            encryption_result = self._check_encryption_strength(metadata)
            self._process_check_result(
                encryption_result, violations, risks, recommendations
            )

            result = ValidationResult(
                is_valid=len(violations) == 0,
                risks=list(set(risks)),
                violations=violations,
                recommendations=list(set(recommendations)),
                metadata={
                    "timestamp": datetime.utcnow().isoformat(),
                    "storage_type": metadata.storage_type,
                    "vector_count": metadata.vector_count,
                    "checks_performed": [
                        rule.name for rule in self.validation_rules.values()
                    ]
                }
            )

            if not result.is_valid and self.security_logger:
                self.security_logger.log_security_event(
                    "storage_validation_failure",
                    risks=[r.value for r in risks],
                    violations=violations,
                    storage_type=metadata.storage_type
                )

            self.validation_history.append(result)
            return result

        except Exception as e:
            if self.security_logger:
                self.security_logger.log_security_event(
                    "storage_validation_error",
                    error=str(e)
                )
            raise SecurityError(f"Storage validation failed: {str(e)}")

    def _check_access_control(self, 
                            metadata: StorageMetadata,
                            context: Optional[Dict[str, Any]]) -> Tuple[List[str], List[StorageRisk]]:
        """Check access control mechanisms"""
        violations = []
        risks = []
        
        # Get rule parameters
        rule = self.validation_rules["access_control"]
        required_mechanisms = rule.parameters["required_mechanisms"]
        
        # Check context for required mechanisms
        if context:
            for mechanism in required_mechanisms:
                if mechanism not in context:
                    violations.append(
                        f"Missing required access control mechanism: {mechanism}"
                    )
                    risks.append(StorageRisk.UNAUTHORIZED_ACCESS)
                    
            # Check authentication
            if context.get("authentication") == "none":
                violations.append("No authentication mechanism configured")
                risks.append(StorageRisk.UNAUTHORIZED_ACCESS)
                
            # Check encryption
            if not context.get("encryption", {}).get("enabled", False):
                violations.append("Storage encryption not enabled")
                risks.append(StorageRisk.ENCRYPTION_WEAKNESS)
        else:
            violations.append("No access control context provided")
            risks.append(StorageRisk.UNAUTHORIZED_ACCESS)
            
        return violations, risks

    def _check_data_integrity(self, 
                            metadata: StorageMetadata,
                            vectors: Optional[np.ndarray]) -> Tuple[List[str], List[StorageRisk]]:
        """Check data integrity"""
        violations = []
        risks = []
        
        # Verify metadata checksum
        if not self._verify_checksum(metadata):
            violations.append("Metadata checksum verification failed")
            risks.append(StorageRisk.INTEGRITY_VIOLATION)
        
        # Check vectors if provided
        if vectors is not None:
            # Check dimensions
            if len(vectors.shape) != 2:
                violations.append("Invalid vector dimensions")
                risks.append(StorageRisk.DATA_CORRUPTION)
            
            if vectors.shape[1] != metadata.dimension:
                violations.append("Vector dimension mismatch")
                risks.append(StorageRisk.DATA_CORRUPTION)
            
            # Check for NaN or Inf values
            if np.any(np.isnan(vectors)) or np.any(np.isinf(vectors)):
                violations.append("Vectors contain invalid values")
                risks.append(StorageRisk.DATA_CORRUPTION)
            
        return violations, risks

    def _check_index_security(self, 
                            metadata: StorageMetadata,
                            context: Optional[Dict[str, Any]]) -> Tuple[List[str], List[StorageRisk]]:
        """Check index security"""
        violations = []
        risks = []
        
        rule = self.validation_rules["index_security"]
        max_age = rule.parameters["max_index_age"]
        required_backups = rule.parameters["required_backups"]
        
        # Check index age
        if context and "index_timestamp" in context:
            index_age = (datetime.utcnow() - 
                        datetime.fromisoformat(context["index_timestamp"])).total_seconds()
            if index_age > max_age:
                violations.append("Index is too old")
                risks.append(StorageRisk.INDEX_MANIPULATION)
        
        # Check backup configuration
        if context and "backups" in context:
            if len(context["backups"]) < required_backups:
                violations.append("Insufficient backup copies")
                risks.append(StorageRisk.BACKUP_FAILURE)
                
            # Check backup freshness
            for backup in context["backups"]:
                if not self._verify_backup(backup):
                    violations.append("Backup verification failed")
                    risks.append(StorageRisk.BACKUP_FAILURE)
                    
        return violations, risks

    def _check_version_control(self, 
                             metadata: StorageMetadata) -> Tuple[List[str], List[StorageRisk]]:
        """Check version control"""
        violations = []
        risks = []
        
        rule = self.validation_rules["version_control"]
        version_pattern = rule.parameters["version_format"]
        
        # Check version format
        if not re.match(version_pattern, metadata.version):
            violations.append("Invalid version format")
            risks.append(StorageRisk.VERSION_MISMATCH)
        
        # Check version compatibility
        if not self._check_version_compatibility(metadata.version):
            violations.append("Version compatibility check failed")
            risks.append(StorageRisk.VERSION_MISMATCH)
            
        return violations, risks

    def _check_encryption_strength(self, 
                                 metadata: StorageMetadata) -> Tuple[List[str], List[StorageRisk]]:
        """Check encryption mechanisms"""
        violations = []
        risks = []
        
        rule = self.validation_rules["encryption_strength"]
        min_key_size = rule.parameters["min_key_size"]
        allowed_algorithms = rule.parameters["allowed_algorithms"]
        
        if metadata.encryption_info:
            # Check key size
            key_size = metadata.encryption_info.get("key_size", 0)
            if key_size < min_key_size:
                violations.append(f"Encryption key size below minimum: {key_size}")
                risks.append(StorageRisk.ENCRYPTION_WEAKNESS)
            
            # Check algorithm
            algorithm = metadata.encryption_info.get("algorithm")
            if algorithm not in allowed_algorithms:
                violations.append(f"Unsupported encryption algorithm: {algorithm}")
                risks.append(StorageRisk.ENCRYPTION_WEAKNESS)
        else:
            violations.append("Missing encryption information")
            risks.append(StorageRisk.ENCRYPTION_WEAKNESS)
            
        return violations, risks

    def _verify_checksum(self, metadata: StorageMetadata) -> bool:
        """Verify metadata checksum"""
        try:
            # Create a copy without the checksum field
            meta_dict = {
                k: v for k, v in metadata.__dict__.items() 
                if k != 'checksum'
            }
            computed_checksum = hashlib.sha256(
                json.dumps(meta_dict, sort_keys=True).encode()
            ).hexdigest()
            return computed_checksum == metadata.checksum
        except Exception:
            return False

    def _verify_backup(self, backup_info: Dict[str, Any]) -> bool:
        """Verify backup integrity"""
        try:
            # Check backup age
            backup_age = (datetime.utcnow() - 
                         datetime.fromisoformat(backup_info["timestamp"])).total_seconds()
            if backup_age > self.security_checks["backup_validation"]["max_age"]:
                return False
            
            # Check integrity if required
            if (self.security_checks["backup_validation"]["verify_integrity"] and
                not self._verify_backup_integrity(backup_info)):
                return False
                
            return True
        except Exception:
            return False

    def _verify_backup_integrity(self, backup_info: Dict[str, Any]) -> bool:
        """Verify backup data integrity"""
        try:
            return (backup_info.get("checksum") == 
                   backup_info.get("computed_checksum"))
        except Exception:
            return False

    def _check_version_compatibility(self, version: str) -> bool:
        """Check version compatibility"""
        try:
            major, minor, patch = map(int, version.split('.'))
            # Add your version compatibility logic here
            return True
        except Exception:
            return False

    def _process_check_result(self,
                            check_result: Tuple[List[str], List[StorageRisk]],
                            violations: List[str],
                            risks: List[StorageRisk],
                            recommendations: List[str]):
        """Process check results and update tracking lists"""
        check_violations, check_risks = check_result
        violations.extend(check_violations)
        risks.extend(check_risks)
        
        # Add recommendations based on violations
        for violation in check_violations:
            recommendations.extend(
                self._get_recommendations_for_violation(violation)
            )

    def _get_recommendations_for_violation(self, violation: str) -> List[str]:
        """Get recommendations for a specific violation"""
        recommendations_map = {
            "Missing required access control": [
                "Implement authentication mechanism",
                "Enable access control features",
                "Review security configuration"
            ],
            "Storage encryption not enabled": [
                "Enable storage encryption",
                "Configure encryption settings",
                "Review encryption requirements"
            ],
            "Metadata checksum verification failed": [
                "Verify data integrity",
                "Rebuild metadata checksums",
                "Check for corruption"
            ],            
            "Invalid vector dimensions": [
                "Validate vector format",
                "Check dimension consistency",
                "Review data preprocessing"
            ],
            "Index is too old": [
                "Rebuild vector index",
                "Schedule regular index updates",
                "Monitor index freshness"
            ],
            "Insufficient backup copies": [
                "Configure additional backups",
                "Review backup strategy",
                "Implement backup automation"
            ],
            "Invalid version format": [
                "Update version formatting",
                "Implement version control",
                "Standardize versioning scheme"
            ]
        }
        
        # Get generic recommendations if specific ones not found
        default_recommendations = [
            "Review security configuration",
            "Update validation rules",
            "Monitor system logs"
        ]
        
        return recommendations_map.get(violation, default_recommendations)

    def add_validation_rule(self, name: str, rule: ValidationRule):
        """Add a new validation rule"""
        self.validation_rules[name] = rule

    def remove_validation_rule(self, name: str):
        """Remove a validation rule"""
        self.validation_rules.pop(name, None)

    def update_security_checks(self, updates: Dict[str, Dict[str, Any]]):
        """Update security check configurations"""
        self.security_checks.update(updates)

    def get_validation_history(self) -> List[Dict[str, Any]]:
        """Get history of validation results"""
        return [
            {
                "timestamp": result.metadata["timestamp"],
                "is_valid": result.is_valid,
                "risks": [risk.value for risk in result.risks],
                "violations": result.violations,
                "storage_type": result.metadata["storage_type"]
            }
            for result in self.validation_history
        ]

    def analyze_risks(self) -> Dict[str, Any]:
        """Analyze risk patterns in validation history"""
        if not self.validation_history:
            return {}

        risk_analysis = {
            "total_validations": len(self.validation_history),
            "risk_frequency": defaultdict(int),
            "violation_frequency": defaultdict(int),
            "storage_type_risks": defaultdict(lambda: defaultdict(int)),
            "trend_analysis": self._analyze_risk_trends()
        }

        for result in self.validation_history:
            for risk in result.risks:
                risk_analysis["risk_frequency"][risk.value] += 1
            
            for violation in result.violations:
                risk_analysis["violation_frequency"][violation] += 1
            
            storage_type = result.metadata["storage_type"]
            for risk in result.risks:
                risk_analysis["storage_type_risks"][storage_type][risk.value] += 1

        # Convert to percentages
        total = len(self.validation_history)
        risk_analysis["risk_percentages"] = {
            risk: (count / total) * 100
            for risk, count in risk_analysis["risk_frequency"].items()
        }

        return risk_analysis

    def _analyze_risk_trends(self) -> Dict[str, Any]:
        """Analyze trends in risk patterns"""
        if len(self.validation_history) < 2:
            return {}

        trends = {
            "increasing_risks": [],
            "decreasing_risks": [],
            "persistent_risks": []
        }

        # Group results by time periods (e.g., daily)
        period_risks = defaultdict(lambda: defaultdict(int))
        
        for result in self.validation_history:
            date = datetime.fromisoformat(
                result.metadata["timestamp"]
            ).date().isoformat()
            
            for risk in result.risks:
                period_risks[date][risk.value] += 1

        # Analyze trends
        dates = sorted(period_risks.keys())
        for risk in StorageRisk:
            first_count = period_risks[dates[0]][risk.value]
            last_count = period_risks[dates[-1]][risk.value]
            
            if last_count > first_count:
                trends["increasing_risks"].append(risk.value)
            elif last_count < first_count:
                trends["decreasing_risks"].append(risk.value)
            elif last_count > 0:  # Risk persists
                trends["persistent_risks"].append(risk.value)

        return trends

    def get_security_recommendations(self) -> List[Dict[str, Any]]:
        """Get security recommendations based on validation history"""
        if not self.validation_history:
            return []

        risk_analysis = self.analyze_risks()
        recommendations = []

        # Check high-frequency risks
        for risk, percentage in risk_analysis["risk_percentages"].items():
            if percentage > 20:  # More than 20% occurrence
                recommendations.append({
                    "risk": risk,
                    "frequency": percentage,
                    "severity": "high" if percentage > 50 else "medium",
                    "recommendations": self._get_risk_recommendations(risk)
                })

        # Check risk trends
        trends = risk_analysis.get("trend_analysis", {})
        
        for risk in trends.get("increasing_risks", []):
            recommendations.append({
                "risk": risk,
                "trend": "increasing",
                "severity": "high",
                "recommendations": [
                    "Immediate attention required",
                    "Review recent changes",
                    "Implement additional controls"
                ]
            })

        for risk in trends.get("persistent_risks", []):
            recommendations.append({
                "risk": risk,
                "trend": "persistent",
                "severity": "medium",
                "recommendations": [
                    "Review existing controls",
                    "Consider alternative approaches",
                    "Enhance monitoring"
                ]
            })

        return recommendations

    def _get_risk_recommendations(self, risk: str) -> List[str]:
        """Get recommendations for specific risk"""
        recommendations = {
            "unauthorized_access": [
                "Strengthen access controls",
                "Implement authentication",
                "Review permissions"
            ],
            "data_corruption": [
                "Implement integrity checks",
                "Regular validation",
                "Backup strategy"
            ],
            "index_manipulation": [
                "Secure index updates",
                "Monitor modifications",
                "Version control"
            ],
            "encryption_weakness": [
                "Upgrade encryption",
                "Key rotation",
                "Security audit"
            ],
            "backup_failure": [
                "Review backup strategy",
                "Automated backups",
                "Integrity verification"
            ]
        }
        return recommendations.get(risk, ["Review security configuration"])

    def clear_validation_history(self):
        """Clear validation history"""
        self.validation_history.clear()

    def export_security_report(self) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "validation_rules": {
                name: {
                    "description": rule.description,
                    "severity": rule.severity,
                    "parameters": rule.parameters
                }
                for name, rule in self.validation_rules.items()
            },
            "risk_analysis": self.analyze_risks(),
            "recommendations": self.get_security_recommendations(),
            "validation_history_summary": {
                "total_validations": len(self.validation_history),
                "failure_rate": sum(
                    1 for r in self.validation_history if not r.is_valid
                ) / len(self.validation_history) if self.validation_history else 0
            }
        }