"""
Tests for Sage - IAM Validator
Create this as: tests/test_escalation_detector.py
"""

import pytest
from escalation_detector import (
    PrivilegeEscalationDetector,
    PassRoleDetector,
    CrossAccountDetector,
    merge_escalation_findings
)


class TestPrivilegeEscalationDetector:
    """Test privilege escalation detection."""
    
    def test_detector_initializes(self):
        """Test that detector initializes correctly."""
        detector = PrivilegeEscalationDetector()
        assert detector.graph == {}
        assert detector.role_permissions == {}
        assert detector.findings == []
    
    def test_empty_roles_list(self):
        """Test analyzer with empty roles list."""
        detector = PrivilegeEscalationDetector()
        findings = detector.analyze_roles([])
        assert findings == []
    
    def test_single_role_no_escalation(self):
        """Test single role with no escalation capability."""
        detector = PrivilegeEscalationDetector()
        
        roles = [
            {
                'name': 'reader-role',
                'trust_policy': {'Statement': []},
                'inline_policies': [
                    {
                        'document': {
                            'Statement': [
                                {
                                    'Effect': 'Allow',
                                    'Action': 's3:GetObject',
                                    'Resource': '*'
                                }
                            ]
                        }
                    }
                ],
                'attached_policies': []
            }
        ]
        
        findings = detector.analyze_roles(roles)
        assert findings == []
    
    def test_admin_role_detection(self):
        """Test detection of admin roles."""
        detector = PrivilegeEscalationDetector()
        
        roles = [
            {
                'name': 'admin-role',
                'trust_policy': {'Statement': []},
                'inline_policies': [],
                'attached_policies': [
                    {
                        'name': 'AdministratorAccess'
                    }
                ]
            }
        ]
        
        detector._build_permission_map(roles)
        assert detector._is_admin_role('admin-role')
    
    def test_escalation_capability_detection(self):
        """Test detection of escalation capabilities."""
        detector = PrivilegeEscalationDetector()
        
        roles = [
            {
                'name': 'escalation-role',
                'trust_policy': {'Statement': []},
                'inline_policies': [
                    {
                        'document': {
                            'Statement': [
                                {
                                    'Effect': 'Allow',
                                    'Action': 'iam:AttachUserPolicy',
                                    'Resource': '*'
                                }
                            ]
                        }
                    }
                ],
                'attached_policies': []
            }
        ]
        
        detector._build_permission_map(roles)
        assert detector._has_escalation_capability('escalation-role')
    
    def test_extract_principals(self):
        """Test principal extraction from trust policy."""
        detector = PrivilegeEscalationDetector()
        
        # Test wildcard principal
        principals = detector._extract_principals('*')
        assert '*' in principals
        
        # Test AWS principal dict
        principals = detector._extract_principals({
            'AWS': 'arn:aws:iam::123456789:role/test'
        })
        assert 'arn:aws:iam::123456789:role/test' in principals
        
        # Test list of principals
        principals = detector._extract_principals({
            'AWS': [
                'arn:aws:iam::123456789:role/test1',
                'arn:aws:iam::123456789:role/test2'
            ]
        })
        assert len(principals) == 2


class TestPassRoleDetector:
    """Test PassRole detection."""
    
    def test_passrole_detector_initializes(self):
        """Test PassRole detector initialization."""
        detector = PassRoleDetector()
        assert detector.findings == []
    
    def test_safe_passrole_with_conditions(self):
        """Test that PassRole with conditions is not flagged."""
        detector = PassRoleDetector()
        
        roles = [
            {
                'name': 'lambda-exec',
                'inline_policies': [
                    {
                        'document': {
                            'Statement': [
                                {
                                    'Effect': 'Allow',
                                    'Action': 'iam:PassRole',
                                    'Resource': '*',
                                    'Condition': {
                                        'StringEquals': {
                                            'iam:PassedToService': 'lambda.amazonaws.com'
                                        }
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        ]
        
        findings = detector.analyze_roles(roles)
        # Should have no findings because conditions are present
        assert len(findings) == 0
    
    def test_dangerous_passrole_without_conditions(self):
        """Test that PassRole without conditions is flagged."""
        detector = PassRoleDetector()
        
        roles = [
            {
                'name': 'lambda-exec',
                'inline_policies': [
                    {
                        'document': {
                            'Statement': [
                                {
                                    'Effect': 'Allow',
                                    'Action': 'iam:PassRole',
                                    'Resource': '*'
                                }
                            ]
                        }
                    }
                ]
            }
        ]
        
        findings = detector.analyze_roles(roles)
        assert len(findings) == 1
        assert findings[0]['type'] == 'UNRESTRICTED_PASSROLE'
        assert findings[0]['severity'] == 'HIGH'


class TestCrossAccountDetector:
    """Test cross-account access detection."""
    
    def test_detector_initializes(self):
        """Test cross-account detector initialization."""
        detector = CrossAccountDetector('123456789012')
        assert detector.account_id == '123456789012'
        assert detector.findings == []
    
    def test_safe_cross_account_with_mfa(self):
        """Test that cross-account with MFA is not flagged."""
        detector = CrossAccountDetector('123456789012')
        
        roles = [
            {
                'name': 'cross-account-role',
                'trust_policy': {
                    'Statement': [
                        {
                            'Effect': 'Allow',
                            'Principal': {
                                'AWS': 'arn:aws:iam::987654321098:root'
                            },
                            'Condition': {
                                'Bool': {
                                    'aws:MultiFactorAuthPresent': 'true'
                                }
                            }
                        }
                    ]
                }
            }
        ]
        
        findings = detector.analyze_roles(roles)
        # Should have no findings because MFA is required
        assert len(findings) == 0
    
    def test_dangerous_cross_account_without_mfa(self):
        """Test that cross-account without MFA is flagged."""
        detector = CrossAccountDetector('123456789012')
        
        roles = [
            {
                'name': 'cross-account-role',
                'trust_policy': {
                    'Statement': [
                        {
                            'Effect': 'Allow',
                            'Principal': {
                                'AWS': 'arn:aws:iam::987654321098:root'
                            }
                        }
                    ]
                }
            }
        ]
        
        findings = detector.analyze_roles(roles)
        assert len(findings) == 1
        assert findings[0]['type'] == 'UNRESTRICTED_CROSS_ACCOUNT_ACCESS'
        assert findings[0]['severity'] == 'HIGH'


class TestMergeFindings:
    """Test finding merging functionality."""
    
    def test_merge_empty_findings(self):
        """Test merging when all findings are empty."""
        result = merge_escalation_findings([], [], [], [])
        assert result == []
    
    def test_merge_removes_duplicates(self):
        """Test that merge removes duplicate findings."""
        existing = [
            {
                'resource': 'role1',
                'type': 'TEST',
                'message': 'Same message',
                'severity': 'HIGH',
                'risk_score': 80
            }
        ]
        escalation = [
            {
                'resource': 'role1',
                'type': 'TEST',
                'message': 'Same message',
                'severity': 'HIGH',
                'risk_score': 80
            }
        ]
        
        result = merge_escalation_findings(existing, escalation, [], [])
        # Should only have 1 finding, not 2
        assert len(result) == 1
    
    def test_merge_sorts_by_severity(self):
        """Test that findings are sorted by severity."""
        findings_list = [
            [],
            [
                {
                    'resource': 'role2',
                    'type': 'LOW_RISK',
                    'message': 'Low risk',
                    'severity': 'LOW',
                    'risk_score': 30
                }
            ],
            [
                {
                    'resource': 'role1',
                    'type': 'CRITICAL_RISK',
                    'message': 'Critical risk',
                    'severity': 'CRITICAL',
                    'risk_score': 95
                }
            ],
            []
        ]
        
        result = merge_escalation_findings(*findings_list)
        # CRITICAL should be first
        assert result[0]['severity'] == 'CRITICAL'
        assert result[1]['severity'] == 'LOW'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
