import pytest
import json
from validator_engine import ValidationEngine
from report_generator import ReportGenerator

def test_validation_engine_initialization():
    """Test that the engine initializes correctly."""
    engine = ValidationEngine()
    assert engine.findings == []

def test_mfa_validation():
    """Test MFA validation rule."""
    engine = ValidationEngine()
    users = [{'name': 'testuser', 'mfa_devices': []}]
    findings = engine.validate_all([], users, {})
    
    # Should find MFA_NOT_ENABLED
    mfa_findings = [f for f in findings if f['type'] == 'MFA_NOT_ENABLED']
    assert len(mfa_findings) > 0

def test_wildcard_validation():
    """Test wildcard action detection."""
    engine = ValidationEngine()
    roles = [{
        'name': 'testrole',
        'inline_policies': [{
            'name': 'badpolicy',
            'document': {
                'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]
            }
        }]
    }]
    findings = engine.validate_all(roles, [], {})
    
    # Should find WILDCARD_ACTIONS
    wildcard_findings = [f for f in findings if f['type'] == 'WILDCARD_ACTIONS']
    assert len(wildcard_findings) > 0

def test_report_generator():
    """Test report generation works."""
    test_findings = [
        {
            'type': 'TEST_FINDING',
            'severity': 'MEDIUM',
            'risk_score': 50,
            'resource': 'test',
            'message': 'Test message',
            'fix': 'Test fix'
        }
    ]
    
    summary = ReportGenerator.generate_summary(test_findings)
    assert summary['total_findings'] == 1
    assert summary['by_severity']['MEDIUM'] == 1
