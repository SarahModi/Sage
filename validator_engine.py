"""
Validation Engine - Core security rules and risk scoring
Enhanced with PolicyEvaluationEngine for accurate IAM analysis
"""

from typing import Dict, List
from datetime import datetime
from policy_evaluation_engine import PolicyEvaluationEngine, EvaluationResult


class ValidationEngine:
    """
    Core validation logic.
    Contains all security rules.
    Uses PolicyEvaluationEngine for accurate permission analysis.
    Returns findings with risk scores.
    """
    
    def __init__(self, aws_client=None):
        self.findings = []
        self.policy_engine = PolicyEvaluationEngine()
        self.aws_client = aws_client
    
    def validate_all(self, roles: List[Dict], users: List[Dict], root_data: Dict) -> List[Dict]:
        """Run all validations."""
        print("\n🔍 Running security validations...")
        
        for role in roles:
            self._validate_role(role)
        
        for user in users:
            self._validate_user(user)
        
        self._validate_root_account(root_data)
        
        print(f"✅ Found {len(self.findings)} findings")
        return self.findings
    
    def _validate_role(self, role: Dict):
        """Validate a single role against all rules."""
        role_name = role['name']
        
        # Validate trust policy
        trust_policy = role.get('trust_policy', {})
        if trust_policy:
            self._check_overprivileged_principal(role_name, trust_policy)
        
        # Collect all policies for deep evaluation
        identity_policies = []
        
        # Inline policies
        for policy in role.get('inline_policies', []):
            identity_policies.append(policy['document'])
        
        # Attached managed policies (if aws_client available)
        if self.aws_client:
            for attached in role.get('attached_policies', []):
                policy_doc = self.aws_client.get_policy_version(attached['arn'])
                if policy_doc:
                    identity_policies.append(policy_doc)
        
        # Use policy evaluation engine for accurate analysis
        if identity_policies:
            overprivilege_findings = self.policy_engine.find_overprivileged_identity(
                identity_policies=identity_policies
            )
            
            for finding in overprivilege_findings:
                finding['resource'] = role_name
                finding['type'] = finding.get('type', 'UNKNOWN')
                if 'severity' not in finding:
                    finding['severity'] = 'MEDIUM'
                if 'risk_score' not in finding:
                    finding['risk_score'] = 65
                self.findings.append(finding)
    
    def _validate_user(self, user: Dict):
        """Validate a single user."""
        user_name = user['name']
        
        # Collect all policies
        identity_policies = []
        
        for policy in user.get('inline_policies', []):
            identity_policies.append(policy['document'])
        
        # Attached managed policies (if aws_client available)
        if self.aws_client:
            for attached in user.get('attached_policies', []):
                policy_doc = self.aws_client.get_policy_version(attached['arn'])
                if policy_doc:
                    identity_policies.append(policy_doc)
        
        # Use policy evaluation engine
        if identity_policies:
            overprivilege_findings = self.policy_engine.find_overprivileged_identity(
                identity_policies=identity_policies
            )
            
            for finding in overprivilege_findings:
                finding['resource'] = user_name
                finding['type'] = finding.get('type', 'UNKNOWN')
                if 'severity' not in finding:
                    finding['severity'] = 'MEDIUM'
                if 'risk_score' not in finding:
                    finding['risk_score'] = 65
                self.findings.append(finding)
        
        # Check for old access keys
        for key in user.get('access_keys', []):
            created_date = datetime.fromisoformat(key['created'])
            days_old = (datetime.now(created_date.tzinfo) - created_date).days
            if days_old > 90:
                self.findings.append({
                    'type': 'OLD_ACCESS_KEY',
                    'severity': 'MEDIUM',
                    'risk_score': 60,
                    'resource': user_name,
                    'message': f'Access key {key["access_key_id"]} is {days_old} days old',
                    'fix': 'Rotate access key: delete old one, create new one'
                })
        
        # Check for MFA
        if not user.get('mfa_devices'):
            self.findings.append({
                'type': 'MFA_NOT_ENABLED',
                'severity': 'HIGH',
                'risk_score': 75,
                'resource': user_name,
                'message': 'MFA not enabled on user account',
                'fix': 'Enable MFA: aws iam enable-mfa-device'
            })
    
    def _validate_root_account(self, root_data: Dict):
        """Validate root account security."""
        if root_data.get('has_access_keys'):
            self.findings.append({
                'type': 'ROOT_HAS_ACCESS_KEYS',
                'severity': 'CRITICAL',
                'risk_score': 95,
                'resource': '<root>',
                'message': 'Root account has active access keys',
                'fix': 'Delete root access keys immediately: aws iam delete-access-key'
            })
        
        if not root_data.get('mfa_enabled'):
            self.findings.append({
                'type': 'ROOT_MFA_DISABLED',
                'severity': 'CRITICAL',
                'risk_score': 90,
                'resource': '<root>',
                'message': 'MFA not enabled on root account',
                'fix': 'Enable MFA on root account via AWS Console'
            })
    
    def _check_overprivileged_principal(self, role_name: str, trust_policy: Dict):
        """Check if trust policy allows anyone to assume role."""
        statements = trust_policy.get('Statement', [])
        for stmt in statements:
            principal = stmt.get('Principal', {})
            if principal == '*':
                self.findings.append({
                    'type': 'OVERPRIVILEGED_PRINCIPAL',
                    'severity': 'CRITICAL',
                    'risk_score': 95,
                    'resource': role_name,
                    'message': 'Trust policy allows ANY principal to assume this role',
                    'fix': f'Change Principal to: {{"AWS": "arn:aws:iam::ACCOUNT_ID:root"}}'
                })
    
    def _normalize_list(self, value) -> List[str]:
        """Convert to list if string."""
        if isinstance(value, str):
            return [value]
        return list(value) if value else []
