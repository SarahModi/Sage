"""
Validation Engine - Core security rules and risk scoring
"""

from typing import Dict, List
from datetime import datetime


class ValidationEngine:
    """
    Core validation logic.
    Contains all security rules.
    Returns findings with risk scores.
    """
    
    def __init__(self):
        self.findings = []
    
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
        
        trust_policy = role.get('trust_policy', {})
        if trust_policy:
            self._check_overprivileged_principal(role_name, trust_policy)
        
        for policy in role.get('inline_policies', []):
            self._check_policy(role_name, policy, 'role')
        
        for policy in role.get('attached_policies', []):
            if policy['name'] == 'AdministratorAccess':
                self.findings.append({
                    'type': 'ADMIN_ROLE',
                    'severity': 'MEDIUM',
                    'risk_score': 65,
                    'resource': role_name,
                    'message': 'AdministratorAccess policy attached to role',
                    'fix': 'Use least-privilege policy instead of full admin access'
                })
    
    def _validate_user(self, user: Dict):
        """Validate a single user."""
        user_name = user['name']
        
        for policy in user.get('attached_policies', []):
            if policy['name'] == 'AdministratorAccess':
                self.findings.append({
                    'type': 'ADMIN_ATTACHED_TO_USER',
                    'severity': 'HIGH',
                    'risk_score': 80,
                    'resource': user_name,
                    'message': 'AdministratorAccess policy attached directly to user (should use role)',
                    'fix': 'Create a role with needed permissions, assign role to user instead'
                })
        
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
    
    def _check_policy(self, resource_name: str, policy: Dict, resource_type: str):
        """Check a policy for dangerous patterns."""
        policy_doc = policy.get('document', {})
        statements = policy_doc.get('Statement', [])
        
        for stmt in statements:
            effect = stmt.get('Effect', 'Deny')
            if effect != 'Allow':
                continue
            
            actions = self._normalize_list(stmt.get('Action', []))
            resources = self._normalize_list(stmt.get('Resource', []))
            
            if '*' in actions:
                self.findings.append({
                    'type': 'WILDCARD_ACTIONS',
                    'severity': 'CRITICAL',
                    'risk_score': 95,
                    'resource': resource_name,
                    'message': 'Policy allows ALL actions (*)',
                    'fix': 'Replace * with specific actions (s3:GetObject, s3:PutObject, etc.)'
                })
            
            if '*' in resources and any(a in actions for a in ['iam:*', 's3:*', 'ec2:*']):
                self.findings.append({
                    'type': 'WILDCARD_RESOURCES',
                    'severity': 'CRITICAL',
                    'risk_score': 95,
                    'resource': resource_name,
                    'message': 'Policy allows actions on ALL resources (*)',
                    'fix': 'Specify exact resources: arn:aws:s3:::bucket-name/*'
                })
            
            if 'iam:*' in actions:
                self.findings.append({
                    'type': 'IAM_WILDCARD',
                    'severity': 'CRITICAL',
                    'risk_score': 95,
                    'resource': resource_name,
                    'message': 'Policy allows unrestricted IAM actions (iam:*)',
                    'fix': 'Use specific IAM actions: iam:GetRole, iam:ListRoles, etc.'
                })
    
    def _normalize_list(self, value) -> List[str]:
        """Convert to list if string."""
        if isinstance(value, str):
            return [value]
        return list(value) if value else []
