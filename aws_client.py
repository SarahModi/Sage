"""
AWS Client - Handles all AWS API interactions
"""

import boto3
from typing import Dict, List
from datetime import datetime


class AWSClient:
    """
    Handles all AWS API calls safely.
    Pulls IAM roles, users, policies, and trust relationships.
    """
    
    def __init__(self, profile_name: str = 'default'):
        """Initialize AWS client with specific profile."""
        try:
            session = boto3.Session(profile_name=profile_name)
            self.iam_client = session.client('iam')
            self.account_id = session.client('sts').get_caller_identity()['Account']
            print(f"✅ Connected to AWS Account: {self.account_id}")
        except Exception as e:
            print(f"❌ Failed to connect to AWS: {e}")
            raise
    
    def get_all_roles(self) -> List[Dict]:
        """Fetch all IAM roles from account."""
        print("📋 Fetching all IAM roles...")
        roles = []
        try:
            paginator = self.iam_client.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page.get('Roles', []):
                    role_data = {
                        'name': role['RoleName'],
                        'arn': role['Arn'],
                        'created': role['CreateDate'].isoformat(),
                        'trust_policy': role.get('AssumeRolePolicyDocument', {}),
                        'inline_policies': self._get_inline_policies(role['RoleName']),
                        'attached_policies': self._get_attached_policies(role['RoleName'])
                    }
                    roles.append(role_data)
            print(f"✅ Found {len(roles)} roles")
            return roles
        except Exception as e:
            print(f"❌ Error fetching roles: {e}")
            return []
    
    def get_all_users(self) -> List[Dict]:
        """Fetch all IAM users from account."""
        print("👤 Fetching all IAM users...")
        users = []
        try:
            paginator = self.iam_client.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page.get('Users', []):
                    user_data = {
                        'name': user['UserName'],
                        'arn': user['Arn'],
                        'created': user['CreateDate'].isoformat(),
                        'inline_policies': self._get_user_inline_policies(user['UserName']),
                        'attached_policies': self._get_user_attached_policies(user['UserName']),
                        'access_keys': self._get_access_keys(user['UserName']),
                        'mfa_devices': self._get_mfa_devices(user['UserName'])
                    }
                    users.append(user_data)
            print(f"✅ Found {len(users)} users")
            return users
        except Exception as e:
            print(f"❌ Error fetching users: {e}")
            return []
    
    def check_root_account(self) -> Dict:
        """Check root account security posture."""
        print("🔑 Checking root account...")
        root_data = {
            'has_access_keys': False,
            'mfa_enabled': False,
        }
        try:
            cred_report = self.iam_client.get_credential_report()
            report_data = cred_report['Content'].decode('utf-8')
            
            for line in report_data.split('\n')[1:]:
                if line.startswith('<root_account>'):
                    fields = line.split(',')
                    root_data['access_key_1_active'] = fields[3] == 'true'
                    root_data['access_key_2_active'] = fields[8] == 'true'
                    root_data['mfa_enabled'] = fields[9] == 'true'
                    if root_data['access_key_1_active'] or root_data['access_key_2_active']:
                        root_data['has_access_keys'] = True
        except Exception as e:
            print(f"⚠️  Could not check root account: {e}")
        
        return root_data
    
    def _get_inline_policies(self, role_name: str) -> List[Dict]:
        """Get inline policies for a role."""
        policies = []
        try:
            paginator = self.iam_client.get_paginator('list_role_policies')
            for page in paginator.paginate(RoleName=role_name):
                for policy_name in page.get('PolicyNames', []):
                    policy_doc = self.iam_client.get_role_policy(
                        RoleName=role_name,
                        PolicyName=policy_name
                    )
                    policies.append({
                        'name': policy_name,
                        'document': policy_doc['RolePolicyDocument']
                    })
        except Exception:
            pass
        return policies
    
    def _get_attached_policies(self, role_name: str) -> List[Dict]:
        """Get attached managed policies for a role."""
        policies = []
        try:
            paginator = self.iam_client.get_paginator('list_attached_role_policies')
            for page in paginator.paginate(RoleName=role_name):
                for policy in page.get('AttachedPolicies', []):
                    policies.append({
                        'name': policy['PolicyName'],
                        'arn': policy['PolicyArn']
                    })
        except Exception:
            pass
        return policies
    
    def _get_user_inline_policies(self, user_name: str) -> List[Dict]:
        """Get inline policies for a user."""
        policies = []
        try:
            paginator = self.iam_client.get_paginator('list_user_policies')
            for page in paginator.paginate(UserName=user_name):
                for policy_name in page.get('PolicyNames', []):
                    policy_doc = self.iam_client.get_user_policy(
                        UserName=user_name,
                        PolicyName=policy_name
                    )
                    policies.append({
                        'name': policy_name,
                        'document': policy_doc['UserPolicyDocument']
                    })
        except Exception:
            pass
        return policies
    
    def _get_user_attached_policies(self, user_name: str) -> List[Dict]:
        """Get attached managed policies for a user."""
        policies = []
        try:
            paginator = self.iam_client.get_paginator('list_attached_user_policies')
            for page in paginator.paginate(UserName=user_name):
                for policy in page.get('AttachedPolicies', []):
                    policies.append({
                        'name': policy['PolicyName'],
                        'arn': policy['PolicyArn']
                    })
        except Exception:
            pass
        return policies
    
    def _get_access_keys(self, user_name: str) -> List[Dict]:
        """Get access keys for a user."""
        keys = []
        try:
            response = self.iam_client.list_access_keys(UserName=user_name)
            for key in response.get('AccessKeyMetadata', []):
                keys.append({
                    'access_key_id': key['AccessKeyId'],
                    'status': key['Status'],
                    'created': key['CreateDate'].isoformat()
                })
        except Exception:
            pass
        return keys
    
    def _get_mfa_devices(self, user_name: str) -> List[str]:
        """Get MFA devices for a user."""
        devices = []
        try:
            response = self.iam_client.list_mfa_devices(UserName=user_name)
            for device in response.get('MFADevices', []):
                devices.append(device['SerialNumber'])
        except Exception:
            pass
        return devices

# Add after _get_mfa_devices() method:

def get_permission_boundary(self, name: str, is_user: bool = False) -> Dict:
    """
    Get permission boundary for a user or role.
    Permission boundaries limit the maximum permissions.
    """
    try:
        if is_user:
            response = self.iam_client.get_user(UserName=name)
        else:
            response = self.iam_client.get_role(RoleName=name)
        
        # Permission boundary is stored as ARN
        boundary_arn = response.get('User', {}).get('PermissionsBoundary', {}).get('PermissionsBoundaryArn') if is_user else response.get('Role', {}).get('PermissionsBoundary', {}).get('PermissionsBoundaryArn')
        
        if not boundary_arn:
            return None
        
        # Fetch the actual policy document
        return self.get_policy_version(boundary_arn)
    except Exception:
        return None

def get_policy_version(self, policy_arn: str, version_id: str = None) -> Dict:
    """
    Get specific version of a managed policy.
    If no version_id provided, gets the default version.
    """
    try:
        if not version_id:
            # Get default version
            policy = self.iam_client.get_policy(PolicyArn=policy_arn)
            version_id = policy['Policy']['DefaultVersionId']
        
        response = self.iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id
        )
        return response['PolicyVersion']['Document']
    except Exception as e:
        print(f"⚠️  Could not fetch policy {policy_arn}: {e}")
        return None

def get_all_policy_versions(self, policy_arn: str) -> List[Dict]:
    """Get all versions of a managed policy"""
    try:
        versions = []
        paginator = self.iam_client.get_paginator('list_policy_versions')
        for page in paginator.paginate(PolicyArn=policy_arn):
            for version in page.get('Versions', []):
                versions.append({
                    'version_id': version['VersionId'],
                    'is_default': version['IsDefaultVersion'],
                    'create_date': version['CreateDate'].isoformat()
                })
        return versions
    except Exception:
        return []
