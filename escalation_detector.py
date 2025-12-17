from typing import Dict, List, Set, Tuple
from collections import defaultdict, deque


class PrivilegeEscalationDetector:
    """
    Detects privilege escalation paths using graph algorithms.
    
    Algorithm:
    1. Build directed graph of IAM trust relationships
    2. Use BFS to find paths from low-privilege to high-privilege roles
    3. Score escalation risk based on path length and permissions
    """
    
    # Actions that allow privilege escalation
    ESCALATION_ACTIONS = {
        'iam:AttachUserPolicy',
        'iam:AttachGroupPolicy',
        'iam:AttachRolePolicy',
        'iam:PutUserPolicy',
        'iam:PutGroupPolicy',
        'iam:PutRolePolicy',
        'iam:CreatePolicyVersion',
        'iam:SetDefaultPolicyVersion',
        'iam:PassRole',
        'sts:AssumeRole',
        'ec2:RunInstances',
        'lambda:CreateFunction',
        'lambda:InvokeFunction'
    }
    
    # Permissions that indicate admin-level access
    ADMIN_PERMISSIONS = {
        'iam:*',
        's3:*',
        'ec2:*',
        'rds:*',
        'lambda:*',
        'dynamodb:*',
        'kms:*',
        '*'
    }
    
    def __init__(self):
        """Initialize the escalation detector."""
        self.graph = defaultdict(list)  # role -> [roles it can assume]
        self.role_permissions = {}  # role -> set of permissions
        self.findings = []
    
    def analyze_roles(self, roles: List[Dict]) -> List[Dict]:
        """
        Analyze roles for escalation paths.
        
        Args:
            roles: List of role dicts with trust policies and permissions
        
        Returns:
            List of escalation findings
        """
        # Step 1: Build the permission map
        self._build_permission_map(roles)
        
        # Step 2: Build the trust relationship graph
        self._build_trust_graph(roles)
        
        # Step 3: Find escalation paths
        self._find_escalation_paths(roles)
        
        return self.findings
    
    def _build_permission_map(self, roles: List[Dict]):
        """Extract and store all permissions for each role."""
        for role in roles:
            role_name = role['name']
            permissions = set()
            
            # Extract from inline policies
            for policy in role.get('inline_policies', []):
                perms = self._extract_permissions_from_policy(policy.get('document', {}))
                permissions.update(perms)
            
            # Extract from attached policies (we only have names, but that's enough)
            for policy in role.get('attached_policies', []):
                policy_name = policy.get('name', '')
                if 'Admin' in policy_name or '*' in policy_name:
                    permissions.add('*')  # Treat admin policies as wildcard
            
            self.role_permissions[role_name] = permissions
    
    def _extract_permissions_from_policy(self, policy_doc: Dict) -> Set[str]:
        """Extract action names from a policy document."""
        permissions = set()
        
        for statement in policy_doc.get('Statement', []):
            if statement.get('Effect') != 'Allow':
                continue
            
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                permissions.add(actions)
            else:
                permissions.update(actions)
        
        return permissions
    
    def _build_trust_graph(self, roles: List[Dict]):
    """Build directed graph of trust relationships."""
    # First, create a set of all role names for O(1) lookup
    role_names = {r['name'] for r in roles}  # ← ADD THIS LINE
    
    for role in roles:
        role_name = role['name']
        trust_policy = role.get('trust_policy', {})
        
        # Extract principals that can assume this role
        for statement in trust_policy.get('Statement', []):
            if statement.get('Effect') != 'Allow':
                continue
            
            principals = self._extract_principals(statement.get('Principal', {}))
            
            for principal in principals:
                # If principal is another role in this account, add edge
                if principal in role_names:  # ← USE THE SET (much faster)
                    if role_name not in self.graph[principal]:  # ← AVOID DUPLICATES
                        self.graph[principal].append(role_name)
    
    def _extract_principals(self, principal_field) -> Set[str]:
        """Extract principal names from trust policy."""
        principals = set()
        
        if isinstance(principal_field, str):
            if principal_field == '*':
                # Wildcard principal - very dangerous
                return {'*'}
            return {principal_field}
        
        elif isinstance(principal_field, dict):
            # Extract from AWS, Service, Federated fields
            for key in ['AWS', 'Service', 'Federated']:
                value = principal_field.get(key, [])
                if isinstance(value, str):
                    principals.add(value)
                else:
                    principals.update(value)
        
        return principals
    
    def _find_escalation_paths(self, roles: List[Dict]):
        """Find all privilege escalation paths."""
        role_names = [r['name'] for r in roles]
        
        for start_role in role_names:
            # Check if this role has escalation permissions
            if self._has_escalation_capability(start_role):
                # Find what admin roles it can reach
                admin_roles = self._find_reachable_admin_roles(start_role)
                
                if admin_roles:
                    for admin_role in admin_roles:
                        path = self._find_shortest_path(start_role, admin_role)
                        
                        self.findings.append({
                            'type': 'PRIVILEGE_ESCALATION_PATH',
                            'severity': self._calculate_escalation_severity(path),
                            'risk_score': self._calculate_escalation_risk(start_role, path),
                            'resource': start_role,
                            'message': f'Privilege escalation path detected: {start_role} → {" → ".join(path[1:])} (admin)',
                            'path': path,
                            'fix': f'Remove escalation capability from {start_role} or restrict trust policies'
                        })
    
    def _has_escalation_capability(self, role_name: str) -> bool:
        """Check if role has permissions to escalate privileges."""
        perms = self.role_permissions.get(role_name, set())
        
        # Check for escalation actions
        if any(action in perms for action in self.ESCALATION_ACTIONS):
            return True
        
        # Check for wildcard actions
        if any('*' in perm for perm in perms):
            return True
        
        return False
    
    def _find_reachable_admin_roles(self, start_role: str) -> List[str]:
        """Find all admin roles reachable from start_role using BFS."""
        visited = set()
        queue = deque([start_role])
        admin_roles = []
        
        while queue:
            current_role = queue.popleft()
            
            if current_role in visited:
                continue
            visited.add(current_role)
            
            # Check if current role is admin
            if self._is_admin_role(current_role):
                admin_roles.append(current_role)
                continue  # Don't expand further from admin role
            
            # Explore roles that can be assumed from here
            for next_role in self.graph.get(current_role, []):
                if next_role not in visited:
                    queue.append(next_role)
        
        return admin_roles
    
    def _is_admin_role(self, role_name: str) -> bool:
        """Check if a role has admin-level permissions."""
        perms = self.role_permissions.get(role_name, set())
        return any(admin_perm in perms for admin_perm in self.ADMIN_PERMISSIONS)
    
    def _find_shortest_path(self, start: str, end: str) -> List[str]:
        """Find shortest path from start role to end role."""
        visited = set()
        queue = deque([(start, [start])])
        
        while queue:
            current, path = queue.popleft()
            
            if current == end:
                return path
            
            if current in visited:
                continue
            visited.add(current)
            
            for next_role in self.graph.get(current, []):
                if next_role not in visited:
                    queue.append((next_role, path + [next_role]))
        
        return [start, end]  # Direct path if BFS doesn't find
    
    def _calculate_escalation_severity(self, path: List[str]) -> str:
        """Determine severity based on path length."""
        path_length = len(path) - 1
        
        if path_length == 1:
            return 'CRITICAL'
        elif path_length == 2:
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def _calculate_escalation_risk(self, start_role: str, path: List[str]) -> int:
        """Calculate risk score (1-100) for escalation."""
        base_score = 85
        
        # Direct escalation = highest risk
        if len(path) == 2:
            return 95
        
        # Each hop reduces risk slightly
        hop_penalty = (len(path) - 2) * 5
        score = base_score - hop_penalty
        
        return max(70, score)  # Minimum 70 for any escalation path


class PassRoleDetector:
    """
    Detects dangerous iam:PassRole usage.
    PassRole allows identity to pass role to other services (EC2, Lambda, etc.)
    which can lead to privilege escalation.
    """
    
    def __init__(self):
        self.findings = []
    
    def analyze_roles(self, roles: List[Dict]) -> List[Dict]:
        """Find dangerous PassRole usage."""
        for role in roles:
            self._check_passrole(role)
        
        return self.findings
    
    def _check_passrole(self, role: Dict):
        """Check if role has iam:PassRole without conditions."""
        role_name = role['name']
        
        for policy in role.get('inline_policies', []):
            policy_doc = policy.get('document', {})
            
            for statement in policy_doc.get('Statement', []):
                if statement.get('Effect') != 'Allow':
                    continue
                
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                if any('PassRole' in action for action in actions):
                    # Check if there are conditions restricting it
                    has_conditions = bool(statement.get('Condition'))
                    
                    if not has_conditions or 'iam:PassedToService' not in str(statement.get('Condition', {})):
                        self.findings.append({
                            'type': 'UNRESTRICTED_PASSROLE',
                            'severity': 'HIGH',
                            'risk_score': 80,
                            'resource': role_name,
                            'message': 'iam:PassRole without proper conditions - can escalate via EC2/Lambda',
                            'fix': 'Add Condition with StringEquals on iam:PassedToService (ec2.amazonaws.com, lambda.amazonaws.com, etc.)'
                        })


class CrossAccountDetector:
    """
    Detects potentially dangerous cross-account access.
    """
    
    def __init__(self, account_id: str):
        self.account_id = account_id
        self.findings = []
    
    def analyze_roles(self, roles: List[Dict]) -> List[Dict]:
        """Find dangerous cross-account access."""
        for role in roles:
            self._check_cross_account(role)
        
        return self.findings
    
    def _check_cross_account(self, role: Dict):
        """Check trust policy for cross-account risks."""
        role_name = role['name']
        trust_policy = role.get('trust_policy', {})
        
        for statement in trust_policy.get('Statement', []):
            principal = statement.get('Principal', {})
            
            # Check for cross-account principal
            if isinstance(principal, dict):
                aws_principals = principal.get('AWS', [])
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                
                for principal_arn in aws_principals:
                    if 'arn:aws:iam::' in principal_arn:
                        # Extract account ID from ARN
                        principal_account = principal_arn.split(':')[4]
                        
                        if principal_account != self.account_id and principal_account != '':
                            # Check if there are conditions limiting access
                            has_mfa_condition = 'MFA' in str(statement.get('Condition', {}))
                            
                            if not has_mfa_condition:
                                self.findings.append({
                                    'type': 'UNRESTRICTED_CROSS_ACCOUNT_ACCESS',
                                    'severity': 'HIGH',
                                    'risk_score': 75,
                                    'resource': role_name,
                                    'message': f'Cross-account access allowed without MFA requirement ({principal_account})',
                                    'fix': 'Add Condition requiring MFA: "aws:MultiFactorAuthPresent": "true"'
                                })


def merge_escalation_findings(existing_findings: List[Dict], 
                              escalation_findings: List[Dict],
                              passrole_findings: List[Dict],
                              crossaccount_findings: List[Dict]) -> List[Dict]:
    """
    Merge all escalation-related findings with existing findings.
    Remove duplicates and prioritize by severity.
    """
    all_findings = existing_findings + escalation_findings + passrole_findings + crossaccount_findings
    
    # Sort by severity (CRITICAL first)
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    all_findings.sort(key=lambda f: (severity_order.get(f['severity'], 4), -f['risk_score']))
    
    # Remove exact duplicates (same resource, type, and message)
    seen = set()
    unique_findings = []
    
    for finding in all_findings:
        key = (finding['resource'], finding['type'], finding['message'])
        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)
    
    return unique_findings
