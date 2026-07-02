"""
HostVigil Attack Path Engine

Analyzes scan findings to build potential lateral movement chains and
privilege escalation paths. Maps initial access vectors, lateral movement
opportunities, and privilege escalation routes into end-to-end attack chains.

Output includes a vis.js-compatible graph for dashboard visualization.
"""

import sqlite3
import json
import logging
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
from datetime import datetime, timezone

logger = logging.getLogger('hostvigil.attack_paths')

# Attack techniques mapped to findings
ATTACK_TECHNIQUES = {
    'smb_relay': {
        'name': 'SMB Relay Attack',
        'description': 'SMB signing disabled allows NTLMv2 relay to gain code execution',
        'mitre': 'T1557.001',
        'requires': ['smb_signing_disabled'],
        'gains': 'code_execution',
        'severity': 'critical',
    },
    'null_session': {
        'name': 'SMB Null Session Enumeration',
        'description': 'Anonymous SMB access reveals users, shares, and domain info',
        'mitre': 'T1087.002',
        'requires': ['smb_null_session'],
        'gains': 'domain_info',
        'severity': 'high',
    },
    'default_creds_rce': {
        'name': 'Default Credentials → RCE',
        'description': 'Service with default credentials allows command execution',
        'mitre': 'T1078.001',
        'requires': ['default_credentials'],
        'gains': 'code_execution',
        'severity': 'critical',
    },
    'redis_rce': {
        'name': 'Redis Unauthenticated → RCE',
        'description': 'Redis without auth allows writing SSH keys or cron for shell',
        'mitre': 'T1210',
        'requires': ['redis_no_auth'],
        'gains': 'code_execution',
        'severity': 'critical',
    },
    'docker_escape': {
        'name': 'Docker API → Host Takeover',
        'description': 'Exposed Docker API allows container creation with host mount',
        'mitre': 'T1610',
        'requires': ['docker_api_exposed'],
        'gains': 'host_takeover',
        'severity': 'critical',
    },
    'kerberoast': {
        'name': 'Kerberoasting',
        'description': 'Service accounts with SPNs can be roasted for password hashes',
        'mitre': 'T1558.003',
        'requires': ['kerberoastable_accounts'],
        'gains': 'credentials',
        'severity': 'high',
    },
    'asrep_roast': {
        'name': 'AS-REP Roasting',
        'description': 'Accounts without pre-auth can be roasted offline',
        'mitre': 'T1558.004',
        'requires': ['asrep_roastable_accounts'],
        'gains': 'credentials',
        'severity': 'high',
    },
    'rdp_lateral': {
        'name': 'RDP Lateral Movement',
        'description': 'Compromised credentials + open RDP allows lateral movement',
        'mitre': 'T1021.001',
        'requires': ['rdp_open', 'credentials'],
        'gains': 'lateral_access',
        'severity': 'high',
    },
    'winrm_lateral': {
        'name': 'WinRM Lateral Movement',
        'description': 'PowerShell remoting for stealthy lateral movement',
        'mitre': 'T1021.006',
        'requires': ['winrm_open', 'credentials'],
        'gains': 'lateral_access',
        'severity': 'high',
    },
    'ssh_lateral': {
        'name': 'SSH Lateral Movement',
        'description': 'Compromised credentials or keys allow SSH access',
        'mitre': 'T1021.004',
        'requires': ['ssh_open', 'credentials'],
        'gains': 'lateral_access',
        'severity': 'medium',
    },
    'expired_cert_mitm': {
        'name': 'Expired Certificate → MITM',
        'description': 'Expired/self-signed certs may allow traffic interception',
        'mitre': 'T1557',
        'requires': ['expired_certificate', 'self_signed_cert'],
        'gains': 'traffic_interception',
        'severity': 'medium',
    },
    'elasticsearch_data': {
        'name': 'Elasticsearch Data Exfiltration',
        'description': 'Unauthenticated Elasticsearch exposes indexed data',
        'mitre': 'T1213',
        'requires': ['elasticsearch_no_auth'],
        'gains': 'data_access',
        'severity': 'high',
    },
    'ldap_anon_enum': {
        'name': 'LDAP Anonymous Enumeration',
        'description': 'Anonymous LDAP bind reveals domain structure and accounts',
        'mitre': 'T1087.002',
        'requires': ['ldap_anonymous_bind'],
        'gains': 'domain_info',
        'severity': 'medium',
    },
}


class AttackPathEngine:
    """Analyzes findings to construct potential attack paths.

    Builds a directed graph of:
    - Initial access vectors (what can we exploit from zero knowledge)
    - Lateral movement paths (how to move from host to host)
    - Privilege escalation (how to go from user to admin/DA)
    """

    def __init__(self, db_path: str):
        self.db_path = db_path

    def analyze(self) -> Dict:
        """Run full attack path analysis.

        Returns:
            {
                'initial_access': [...],
                'lateral_movement': [...],
                'privilege_escalation': [...],
                'attack_chains': [...],
                'graph': {'nodes': [...], 'edges': [...]},
                'risk_score': float,
                'summary': str,
            }
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row

        try:
            # Gather all findings
            findings = self._gather_findings(conn)

            # Build attack vectors
            initial_access = self._find_initial_access(conn, findings)
            lateral_paths = self._find_lateral_movement(conn, findings)
            priv_esc = self._find_privilege_escalation(conn, findings)

            # Build chains (initial → lateral → priv esc)
            chains = self._build_attack_chains(initial_access, lateral_paths, priv_esc)

            # Build visualization graph
            graph = self._build_graph(initial_access, lateral_paths, priv_esc, chains)

            # Calculate overall risk score
            risk_score = self._calculate_risk_score(initial_access, lateral_paths, priv_esc)
        finally:
            conn.close()

        return {
            'initial_access': initial_access,
            'lateral_movement': lateral_paths,
            'privilege_escalation': priv_esc,
            'attack_chains': chains,
            'graph': graph,
            'risk_score': risk_score,
            'summary': self._generate_summary(initial_access, lateral_paths, priv_esc, chains, risk_score),
        }

    def _gather_findings(self, conn) -> Dict:
        """Collect all relevant findings from the database."""
        findings = {
            'hosts': [],
            'ports': [],
            'vulns': [],
            'services': [],
            'creds': [],
            'enum': [],
            'tls': [],
        }

        findings['hosts'] = [dict(r) for r in conn.execute(
            'SELECT * FROM hosts WHERE is_active = 1'
        ).fetchall()]

        findings['ports'] = [dict(r) for r in conn.execute(
            'SELECT p.*, h.ip, h.hostname FROM ports p JOIN hosts h ON h.id = p.host_id WHERE p.is_active = 1'
        ).fetchall()]

        findings['vulns'] = [dict(r) for r in conn.execute(
            'SELECT v.*, h.ip, h.hostname FROM vulnerabilities v JOIN hosts h ON h.id = v.host_id'
        ).fetchall()]

        # Service enumeration findings
        try:
            findings['enum'] = [dict(r) for r in conn.execute(
                'SELECT se.*, h.ip, h.hostname FROM service_enumeration se '
                'LEFT JOIN hosts h ON h.id = se.host_id'
            ).fetchall()]
        except Exception as e:
            logger.warning("Failed to load service_enumeration findings: %s", e)

        # Credential spray results
        try:
            findings['creds'] = [dict(r) for r in conn.execute(
                'SELECT c.*, h.ip, h.hostname FROM credential_results c '
                'JOIN hosts h ON h.id = c.host_id WHERE c.success = 1'
            ).fetchall()]
        except Exception as e:
            logger.warning("Failed to load credential_results findings: %s", e)

        # TLS findings
        try:
            findings['tls'] = [dict(r) for r in conn.execute(
                'SELECT * FROM tls_certificates WHERE is_expired = 1 OR is_self_signed = 1'
            ).fetchall()]
        except Exception as e:
            logger.warning("Failed to load tls_certificates findings: %s", e)

        return findings

    def _find_initial_access(self, conn, findings: Dict) -> List[Dict]:
        """Identify initial access vectors from findings."""
        vectors = []

        # Check for unauthenticated services
        for enum in findings.get('enum', []):
            data = {}
            try:
                data = json.loads(enum.get('enum_data', '{}') or '{}')
            except (json.JSONDecodeError, TypeError):
                data = {}

            # Newer schemas store summary data in details and severity in severity.
            if not data and enum.get('details'):
                try:
                    details_data = json.loads(enum.get('details', '{}') or '{}')
                    if isinstance(details_data, dict):
                        data = details_data.get('enum_data', {}) if isinstance(details_data.get('enum_data', {}), dict) else {}
                except (json.JSONDecodeError, TypeError):
                    data = {}

            risk = (enum.get('risk_level') or enum.get('severity') or 'info').lower()

            if risk in ('critical', 'high'):
                technique = None
                if 'redis' in (enum.get('service_type', '') or '').lower():
                    technique = ATTACK_TECHNIQUES.get('redis_rce')
                elif 'docker' in (enum.get('service_type', '') or '').lower():
                    technique = ATTACK_TECHNIQUES.get('docker_escape')
                elif 'elasticsearch' in (enum.get('service_type', '') or '').lower():
                    technique = ATTACK_TECHNIQUES.get('elasticsearch_data')
                elif 'smb' in (enum.get('service_type', '') or '').lower():
                    if data.get('signing_required') is False:
                        technique = ATTACK_TECHNIQUES.get('smb_relay')
                    elif data.get('null_session'):
                        technique = ATTACK_TECHNIQUES.get('null_session')
                elif 'ldap' in (enum.get('service_type', '') or '').lower():
                    technique = ATTACK_TECHNIQUES.get('ldap_anon_enum')

                if technique:
                    vectors.append({
                        'host_ip': enum.get('ip', ''),
                        'port': enum.get('port', 0),
                        'technique': technique['name'],
                        'mitre': technique['mitre'],
                        'severity': technique['severity'],
                        'description': technique['description'],
                        'gains': technique['gains'],
                    })

        # Check successful credential sprays
        for cred in findings.get('creds', []):
            vectors.append({
                'host_ip': cred.get('ip', ''),
                'port': cred.get('port', 0),
                'technique': 'Default Credentials \u2192 RCE',
                'mitre': 'T1078.001',
                'severity': 'critical',
                'description': f"Valid credentials found for {cred.get('service', 'unknown')} ({cred.get('username', '')})",
                'gains': 'code_execution',
            })

        # Check Nuclei critical findings
        for vuln in findings.get('vulns', []):
            if (vuln.get('severity', '') or '').lower() == 'critical':
                vectors.append({
                    'host_ip': vuln.get('ip', ''),
                    'port': 0,
                    'technique': vuln.get('name', 'Critical Vulnerability'),
                    'mitre': 'T1190',
                    'severity': 'critical',
                    'description': vuln.get('description', ''),
                    'gains': 'code_execution',
                })

        return vectors

    def _find_lateral_movement(self, conn, findings: Dict) -> List[Dict]:
        """Identify lateral movement opportunities."""
        paths = []

        # Find all hosts with RDP/SSH/WinRM open
        for port_info in findings.get('ports', []):
            port = port_info.get('port', 0)
            ip = port_info.get('ip', '')
            service = port_info.get('service', '') or ''

            if port == 3389 or 'rdp' in service.lower():
                paths.append({
                    'from': '*',  # Any compromised host with creds
                    'to': ip,
                    'port': port,
                    'method': 'RDP',
                    'technique': ATTACK_TECHNIQUES['rdp_lateral']['name'],
                    'mitre': 'T1021.001',
                    'requires': 'Valid credentials',
                })
            elif port == 22 or 'ssh' in service.lower():
                paths.append({
                    'from': '*',
                    'to': ip,
                    'port': port,
                    'method': 'SSH',
                    'technique': ATTACK_TECHNIQUES['ssh_lateral']['name'],
                    'mitre': 'T1021.004',
                    'requires': 'Valid credentials or SSH key',
                })
            elif port in (5985, 5986) or 'winrm' in service.lower():
                paths.append({
                    'from': '*',
                    'to': ip,
                    'port': port,
                    'method': 'WinRM',
                    'technique': ATTACK_TECHNIQUES['winrm_lateral']['name'],
                    'mitre': 'T1021.006',
                    'requires': 'Valid credentials (admin)',
                })

        # SMB relay paths (from any host to signing-disabled host)
        for enum in findings.get('enum', []):
            try:
                data = json.loads(enum.get('enum_data', '{}') or '{}')
            except (json.JSONDecodeError, TypeError):
                data = {}
            if data.get('signing_required') is False:
                paths.append({
                    'from': '*',
                    'to': enum.get('ip', ''),
                    'port': 445,
                    'method': 'SMB Relay',
                    'technique': 'NTLM Relay to unsigned SMB',
                    'mitre': 'T1557.001',
                    'requires': 'Network position (MITM or coerced auth)',
                })

        return paths

    def _find_privilege_escalation(self, conn, findings: Dict) -> List[Dict]:
        """Identify privilege escalation paths."""
        priv_esc = []

        # Kerberoasting
        try:
            ad_objects = conn.execute(
                "SELECT * FROM ad_objects WHERE object_type = 'kerberoastable'"
            ).fetchall()
            if ad_objects:
                priv_esc.append({
                    'technique': 'Kerberoasting',
                    'mitre': 'T1558.003',
                    'targets': len(ad_objects),
                    'description': f"{len(ad_objects)} service accounts with SPNs can be roasted offline",
                    'severity': 'high',
                    'gains': 'Service account credentials (potentially DA)',
                })
        except Exception:
            pass

        # AS-REP Roasting
        try:
            asrep = conn.execute(
                "SELECT * FROM ad_objects WHERE object_type = 'asrep_roastable'"
            ).fetchall()
            if asrep:
                priv_esc.append({
                    'technique': 'AS-REP Roasting',
                    'mitre': 'T1558.004',
                    'targets': len(asrep),
                    'description': f"{len(asrep)} accounts without pre-auth requirement",
                    'severity': 'high',
                    'gains': 'User credentials',
                })
        except Exception:
            pass

        # Domain Admin via credential chain
        if findings.get('creds'):
            priv_esc.append({
                'technique': 'Credential Reuse',
                'mitre': 'T1078',
                'targets': len(findings['creds']),
                'description': 'Compromised credentials may grant access to higher-privilege systems',
                'severity': 'high',
                'gains': 'Elevated privileges via password reuse',
            })

        return priv_esc

    def _build_attack_chains(self, initial: List, lateral: List, priv_esc: List) -> List[Dict]:
        """Build end-to-end attack chains from initial access to objective."""
        chains = []

        for ia in initial:
            chain = {
                'id': len(chains),
                'steps': [],
                'severity': ia['severity'],
                'objective': 'Unknown',
            }

            # Step 1: Initial access
            chain['steps'].append({
                'step': 1,
                'type': 'initial_access',
                'host': ia['host_ip'],
                'technique': ia['technique'],
                'mitre': ia['mitre'],
            })

            # Step 2: Find lateral movement from this host
            next_targets = [l for l in lateral if l['to'] != ia['host_ip']]
            if next_targets:
                target = next_targets[0]  # Pick first available
                chain['steps'].append({
                    'step': 2,
                    'type': 'lateral_movement',
                    'host': target['to'],
                    'technique': target['technique'],
                    'mitre': target['mitre'],
                })

            # Step 3: Privilege escalation
            if priv_esc:
                pe = priv_esc[0]
                chain['steps'].append({
                    'step': 3,
                    'type': 'privilege_escalation',
                    'technique': pe['technique'],
                    'mitre': pe['mitre'],
                    'gains': pe['gains'],
                })
                chain['objective'] = pe['gains']

            if chain['steps']:
                chains.append(chain)

        # Sort by severity and length
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        chains.sort(key=lambda c: severity_order.get(c['severity'], 9))

        return chains[:20]  # Top 20 chains

    def _build_graph(self, initial, lateral, priv_esc, chains) -> Dict:
        """Build a visualization-ready graph of attack paths."""
        nodes = {}
        edges = []

        # Add attacker node
        nodes['attacker'] = {
            'id': 'attacker',
            'label': 'Attacker',
            'type': 'attacker',
            'color': '#ff1744',
            'size': 30,
        }

        # Add initial access targets
        for ia in initial:
            node_id = ia['host_ip']
            if node_id not in nodes:
                nodes[node_id] = {
                    'id': node_id,
                    'label': ia['host_ip'],
                    'type': 'target',
                    'color': '#dc3545',
                    'size': 25,
                    'techniques': [],
                }
            nodes[node_id]['techniques'].append(ia['technique'])

            edges.append({
                'from': 'attacker',
                'to': node_id,
                'label': ia['technique'][:30],
                'color': '#dc3545',
                'dashes': False,
            })

        # Add lateral movement paths
        for lm in lateral[:50]:  # Limit edges
            target_id = lm['to']
            if target_id not in nodes:
                nodes[target_id] = {
                    'id': target_id,
                    'label': target_id,
                    'type': 'reachable',
                    'color': '#fcb92c',
                    'size': 15,
                    'techniques': [],
                }
            nodes[target_id]['techniques'].append(lm['method'])

            # Connect from initial access nodes
            for ia in initial[:5]:
                edges.append({
                    'from': ia['host_ip'],
                    'to': target_id,
                    'label': lm['method'],
                    'color': '#fcb92c',
                    'dashes': True,
                })
                break  # One edge per lateral target

        # Add privilege escalation as a "crown" node
        if priv_esc:
            nodes['objective'] = {
                'id': 'objective',
                'label': 'Domain Admin / Objective',
                'type': 'objective',
                'color': '#9c27b0',
                'size': 35,
            }
            # Connect from lateral targets
            connected = False
            for node_id, node in nodes.items():
                if node.get('type') == 'reachable' and not connected:
                    edges.append({
                        'from': node_id,
                        'to': 'objective',
                        'label': priv_esc[0]['technique'],
                        'color': '#9c27b0',
                        'dashes': False,
                    })
                    connected = True
            if not connected:
                for ia in initial[:1]:
                    edges.append({
                        'from': ia['host_ip'],
                        'to': 'objective',
                        'label': priv_esc[0]['technique'],
                        'color': '#9c27b0',
                        'dashes': False,
                    })

        return {
            'nodes': list(nodes.values()),
            'edges': edges,
        }

    def _calculate_risk_score(self, initial, lateral, priv_esc) -> float:
        """Calculate an overall risk score (0-100)."""
        score = 0.0

        # Initial access severity
        for ia in initial:
            if ia['severity'] == 'critical':
                score += 25
            elif ia['severity'] == 'high':
                score += 15
            elif ia['severity'] == 'medium':
                score += 8

        # Lateral movement availability
        unique_lateral = set(l['to'] for l in lateral)
        score += min(20, len(unique_lateral) * 2)

        # Privilege escalation paths
        for pe in priv_esc:
            if pe['severity'] == 'critical':
                score += 20
            elif pe['severity'] == 'high':
                score += 10

        return min(100.0, score)

    def _generate_summary(self, initial, lateral, priv_esc, chains, risk_score) -> str:
        """Generate a human-readable summary."""
        parts = [f"Risk Score: {risk_score:.0f}/100"]

        if initial:
            parts.append(f"{len(initial)} initial access vector(s) identified")
        if lateral:
            unique_targets = set(l['to'] for l in lateral)
            parts.append(f"{len(unique_targets)} hosts reachable via lateral movement")
        if priv_esc:
            parts.append(f"{len(priv_esc)} privilege escalation path(s)")
        if chains:
            parts.append(f"{len(chains)} complete attack chain(s) from initial access to objective")

        if risk_score >= 75:
            parts.append("CRITICAL: Multiple high-confidence paths to domain compromise exist.")
        elif risk_score >= 50:
            parts.append("HIGH: Significant attack surface with exploitable paths.")
        elif risk_score >= 25:
            parts.append("MEDIUM: Some attack vectors present but limited chaining.")
        else:
            parts.append("LOW: Limited attack surface detected.")

        return ' | '.join(parts)
