"""
Transform Engine v2.0 - 30+ Granular Transforms + Auto-Chaining
Maltego killer — AI-powered transform orchestration
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
import time
from typing import List, Dict
from sentinel_intel.core.database import db
from sentinel_intel.core.email_engine import EmailEngine
from sentinel_intel.core.phone_engine import PhoneEngine
from sentinel_intel.core.ip_engine import IPEngine
from sentinel_intel.core.person_engine import PersonEngine
from sentinel_intel.core.domain_engine import DomainEngine
from sentinel_intel.core.username_engine import UsernameEngine
from sentinel_intel.core.hash_engine import HashEngine
from sentinel_intel.core.cryptocurrency_engine import CryptocurrencyEngine
from sentinel_intel.core.url_engine import URLEngine
from sentinel_intel.core.company_engine import CompanyEngine
from sentinel_intel.core.cve_engine import CVEEngine
from sentinel_intel.core.malware_engine import MalwareEngine
from sentinel_intel.core.breach_engine import BreachEngine

class TransformEngine:
    """Master transform orchestrator with 30+ transforms"""
    
    def __init__(self):
        self.engines = {
            'email': EmailEngine(),
            'phone': PhoneEngine(),
            'ip': IPEngine(),
            'person': PersonEngine(),
            'domain': DomainEngine(),
            'username': UsernameEngine(),
            'hash': HashEngine(),
            'cryptocurrency': CryptocurrencyEngine(),
            'url': URLEngine(),
            'company': CompanyEngine(),
            'cve': CVEEngine(),
            'malware': MalwareEngine(),
            'breach': BreachEngine()
        }
        
        # 30+ Transform definitions
        self.transforms = {
            # Email transforms
            'email_to_breaches': {'engine': 'email', 'extract': 'breaches'},
            'email_to_profiles': {'engine': 'email', 'extract': 'profiles'},
            'email_to_domains': {'engine': 'email', 'extract': 'domains'},
            'email_to_usernames': {'engine': 'email', 'extract': 'usernames'},
            'email_to_phones': {'engine': 'email', 'extract': 'phones'},
            'email_to_names': {'engine': 'email', 'extract': 'names'},
            'email_to_social_media': {'engine': 'email', 'extract': 'social_media'},
            
            # Phone transforms
            'phone_to_carrier': {'engine': 'phone', 'extract': 'carrier'},
            'phone_to_location': {'engine': 'phone', 'extract': 'country'},
            'phone_to_messaging_apps': {'engine': 'phone', 'extract': 'messaging_apps'},
            'phone_to_names': {'engine': 'phone', 'extract': 'names'},
            'phone_to_emails': {'engine': 'phone', 'extract': 'emails'},
            'phone_to_profiles': {'engine': 'phone', 'extract': 'profiles'},
            
            # IP transforms
            'ip_to_geolocation': {'engine': 'ip', 'extract': 'geolocation'},
            'ip_to_ports': {'engine': 'ip', 'extract': 'ports'},
            'ip_to_vulns': {'engine': 'ip', 'extract': 'vulns'},
            'ip_to_domains': {'engine': 'ip', 'extract': 'domains'},
            'ip_to_asn': {'engine': 'ip', 'extract': 'asn'},
            'ip_to_threat_intel': {'engine': 'ip', 'extract': 'threat_intel'},
            
            # Domain transforms
            'domain_to_ips': {'engine': 'domain', 'extract': 'ips'},
            'domain_to_subdomains': {'engine': 'domain', 'extract': 'subdomains'},
            'domain_to_whois': {'engine': 'domain', 'extract': 'whois'},
            'domain_to_tech_stack': {'engine': 'domain', 'extract': 'tech_stack'},
            'domain_to_certificates': {'engine': 'domain', 'extract': 'certificates'},
            'domain_to_nameservers': {'engine': 'domain', 'extract': 'nameservers'},
            
            # Person transforms
            'person_to_emails': {'engine': 'person', 'extract': 'emails'},
            'person_to_phones': {'engine': 'person', 'extract': 'phones'},
            'person_to_usernames': {'engine': 'person', 'extract': 'usernames'},
            'person_to_profiles': {'engine': 'person', 'extract': 'profiles'},
            'person_to_addresses': {'engine': 'person', 'extract': 'addresses'},
            'person_to_jobs': {'engine': 'person', 'extract': 'jobs'},
            
            # Username transforms
            'username_to_platforms': {'engine': 'username', 'extract': 'found_platforms'},
            'username_to_profile_links': {'engine': 'username', 'extract': 'profile_links'},
            
            # Hash transforms
            'hash_to_malware_families': {'engine': 'hash', 'extract': 'malware_families'},
            'hash_to_threat_names': {'engine': 'hash', 'extract': 'threat_names'},
            'hash_to_file_info': {'engine': 'hash', 'extract': 'file_info'},
            
            # Cryptocurrency transforms
            'crypto_to_transactions': {'engine': 'cryptocurrency', 'extract': 'transactions'},
            'crypto_to_related_addresses': {'engine': 'cryptocurrency', 'extract': 'related_addresses'},
            'crypto_to_balance': {'engine': 'cryptocurrency', 'extract': 'balance'},
            
            # URL transforms
            'url_to_redirects': {'engine': 'url', 'extract': 'redirects'},
            'url_to_domain': {'engine': 'url', 'extract': 'domain'},
            'url_to_ip': {'engine': 'url', 'extract': 'ip'},
            'url_to_threat_names': {'engine': 'url', 'extract': 'threat_names'},
            'url_to_technologies': {'engine': 'url', 'extract': 'technologies'},
            'url_to_certificates': {'engine': 'url', 'extract': 'certificates'},
            
            # Company transforms
            'company_to_domain': {'engine': 'company', 'extract': 'domain'},
            'company_to_domains': {'engine': 'company', 'extract': 'domains'},
            'company_to_employees': {'engine': 'company', 'extract': 'employees'},
            'company_to_emails': {'engine': 'company', 'extract': 'emails'},
            'company_to_social_media': {'engine': 'company', 'extract': 'social_media'},
            'company_to_technologies': {'engine': 'company', 'extract': 'technologies'},
            'company_to_jobs': {'engine': 'company', 'extract': 'jobs'},
            
            # CVE transforms
            'cve_to_exploits': {'engine': 'cve', 'extract': 'exploits'},
            'cve_to_affected_products': {'engine': 'cve', 'extract': 'affected_products'},
            'cve_to_vendors': {'engine': 'cve', 'extract': 'vendors'},
            'cve_to_patches': {'engine': 'cve', 'extract': 'patches'},
            'cve_to_references': {'engine': 'cve', 'extract': 'references'},
            
            # Malware transforms
            'malware_to_samples': {'engine': 'malware', 'extract': 'samples'},
            'malware_to_iocs': {'engine': 'malware', 'extract': 'iocs'},
            'malware_to_c2_servers': {'engine': 'malware', 'extract': 'c2_servers'},
            'malware_to_behavior': {'engine': 'malware', 'extract': 'behavior'},
            'malware_to_campaigns': {'engine': 'malware', 'extract': 'campaigns'},
            'malware_to_hashes': {'engine': 'malware', 'extract': 'hashes'},
            
            # Breach transforms
            'breach_to_breaches': {'engine': 'breach', 'extract': 'breaches'},
            'breach_to_passwords': {'engine': 'breach', 'extract': 'passwords'},
            'breach_to_leaks': {'engine': 'breach', 'extract': 'leaks'},
            'breach_to_pastes': {'engine': 'breach', 'extract': 'pastes'},
            'breach_to_emails': {'engine': 'breach', 'extract': 'emails'},
            'breach_to_usernames': {'engine': 'breach', 'extract': 'usernames'}
        }
    
    def execute(self, node_id: str, transform_type: str) -> List[Dict]:
        """Execute transform and add results to graph"""
        start_time = time.time()
        nodes = [n for n in db.get_nodes() if n['id'] == node_id]
        if not nodes:
            return []
        
        node = nodes[0]
        entity_type = node['entity_type']
        label = node['label']
        results = []
        
        # Check if transform is defined
        if transform_type in self.transforms:
            transform_def = self.transforms[transform_type]
            engine_name = transform_def['engine']
            extract_field = transform_def['extract']
            
            # Execute engine investigation
            engine = self.engines.get(engine_name)
            if engine:
                data = engine.investigate(label)
                results = self._extract_and_create_nodes(node_id, data, extract_field, transform_type)
        
        # Legacy full investigation transforms
        elif transform_type == 'email_investigate' and entity_type == 'email':
            data = self.engines['email'].investigate(label)
            
            # Update source node with Groq analysis
            if data.get('groq_analysis'):
                node = [n for n in db.get_nodes() if n['id'] == node_id]
                if node:
                    props = node[0].get('properties', {})
                    props['groq_analysis'] = data['groq_analysis']
                    db.update_node_properties(node_id, props)
            
            results = self._process_email_results(node_id, data)
        elif transform_type == 'phone_investigate' and entity_type == 'phone':
            data = self.engines['phone'].investigate(label)
            
            # Update source node with Groq analysis
            if data.get('groq_analysis'):
                node = [n for n in db.get_nodes() if n['id'] == node_id]
                if node:
                    props = node[0].get('properties', {})
                    props['groq_analysis'] = data['groq_analysis']
                    db.update_node_properties(node_id, props)
            
            results = self._process_phone_results(node_id, data)
        elif transform_type == 'ip_investigate' and entity_type == 'ip':
            data = self.engines['ip'].investigate(label)
            
            # Update source node with Groq analysis
            if data.get('groq_analysis'):
                node = [n for n in db.get_nodes() if n['id'] == node_id]
                if node:
                    props = node[0].get('properties', {})
                    props['groq_analysis'] = data['groq_analysis']
                    db.update_node_properties(node_id, props)
            
            results = self._process_ip_results(node_id, data)
        elif transform_type == 'person_investigate' and entity_type == 'person':
            data = self.engines['person'].investigate(label)
            
            # Update source node with Groq analysis
            if data.get('groq_analysis'):
                node = [n for n in db.get_nodes() if n['id'] == node_id]
                if node:
                    props = node[0].get('properties', {})
                    props['groq_analysis'] = data['groq_analysis']
                    db.update_node_properties(node_id, props)
            
            results = self._process_person_results(node_id, data)
        elif transform_type == 'domain_investigate' and entity_type == 'domain':
            data = self.engines['domain'].investigate(label)
            
            # Update source node with Groq analysis
            if data.get('groq_analysis'):
                node = [n for n in db.get_nodes() if n['id'] == node_id]
                if node:
                    props = node[0].get('properties', {})
                    props['groq_analysis'] = data['groq_analysis']
                    db.update_node_properties(node_id, props)
            
            results = self._process_domain_results(node_id, data)
        elif transform_type == 'username_investigate' and entity_type == 'username':
            data = self.engines['username'].investigate(label)
            
            # Update source node with Groq analysis
            if data.get('groq_analysis'):
                node = [n for n in db.get_nodes() if n['id'] == node_id]
                if node:
                    props = node[0].get('properties', {})
                    props['groq_analysis'] = data['groq_analysis']
                    db.update_node_properties(node_id, props)
            
            results = self._process_username_results(node_id, data)
        elif transform_type == 'hash_investigate' and entity_type == 'hash':
            data = self.engines['hash'].investigate(label)
            
            # Update source node with Groq analysis
            if data.get('groq_analysis'):
                node = [n for n in db.get_nodes() if n['id'] == node_id]
                if node:
                    props = node[0].get('properties', {})
                    props['groq_analysis'] = data['groq_analysis']
                    db.update_node_properties(node_id, props)
            
            results = self._process_hash_results(node_id, data)
        elif transform_type == 'crypto_investigate' and entity_type == 'cryptocurrency':
            data = self.engines['cryptocurrency'].investigate(label)
            
            # Update source node with Groq analysis
            if data.get('groq_analysis'):
                node = [n for n in db.get_nodes() if n['id'] == node_id]
                if node:
                    props = node[0].get('properties', {})
                    props['groq_analysis'] = data['groq_analysis']
                    db.update_node_properties(node_id, props)
            
            results = self._process_crypto_results(node_id, data)
        elif transform_type == 'url_investigate' and entity_type == 'url':
            data = self.engines['url'].investigate(label)
            # Update source node properties
            url_props = {
                'status_code': data.get('status_code'),
                'malicious': data.get('malicious'),
                'phishing': data.get('phishing'),
                'threat_score': data.get('threat_score'),
                'screenshot': data.get('screenshot')
            }
            url_props = {k: v for k, v in url_props.items() if v is not None}
            if url_props:
                db.update_node_properties(node_id, url_props)
            results = self._process_url_results(node_id, data)
        elif transform_type == 'company_investigate' and entity_type == 'company':
            data = self.engines['company'].investigate(label)
            # Update source node properties with company data
            company_props = {
                'website': data.get('website'),
                'industry': data.get('industry'),
                'location': data.get('location'),
                'employees_count': data.get('employees_count'),
                'founded': data.get('founded'),
                'description': data.get('description')
            }
            # Remove None values
            company_props = {k: v for k, v in company_props.items() if v is not None}
            if company_props:
                db.update_node_properties(node_id, company_props)
            results = self._process_company_results(node_id, data)
        elif transform_type == 'cve_investigate' and entity_type == 'cve':
            data = self.engines['cve'].investigate(label)
            # Update source node properties
            cve_props = {
                'cvss_score': data.get('cvss_score'),
                'severity': data.get('severity'),
                'published': data.get('published'),
                'description': data.get('description'),
                'exploited': data.get('exploited')
            }
            cve_props = {k: v for k, v in cve_props.items() if v is not None}
            if cve_props:
                db.update_node_properties(node_id, cve_props)
            results = self._process_cve_results(node_id, data)
        elif transform_type == 'malware_investigate' and entity_type == 'malware':
            data = self.engines['malware'].investigate(label)
            # Update source node properties
            malware_props = {
                'family': data.get('family'),
                'type': data.get('type'),
                'first_seen': data.get('first_seen'),
                'threat_level': data.get('threat_level')
            }
            malware_props = {k: v for k, v in malware_props.items() if v is not None}
            if malware_props:
                db.update_node_properties(node_id, malware_props)
            results = self._process_malware_results(node_id, data)
        elif transform_type == 'breach_investigate' and entity_type == 'breach':
            data = self.engines['breach'].investigate(label)
            # Update source node properties
            breach_props = {
                'date': data.get('date'),
                'records': data.get('records'),
                'verified': data.get('verified'),
                'data_classes': data.get('data_classes')
            }
            breach_props = {k: v for k, v in breach_props.items() if v is not None}
            if breach_props:
                db.update_node_properties(node_id, breach_props)
            results = self._process_breach_results(node_id, data)
        
        # Log transform
        execution_time = time.time() - start_time
        api_used = ','.join(data.get('sources', [])) if results and 'data' in locals() else 'none'
        db.log_transform(node_id, transform_type, entity_type, len(results), api_used, ml_enhanced=True, execution_time=execution_time)
        
        return results
    
    def _extract_and_create_nodes(self, source_node: str, data: Dict, field: str, transform_type: str) -> List[Dict]:
        """Extract specific field and create nodes"""
        results = []
        extracted_data = data.get(field, [])
        
        # Handle different data types
        if isinstance(extracted_data, list):
            for item in extracted_data[:20]:  # Limit to 20 nodes
                if isinstance(item, dict):
                    # Complex object (e.g., breach, profile)
                    node_type = self._infer_node_type(field, item)
                    label = item.get('name') or item.get('platform') or item.get('source') or str(item)[:50]
                    new_node = db.add_node(node_type, label, item, confidence=0.8)
                    relationship = self._infer_relationship(transform_type)
                    db.add_edge(source_node, new_node, relationship, confidence=0.8)
                    results.append({'node_id': new_node, 'type': node_type})
                elif isinstance(item, str):
                    # Simple string
                    node_type = self._infer_node_type(field, item)
                    new_node = db.add_node(node_type, item, {}, confidence=0.8)
                    relationship = self._infer_relationship(transform_type)
                    db.add_edge(source_node, new_node, relationship, confidence=0.8)
                    results.append({'node_id': new_node, 'type': node_type})
        elif isinstance(extracted_data, dict):
            # Single object
            node_type = self._infer_node_type(field, extracted_data)
            label = str(extracted_data)[:50]
            new_node = db.add_node(node_type, label, extracted_data, confidence=0.9)
            relationship = self._infer_relationship(transform_type)
            db.add_edge(source_node, new_node, relationship, confidence=0.9)
            results.append({'node_id': new_node, 'type': node_type})
        elif extracted_data:
            # Simple value
            node_type = self._infer_node_type(field, extracted_data)
            new_node = db.add_node(node_type, str(extracted_data), {}, confidence=0.9)
            relationship = self._infer_relationship(transform_type)
            db.add_edge(source_node, new_node, relationship, confidence=0.9)
            results.append({'node_id': new_node, 'type': node_type})
        
        return results
    
    def _infer_node_type(self, field: str, data) -> str:
        """Infer node type from field name"""
        type_map = {
            'breaches': 'breach',
            'profiles': 'username',
            'domains': 'domain',
            'usernames': 'username',
            'phones': 'phone',
            'names': 'person',
            'emails': 'email',
            'social_media': 'username',
            'carrier': 'company',
            'country': 'location',
            'messaging_apps': 'username',
            'geolocation': 'location',
            'ports': 'port',
            'vulns': 'cve',
            'threat_intel': 'threat',
            'ips': 'ip',
            'subdomains': 'domain',
            'whois': 'company',
            'tech_stack': 'technology',
            'certificates': 'certificate',
            'nameservers': 'domain',
            'addresses': 'location',
            'jobs': 'company',
            'found_platforms': 'username',
            'profile_links': 'url',
            'malware_families': 'malware',
            'threat_names': 'threat',
            'file_info': 'file',
            'transactions': 'transaction',
            'related_addresses': 'cryptocurrency',
            'balance': 'cryptocurrency'
        }
        return type_map.get(field, 'unknown')
    
    def _infer_relationship(self, transform_type: str) -> str:
        """Infer relationship from transform type"""
        rel_map = {
            'email_to_breaches': 'found_in_breach',
            'email_to_profiles': 'has_profile',
            'email_to_domains': 'belongs_to_domain',
            'email_to_usernames': 'uses_username',
            'email_to_phones': 'has_phone',
            'email_to_names': 'belongs_to',
            'phone_to_carrier': 'carrier',
            'phone_to_location': 'located_in',
            'phone_to_messaging_apps': 'registered_on',
            'phone_to_names': 'belongs_to',
            'phone_to_emails': 'linked_to',
            'ip_to_geolocation': 'located_in',
            'ip_to_ports': 'open_port',
            'ip_to_vulns': 'vulnerable_to',
            'ip_to_domains': 'hosts',
            'ip_to_asn': 'belongs_to_asn',
            'domain_to_ips': 'resolves_to',
            'domain_to_subdomains': 'subdomain',
            'domain_to_whois': 'registered_by',
            'domain_to_tech_stack': 'uses_technology',
            'person_to_emails': 'has_email',
            'person_to_phones': 'has_phone',
            'person_to_usernames': 'uses_username',
            'person_to_profiles': 'social_profile',
            'username_to_platforms': 'found_on',
            'hash_to_malware_families': 'identified_as',
            'crypto_to_transactions': 'transaction',
            'crypto_to_related_addresses': 'connected_to'
        }
        return rel_map.get(transform_type, 'related_to')
    
    # Legacy full investigation processors
    def _process_email_results(self, source_node: str, data: Dict) -> List[Dict]:
        results = []
        for breach in data.get('breaches', [])[:10]:
            name = breach.get('name') or breach.get('Name', 'Unknown')
            new_node = db.add_node('breach', name, breach, confidence=0.9)
            db.add_edge(source_node, new_node, 'found_in_breach', confidence=0.9)
            results.append({'node_id': new_node, 'type': 'breach'})
        for profile in data.get('profiles', [])[:10]:
            label = profile.get('source') or profile.get('platform', 'Unknown')
            new_node = db.add_node('username', label, profile, confidence=0.7)
            db.add_edge(source_node, new_node, 'has_profile', confidence=0.7)
            results.append({'node_id': new_node, 'type': 'username'})
        return results
    
    def _process_phone_results(self, source_node: str, data: Dict) -> List[Dict]:
        results = []
        if data.get('carrier'):
            carrier_props = {
                'type': 'carrier',
                'country': data.get('country'),
                'line_type': data.get('line_type')
            }
            new_node = db.add_node('company', data['carrier'], carrier_props, confidence=0.9)
            db.add_edge(source_node, new_node, 'carrier', confidence=0.9)
            results.append({'node_id': new_node, 'type': 'company'})
        if data.get('country'):
            location_props = {
                'type': 'country',
                'country_code': data.get('country_code'),
                'region': data.get('region'),
                'timezone': data.get('timezone'),
                'line_type': data.get('line_type'),
                'valid': data.get('valid')
            }
            new_node = db.add_node('location', data['country'], location_props, confidence=1.0)
            db.add_edge(source_node, new_node, 'located_in', confidence=1.0)
            results.append({'node_id': new_node, 'type': 'location'})
        for app in data.get('messaging_apps', [])[:5]:
            if isinstance(app, dict) and app.get('exists'):
                app_props = {
                    'platform': app.get('platform'),
                    'url': app.get('url'),
                    'method': app.get('method')
                }
                new_node = db.add_node('username', app['platform'], app_props, confidence=0.8)
                db.add_edge(source_node, new_node, 'registered_on', confidence=0.8)
                results.append({'node_id': new_node, 'type': 'username'})
        return results
    
    def _process_ip_results(self, source_node: str, data: Dict) -> List[Dict]:
        results = []
        geo = data.get('geolocation', {})
        if geo and geo.get('country'):
            # Pass full geolocation data as properties
            new_node = db.add_node('location', geo['country'], geo, confidence=0.95)
            db.add_edge(source_node, new_node, 'located_in', confidence=0.95)
            results.append({'node_id': new_node, 'type': 'location'})
        for port in data.get('ports', [])[:10]:
            port_props = {
                'ip': data['ip'],
                'port': port
            }
            new_node = db.add_node('port', str(port), port_props, confidence=1.0)
            db.add_edge(source_node, new_node, 'open_port', confidence=1.0)
            results.append({'node_id': new_node, 'type': 'port'})
        for domain in data.get('domains', [])[:10]:
            new_node = db.add_node('domain', domain, {'ip': data['ip']}, confidence=0.8)
            db.add_edge(source_node, new_node, 'hosts', confidence=0.8)
            results.append({'node_id': new_node, 'type': 'domain'})
        if data.get('asn') and data['asn'].get('name'):
            new_node = db.add_node('company', data['asn']['name'], data['asn'], confidence=0.9)
            db.add_edge(source_node, new_node, 'belongs_to_asn', confidence=0.9)
            results.append({'node_id': new_node, 'type': 'company'})
        return results
    
    def _process_person_results(self, source_node: str, data: Dict) -> List[Dict]:
        results = []
        for email in data.get('emails', [])[:5]:
            new_node = db.add_node('email', email, {}, confidence=0.8)
            db.add_edge(source_node, new_node, 'has_email', confidence=0.8)
            results.append({'node_id': new_node, 'type': 'email'})
        for phone in data.get('phones', [])[:5]:
            new_node = db.add_node('phone', phone, {}, confidence=0.8)
            db.add_edge(source_node, new_node, 'has_phone', confidence=0.8)
            results.append({'node_id': new_node, 'type': 'phone'})
        return results
    
    def _process_domain_results(self, source_node: str, data: Dict) -> List[Dict]:
        results = []
        for ip in data.get('ips', [])[:5]:
            new_node = db.add_node('ip', ip, {}, confidence=1.0)
            db.add_edge(source_node, new_node, 'resolves_to', confidence=1.0)
            results.append({'node_id': new_node, 'type': 'ip'})
        for subdomain in data.get('subdomains', [])[:20]:
            new_node = db.add_node('domain', subdomain, {'parent': data['domain']}, confidence=0.9)
            db.add_edge(source_node, new_node, 'subdomain', confidence=0.9)
            results.append({'node_id': new_node, 'type': 'domain'})
        return results
    
    def _process_username_results(self, source_node: str, data: Dict) -> List[Dict]:
        results = []
        for link in data.get('profile_links', [])[:20]:
            new_node = db.add_node('url', link['url'], link, confidence=0.9)
            db.add_edge(source_node, new_node, 'found_on', confidence=0.9)
            results.append({'node_id': new_node, 'type': 'url'})
        return results
    
    def _process_hash_results(self, source_node: str, data: Dict) -> List[Dict]:
        results = []
        for family in data.get('malware_families', [])[:10]:
            new_node = db.add_node('malware', family, {}, confidence=0.9)
            db.add_edge(source_node, new_node, 'identified_as', confidence=0.9)
            results.append({'node_id': new_node, 'type': 'malware'})
        return results
    
    def _process_crypto_results(self, source_node: str, data: Dict) -> List[Dict]:
        results = []
        for addr in data.get('related_addresses', [])[:20]:
            new_node = db.add_node('cryptocurrency', addr, {}, confidence=0.8)
            db.add_edge(source_node, new_node, 'connected_to', confidence=0.8)
            results.append({'node_id': new_node, 'type': 'cryptocurrency'})
        return results
    
    def _process_url_results(self, source_node: str, data: Dict) -> List[Dict]:
        results = []
        if data.get('domain'):
            new_node = db.add_node('domain', data['domain'], {'ip': data.get('ip'), 'registrar': data.get('registrar')}, confidence=1.0)
            db.add_edge(source_node, new_node, 'resolves_to', confidence=1.0)
            results.append({'node_id': new_node, 'type': 'domain'})
        if data.get('ip'):
            new_node = db.add_node('ip', data['ip'], {'country': data.get('country'), 'asn': data.get('asn'), 'isp': data.get('isp')}, confidence=0.9)
            db.add_edge(source_node, new_node, 'hosted_on', confidence=0.9)
            results.append({'node_id': new_node, 'type': 'ip'})
        for redirect in data.get('redirects', [])[:5]:
            new_node = db.add_node('url', redirect['url'], redirect, confidence=0.8)
            db.add_edge(source_node, new_node, 'redirects_to', confidence=0.8)
            results.append({'node_id': new_node, 'type': 'url'})
        for threat in data.get('threat_names', [])[:10]:
            threat_props = {'source': data.get('source'), 'malicious': data.get('malicious'), 'phishing': data.get('phishing')}
            new_node = db.add_node('threat', threat, threat_props, confidence=0.9)
            db.add_edge(source_node, new_node, 'identified_as', confidence=0.9)
            results.append({'node_id': new_node, 'type': 'threat'})
        for tech in data.get('technologies', [])[:10]:
            new_node = db.add_node('technology', tech, {'category': 'web'}, confidence=0.8)
            db.add_edge(source_node, new_node, 'uses_technology', confidence=0.8)
            results.append({'node_id': new_node, 'type': 'technology'})
        return results
    
    def _process_company_results(self, source_node: str, data: Dict) -> List[Dict]:
        results = []
        if data.get('domain'):
            new_node = db.add_node('domain', data['domain'], {'website': data.get('website'), 'company': data.get('name')}, confidence=1.0)
            db.add_edge(source_node, new_node, 'owns_domain', confidence=1.0)
            results.append({'node_id': new_node, 'type': 'domain'})
        for domain in data.get('domains', [])[:10]:
            new_node = db.add_node('domain', domain, {'company': data.get('name')}, confidence=0.8)
            db.add_edge(source_node, new_node, 'owns_domain', confidence=0.8)
            results.append({'node_id': new_node, 'type': 'domain'})
        for employee in data.get('employees', [])[:20]:
            name = employee.get('name') or employee.get('email', '').split('@')[0]
            emp_props = {'title': employee.get('title'), 'linkedin': employee.get('linkedin'), 'company': data.get('name')}
            new_node = db.add_node('person', name, emp_props, confidence=0.7)
            db.add_edge(source_node, new_node, 'employs', confidence=0.7)
            results.append({'node_id': new_node, 'type': 'person'})
        for email in data.get('emails', [])[:20]:
            new_node = db.add_node('email', email, {'company': data.get('name'), 'domain': data.get('domain')}, confidence=0.8)
            db.add_edge(source_node, new_node, 'has_email', confidence=0.8)
            results.append({'node_id': new_node, 'type': 'email'})
        for social in data.get('social_media', [])[:10]:
            social_props = {'platform': social.get('platform'), 'url': social.get('url'), 'followers': social.get('followers')}
            new_node = db.add_node('username', social['platform'], social_props, confidence=0.8)
            db.add_edge(source_node, new_node, 'social_profile', confidence=0.8)
            results.append({'node_id': new_node, 'type': 'username'})
        for tech in data.get('technologies', [])[:10]:
            new_node = db.add_node('technology', tech, {'company': data.get('name')}, confidence=0.7)
            db.add_edge(source_node, new_node, 'uses_technology', confidence=0.7)
            results.append({'node_id': new_node, 'type': 'technology'})
        return results
    
    def _process_cve_results(self, source_node: str, data: Dict) -> List[Dict]:
        results = []
        for product in data.get('affected_products', [])[:20]:
            prod_props = {'vendor': data.get('vendor'), 'cvss': data.get('cvss_score'), 'severity': data.get('severity')}
            new_node = db.add_node('technology', product, prod_props, confidence=0.9)
            db.add_edge(source_node, new_node, 'affects', confidence=0.9)
            results.append({'node_id': new_node, 'type': 'technology'})
        for vendor in data.get('vendors', [])[:10]:
            new_node = db.add_node('company', vendor, {'cve_count': data.get('cve_count')}, confidence=0.8)
            db.add_edge(source_node, new_node, 'affects_vendor', confidence=0.8)
            results.append({'node_id': new_node, 'type': 'company'})
        for exploit in data.get('exploits', [])[:10]:
            exploit_name = exploit.get('title') or exploit.get('id', 'Unknown')
            exp_props = {'type': exploit.get('type'), 'platform': exploit.get('platform'), 'url': exploit.get('url')}
            new_node = db.add_node('exploit', exploit_name, exp_props, confidence=0.9)
            db.add_edge(source_node, new_node, 'has_exploit', confidence=0.9)
            results.append({'node_id': new_node, 'type': 'exploit'})
        for cwe in data.get('cwe', [])[:5]:
            cwe_props = {'name': data.get('cwe_name'), 'description': data.get('description')}
            new_node = db.add_node('cwe', cwe, cwe_props, confidence=1.0)
            db.add_edge(source_node, new_node, 'weakness_type', confidence=1.0)
            results.append({'node_id': new_node, 'type': 'cwe'})
        return results
    
    def _process_malware_results(self, source_node: str, data: Dict) -> List[Dict]:
        results = []
        # IOC IPs
        for ip in data.get('iocs', {}).get('ips', [])[:20]:
            new_node = db.add_node('ip', ip, {'type': 'c2_server', 'malware': data.get('name')}, confidence=0.9)
            db.add_edge(source_node, new_node, 'c2_server', confidence=0.9)
            results.append({'node_id': new_node, 'type': 'ip'})
        # IOC Domains
        for domain in data.get('iocs', {}).get('domains', [])[:20]:
            new_node = db.add_node('domain', domain, {'type': 'c2_domain', 'malware': data.get('name')}, confidence=0.9)
            db.add_edge(source_node, new_node, 'c2_domain', confidence=0.9)
            results.append({'node_id': new_node, 'type': 'domain'})
        # IOC URLs
        for url in data.get('iocs', {}).get('urls', [])[:20]:
            new_node = db.add_node('url', url, {'type': 'malicious', 'malware': data.get('name')}, confidence=0.9)
            db.add_edge(source_node, new_node, 'malicious_url', confidence=0.9)
            results.append({'node_id': new_node, 'type': 'url'})
        # Hashes
        for sha256 in data.get('hashes', {}).get('sha256', [])[:10]:
            new_node = db.add_node('hash', sha256, {'type': 'sha256', 'malware': data.get('name')}, confidence=1.0)
            db.add_edge(source_node, new_node, 'sample_hash', confidence=1.0)
            results.append({'node_id': new_node, 'type': 'hash'})
        # Campaigns
        for campaign in data.get('campaigns', [])[:10]:
            campaign_name = campaign.get('name', 'Unknown')
            camp_props = {'description': campaign.get('description'), 'first_seen': campaign.get('first_seen')}
            new_node = db.add_node('campaign', campaign_name, camp_props, confidence=0.8)
            db.add_edge(source_node, new_node, 'part_of_campaign', confidence=0.8)
            results.append({'node_id': new_node, 'type': 'campaign'})
        return results
    
    def _process_breach_results(self, source_node: str, data: Dict) -> List[Dict]:
        results = []
        # Breaches
        for breach in data.get('breaches', [])[:20]:
            breach_name = breach.get('name') or breach.get('title', 'Unknown')
            breach_props = {'date': breach.get('date'), 'records': breach.get('records'), 'verified': breach.get('verified')}
            new_node = db.add_node('breach', breach_name, breach_props, confidence=0.9)
            db.add_edge(source_node, new_node, 'found_in_breach', confidence=0.9)
            results.append({'node_id': new_node, 'type': 'breach'})
        # Emails
        for email in data.get('emails', [])[:20]:
            new_node = db.add_node('email', email, {'breach_count': data.get('breach_count')}, confidence=0.8)
            db.add_edge(source_node, new_node, 'linked_email', confidence=0.8)
            results.append({'node_id': new_node, 'type': 'email'})
        # Usernames
        for username in data.get('usernames', [])[:20]:
            new_node = db.add_node('username', username, {'source': data.get('source')}, confidence=0.7)
            db.add_edge(source_node, new_node, 'linked_username', confidence=0.7)
            results.append({'node_id': new_node, 'type': 'username'})
        # Phones
        for phone in data.get('phones', [])[:10]:
            new_node = db.add_node('phone', phone, {'source': data.get('source')}, confidence=0.8)
            db.add_edge(source_node, new_node, 'linked_phone', confidence=0.8)
            results.append({'node_id': new_node, 'type': 'phone'})
        # Domains
        for domain in data.get('domains', [])[:10]:
            new_node = db.add_node('domain', domain, {'breached': True}, confidence=0.7)
            db.add_edge(source_node, new_node, 'breached_domain', confidence=0.7)
            results.append({'node_id': new_node, 'type': 'domain'})
        return results

engine = TransformEngine()
