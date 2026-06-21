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
from sentinel_intel.core.database_engine import DatabaseEngine

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
            'breach': BreachEngine(),
            'database': DatabaseEngine()
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
            'breach_to_usernames': {'engine': 'breach', 'extract': 'usernames'},
            
            # Database transforms (NEW - 14th Engine)
            'database_search': {'engine': 'database', 'extract': 'entities'},
            'database_query_history': {'engine': 'database', 'extract': 'timeline'},
            'database_find_related': {'engine': 'database', 'extract': 'relationships'},
            'database_statistics': {'engine': 'database', 'extract': 'stats'}
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
        """Process email results with SUB-ENTITY creation (Maltego style)"""
        results = []
        
        # 1. Domain -> IP -> Location hierarchy
        for domain in data.get('domains', [])[:3]:
            domain_props = {'source': 'email_domain', 'email': data.get('email')}
            domain_node = db.add_node('domain', domain, domain_props, confidence=1.0)
            db.add_edge(source_node, domain_node, 'belongs_to_domain', confidence=1.0)
            results.append({'node_id': domain_node, 'type': 'domain'})
            
            # SUB-ENTITY: Domain -> IP (DNS lookup simulation)
            # In real implementation, do actual DNS lookup
            # For now, create placeholder if domain investigation was done
            # This will be enhanced when domain_engine is updated
        
        # 2. Breaches -> Paste Sites hierarchy
        for breach in data.get('breaches', [])[:10]:
            name = breach.get('name') or breach.get('Name', 'Unknown')
            breach_props = {
                'date': breach.get('date') or breach.get('BreachDate'),
                'records': breach.get('records') or breach.get('PwnCount'),
                'verified': breach.get('verified') or breach.get('IsVerified'),
                'data_classes': breach.get('data_classes') or breach.get('DataClasses', [])
            }
            breach_node = db.add_node('breach', name, breach_props, confidence=0.9)
            db.add_edge(source_node, breach_node, 'found_in_breach', confidence=0.9)
            results.append({'node_id': breach_node, 'type': 'breach'})
            
            # SUB-ENTITY: Breach -> Domain (breach website)
            if breach.get('domain') or breach.get('Domain'):
                breach_domain = breach.get('domain') or breach.get('Domain')
                bd_node = db.add_node('domain', breach_domain, {'type': 'breached_site'}, confidence=1.0)
                db.add_edge(breach_node, bd_node, 'breached_domain', confidence=1.0)
                results.append({'node_id': bd_node, 'type': 'domain'})
        
        # 3. Pastes -> Paste Sites hierarchy
        for paste in data.get('pastes', [])[:10]:
            paste_source = paste.get('source') or paste.get('Source', 'Unknown')
            paste_props = {
                'paste_id': paste.get('id') or paste.get('Id'),
                'title': paste.get('title') or paste.get('Title'),
                'date': paste.get('date') or paste.get('Date')
            }
            paste_node = db.add_node('paste', f"{paste_source}/{paste_props['paste_id']}", paste_props, confidence=0.8)
            db.add_edge(source_node, paste_node, 'found_in_paste', confidence=0.8)
            results.append({'node_id': paste_node, 'type': 'paste'})
            
            # SUB-ENTITY: Paste -> Paste Site (Pastebin, GitHub Gist, etc.)
            paste_site_props = {'type': 'paste_platform', 'platform': paste_source}
            site_node = db.add_node('paste_site', paste_source, paste_site_props, confidence=1.0)
            db.add_edge(paste_node, site_node, 'hosted_on', confidence=1.0)
            results.append({'node_id': site_node, 'type': 'paste_site'})
        
        # 4. Social Profiles -> Platform Details -> URLs
        for profile in data.get('profiles', [])[:10]:
            platform = profile.get('source') or profile.get('platform', 'Unknown')
            profile_props = {
                'username': profile.get('username'),
                'url': profile.get('url') or profile.get('html_url') or profile.get('profile_url'),
                'avatar': profile.get('avatar') or profile.get('avatar_url'),
                'type': profile.get('type'),
                'score': profile.get('score')
            }
            profile_node = db.add_node('social_profile', platform, profile_props, confidence=0.7)
            db.add_edge(source_node, profile_node, 'has_profile', confidence=0.7)
            results.append({'node_id': profile_node, 'type': 'social_profile'})
            
            # SUB-ENTITY: Profile -> Username
            if profile.get('username'):
                username_node = db.add_node('username', profile['username'], {'platform': platform}, confidence=0.8)
                db.add_edge(profile_node, username_node, 'username', confidence=0.8)
                results.append({'node_id': username_node, 'type': 'username'})
            
            # SUB-ENTITY: Profile -> URL
            if profile_props.get('url'):
                url_node = db.add_node('url', profile_props['url'], {'platform': platform}, confidence=0.9)
                db.add_edge(profile_node, url_node, 'profile_url', confidence=0.9)
                results.append({'node_id': url_node, 'type': 'url'})
        
        # 5. Usernames extracted (linked to email)
        for username in data.get('usernames', [])[:10]:
            username_node = db.add_node('username', username, {'source': 'email_investigation'}, confidence=0.6)
            db.add_edge(source_node, username_node, 'uses_username', confidence=0.6)
            results.append({'node_id': username_node, 'type': 'username'})
        
        # 6. Names -> Person entities
        for name in data.get('names', [])[:5]:
            person_node = db.add_node('person', name, {'source': 'email_lookup'}, confidence=0.7)
            db.add_edge(source_node, person_node, 'belongs_to', confidence=0.7)
            results.append({'node_id': person_node, 'type': 'person'})
        
        # 7. Phones linked to email
        for phone in data.get('phones', [])[:5]:
            phone_node = db.add_node('phone', phone, {'source': 'email_lookup'}, confidence=0.7)
            db.add_edge(source_node, phone_node, 'has_phone', confidence=0.7)
            results.append({'node_id': phone_node, 'type': 'phone'})
        
        # 8. Data Leaks -> Database -> Leaked Data Types
        for leak in data.get('data_leaks', [])[:10]:
            db_name = leak.get('database_name', 'Unknown')
            leak_props = {
                'username': leak.get('username'),
                'has_password': 'Yes' if leak.get('password') else 'No',
                'name': leak.get('name'),
                'ip': leak.get('ip_address'),
                'phone': leak.get('phone')
            }
            leak_node = db.add_node('data_leak', db_name, leak_props, confidence=0.9)
            db.add_edge(source_node, leak_node, 'found_in_leak', confidence=0.9)
            results.append({'node_id': leak_node, 'type': 'data_leak'})
            
            # SUB-ENTITY: Leak -> Username (if available)
            if leak.get('username'):
                leak_username = db.add_node('username', leak['username'], {'source': 'data_leak', 'database': db_name}, confidence=0.8)
                db.add_edge(leak_node, leak_username, 'leaked_username', confidence=0.8)
                results.append({'node_id': leak_username, 'type': 'username'})
            
            # SUB-ENTITY: Leak -> Phone (if available)
            if leak.get('phone'):
                leak_phone = db.add_node('phone', leak['phone'], {'source': 'data_leak', 'database': db_name}, confidence=0.8)
                db.add_edge(leak_node, leak_phone, 'leaked_phone', confidence=0.8)
                results.append({'node_id': leak_phone, 'type': 'phone'})
            
            # SUB-ENTITY: Leak -> IP (if available)
            if leak.get('ip_address'):
                leak_ip = db.add_node('ip', leak['ip_address'], {'source': 'data_leak', 'database': db_name}, confidence=0.8)
                db.add_edge(leak_node, leak_ip, 'leaked_ip', confidence=0.8)
                results.append({'node_id': leak_ip, 'type': 'ip'})
        
        return results
    
    def _process_phone_results(self, source_node: str, data: Dict) -> List[Dict]:
        """Process phone results with SUB-ENTITY creation (Maltego style)"""
        results = []
        
        # Carrier -> Create as separate entity
        if data.get('carrier'):
            carrier_props = {
                'type': 'carrier',
                'country': data.get('country'),
                'line_type': data.get('line_type')
            }
            carrier_node = db.add_node('company', data['carrier'], carrier_props, confidence=0.9)
            db.add_edge(source_node, carrier_node, 'carrier', confidence=0.9)
            results.append({'node_id': carrier_node, 'type': 'company'})
            
            # SUB-ENTITIES of Carrier
            # Carrier -> Country
            if data.get('country'):
                country_node = db.add_node('location', data['country'], {'type': 'country'}, confidence=1.0)
                db.add_edge(carrier_node, country_node, 'operates_in', confidence=1.0)
                results.append({'node_id': country_node, 'type': 'location'})
        
        # Location -> Create as main entity with sub-entities
        if data.get('country'):
            location_props = {
                'type': 'country',
                'country_code': data.get('country_code'),
                'region': data.get('region'),
                'timezone': data.get('timezone'),
                'line_type': data.get('line_type'),
                'valid': data.get('valid')
            }
            location_node = db.add_node('location', data['country'], location_props, confidence=1.0)
            db.add_edge(source_node, location_node, 'located_in', confidence=1.0)
            results.append({'node_id': location_node, 'type': 'location'})
            
            # SUB-ENTITIES of Location
            # Country -> Region (if available)
            if data.get('region'):
                region_node = db.add_node('location', data['region'], {'type': 'region', 'parent': data['country']}, confidence=0.9)
                db.add_edge(location_node, region_node, 'contains_region', confidence=0.9)
                results.append({'node_id': region_node, 'type': 'location'})
            
            # Country -> Timezone
            if data.get('timezone'):
                tz_node = db.add_node('timezone', data['timezone'], {'country': data['country']}, confidence=1.0)
                db.add_edge(location_node, tz_node, 'timezone', confidence=1.0)
                results.append({'node_id': tz_node, 'type': 'timezone'})
        
        # Line Type -> Create as property node
        if data.get('line_type'):
            linetype_props = {
                'type': 'phone_property',
                'category': 'line_type',
                'valid': data.get('valid')
            }
            linetype_node = db.add_node('phone_property', data['line_type'], linetype_props, confidence=1.0)
            db.add_edge(source_node, linetype_node, 'has_line_type', confidence=1.0)
            results.append({'node_id': linetype_node, 'type': 'phone_property'})
        
        # Messaging Apps -> Each app as entity with sub-properties
        for app in data.get('messaging_apps', [])[:5]:
            if isinstance(app, dict) and app.get('exists'):
                app_props = {
                    'platform': app.get('platform'),
                    'url': app.get('url'),
                    'method': app.get('method'),
                    'verified': app.get('exists')
                }
                app_node = db.add_node('social_platform', app['platform'], app_props, confidence=0.8)
                db.add_edge(source_node, app_node, 'registered_on', confidence=0.8)
                results.append({'node_id': app_node, 'type': 'social_platform'})
                
                # SUB-ENTITY: App -> URL (profile link)
                if app.get('url'):
                    url_node = db.add_node('url', app['url'], {'platform': app['platform']}, confidence=0.8)
                    db.add_edge(app_node, url_node, 'profile_url', confidence=0.8)
                    results.append({'node_id': url_node, 'type': 'url'})
        
        # Names (if found from phone lookup)
        for name in data.get('names', [])[:3]:
            name_node = db.add_node('person', name, {'source': 'phone_lookup'}, confidence=0.6)
            db.add_edge(source_node, name_node, 'belongs_to', confidence=0.6)
            results.append({'node_id': name_node, 'type': 'person'})
        
        # Emails (if found from phone lookup)
        for email in data.get('emails', [])[:3]:
            email_node = db.add_node('email', email, {'source': 'phone_lookup'}, confidence=0.7)
            db.add_edge(source_node, email_node, 'linked_to', confidence=0.7)
            results.append({'node_id': email_node, 'type': 'email'})
        
        # Social Profiles (if found)
        for profile in data.get('profiles', [])[:5]:
            if isinstance(profile, dict):
                platform = profile.get('platform', 'Unknown')
                profile_props = {
                    'url': profile.get('url'),
                    'username': profile.get('username'),
                    'verified': profile.get('verified')
                }
                profile_node = db.add_node('social_profile', platform, profile_props, confidence=0.7)
                db.add_edge(source_node, profile_node, 'has_profile', confidence=0.7)
                results.append({'node_id': profile_node, 'type': 'social_profile'})
        
        return results
    
    def _process_ip_results(self, source_node: str, data: Dict) -> List[Dict]:
        """Process IP results with SUB-ENTITY creation (Maltego style)"""
        results = []
        
        # 1. Location hierarchy: IP -> Location -> ISP/ASN -> Network Range
        geo = data.get('geolocation', {})
        if geo and geo.get('country'):
            # Main Location node
            location_props = {
                'country': geo.get('country'),
                'country_code': geo.get('country_code'),
                'region': geo.get('region'),
                'city': geo.get('city'),
                'zip': geo.get('zip'),
                'lat': geo.get('lat'),
                'lon': geo.get('lon'),
                'timezone': geo.get('timezone'),
                'mobile': geo.get('mobile'),
                'proxy': geo.get('proxy'),
                'hosting': geo.get('hosting')
            }
            location_node = db.add_node('location', f"{geo.get('city', '')}, {geo['country']}", location_props, confidence=0.95)
            db.add_edge(source_node, location_node, 'located_in', confidence=0.95)
            results.append({'node_id': location_node, 'type': 'location'})
            
            # SUB-ENTITY: Location -> ISP
            if geo.get('isp'):
                isp_props = {
                    'type': 'isp',
                    'org': geo.get('org'),
                    'country': geo.get('country')
                }
                isp_node = db.add_node('company', geo['isp'], isp_props, confidence=0.9)
                db.add_edge(location_node, isp_node, 'isp', confidence=0.9)
                results.append({'node_id': isp_node, 'type': 'company'})
            
            # SUB-ENTITY: Location -> ASN
            if data.get('asn') and data['asn'].get('name'):
                asn_props = {
                    'number': data['asn'].get('number'),
                    'name': data['asn'].get('name'),
                    'type': 'asn'
                }
                asn_node = db.add_node('asn', data['asn']['name'], asn_props, confidence=0.9)
                db.add_edge(location_node, asn_node, 'asn', confidence=0.9)
                results.append({'node_id': asn_node, 'type': 'asn'})
                
                # SUB-SUB-ENTITY: ASN -> Network Range (if available)
                if asn_props.get('number'):
                    netrange_props = {'asn': asn_props['number'], 'type': 'network_range'}
                    netrange_node = db.add_node('network_range', asn_props['number'], netrange_props, confidence=0.8)
                    db.add_edge(asn_node, netrange_node, 'owns_range', confidence=0.8)
                    results.append({'node_id': netrange_node, 'type': 'network_range'})
        
        # 2. Ports -> Services -> Vulnerabilities hierarchy
        for port in data.get('ports', [])[:10]:
            port_props = {
                'ip': data['ip'],
                'port': port,
                'state': 'open'
            }
            port_node = db.add_node('port', str(port), port_props, confidence=1.0)
            db.add_edge(source_node, port_node, 'open_port', confidence=1.0)
            results.append({'node_id': port_node, 'type': 'port'})
            
            # SUB-ENTITY: Port -> Service (from services data)
            matching_services = [s for s in data.get('services', []) if s.get('port') == port]
            for service in matching_services[:1]:  # One service per port
                service_props = {
                    'port': port,
                    'transport': service.get('transport') or service.get('transport_protocol'),
                    'product': service.get('product') or service.get('service_name'),
                    'version': service.get('version'),
                    'banner': service.get('banner', '')[:200]
                }
                service_name = service_props.get('product') or f"Unknown Service"
                service_node = db.add_node('service', service_name, service_props, confidence=0.9)
                db.add_edge(port_node, service_node, 'runs_service', confidence=0.9)
                results.append({'node_id': service_node, 'type': 'service'})
                
                # SUB-SUB-ENTITY: Service -> Vulnerability (from vulns/cves)
                for vuln in data.get('cves', [])[:3]:  # Top 3 CVEs per service
                    vuln_props = {
                        'cve': vuln.get('cve'),
                        'cvss': vuln.get('cvss'),
                        'service': service_name,
                        'port': port
                    }
                    vuln_node = db.add_node('cve', vuln['cve'], vuln_props, confidence=0.85)
                    db.add_edge(service_node, vuln_node, 'vulnerable_to', confidence=0.85)
                    results.append({'node_id': vuln_node, 'type': 'cve'})
        
        # 3. Domains -> Subdomains hierarchy
        for domain in data.get('domains', [])[:10]:
            domain_props = {'ip': data['ip'], 'source': 'ip_lookup'}
            domain_node = db.add_node('domain', domain, domain_props, confidence=0.8)
            db.add_edge(source_node, domain_node, 'hosts', confidence=0.8)
            results.append({'node_id': domain_node, 'type': 'domain'})
            
            # SUB-ENTITY: Domain -> Subdomains (placeholder for future domain investigation)
            # When domain_investigate is done, subdomains will be populated
        
        # 4. Hostnames
        for hostname in data.get('hostnames', [])[:10]:
            hostname_node = db.add_node('domain', hostname, {'ip': data['ip'], 'type': 'hostname'}, confidence=0.9)
            db.add_edge(source_node, hostname_node, 'hostname', confidence=0.9)
            results.append({'node_id': hostname_node, 'type': 'domain'})
        
        # 5. Threat Intelligence -> Malware
        for threat in data.get('threat_intel', [])[:5]:
            threat_source = threat.get('source', 'Unknown')
            threat_props = {
                'source': threat_source,
                'classification': threat.get('classification'),
                'noise': threat.get('noise'),
                'pulse_count': threat.get('pulse_count'),
                'votes': threat.get('votes')
            }
            threat_node = db.add_node('threat', f"{threat_source}_intel", threat_props, confidence=0.8)
            db.add_edge(source_node, threat_node, 'threat_intel', confidence=0.8)
            results.append({'node_id': threat_node, 'type': 'threat'})
        
        # 6. Malware associations
        for malware in data.get('malware', [])[:5]:
            if isinstance(malware, dict):
                malware_name = malware.get('name', 'Unknown')
                malware_node = db.add_node('malware', malware_name, malware, confidence=0.85)
                db.add_edge(source_node, malware_node, 'associated_malware', confidence=0.85)
                results.append({'node_id': malware_node, 'type': 'malware'})
        
        # 7. Cloud provider (if detected)
        if data.get('cloud', {}).get('is_cloud'):
            cloud_data = data['cloud']
            cloud_props = {
                'provider': cloud_data.get('provider'),
                'service': cloud_data.get('service'),
                'region': cloud_data.get('region')
            }
            cloud_node = db.add_node('cloud_provider', cloud_data['provider'], cloud_props, confidence=0.95)
            db.add_edge(source_node, cloud_node, 'hosted_on', confidence=0.95)
            results.append({'node_id': cloud_node, 'type': 'cloud_provider'})
        
        return results
    
    def _process_person_results(self, source_node: str, data: Dict) -> List[Dict]:
        """Process person results with SUB-ENTITY creation (Maltego style)"""
        results = []
        
        # 1. Person -> Emails -> Domains hierarchy
        for email in data.get('emails', [])[:5]:
            email_props = {'source': 'person_investigation'}
            email_node = db.add_node('email', email, email_props, confidence=0.8)
            db.add_edge(source_node, email_node, 'has_email', confidence=0.8)
            results.append({'node_id': email_node, 'type': 'email'})
            
            # SUB-ENTITY: Email -> Domain
            if '@' in email:
                domain = email.split('@')[1]
                domain_props = {'type': 'email_domain', 'email': email}
                domain_node = db.add_node('domain', domain, domain_props, confidence=1.0)
                db.add_edge(email_node, domain_node, 'belongs_to_domain', confidence=1.0)
                results.append({'node_id': domain_node, 'type': 'domain'})
        
        # 2. Person -> Phones -> Carriers hierarchy
        for phone in data.get('phones', [])[:5]:
            phone_props = {'source': 'person_investigation'}
            phone_node = db.add_node('phone', phone, phone_props, confidence=0.8)
            db.add_edge(source_node, phone_node, 'has_phone', confidence=0.8)
            results.append({'node_id': phone_node, 'type': 'phone'})
            
            # SUB-ENTITY: Phone -> Carrier (placeholder - would need phone lookup)
            # When phone_investigate is run, carrier info will be populated
        
        # 3. Person -> Usernames -> Platforms hierarchy
        for username in data.get('usernames', [])[:10]:
            username_props = {'source': 'person_investigation'}
            username_node = db.add_node('username', username, username_props, confidence=0.7)
            db.add_edge(source_node, username_node, 'uses_username', confidence=0.7)
            results.append({'node_id': username_node, 'type': 'username'})
        
        # 4. Person -> Social Profiles -> Platform URLs hierarchy
        for profile in data.get('profiles', [])[:15]:
            platform = profile.get('platform', 'Unknown')
            profile_props = {
                'username': profile.get('username'),
                'name': profile.get('name'),
                'bio': profile.get('bio', '')[:200] if profile.get('bio') else None,
                'location': profile.get('location'),
                'followers': profile.get('followers'),
                'following': profile.get('following'),
                'avatar': profile.get('avatar'),
                'url': profile.get('url'),
                'exists': profile.get('exists', True),
                'fake_probability': profile.get('fake_probability')
            }
            profile_node = db.add_node('social_profile', platform, profile_props, confidence=0.75)
            db.add_edge(source_node, profile_node, 'social_profile', confidence=0.75)
            results.append({'node_id': profile_node, 'type': 'social_profile'})
            
            # SUB-ENTITY: Profile -> Username
            if profile.get('username'):
                profile_username = db.add_node('username', profile['username'], {'platform': platform}, confidence=0.85)
                db.add_edge(profile_node, profile_username, 'username', confidence=0.85)
                results.append({'node_id': profile_username, 'type': 'username'})
            
            # SUB-ENTITY: Profile -> URL
            if profile.get('url'):
                url_node = db.add_node('url', profile['url'], {'platform': platform, 'type': 'profile_url'}, confidence=0.9)
                db.add_edge(profile_node, url_node, 'profile_url', confidence=0.9)
                results.append({'node_id': url_node, 'type': 'url'})
            
            # SUB-ENTITY: Profile -> Location (if available)
            if profile.get('location'):
                location_node = db.add_node('location', profile['location'], {'source': platform}, confidence=0.6)
                db.add_edge(profile_node, location_node, 'located_in', confidence=0.6)
                results.append({'node_id': location_node, 'type': 'location'})
            
            # SUB-ENTITY: Profile -> Company (if GitHub profile with company)
            if platform == 'github' and profile.get('company'):
                company_node = db.add_node('company', profile['company'], {'source': 'github', 'type': 'employer'}, confidence=0.7)
                db.add_edge(profile_node, company_node, 'works_at', confidence=0.7)
                results.append({'node_id': company_node, 'type': 'company'})
        
        # 5. Person -> Addresses -> Locations hierarchy
        for address in data.get('addresses', [])[:5]:
            address_props = {'type': 'physical_address', 'source': 'person_investigation'}
            address_node = db.add_node('location', address, address_props, confidence=0.65)
            db.add_edge(source_node, address_node, 'located_at', confidence=0.65)
            results.append({'node_id': address_node, 'type': 'location'})
        
        # 6. Person -> Jobs -> Companies hierarchy
        for job in data.get('jobs', [])[:10]:
            if isinstance(job, dict):
                company = job.get('company', 'Unknown')
                job_props = {
                    'title': job.get('title'),
                    'start_date': job.get('start_date'),
                    'end_date': job.get('end_date'),
                    'current': job.get('current', False)
                }
                job_node = db.add_node('job', f"{job.get('title', 'Unknown')} at {company}", job_props, confidence=0.75)
                db.add_edge(source_node, job_node, 'employment', confidence=0.75)
                results.append({'node_id': job_node, 'type': 'job'})
                
                # SUB-ENTITY: Job -> Company
                company_props = {'type': 'employer'}
                company_node = db.add_node('company', company, company_props, confidence=0.8)
                db.add_edge(job_node, company_node, 'employer', confidence=0.8)
                results.append({'node_id': company_node, 'type': 'company'})
            elif isinstance(job, str):
                # Simple string job format
                job_node = db.add_node('job', job, {'source': 'person_investigation'}, confidence=0.6)
                db.add_edge(source_node, job_node, 'employment', confidence=0.6)
                results.append({'node_id': job_node, 'type': 'job'})
        
        # 7. Person -> Education -> Institutions
        for edu in data.get('education', [])[:5]:
            if isinstance(edu, dict):
                institution = edu.get('school', 'Unknown')
                edu_props = {
                    'degree': edu.get('degree'),
                    'field': edu.get('field'),
                    'start_year': edu.get('start_year'),
                    'end_year': edu.get('end_year')
                }
                edu_node = db.add_node('education', f"{edu.get('degree', 'Degree')} at {institution}", edu_props, confidence=0.7)
                db.add_edge(source_node, edu_node, 'education', confidence=0.7)
                results.append({'node_id': edu_node, 'type': 'education'})
                
                # SUB-ENTITY: Education -> Institution
                institution_node = db.add_node('institution', institution, {'type': 'educational'}, confidence=0.8)
                db.add_edge(edu_node, institution_node, 'institution', confidence=0.8)
                results.append({'node_id': institution_node, 'type': 'institution'})
            elif isinstance(edu, str):
                edu_node = db.add_node('education', edu, {'source': 'person_investigation'}, confidence=0.6)
                db.add_edge(source_node, edu_node, 'education', confidence=0.6)
                results.append({'node_id': edu_node, 'type': 'education'})
        
        # 8. Person -> Names (alternative names)
        for name in data.get('names', [])[:5]:
            if name and name != data.get('query'):
                name_props = {'type': 'alternative_name', 'source': 'person_investigation'}
                name_node = db.add_node('person', name, name_props, confidence=0.65)
                db.add_edge(source_node, name_node, 'also_known_as', confidence=0.65)
                results.append({'node_id': name_node, 'type': 'person'})
        
        # 9. Person -> Images (avatars, profile pictures)
        for image in data.get('images', [])[:10]:
            if isinstance(image, str):
                image_props = {'type': 'profile_picture', 'source': 'person_investigation'}
                image_node = db.add_node('image', image, image_props, confidence=0.7)
                db.add_edge(source_node, image_node, 'has_image', confidence=0.7)
                results.append({'node_id': image_node, 'type': 'image'})
        
        # 10. Person -> Websites
        for website in data.get('websites', [])[:10]:
            website_props = {'type': 'personal_website', 'source': 'person_investigation'}
            website_node = db.add_node('url', website, website_props, confidence=0.7)
            db.add_edge(source_node, website_node, 'owns_website', confidence=0.7)
            results.append({'node_id': website_node, 'type': 'url'})
        
        # 11. Person -> Social Media Posts -> Platforms
        platforms_seen = set()
        for post in data.get('social_media', [])[:15]:
            platform = post.get('platform', 'Unknown')
            post_props = {
                'text': post.get('text', '')[:200],
                'url': post.get('url'),
                'posted': post.get('posted'),
                'user': post.get('user')
            }
            post_node = db.add_node('social_post', f"{platform}_post", post_props, confidence=0.6)
            db.add_edge(source_node, post_node, 'posted', confidence=0.6)
            results.append({'node_id': post_node, 'type': 'social_post'})
            
            # SUB-ENTITY: Post -> Platform (only once per platform)
            if platform not in platforms_seen:
                platforms_seen.add(platform)
                platform_node = db.add_node('social_platform', platform, {'type': 'social_network'}, confidence=0.8)
                db.add_edge(post_node, platform_node, 'posted_on', confidence=0.8)
                results.append({'node_id': platform_node, 'type': 'social_platform'})
        
        # 12. Person -> Identity Clusters (ML-based grouping)
        for cluster in data.get('clusters', [])[:5]:
            if isinstance(cluster, dict):
                cluster_props = {
                    'confidence': cluster.get('confidence'),
                    'members': cluster.get('members', [])[:10],
                    'type': 'identity_cluster'
                }
                cluster_node = db.add_node('identity_cluster', f"Cluster_{cluster.get('id', 'Unknown')}", cluster_props, confidence=0.7)
                db.add_edge(source_node, cluster_node, 'belongs_to_cluster', confidence=0.7)
                results.append({'node_id': cluster_node, 'type': 'identity_cluster'})
        
        return results
    
    def _process_domain_results(self, source_node: str, data: Dict) -> List[Dict]:
        """Process domain results with SUB-ENTITY creation (Maltego style)"""
        results = []
        
        # 1. Domain -> IPs -> Location hierarchy
        for ip in data.get('ips', [])[:5]:
            ip_props = {'domain': data['domain'], 'source': 'dns_lookup'}
            ip_node = db.add_node('ip', ip, ip_props, confidence=1.0)
            db.add_edge(source_node, ip_node, 'resolves_to', confidence=1.0)
            results.append({'node_id': ip_node, 'type': 'ip'})
            
            # SUB-ENTITY: IP -> Location (placeholder - will be filled when IP is investigated)
            # This creates the hierarchy: Domain -> IP -> Location
        
        # 2. Domain -> Subdomains -> IP Addresses hierarchy
        for subdomain in data.get('subdomains', [])[:20]:
            subdomain_props = {'parent': data['domain'], 'source': 'subdomain_enum'}
            subdomain_node = db.add_node('domain', subdomain, subdomain_props, confidence=0.9)
            db.add_edge(source_node, subdomain_node, 'subdomain', confidence=0.9)
            results.append({'node_id': subdomain_node, 'type': 'domain'})
            
            # SUB-ENTITY: Subdomain -> IP (would require DNS lookup per subdomain)
            # In full implementation, resolve each subdomain to its IP
        
        # 3. Domain -> Technologies -> Versions -> CVEs hierarchy
        for tech_name, tech_info in (data.get('tech_stack', {}) if isinstance(data.get('tech_stack'), dict) else {}).items():
            tech_props = {
                'category': tech_info.get('category') if isinstance(tech_info, dict) else 'unknown',
                'confidence': tech_info.get('confidence') if isinstance(tech_info, dict) else 0.8
            }
            tech_node = db.add_node('technology', tech_name, tech_props, confidence=0.8)
            db.add_edge(source_node, tech_node, 'uses_technology', confidence=0.8)
            results.append({'node_id': tech_node, 'type': 'technology'})
            
            # SUB-ENTITY: Technology -> Version
            if isinstance(tech_info, dict) and tech_info.get('version'):
                version_props = {
                    'version': tech_info['version'],
                    'technology': tech_name
                }
                version_node = db.add_node('version', tech_info['version'], version_props, confidence=0.9)
                db.add_edge(tech_node, version_node, 'version', confidence=0.9)
                results.append({'node_id': version_node, 'type': 'version'})
                
                # SUB-SUB-ENTITY: Version -> CVE (placeholder for CVE lookup)
                # In full implementation, lookup CVEs for specific tech+version
        
        # Handle tech_stack as list (alternative format)
        if isinstance(data.get('tech_stack'), list):
            for tech in data.get('tech_stack', [])[:15]:
                if isinstance(tech, str):
                    tech_node = db.add_node('technology', tech, {'category': 'web'}, confidence=0.7)
                    db.add_edge(source_node, tech_node, 'uses_technology', confidence=0.7)
                    results.append({'node_id': tech_node, 'type': 'technology'})
                elif isinstance(tech, dict):
                    tech_name = tech.get('name', 'Unknown')
                    tech_node = db.add_node('technology', tech_name, tech, confidence=0.8)
                    db.add_edge(source_node, tech_node, 'uses_technology', confidence=0.8)
                    results.append({'node_id': tech_node, 'type': 'technology'})
        
        # 4. Domain -> Certificates -> Issuer hierarchy
        for cert in data.get('certificates', [])[:10]:
            cert_cn = cert.get('common_name') or cert.get('name_value', 'Unknown')
            cert_props = {
                'issuer': cert.get('issuer') or cert.get('issuer_name'),
                'not_before': cert.get('not_before'),
                'not_after': cert.get('not_after'),
                'common_name': cert_cn
            }
            cert_node = db.add_node('certificate', cert_cn, cert_props, confidence=0.85)
            db.add_edge(source_node, cert_node, 'has_certificate', confidence=0.85)
            results.append({'node_id': cert_node, 'type': 'certificate'})
            
            # SUB-ENTITY: Certificate -> Issuer (CA)
            if cert_props.get('issuer'):
                issuer_props = {'type': 'certificate_authority'}
                issuer_node = db.add_node('certificate_authority', cert_props['issuer'], issuer_props, confidence=0.9)
                db.add_edge(cert_node, issuer_node, 'issued_by', confidence=0.9)
                results.append({'node_id': issuer_node, 'type': 'certificate_authority'})
        
        # 5. Domain -> WHOIS -> Registrar/Registrant
        whois = data.get('whois', {})
        if whois.get('registrar'):
            registrar_props = {
                'type': 'registrar',
                'creation_date': whois.get('creation_date'),
                'expiration_date': whois.get('expiration_date')
            }
            registrar_node = db.add_node('company', whois['registrar'], registrar_props, confidence=0.95)
            db.add_edge(source_node, registrar_node, 'registered_by', confidence=0.95)
            results.append({'node_id': registrar_node, 'type': 'company'})
        
        if whois.get('registrant'):
            registrant_props = {
                'type': 'domain_owner',
                'email': whois.get('registrant_email'),
                'org': whois.get('registrant_org')
            }
            registrant_node = db.add_node('person', whois['registrant'], registrant_props, confidence=0.8)
            db.add_edge(source_node, registrant_node, 'owned_by', confidence=0.8)
            results.append({'node_id': registrant_node, 'type': 'person'})
            
            # SUB-ENTITY: Registrant -> Email
            if whois.get('registrant_email'):
                email_node = db.add_node('email', whois['registrant_email'], {'source': 'whois'}, confidence=0.9)
                db.add_edge(registrant_node, email_node, 'has_email', confidence=0.9)
                results.append({'node_id': email_node, 'type': 'email'})
        
        # 6. Domain -> Nameservers
        for ns in data.get('nameservers', [])[:10]:
            ns_props = {'type': 'nameserver', 'domain': data['domain']}
            ns_node = db.add_node('nameserver', str(ns).rstrip('.'), ns_props, confidence=1.0)
            db.add_edge(source_node, ns_node, 'nameserver', confidence=1.0)
            results.append({'node_id': ns_node, 'type': 'nameserver'})
        
        # 7. Domain -> MX Records (Mail Servers)
        for mx in data.get('mx_records', [])[:10]:
            if isinstance(mx, dict):
                mx_server = str(mx.get('server', '')).rstrip('.')
                mx_props = {
                    'priority': mx.get('priority'),
                    'type': 'mail_server'
                }
                mx_node = db.add_node('mail_server', mx_server, mx_props, confidence=1.0)
                db.add_edge(source_node, mx_node, 'mail_server', confidence=1.0)
                results.append({'node_id': mx_node, 'type': 'mail_server'})
        
        # 8. Domain -> CMS/Framework/CDN
        if data.get('cms'):
            cms_node = db.add_node('technology', data['cms'], {'type': 'cms'}, confidence=0.85)
            db.add_edge(source_node, cms_node, 'uses_cms', confidence=0.85)
            results.append({'node_id': cms_node, 'type': 'technology'})
        
        if data.get('cdn'):
            cdn_node = db.add_node('company', data['cdn'], {'type': 'cdn'}, confidence=0.9)
            db.add_edge(source_node, cdn_node, 'uses_cdn', confidence=0.9)
            results.append({'node_id': cdn_node, 'type': 'company'})
        
        if data.get('hosting'):
            hosting_node = db.add_node('company', data['hosting'], {'type': 'hosting_provider'}, confidence=0.85)
            db.add_edge(source_node, hosting_node, 'hosted_by', confidence=0.85)
            results.append({'node_id': hosting_node, 'type': 'company'})
        
        # 9. Domain -> Related Domains
        for related in data.get('related_domains', [])[:15]:
            if isinstance(related, str) and related != data['domain']:
                related_node = db.add_node('domain', related, {'relation': 'discovered'}, confidence=0.6)
                db.add_edge(source_node, related_node, 'related_to', confidence=0.6)
                results.append({'node_id': related_node, 'type': 'domain'})
        
        # 10. Domain -> Threat Intelligence
        for threat in data.get('threat_intel', [])[:5]:
            threat_source = threat.get('source', 'Unknown')
            threat_props = {
                'source': threat_source,
                'votes': threat.get('votes'),
                'pulse_count': threat.get('pulse_count'),
                'tags': threat.get('tags', [])
            }
            threat_node = db.add_node('threat', f"{threat_source}_intel", threat_props, confidence=0.75)
            db.add_edge(source_node, threat_node, 'threat_intel', confidence=0.75)
            results.append({'node_id': threat_node, 'type': 'threat'})
        
        return results
    
    def _process_username_results(self, source_node: str, data: Dict) -> List[Dict]:
        """Process username results with SUB-ENTITY creation (Maltego style)"""
        results = []
        
        # 1. Username -> Found Platforms -> Profile URLs hierarchy
        for link in data.get('profile_links', [])[:20]:
            platform = link.get('platform', 'Unknown')
            url = link.get('url', '')
            extra_data = link.get('data', {})
            
            platform_props = {
                'platform': platform,
                'exists': True,
                'url': url,
                'followers': extra_data.get('followers'),
                'repos': extra_data.get('repos'),
                'last_active': extra_data.get('last_active')
            }
            platform_node = db.add_node('social_platform', platform, platform_props, confidence=0.9)
            db.add_edge(source_node, platform_node, 'found_on', confidence=0.9)
            results.append({'node_id': platform_node, 'type': 'social_platform'})
            
            # SUB-ENTITY: Platform -> Profile URL
            if url:
                url_props = {
                    'platform': platform,
                    'type': 'profile_url',
                    'username': data.get('username')
                }
                url_node = db.add_node('url', url, url_props, confidence=1.0)
                db.add_edge(platform_node, url_node, 'profile_url', confidence=1.0)
                results.append({'node_id': url_node, 'type': 'url'})
            
            # SUB-ENTITY: Platform -> Last Active Date (if available)
            if extra_data.get('last_active'):
                date_props = {
                    'date': extra_data['last_active'],
                    'platform': platform,
                    'type': 'activity_timestamp'
                }
                date_node = db.add_node('timestamp', extra_data['last_active'], date_props, confidence=0.8)
                db.add_edge(platform_node, date_node, 'last_active', confidence=0.8)
                results.append({'node_id': date_node, 'type': 'timestamp'})
        
        # 2. Username -> Variant Usernames hierarchy
        for variant in data.get('username_variants', [])[:10]:
            variant_props = {
                'original': data.get('username'),
                'type': 'username_variant',
                'similarity': 0.8  # ML-based similarity score
            }
            variant_node = db.add_node('username', variant, variant_props, confidence=0.7)
            db.add_edge(source_node, variant_node, 'variant', confidence=0.7)
            results.append({'node_id': variant_node, 'type': 'username'})
        
        return results
    
    def _process_hash_results(self, source_node: str, data: Dict) -> List[Dict]:
        """Process hash results with SUB-ENTITY creation (Maltego style)"""
        results = []
        
        # 1. Hash -> Malware Families -> Type/Category hierarchy
        for family in data.get('malware_families', [])[:10]:
            family_props = {
                'hash': data.get('hash'),
                'type': 'malware_family',
                'malicious': data.get('malicious', False)
            }
            family_node = db.add_node('malware', family, family_props, confidence=0.9)
            db.add_edge(source_node, family_node, 'identified_as', confidence=0.9)
            results.append({'node_id': family_node, 'type': 'malware'})
            
            # SUB-ENTITY: Malware Family -> Type (Trojan, Ransomware, etc.)
            # Extract type from family name if possible
            malware_types = ['trojan', 'ransomware', 'worm', 'backdoor', 'rootkit', 'spyware', 'adware', 'virus']
            for mtype in malware_types:
                if mtype in family.lower():
                    type_props = {'malware_family': family, 'category': mtype}
                    type_node = db.add_node('malware_type', mtype.capitalize(), type_props, confidence=0.8)
                    db.add_edge(family_node, type_node, 'malware_type', confidence=0.8)
                    results.append({'node_id': type_node, 'type': 'malware_type'})
                    break
        
        # 2. Hash -> File Info -> File Properties hierarchy
        file_info = data.get('file_info', {})
        if file_info and file_info.get('file_name'):
            file_props = {
                'name': file_info.get('file_name'),
                'type': file_info.get('file_type'),
                'size': file_info.get('file_size'),
                'mime': file_info.get('mime_type'),
                'hash': data.get('hash')
            }
            file_node = db.add_node('file', file_info['file_name'], file_props, confidence=0.95)
            db.add_edge(source_node, file_node, 'file_info', confidence=0.95)
            results.append({'node_id': file_node, 'type': 'file'})
            
            # SUB-ENTITY: File -> File Type
            if file_info.get('file_type'):
                ftype_props = {'file_name': file_info['file_name']}
                ftype_node = db.add_node('file_type', file_info['file_type'], ftype_props, confidence=1.0)
                db.add_edge(file_node, ftype_node, 'file_type', confidence=1.0)
                results.append({'node_id': ftype_node, 'type': 'file_type'})
            
            # SUB-ENTITY: File -> File Size
            if file_info.get('file_size'):
                size_props = {'bytes': file_info['file_size'], 'file_name': file_info['file_name']}
                size_node = db.add_node('file_size', f"{file_info['file_size']} bytes", size_props, confidence=1.0)
                db.add_edge(file_node, size_node, 'size', confidence=1.0)
                results.append({'node_id': size_node, 'type': 'file_size'})
        
        # 3. Hash -> Threat Names (Detection Names)
        for threat in data.get('threat_names', [])[:15]:
            threat_props = {
                'hash': data.get('hash'),
                'type': 'detection_name',
                'malicious': data.get('malicious', False)
            }
            threat_node = db.add_node('threat', threat, threat_props, confidence=0.85)
            db.add_edge(source_node, threat_node, 'detected_as', confidence=0.85)
            results.append({'node_id': threat_node, 'type': 'threat'})
        
        # 4. Hash -> Alternative Hashes (MD5, SHA1, SHA256)
        if file_info:
            for hash_type in ['md5', 'sha1', 'sha256']:
                if file_info.get(hash_type) and file_info[hash_type] != data.get('hash'):
                    alt_hash_props = {'type': hash_type.upper(), 'related_to': data.get('hash')}
                    alt_hash_node = db.add_node('hash', file_info[hash_type], alt_hash_props, confidence=1.0)
                    db.add_edge(source_node, alt_hash_node, 'alternative_hash', confidence=1.0)
                    results.append({'node_id': alt_hash_node, 'type': 'hash'})
        
        # 5. Hash -> Network Activity (IPs, Domains from sandbox)
        for net_activity in data.get('network_activity', [])[:10]:
            if isinstance(net_activity, dict):
                # IP connections
                if net_activity.get('ip'):
                    ip_props = {'type': 'c2_communication', 'hash': data.get('hash')}
                    ip_node = db.add_node('ip', net_activity['ip'], ip_props, confidence=0.85)
                    db.add_edge(source_node, ip_node, 'connects_to', confidence=0.85)
                    results.append({'node_id': ip_node, 'type': 'ip'})
                
                # Domain connections
                if net_activity.get('domain'):
                    domain_props = {'type': 'c2_domain', 'hash': data.get('hash')}
                    domain_node = db.add_node('domain', net_activity['domain'], domain_props, confidence=0.85)
                    db.add_edge(source_node, domain_node, 'contacts', confidence=0.85)
                    results.append({'node_id': domain_node, 'type': 'domain'})
        
        # 6. Hash -> Dropped Files
        for dropped in data.get('dropped_files', [])[:10]:
            if isinstance(dropped, dict) and dropped.get('filename'):
                dropped_props = {
                    'filename': dropped['filename'],
                    'path': dropped.get('path'),
                    'size': dropped.get('size'),
                    'parent_hash': data.get('hash')
                }
                dropped_node = db.add_node('file', dropped['filename'], dropped_props, confidence=0.8)
                db.add_edge(source_node, dropped_node, 'drops_file', confidence=0.8)
                results.append({'node_id': dropped_node, 'type': 'file'})
        
        # 7. Hash -> Registry Keys (Windows)
        for reg_key in data.get('registry_keys', [])[:10]:
            reg_props = {'type': 'registry_modification', 'hash': data.get('hash')}
            reg_node = db.add_node('registry_key', reg_key, reg_props, confidence=0.8)
            db.add_edge(source_node, reg_node, 'modifies_registry', confidence=0.8)
            results.append({'node_id': reg_node, 'type': 'registry_key'})
        
        # 8. Hash -> Behavior Indicators
        for behavior in data.get('behavior', [])[:10]:
            if isinstance(behavior, dict):
                behavior_desc = behavior.get('description', 'Unknown')
                behavior_props = {
                    'process': behavior.get('process'),
                    'action': behavior.get('action'),
                    'hash': data.get('hash')
                }
                behavior_node = db.add_node('behavior', behavior_desc, behavior_props, confidence=0.75)
                db.add_edge(source_node, behavior_node, 'exhibits_behavior', confidence=0.75)
                results.append({'node_id': behavior_node, 'type': 'behavior'})
        
        return results
    
    def _process_crypto_results(self, source_node: str, data: Dict) -> List[Dict]:
        """Process cryptocurrency results with SUB-ENTITY creation (Maltego style)"""
        results = []
        
        # 1. Crypto Address -> Transactions -> Related Addresses hierarchy
        for tx in data.get('transactions', [])[:15]:
            if isinstance(tx, dict):
                tx_hash = tx.get('hash', 'Unknown')
                tx_props = {
                    'hash': tx_hash,
                    'timestamp': tx.get('time') or tx.get('timestamp'),
                    'value': tx.get('value'),
                    'from': tx.get('from'),
                    'to': tx.get('to'),
                    'confirmations': tx.get('confirmations'),
                    'crypto_type': data.get('crypto_type')
                }
                tx_node = db.add_node('transaction', tx_hash[:16], tx_props, confidence=0.95)
                db.add_edge(source_node, tx_node, 'transaction', confidence=0.95)
                results.append({'node_id': tx_node, 'type': 'transaction'})
                
                # SUB-ENTITY: Transaction -> Timestamp
                if tx.get('time') or tx.get('timestamp'):
                    timestamp = tx.get('time') or tx.get('timestamp')
                    ts_props = {'transaction': tx_hash, 'value': tx.get('value')}
                    ts_node = db.add_node('timestamp', str(timestamp), ts_props, confidence=1.0)
                    db.add_edge(tx_node, ts_node, 'timestamp', confidence=1.0)
                    results.append({'node_id': ts_node, 'type': 'timestamp'})
                
                # SUB-ENTITY: Transaction -> Amount/Value
                if tx.get('value'):
                    amount_props = {
                        'amount': tx['value'],
                        'currency': data.get('crypto_type'),
                        'transaction': tx_hash
                    }
                    amount_node = db.add_node('amount', f"{tx['value']} {data.get('crypto_type', 'CRYPTO')}", amount_props, confidence=1.0)
                    db.add_edge(tx_node, amount_node, 'amount', confidence=1.0)
                    results.append({'node_id': amount_node, 'type': 'amount'})
        
        # 2. Crypto Address -> Related Addresses -> Risk Score hierarchy
        for addr in data.get('related_addresses', [])[:20]:
            addr_props = {
                'related_to': data.get('address'),
                'crypto_type': data.get('crypto_type'),
                'relation': 'transacted_with'
            }
            addr_node = db.add_node('cryptocurrency', addr, addr_props, confidence=0.8)
            db.add_edge(source_node, addr_node, 'connected_to', confidence=0.8)
            results.append({'node_id': addr_node, 'type': 'cryptocurrency'})
        
        # 3. Crypto Address -> Balance -> Currency
        if data.get('balance'):
            balance_props = {
                'balance': data['balance'],
                'currency': data.get('crypto_type'),
                'balance_usd': data.get('balance_usd'),
                'address': data.get('address')
            }
            balance_node = db.add_node('balance', f"{data['balance']} {data.get('crypto_type', 'CRYPTO')}", balance_props, confidence=1.0)
            db.add_edge(source_node, balance_node, 'balance', confidence=1.0)
            results.append({'node_id': balance_node, 'type': 'balance'})
            
            # SUB-ENTITY: Balance -> Currency Type
            currency_props = {'type': 'cryptocurrency', 'name': data.get('crypto_type')}
            currency_node = db.add_node('currency', data.get('crypto_type', 'Unknown').upper(), currency_props, confidence=1.0)
            db.add_edge(balance_node, currency_node, 'currency', confidence=1.0)
            results.append({'node_id': currency_node, 'type': 'currency'})
        
        # 4. Crypto Address -> Abuse Reports
        for abuse in data.get('abuse_reports', [])[:10]:
            if isinstance(abuse, dict):
                abuse_count = abuse.get('count', 0)
                abuse_props = {
                    'count': abuse_count,
                    'address': data.get('address'),
                    'crypto_type': data.get('crypto_type')
                }
                abuse_node = db.add_node('abuse_report', f"{abuse_count} reports", abuse_props, confidence=0.9)
                db.add_edge(source_node, abuse_node, 'abuse_reports', confidence=0.9)
                results.append({'node_id': abuse_node, 'type': 'abuse_report'})
                
                # SUB-ENTITY: Abuse Report -> Recent Reports
                for recent in abuse.get('recent', [])[:5]:
                    if isinstance(recent, dict):
                        report_props = {
                            'reporter': recent.get('reporter'),
                            'description': recent.get('description', '')[:100],
                            'date': recent.get('date')
                        }
                        report_node = db.add_node('report', recent.get('description', 'Report')[:50], report_props, confidence=0.85)
                        db.add_edge(abuse_node, report_node, 'recent_report', confidence=0.85)
                        results.append({'node_id': report_node, 'type': 'report'})
        
        # 5. Crypto Address -> Tags (Exchange, Mixer, etc.)
        for tag in data.get('tags', [])[:10]:
            tag_props = {
                'address': data.get('address'),
                'crypto_type': data.get('crypto_type')
            }
            tag_node = db.add_node('tag', tag, tag_props, confidence=0.75)
            db.add_edge(source_node, tag_node, 'tagged_as', confidence=0.75)
            results.append({'node_id': tag_node, 'type': 'tag'})
        
        # 6. Special indicators
        # Whale Activity
        if data.get('whale_activity'):
            whale_props = {'type': 'whale_indicator', 'address': data.get('address')}
            whale_node = db.add_node('indicator', 'Whale Activity', whale_props, confidence=0.9)
            db.add_edge(source_node, whale_node, 'indicator', confidence=0.9)
            results.append({'node_id': whale_node, 'type': 'indicator'})
        
        # Mixer Usage
        if data.get('mixer_usage'):
            mixer_props = {'type': 'mixer_indicator', 'address': data.get('address')}
            mixer_node = db.add_node('indicator', 'Mixer Usage', mixer_props, confidence=0.85)
            db.add_edge(source_node, mixer_node, 'indicator', confidence=0.85)
            results.append({'node_id': mixer_node, 'type': 'indicator'})
        
        # Exchange Deposit
        if data.get('exchange_deposit'):
            exchange_props = {'type': 'exchange_indicator', 'address': data.get('address')}
            exchange_node = db.add_node('indicator', 'Exchange Deposit', exchange_props, confidence=0.8)
            db.add_edge(source_node, exchange_node, 'indicator', confidence=0.8)
            results.append({'node_id': exchange_node, 'type': 'indicator'})
        
        return results
    
    def _process_url_results(self, source_node: str, data: Dict) -> List[Dict]:
        """Process URL results with SUB-ENTITY creation (Maltego style)"""
        results = []
        
        # 1. URL -> Domain -> IP hierarchy
        if data.get('domain'):
            domain_props = {
                'url': data.get('url'),
                'malicious': data.get('malicious'),
                'phishing': data.get('phishing')
            }
            domain_node = db.add_node('domain', data['domain'], domain_props, confidence=1.0)
            db.add_edge(source_node, domain_node, 'resolves_to', confidence=1.0)
            results.append({'node_id': domain_node, 'type': 'domain'})
            
            # SUB-ENTITY: Domain -> IP
            if data.get('ip'):
                ip_props = {
                    'domain': data['domain'],
                    'country': data.get('country'),
                    'server': data.get('server')
                }
                ip_node = db.add_node('ip', data['ip'], ip_props, confidence=0.9)
                db.add_edge(domain_node, ip_node, 'hosted_on', confidence=0.9)
                results.append({'node_id': ip_node, 'type': 'ip'})
                
                # SUB-SUB-ENTITY: IP -> Location
                if data.get('country'):
                    location_props = {'ip': data['ip'], 'type': 'hosting_location'}
                    location_node = db.add_node('location', data['country'], location_props, confidence=0.85)
                    db.add_edge(ip_node, location_node, 'located_in', confidence=0.85)
                    results.append({'node_id': location_node, 'type': 'location'})
        
        # 2. URL -> Redirects -> Final URL hierarchy
        for redirect in data.get('redirects', [])[:10]:
            if isinstance(redirect, dict) and redirect.get('url'):
                redirect_props = {
                    'status': redirect.get('status'),
                    'order': data['redirects'].index(redirect),
                    'source_url': data.get('url')
                }
                redirect_node = db.add_node('url', redirect['url'], redirect_props, confidence=0.9)
                db.add_edge(source_node, redirect_node, 'redirects_to', confidence=0.9)
                results.append({'node_id': redirect_node, 'type': 'url'})
        
        # Final URL (after all redirects)
        if data.get('final_url') and data['final_url'] != data.get('url'):
            final_props = {'type': 'final_destination', 'original_url': data.get('url')}
            final_node = db.add_node('url', data['final_url'], final_props, confidence=1.0)
            db.add_edge(source_node, final_node, 'final_destination', confidence=1.0)
            results.append({'node_id': final_node, 'type': 'url'})
        
        # 3. URL -> Threat Names
        for threat in data.get('threat_names', [])[:15]:
            threat_props = {
                'url': data.get('url'),
                'malicious': data.get('malicious'),
                'type': 'url_threat'
            }
            threat_node = db.add_node('threat', threat, threat_props, confidence=0.85)
            db.add_edge(source_node, threat_node, 'identified_as', confidence=0.85)
            results.append({'node_id': threat_node, 'type': 'threat'})
        
        # 4. URL -> Technologies -> Versions hierarchy
        for tech in data.get('technologies', [])[:10]:
            if isinstance(tech, str):
                tech_props = {'url': data.get('url'), 'category': 'web'}
                tech_node = db.add_node('technology', tech, tech_props, confidence=0.8)
                db.add_edge(source_node, tech_node, 'uses_technology', confidence=0.8)
                results.append({'node_id': tech_node, 'type': 'technology'})
            elif isinstance(tech, dict):
                tech_name = tech.get('name', 'Unknown')
                tech_props = {
                    'version': tech.get('version'),
                    'category': tech.get('category'),
                    'url': data.get('url')
                }
                tech_node = db.add_node('technology', tech_name, tech_props, confidence=0.8)
                db.add_edge(source_node, tech_node, 'uses_technology', confidence=0.8)
                results.append({'node_id': tech_node, 'type': 'technology'})
                
                # SUB-ENTITY: Technology -> Version
                if tech.get('version'):
                    version_props = {'technology': tech_name, 'url': data.get('url')}
                    version_node = db.add_node('version', tech['version'], version_props, confidence=0.9)
                    db.add_edge(tech_node, version_node, 'version', confidence=0.9)
                    results.append({'node_id': version_node, 'type': 'version'})
        
        # 5. URL -> Certificates -> Issuer hierarchy
        for cert in data.get('certificates', [])[:5]:
            if isinstance(cert, dict):
                cert_subject = cert.get('subject', 'Unknown Certificate')
                cert_props = {
                    'issuer': cert.get('issuer'),
                    'valid_from': cert.get('valid_from'),
                    'valid_to': cert.get('valid_to'),
                    'expired': cert.get('expired'),
                    'domain': data.get('domain')
                }
                cert_node = db.add_node('certificate', cert_subject, cert_props, confidence=0.9)
                db.add_edge(source_node, cert_node, 'has_certificate', confidence=0.9)
                results.append({'node_id': cert_node, 'type': 'certificate'})
                
                # SUB-ENTITY: Certificate -> Issuer (CA)
                if cert.get('issuer'):
                    issuer_props = {'type': 'certificate_authority'}
                    issuer_node = db.add_node('certificate_authority', cert['issuer'], issuer_props, confidence=0.95)
                    db.add_edge(cert_node, issuer_node, 'issued_by', confidence=0.95)
                    results.append({'node_id': issuer_node, 'type': 'certificate_authority'})
        
        # 6. URL -> Reports (from URLhaus, PhishTank, etc.)
        for report in data.get('reports', [])[:10]:
            if isinstance(report, dict):
                report_source = report.get('source', 'Unknown')
                report_props = {
                    'source': report_source,
                    'threat': report.get('threat'),
                    'date': report.get('date_added') or report.get('submission_time'),
                    'verified': report.get('verified'),
                    'url': data.get('url')
                }
                report_node = db.add_node('threat_report', f"{report_source}_report", report_props, confidence=0.85)
                db.add_edge(source_node, report_node, 'reported_by', confidence=0.85)
                results.append({'node_id': report_node, 'type': 'threat_report'})
        
        return results
    
    def _process_company_results(self, source_node: str, data: Dict) -> List[Dict]:
        """Process company results with SUB-ENTITY creation (Maltego style)"""
        results = []
        
        # 1. Company -> Domains -> IPs hierarchy
        if data.get('domain'):
            domain_props = {'website': data.get('website'), 'company': data.get('company'), 'type': 'primary_domain'}
            domain_node = db.add_node('domain', data['domain'], domain_props, confidence=1.0)
            db.add_edge(source_node, domain_node, 'owns_domain', confidence=1.0)
            results.append({'node_id': domain_node, 'type': 'domain'})
            
            # SUB-ENTITY: Domain -> IPs (placeholder for DNS lookup)
        
        for domain in data.get('domains', [])[:10]:
            if domain != data.get('domain'):
                domain_props = {'company': data.get('company'), 'type': 'related_domain'}
                domain_node = db.add_node('domain', domain, domain_props, confidence=0.8)
                db.add_edge(source_node, domain_node, 'owns_domain', confidence=0.8)
                results.append({'node_id': domain_node, 'type': 'domain'})
        
        # 2. Company -> Employees -> Email/LinkedIn hierarchy
        for employee in data.get('employees', [])[:20]:
            name = employee.get('name') or employee.get('email', '').split('@')[0] if employee.get('email') else 'Unknown'
            emp_props = {
                'title': employee.get('title') or employee.get('position'),
                'department': employee.get('department'),
                'linkedin': employee.get('linkedin'),
                'email': employee.get('email'),
                'company': data.get('company')
            }
            emp_node = db.add_node('person', name, emp_props, confidence=0.7)
            db.add_edge(source_node, emp_node, 'employs', confidence=0.7)
            results.append({'node_id': emp_node, 'type': 'person'})
            
            # SUB-ENTITY: Employee -> Email
            if employee.get('email'):
                email_props = {'employee': name, 'company': data.get('company')}
                email_node = db.add_node('email', employee['email'], email_props, confidence=0.9)
                db.add_edge(emp_node, email_node, 'has_email', confidence=0.9)
                results.append({'node_id': email_node, 'type': 'email'})
            
            # SUB-ENTITY: Employee -> LinkedIn Profile
            if employee.get('linkedin'):
                linkedin_props = {'employee': name, 'type': 'linkedin_profile'}
                linkedin_node = db.add_node('url', employee['linkedin'], linkedin_props, confidence=0.9)
                db.add_edge(emp_node, linkedin_node, 'linkedin_profile', confidence=0.9)
                results.append({'node_id': linkedin_node, 'type': 'url'})
        
        # 3. Company -> Email Addresses (not tied to specific employee)
        for email in data.get('emails', [])[:20]:
            if email and not any(e.get('email') == email for e in data.get('employees', [])):
                email_props = {'company': data.get('company'), 'domain': data.get('domain')}
                email_node = db.add_node('email', email, email_props, confidence=0.8)
                db.add_edge(source_node, email_node, 'has_email', confidence=0.8)
                results.append({'node_id': email_node, 'type': 'email'})
        
        # 4. Company -> Social Media -> Platform URLs
        for platform, handle in (data.get('social_media', {}) or {}).items():
            if handle:
                social_props = {
                    'platform': platform,
                    'handle': handle,
                    'company': data.get('company')
                }
                social_node = db.add_node('social_profile', f"{platform}_{handle}", social_props, confidence=0.8)
                db.add_edge(source_node, social_node, 'social_profile', confidence=0.8)
                results.append({'node_id': social_node, 'type': 'social_profile'})
                
                # SUB-ENTITY: Social Profile -> URL
                url_map = {
                    'twitter': f'https://twitter.com/{handle}',
                    'facebook': f'https://facebook.com/{handle}',
                    'linkedin': f'https://linkedin.com/company/{handle}',
                    'instagram': f'https://instagram.com/{handle}'
                }
                if platform in url_map:
                    url_props = {'platform': platform, 'type': 'social_media_url'}
                    url_node = db.add_node('url', url_map[platform], url_props, confidence=0.9)
                    db.add_edge(social_node, url_node, 'profile_url', confidence=0.9)
                    results.append({'node_id': url_node, 'type': 'url'})
        
        # 5. Company -> Technologies -> Versions hierarchy
        for tech in (data.get('technologies', []) or [])[:15]:
            if isinstance(tech, str):
                tech_props = {'company': data.get('company'), 'category': 'unknown'}
                tech_node = db.add_node('technology', tech, tech_props, confidence=0.7)
                db.add_edge(source_node, tech_node, 'uses_technology', confidence=0.7)
                results.append({'node_id': tech_node, 'type': 'technology'})
            elif isinstance(tech, dict):
                tech_name = tech.get('name', 'Unknown')
                tech_props = {
                    'category': tech.get('category'),
                    'company': data.get('company')
                }
                tech_node = db.add_node('technology', tech_name, tech_props, confidence=0.8)
                db.add_edge(source_node, tech_node, 'uses_technology', confidence=0.8)
                results.append({'node_id': tech_node, 'type': 'technology'})
                
                # SUB-ENTITY: Technology -> Version
                if tech.get('version'):
                    version_props = {'technology': tech_name, 'version': tech['version']}
                    version_node = db.add_node('version', tech['version'], version_props, confidence=0.9)
                    db.add_edge(tech_node, version_node, 'version', confidence=0.9)
                    results.append({'node_id': version_node, 'type': 'version'})
        
        # 6. Company -> Jobs -> Job Titles
        for job in data.get('jobs', [])[:15]:
            if isinstance(job, dict):
                job_title = job.get('title', 'Unknown Position')
                job_props = {
                    'source': job.get('source'),
                    'company': data.get('company'),
                    'location': job.get('location')
                }
                job_node = db.add_node('job', job_title, job_props, confidence=0.7)
                db.add_edge(source_node, job_node, 'hiring_for', confidence=0.7)
                results.append({'node_id': job_node, 'type': 'job'})
        
        # 7. Company -> Addresses -> Locations
        for address in data.get('addresses', [])[:5]:
            if isinstance(address, dict) and address.get('address'):
                location_str = address.get('city', '') or address.get('address', '')
                location_props = {
                    'type': address.get('type'),
                    'full_address': address.get('address'),
                    'city': address.get('city'),
                    'state': address.get('state'),
                    'country': address.get('country'),
                    'lat': address.get('lat'),
                    'lng': address.get('lng')
                }
                location_node = db.add_node('location', location_str, location_props, confidence=0.8)
                db.add_edge(source_node, location_node, 'located_at', confidence=0.8)
                results.append({'node_id': location_node, 'type': 'location'})
        
        # 8. Company -> Acquisitions
        for acq in data.get('acquisitions', [])[:10]:
            if isinstance(acq, dict) and acq.get('company'):
                acq_props = {
                    'date': acq.get('date'),
                    'price': acq.get('price'),
                    'acquirer': data.get('company')
                }
                acq_node = db.add_node('company', acq['company'], acq_props, confidence=0.85)
                db.add_edge(source_node, acq_node, 'acquired', confidence=0.85)
                results.append({'node_id': acq_node, 'type': 'company'})
        
        # 9. Company -> Competitors
        for competitor in data.get('competitors', [])[:10]:
            competitor_props = {'industry': data.get('industry'), 'relation': 'competitor'}
            competitor_node = db.add_node('company', competitor, competitor_props, confidence=0.7)
            db.add_edge(source_node, competitor_node, 'competes_with', confidence=0.7)
            results.append({'node_id': competitor_node, 'type': 'company'})
        
        return results
    
    def _process_cve_results(self, source_node: str, data: Dict) -> List[Dict]:
        """Process CVE results with SUB-ENTITY creation (Maltego style)"""
        results = []
        
        # 1. CVE -> Affected Products -> Versions -> Vendors hierarchy
        for product in data.get('affected_products', [])[:20]:
            prod_props = {
                'cve': data.get('cve_id'),
                'cvss': data.get('cvss_v3', {}).get('score'),
                'severity': data.get('severity')
            }
            prod_node = db.add_node('technology', product, prod_props, confidence=0.9)
            db.add_edge(source_node, prod_node, 'affects', confidence=0.9)
            results.append({'node_id': prod_node, 'type': 'technology'})
        
        # 2. CVE -> Vendors -> Companies hierarchy
        for vendor in data.get('vendors', [])[:10]:
            vendor_props = {'cve': data.get('cve_id'), 'type': 'software_vendor'}
            vendor_node = db.add_node('company', vendor, vendor_props, confidence=0.8)
            db.add_edge(source_node, vendor_node, 'affects_vendor', confidence=0.8)
            results.append({'node_id': vendor_node, 'type': 'company'})
        
        # 3. CVE -> Exploits -> Exploit Details hierarchy
        for exploit in data.get('exploits', [])[:10]:
            exploit_name = exploit.get('title', exploit.get('id', 'Unknown'))
            exploit_props = {
                'source': exploit.get('source'),
                'id': exploit.get('id'),
                'url': exploit.get('url'),
                'cve': data.get('cve_id')
            }
            exploit_node = db.add_node('exploit', exploit_name, exploit_props, confidence=0.9)
            db.add_edge(source_node, exploit_node, 'has_exploit', confidence=0.9)
            results.append({'node_id': exploit_node, 'type': 'exploit'})
            
            # SUB-ENTITY: Exploit -> URL
            if exploit.get('url'):
                url_props = {'type': 'exploit_url', 'exploit': exploit_name}
                url_node = db.add_node('url', exploit['url'], url_props, confidence=1.0)
                db.add_edge(exploit_node, url_node, 'exploit_url', confidence=1.0)
                results.append({'node_id': url_node, 'type': 'url'})
        
        # 4. CVE -> Patches -> Patched Versions hierarchy
        for patch in data.get('patches', [])[:10]:
            if isinstance(patch, dict):
                package = patch.get('package', 'Unknown')
                patch_props = {
                    'patched_versions': patch.get('patched_versions'),
                    'cve': data.get('cve_id')
                }
                patch_node = db.add_node('patch', f"Patch for {package}", patch_props, confidence=0.85)
                db.add_edge(source_node, patch_node, 'has_patch', confidence=0.85)
                results.append({'node_id': patch_node, 'type': 'patch'})
                
                # SUB-ENTITY: Patch -> Patched Version
                if patch.get('patched_versions'):
                    version_props = {'package': package, 'type': 'patched_version'}
                    version_node = db.add_node('version', patch['patched_versions'], version_props, confidence=0.9)
                    db.add_edge(patch_node, version_node, 'patched_version', confidence=0.9)
                    results.append({'node_id': version_node, 'type': 'version'})
        
        # 5. CVE -> CWE (Weakness Types) -> Category hierarchy
        for cwe in data.get('cwe', [])[:5]:
            cwe_id = cwe if 'CWE-' in cwe else f"CWE-{cwe}"
            cwe_props = {
                'cve': data.get('cve_id'),
                'type': 'weakness'
            }
            cwe_node = db.add_node('cwe', cwe_id, cwe_props, confidence=1.0)
            db.add_edge(source_node, cwe_node, 'weakness_type', confidence=1.0)
            results.append({'node_id': cwe_node, 'type': 'cwe'})
            
            # SUB-ENTITY: CWE -> Category (would require CWE database lookup)
        
        # 6. CVE -> References -> URLs
        for ref in data.get('references', [])[:15]:
            if isinstance(ref, dict) and ref.get('url'):
                ref_props = {
                    'source': ref.get('source'),
                    'tags': ref.get('tags', []),
                    'cve': data.get('cve_id')
                }
                ref_node = db.add_node('url', ref['url'], ref_props, confidence=0.8)
                db.add_edge(source_node, ref_node, 'reference', confidence=0.8)
                results.append({'node_id': ref_node, 'type': 'url'})
        
        # 7. CVE -> Metasploit Modules
        for msf_module in data.get('metasploit_modules', [])[:10]:
            msf_props = {'type': 'metasploit_module', 'cve': data.get('cve_id')}
            msf_node = db.add_node('exploit', msf_module, msf_props, confidence=0.9)
            db.add_edge(source_node, msf_node, 'metasploit_module', confidence=0.9)
            results.append({'node_id': msf_node, 'type': 'exploit'})
        
        return results
    
    def _process_malware_results(self, source_node: str, data: Dict) -> List[Dict]:
        """Process malware results with SUB-ENTITY creation (Maltego style)"""
        results = []
        
        # 1. Malware -> IOC IPs -> Geolocation hierarchy
        for ip in (data.get('iocs', {}).get('ips', []))[:20]:
            ip_props = {'type': 'c2_server', 'malware': data.get('malware')}
            ip_node = db.add_node('ip', ip, ip_props, confidence=0.9)
            db.add_edge(source_node, ip_node, 'c2_server', confidence=0.9)
            results.append({'node_id': ip_node, 'type': 'ip'})
            
            # SUB-ENTITY: IP -> Geolocation (placeholder for IP investigation)
        
        # 2. Malware -> IOC Domains -> Status hierarchy
        for domain in (data.get('iocs', {}).get('domains', []))[:20]:
            domain_props = {'type': 'c2_domain', 'malware': data.get('malware')}
            domain_node = db.add_node('domain', domain, domain_props, confidence=0.9)
            db.add_edge(source_node, domain_node, 'c2_domain', confidence=0.9)
            results.append({'node_id': domain_node, 'type': 'domain'})
            
            # SUB-ENTITY: Domain -> Status (online/offline) - would require live check
        
        # 3. Malware -> IOC URLs
        for url in (data.get('iocs', {}).get('urls', []))[:20]:
            url_props = {'type': 'malicious_url', 'malware': data.get('malware')}
            url_node = db.add_node('url', url, url_props, confidence=0.9)
            db.add_edge(source_node, url_node, 'malicious_url', confidence=0.9)
            results.append({'node_id': url_node, 'type': 'url'})
        
        # 4. Malware -> Hashes (SHA256/MD5/SHA1) hierarchy
        for hash_type in ['sha256', 'md5', 'sha1']:
            for hash_val in (data.get('hashes', {}).get(hash_type, []))[:10]:
                hash_props = {'type': hash_type.upper(), 'malware': data.get('malware')}
                hash_node = db.add_node('hash', hash_val, hash_props, confidence=1.0)
                db.add_edge(source_node, hash_node, 'sample_hash', confidence=1.0)
                results.append({'node_id': hash_node, 'type': 'hash'})
        
        # 5. Malware -> Campaigns -> APT Groups hierarchy
        for campaign in data.get('campaigns', [])[:10]:
            campaign_name = campaign.get('name', 'Unknown') if isinstance(campaign, dict) else campaign
            campaign_props = {
                'description': campaign.get('description') if isinstance(campaign, dict) else None,
                'created': campaign.get('created') if isinstance(campaign, dict) else None,
                'tags': campaign.get('tags', []) if isinstance(campaign, dict) else [],
                'malware': data.get('malware')
            }
            campaign_node = db.add_node('campaign', campaign_name, campaign_props, confidence=0.8)
            db.add_edge(source_node, campaign_node, 'part_of_campaign', confidence=0.8)
            results.append({'node_id': campaign_node, 'type': 'campaign'})
            
            # SUB-ENTITY: Campaign -> APT Group/Threat Actor
            for actor in data.get('threat_actors', [])[:5]:
                actor_props = {'campaign': campaign_name, 'type': 'threat_actor'}
                actor_node = db.add_node('threat_actor', actor, actor_props, confidence=0.75)
                db.add_edge(campaign_node, actor_node, 'attributed_to', confidence=0.75)
                results.append({'node_id': actor_node, 'type': 'threat_actor'})
        
        # 6. Malware -> Samples -> File Details
        for sample in data.get('samples', [])[:10]:
            if isinstance(sample, dict) and sample.get('sha256'):
                sample_name = sample.get('file_name', sample['sha256'][:16])
                sample_props = {
                    'sha256': sample.get('sha256'),
                    'md5': sample.get('md5'),
                    'file_type': sample.get('file_type'),
                    'file_size': sample.get('file_size'),
                    'signature': sample.get('signature'),
                    'first_seen': sample.get('first_seen')
                }
                sample_node = db.add_node('file', sample_name, sample_props, confidence=0.9)
                db.add_edge(source_node, sample_node, 'sample', confidence=0.9)
                results.append({'node_id': sample_node, 'type': 'file'})
        
        # 7. Malware -> Dropped Files
        for dropped in data.get('dropped_files', [])[:10]:
            if isinstance(dropped, dict) and dropped.get('filename'):
                dropped_props = {
                    'filename': dropped['filename'],
                    'path': dropped.get('path'),
                    'size': dropped.get('size'),
                    'sha256': dropped.get('sha256'),
                    'malware': data.get('malware')
                }
                dropped_node = db.add_node('file', dropped['filename'], dropped_props, confidence=0.85)
                db.add_edge(source_node, dropped_node, 'drops_file', confidence=0.85)
                results.append({'node_id': dropped_node, 'type': 'file'})
        
        # 8. Malware -> C2 Servers
        for c2 in data.get('c2_servers', [])[:15]:
            c2_props = {'type': 'command_and_control', 'malware': data.get('malware')}
            # Detect if IP or URL
            if '://' in c2 or '/' in c2:
                c2_node = db.add_node('url', c2, c2_props, confidence=0.9)
            else:
                c2_node = db.add_node('ip', c2.split(':')[0], c2_props, confidence=0.9)
            db.add_edge(source_node, c2_node, 'c2_server', confidence=0.9)
            results.append({'node_id': c2_node, 'type': 'url' if '://' in c2 else 'ip'})
        
        # 9. Malware -> Registry Keys
        for reg_key in (data.get('iocs', {}).get('registry_keys', []))[:10]:
            reg_props = {'type': 'persistence_mechanism', 'malware': data.get('malware')}
            reg_node = db.add_node('registry_key', reg_key, reg_props, confidence=0.85)
            db.add_edge(source_node, reg_node, 'modifies_registry', confidence=0.85)
            results.append({'node_id': reg_node, 'type': 'registry_key'})
        
        # 10. Malware -> Mutexes
        for mutex in (data.get('iocs', {}).get('mutexes', []))[:10]:
            mutex_props = {'type': 'process_mutex', 'malware': data.get('malware')}
            mutex_node = db.add_node('mutex', mutex, mutex_props, confidence=0.9)
            db.add_edge(source_node, mutex_node, 'creates_mutex', confidence=0.9)
            results.append({'node_id': mutex_node, 'type': 'mutex'})
        
        # 11. Malware -> Behavior Indicators
        for behavior in data.get('behavior', [])[:10]:
            if isinstance(behavior, dict):
                behavior_desc = behavior.get('description', behavior.get('sandbox', 'Unknown'))
                behavior_props = {
                    'sandbox': behavior.get('sandbox'),
                    'verdict': behavior.get('verdict'),
                    'malware': data.get('malware')
                }
                behavior_node = db.add_node('behavior', behavior_desc, behavior_props, confidence=0.75)
                db.add_edge(source_node, behavior_node, 'exhibits_behavior', confidence=0.75)
                results.append({'node_id': behavior_node, 'type': 'behavior'})
        
        # 12. Malware -> YARA Rules
        for yara in data.get('yara_rules', [])[:5]:
            yara_props = {'type': 'detection_rule', 'malware': data.get('malware')}
            yara_node = db.add_node('yara_rule', yara[:100], yara_props, confidence=0.8)
            db.add_edge(source_node, yara_node, 'detected_by_yara', confidence=0.8)
            results.append({'node_id': yara_node, 'type': 'yara_rule'})
        
        # 13. Malware -> Capabilities
        for capability in data.get('capabilities', [])[:10]:
            cap_props = {'type': 'malware_capability', 'malware': data.get('malware')}
            cap_node = db.add_node('capability', capability, cap_props, confidence=0.8)
            db.add_edge(source_node, cap_node, 'has_capability', confidence=0.8)
            results.append({'node_id': cap_node, 'type': 'capability'})
        
        return results
    
    def _process_breach_results(self, source_node: str, data: Dict) -> List[Dict]:
        """Process breach results with SUB-ENTITY creation (Maltego style)"""
        results = []
        
        # 1. Breach -> Affected Emails -> Domains hierarchy
        for breach in data.get('breaches', [])[:20]:
            breach_name = breach.get('name') or breach.get('title', 'Unknown')
            breach_props = {
                'name': breach_name,
                'date': breach.get('date') or breach.get('breach_date'),
                'records': breach.get('records') or breach.get('pwn_count'),
                'verified': breach.get('verified') or breach.get('is_verified'),
                'sensitive': breach.get('is_sensitive', False),
                'description': (breach.get('description', '') or '')[:200]
            }
            breach_node = db.add_node('breach', breach_name, breach_props, confidence=0.9)
            db.add_edge(source_node, breach_node, 'found_in_breach', confidence=0.9)
            results.append({'node_id': breach_node, 'type': 'breach'})
            
            # SUB-ENTITY: Breach -> Domain
            if breach.get('domain'):
                domain_props = {'type': 'breached_domain', 'breach': breach_name}
                domain_node = db.add_node('domain', breach['domain'], domain_props, confidence=1.0)
                db.add_edge(breach_node, domain_node, 'breached_domain', confidence=1.0)
                results.append({'node_id': domain_node, 'type': 'domain'})
            
            # SUB-ENTITY: Breach -> Data Classes
            for data_class in (breach.get('data_classes') or breach.get('DataClasses', []))[:10]:
                dc_props = {'type': 'leaked_data_type', 'breach': breach_name}
                dc_node = db.add_node('data_class', data_class, dc_props, confidence=0.95)
                db.add_edge(breach_node, dc_node, 'leaked_data', confidence=0.95)
                results.append({'node_id': dc_node, 'type': 'data_class'})
        
        # 2. Data Leaks -> Database -> Leaked Credentials hierarchy
        for leak in data.get('leaks', [])[:20]:
            source = leak.get('source', 'Unknown')
            db_name = leak.get('database') or leak.get('database_name', 'Unknown DB')
            leak_props = {
                'source': source,
                'database': db_name,
                'date': leak.get('date') or leak.get('date_compromised'),
                'has_password': bool(leak.get('password') or leak.get('hashed_password'))
            }
            leak_node = db.add_node('data_leak', f"{source}_{db_name}", leak_props, confidence=0.85)
            db.add_edge(source_node, leak_node, 'found_in_leak', confidence=0.85)
            results.append({'node_id': leak_node, 'type': 'data_leak'})
            
            # SUB-ENTITY: Leak -> Email
            if leak.get('email'):
                email_props = {'source': 'data_leak', 'database': db_name}
                email_node = db.add_node('email', leak['email'], email_props, confidence=0.9)
                db.add_edge(leak_node, email_node, 'leaked_email', confidence=0.9)
                results.append({'node_id': email_node, 'type': 'email'})
            
            # SUB-ENTITY: Leak -> Username
            if leak.get('username'):
                username_props = {'source': 'data_leak', 'database': db_name}
                username_node = db.add_node('username', leak['username'], username_props, confidence=0.85)
                db.add_edge(leak_node, username_node, 'leaked_username', confidence=0.85)
                results.append({'node_id': username_node, 'type': 'username'})
            
            # SUB-ENTITY: Leak -> Password (anonymized)
            if leak.get('password'):
                pwd_props = {
                    'type': 'plaintext',
                    'length': len(leak['password']),
                    'database': db_name,
                    'anonymized': True
                }
                pwd_node = db.add_node('password', f"***{len(leak['password'])} chars", pwd_props, confidence=0.9)
                db.add_edge(leak_node, pwd_node, 'leaked_password', confidence=0.9)
                results.append({'node_id': pwd_node, 'type': 'password'})
        
        # 3. Pastes -> Paste Site hierarchy
        for paste in data.get('pastes', [])[:10]:
            paste_source = paste.get('source') or paste.get('Source', 'Unknown')
            paste_id = paste.get('id') or paste.get('Id', 'unknown')
            paste_props = {
                'source': paste_source,
                'id': paste_id,
                'title': paste.get('title') or paste.get('Title'),
                'date': paste.get('date') or paste.get('Date'),
                'email_count': paste.get('email_count') or paste.get('EmailCount')
            }
            paste_node = db.add_node('paste', f"{paste_source}_{paste_id}", paste_props, confidence=0.8)
            db.add_edge(source_node, paste_node, 'found_in_paste', confidence=0.8)
            results.append({'node_id': paste_node, 'type': 'paste'})
            
            # SUB-ENTITY: Paste -> Paste Site
            site_props = {'type': 'paste_platform', 'platform': paste_source}
            site_node = db.add_node('paste_site', paste_source, site_props, confidence=1.0)
            db.add_edge(paste_node, site_node, 'hosted_on', confidence=1.0)
            results.append({'node_id': site_node, 'type': 'paste_site'})
        
        # 4. Related Emails found in breaches
        for email in data.get('emails', [])[:10]:
            if email != data.get('identifier'):
                email_props = {'source': 'breach_investigation', 'related': True}
                email_node = db.add_node('email', email, email_props, confidence=0.75)
                db.add_edge(source_node, email_node, 'linked_email', confidence=0.75)
                results.append({'node_id': email_node, 'type': 'email'})
        
        # 5. Related Usernames
        for username in data.get('usernames', [])[:10]:
            username_props = {'source': 'breach_investigation'}
            username_node = db.add_node('username', username, username_props, confidence=0.7)
            db.add_edge(source_node, username_node, 'linked_username', confidence=0.7)
            results.append({'node_id': username_node, 'type': 'username'})
        
        # 6. Related Phones
        for phone in data.get('phones', [])[:10]:
            phone_props = {'source': 'breach_investigation'}
            phone_node = db.add_node('phone', phone, phone_props, confidence=0.8)
            db.add_edge(source_node, phone_node, 'linked_phone', confidence=0.8)
            results.append({'node_id': phone_node, 'type': 'phone'})
        
        # 7. Related Domains
        for domain in data.get('domains', [])[:10]:
            domain_props = {'type': 'breached_domain', 'source': 'breach_investigation'}
            domain_node = db.add_node('domain', domain, domain_props, confidence=0.7)
            db.add_edge(source_node, domain_node, 'breached_domain', confidence=0.7)
            results.append({'node_id': domain_node, 'type': 'domain'})
        
        return results

engine = TransformEngine()
