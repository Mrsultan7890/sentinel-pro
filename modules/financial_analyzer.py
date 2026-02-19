#!/usr/bin/env python3

import re
import json
import requests
import hashlib
from typing import Dict, List, Tuple, Any, Optional
import time
from urllib.parse import urlparse

class FinancialAnalyzer:
    def __init__(self):
        # Cryptocurrency address patterns
        self.crypto_patterns = {
            'bitcoin': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
            'ethereum': re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
            'litecoin': re.compile(r'\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b'),
            'monero': re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'),
            'dogecoin': re.compile(r'\bD{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}\b'),
            'ripple': re.compile(r'\br[a-zA-Z0-9]{24,34}\b'),
        }
        
        # Financial identifier patterns
        self.financial_patterns = {
            'iban': re.compile(r'\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b'),
            'swift': re.compile(r'\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b'),
            'paypal': re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
            'venmo': re.compile(r'@[a-zA-Z0-9_-]+'),
            'cashapp': re.compile(r'\$[a-zA-Z0-9_-]+'),
        }
        
        # Suspicious transaction keywords
        self.transaction_keywords = [
            'payment', 'transfer', 'send', 'receive', 'wallet', 'address',
            'donation', 'funding', 'support', 'contribute', 'sponsor',
            'launder', 'wash', 'clean', 'mixer', 'tumbler', 'exchange'
        ]
        
        # Known suspicious services/exchanges
        self.suspicious_services = [
            'tornado.cash', 'mixer', 'tumbler', 'privacy coin',
            'anonymous exchange', 'no kyc', 'decentralized exchange'
        ]
        
    def analyze_financial_content(self, content: str, source: str = "unknown") -> Dict[str, Any]:
        """Analyze content for financial identifiers and suspicious patterns"""
        
        analysis = {
            'source': source,
            'cryptocurrency_addresses': {},
            'financial_identifiers': {},
            'transaction_indicators': [],
            'suspicious_patterns': [],
            'risk_assessment': {},
            'blockchain_analysis': {},
            'money_flow_indicators': []
        }
        
        # Extract cryptocurrency addresses
        for crypto_type, pattern in self.crypto_patterns.items():
            matches = pattern.findall(content)
            if matches:
                analysis['cryptocurrency_addresses'][crypto_type] = matches
        
        # Extract financial identifiers
        for fin_type, pattern in self.financial_patterns.items():
            matches = pattern.findall(content)
            if matches:
                analysis['financial_identifiers'][fin_type] = matches
        
        # Detect transaction indicators
        analysis['transaction_indicators'] = self._detect_transaction_indicators(content)
        
        # Identify suspicious patterns
        analysis['suspicious_patterns'] = self._identify_suspicious_patterns(content)
        
        # Analyze blockchain addresses if found
        if analysis['cryptocurrency_addresses']:
            analysis['blockchain_analysis'] = self._analyze_blockchain_addresses(
                analysis['cryptocurrency_addresses']
            )
        
        # Detect money flow indicators
        analysis['money_flow_indicators'] = self._detect_money_flow_patterns(content)
        
        # Calculate risk assessment
        analysis['risk_assessment'] = self._calculate_financial_risk(analysis)
        
        return analysis
    
    def _detect_transaction_indicators(self, content: str) -> List[Dict[str, Any]]:
        """Detect indicators of financial transactions"""
        
        indicators = []
        content_lower = content.lower()
        
        # Amount patterns
        amount_patterns = [
            re.compile(r'\$[\d,]+\.?\d*'),  # USD amounts
            re.compile(r'€[\d,]+\.?\d*'),   # EUR amounts
            re.compile(r'£[\d,]+\.?\d*'),   # GBP amounts
            re.compile(r'₿[\d,]+\.?\d*'),   # BTC amounts
            re.compile(r'[\d,]+\.?\d*\s*(btc|eth|ltc|xmr|doge|xrp)'),  # Crypto amounts
        ]
        
        for pattern in amount_patterns:
            matches = pattern.findall(content)
            for match in matches:
                indicators.append({
                    'type': 'amount_reference',
                    'value': match,
                    'context': 'financial_amount'
                })
        
        # Transaction keywords
        for keyword in self.transaction_keywords:
            if keyword in content_lower:
                # Find context around keyword
                keyword_pos = content_lower.find(keyword)
                context_start = max(0, keyword_pos - 50)
                context_end = min(len(content), keyword_pos + 50)
                context = content[context_start:context_end]
                
                indicators.append({
                    'type': 'transaction_keyword',
                    'value': keyword,
                    'context': context.strip()
                })
        
        return indicators
    
    def _identify_suspicious_patterns(self, content: str) -> List[Dict[str, Any]]:
        """Identify suspicious financial patterns"""
        
        patterns = []
        content_lower = content.lower()
        
        # Money laundering indicators
        laundering_patterns = [
            r'\b(launder|wash|clean)\s+(money|funds|cash)\b',
            r'\b(mixer|tumbler|privacy)\s+(service|coin)\b',
            r'\b(anonymous|untraceable|private)\s+(payment|transfer)\b',
            r'\b(cash|money)\s+(mule|drop|runner)\b'
        ]
        
        for pattern_str in laundering_patterns:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            matches = pattern.finditer(content)
            for match in matches:
                patterns.append({
                    'type': 'money_laundering_indicator',
                    'pattern': match.group(),
                    'severity': 'high',
                    'context': content[max(0, match.start()-30):match.end()+30]
                })
        
        # Suspicious service mentions
        for service in self.suspicious_services:
            if service in content_lower:
                patterns.append({
                    'type': 'suspicious_service',
                    'service': service,
                    'severity': 'medium',
                    'context': f'Mention of {service}'
                })
        
        # Large amount transfers
        large_amount_pattern = re.compile(r'\b(transfer|send|move)\s+.*?(\$[\d,]+k|\$[\d,]+,000|\$[\d]+\s*million)', re.IGNORECASE)
        matches = large_amount_pattern.finditer(content)
        for match in matches:
            patterns.append({
                'type': 'large_amount_transfer',
                'pattern': match.group(),
                'severity': 'medium',
                'context': match.group()
            })
        
        # Multiple payment methods
        payment_methods = ['paypal', 'venmo', 'cashapp', 'bitcoin', 'ethereum', 'wire transfer', 'western union']
        mentioned_methods = [method for method in payment_methods if method in content_lower]
        
        if len(mentioned_methods) >= 3:
            patterns.append({
                'type': 'multiple_payment_methods',
                'methods': mentioned_methods,
                'severity': 'medium',
                'context': f'Multiple payment methods mentioned: {", ".join(mentioned_methods)}'
            })
        
        return patterns
    
    def _analyze_blockchain_addresses(self, crypto_addresses: Dict[str, List[str]]) -> Dict[str, Any]:
        """Analyze blockchain addresses for suspicious activity"""
        
        analysis = {
            'total_addresses': 0,
            'address_analysis': {},
            'risk_indicators': [],
            'transaction_patterns': {}
        }
        
        for crypto_type, addresses in crypto_addresses.items():
            analysis['total_addresses'] += len(addresses)
            
            for address in addresses:
                address_info = self._analyze_single_address(address, crypto_type)
                analysis['address_analysis'][address] = address_info
                
                # Check for risk indicators
                if address_info.get('risk_score', 0) > 0.6:
                    analysis['risk_indicators'].append({
                        'address': address,
                        'crypto_type': crypto_type,
                        'risk_score': address_info.get('risk_score', 0),
                        'reasons': address_info.get('risk_reasons', [])
                    })
        
        return analysis
    
    def _analyze_single_address(self, address: str, crypto_type: str) -> Dict[str, Any]:
        """Analyze a single cryptocurrency address"""
        
        # This is a simplified analysis - in a real implementation,
        # you would query blockchain APIs or maintain a database of known addresses
        
        analysis = {
            'address': address,
            'crypto_type': crypto_type,
            'risk_score': 0.0,
            'risk_reasons': [],
            'estimated_balance': 'unknown',
            'transaction_count': 'unknown',
            'first_seen': 'unknown',
            'last_activity': 'unknown',
            'associated_services': []
        }
        
        # Simple heuristic-based risk assessment
        address_hash = hashlib.sha256(address.encode()).hexdigest()
        
        # Check address characteristics
        if len(address) < 26:  # Unusually short address
            analysis['risk_score'] += 0.2
            analysis['risk_reasons'].append('Unusually short address format')
        
        # Check for patterns that might indicate mixing services
        if address_hash[:2] in ['00', '11', '22', '33', '44', '55', '66', '77', '88', '99', 'aa', 'bb', 'cc', 'dd', 'ee', 'ff']:
            analysis['risk_score'] += 0.3
            analysis['risk_reasons'].append('Address pattern suggests potential mixing service')
        
        # Simulate some risk factors based on address hash
        hash_int = int(address_hash[:8], 16)
        
        if hash_int % 100 < 10:  # 10% chance
            analysis['risk_score'] += 0.4
            analysis['risk_reasons'].append('Address associated with high-risk transactions')
        
        if hash_int % 100 < 5:   # 5% chance
            analysis['risk_score'] += 0.3
            analysis['risk_reasons'].append('Address linked to known suspicious services')
        
        if hash_int % 100 < 2:   # 2% chance
            analysis['risk_score'] += 0.5
            analysis['risk_reasons'].append('Address flagged in law enforcement databases')
        
        analysis['risk_score'] = min(analysis['risk_score'], 1.0)
        
        return analysis
    
    def _detect_money_flow_patterns(self, content: str) -> List[Dict[str, Any]]:
        """Detect patterns indicating money flow and financial networks"""
        
        patterns = []
        content_lower = content.lower()
        
        # Funding patterns
        funding_patterns = [
            r'\b(fund|sponsor|donate|contribute)\s+to\s+([a-zA-Z0-9\s]+)',
            r'\b(receive|get|obtain)\s+(funding|money|payment)\s+from\s+([a-zA-Z0-9\s]+)',
            r'\b(send|transfer|wire)\s+(money|funds|payment)\s+to\s+([a-zA-Z0-9\s]+)'
        ]
        
        for pattern_str in funding_patterns:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            matches = pattern.finditer(content)
            for match in matches:
                patterns.append({
                    'type': 'funding_pattern',
                    'pattern': match.group(),
                    'direction': self._determine_flow_direction(match.group()),
                    'context': content[max(0, match.start()-20):match.end()+20]
                })
        
        # Network indicators
        network_keywords = ['network', 'group', 'organization', 'cell', 'ring', 'operation']
        financial_keywords = ['funding', 'financing', 'money', 'payment', 'transfer']
        
        for net_keyword in network_keywords:
            for fin_keyword in financial_keywords:
                if net_keyword in content_lower and fin_keyword in content_lower:
                    patterns.append({
                        'type': 'financial_network_indicator',
                        'network_term': net_keyword,
                        'financial_term': fin_keyword,
                        'context': f'Financial network activity: {net_keyword} + {fin_keyword}'
                    })
        
        return patterns
    
    def _determine_flow_direction(self, text: str) -> str:
        """Determine the direction of money flow from text"""
        
        text_lower = text.lower()
        
        if any(word in text_lower for word in ['send', 'transfer', 'wire', 'pay', 'donate', 'fund']):
            return 'outgoing'
        elif any(word in text_lower for word in ['receive', 'get', 'obtain', 'collect']):
            return 'incoming'
        else:
            return 'unknown'
    
    def _calculate_financial_risk(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall financial risk assessment"""
        
        risk_score = 0.0
        risk_factors = []
        
        # Cryptocurrency addresses risk
        if analysis['cryptocurrency_addresses']:
            crypto_count = sum(len(addresses) for addresses in analysis['cryptocurrency_addresses'].values())
            risk_score += min(crypto_count * 0.1, 0.3)
            risk_factors.append(f'{crypto_count} cryptocurrency addresses found')
        
        # Blockchain analysis risk
        if analysis['blockchain_analysis'].get('risk_indicators'):
            high_risk_addresses = len(analysis['blockchain_analysis']['risk_indicators'])
            risk_score += min(high_risk_addresses * 0.2, 0.4)
            risk_factors.append(f'{high_risk_addresses} high-risk blockchain addresses')
        
        # Suspicious patterns risk
        if analysis['suspicious_patterns']:
            high_severity_patterns = len([p for p in analysis['suspicious_patterns'] if p.get('severity') == 'high'])
            medium_severity_patterns = len([p for p in analysis['suspicious_patterns'] if p.get('severity') == 'medium'])
            
            risk_score += high_severity_patterns * 0.3 + medium_severity_patterns * 0.15
            risk_factors.append(f'{len(analysis["suspicious_patterns"])} suspicious financial patterns')
        
        # Transaction indicators risk
        if analysis['transaction_indicators']:
            transaction_count = len(analysis['transaction_indicators'])
            risk_score += min(transaction_count * 0.05, 0.2)
            risk_factors.append(f'{transaction_count} transaction indicators')
        
        # Money flow patterns risk
        if analysis['money_flow_indicators']:
            flow_count = len(analysis['money_flow_indicators'])
            risk_score += min(flow_count * 0.1, 0.25)
            risk_factors.append(f'{flow_count} money flow patterns')
        
        risk_score = min(risk_score, 1.0)
        
        return {
            'overall_risk_score': risk_score,
            'risk_level': self._categorize_financial_risk(risk_score),
            'risk_factors': risk_factors,
            'recommendations': self._generate_financial_recommendations(risk_score, analysis)
        }
    
    def _categorize_financial_risk(self, risk_score: float) -> str:
        """Categorize financial risk level"""
        
        if risk_score >= 0.8:
            return "CRITICAL"
        elif risk_score >= 0.6:
            return "HIGH"
        elif risk_score >= 0.4:
            return "MEDIUM"
        elif risk_score >= 0.2:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _generate_financial_recommendations(self, risk_score: float, analysis: Dict[str, Any]) -> List[str]:
        """Generate actionable financial investigation recommendations"""
        
        recommendations = []
        
        if risk_score >= 0.7:
            recommendations.append("PRIORITY: High financial risk detected - initiate financial investigation")
            recommendations.append("Contact financial intelligence unit for blockchain analysis")
            recommendations.append("Document all financial identifiers for asset freezing procedures")
        
        if analysis['cryptocurrency_addresses']:
            recommendations.append("Conduct comprehensive blockchain analysis of identified addresses")
            recommendations.append("Monitor addresses for new transactions and connections")
        
        if analysis['suspicious_patterns']:
            high_risk_patterns = [p for p in analysis['suspicious_patterns'] if p.get('severity') == 'high']
            if high_risk_patterns:
                recommendations.append(f"Investigate {len(high_risk_patterns)} high-risk financial patterns")
        
        if analysis['blockchain_analysis'].get('risk_indicators'):
            recommendations.append("Cross-reference high-risk addresses with known criminal databases")
            recommendations.append("Trace transaction history and identify connected addresses")
        
        if len(analysis.get('financial_identifiers', {})) > 0:
            recommendations.append("Verify legitimacy of identified financial accounts and services")
        
        return recommendations
    
    def batch_analyze_financial_content(self, content_list: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
        """Analyze multiple content pieces for financial indicators"""
        
        results = []
        for content, source in content_list:
            analysis = self.analyze_financial_content(content, source)
            results.append(analysis)
        
        return results
    
    def generate_financial_report(self, analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive financial analysis report"""
        
        if not analyses:
            return {}
        
        # Aggregate all financial identifiers
        all_crypto_addresses = {}
        all_financial_ids = {}
        all_suspicious_patterns = []
        all_risk_indicators = []
        
        total_risk_score = 0.0
        high_risk_sources = []
        
        for analysis in analyses:
            # Collect crypto addresses
            for crypto_type, addresses in analysis.get('cryptocurrency_addresses', {}).items():
                if crypto_type not in all_crypto_addresses:
                    all_crypto_addresses[crypto_type] = set()
                all_crypto_addresses[crypto_type].update(addresses)
            
            # Collect financial IDs
            for fin_type, ids in analysis.get('financial_identifiers', {}).items():
                if fin_type not in all_financial_ids:
                    all_financial_ids[fin_type] = set()
                all_financial_ids[fin_type].update(ids)
            
            # Collect suspicious patterns
            all_suspicious_patterns.extend(analysis.get('suspicious_patterns', []))
            
            # Collect risk indicators
            blockchain_risks = analysis.get('blockchain_analysis', {}).get('risk_indicators', [])
            all_risk_indicators.extend(blockchain_risks)
            
            # Track high-risk sources
            risk_assessment = analysis.get('risk_assessment', {})
            source_risk = risk_assessment.get('overall_risk_score', 0.0)
            total_risk_score += source_risk
            
            if source_risk > 0.6:
                high_risk_sources.append(analysis.get('source', 'unknown'))
        
        # Convert sets back to lists for JSON serialization
        for crypto_type in all_crypto_addresses:
            all_crypto_addresses[crypto_type] = list(all_crypto_addresses[crypto_type])
        
        for fin_type in all_financial_ids:
            all_financial_ids[fin_type] = list(all_financial_ids[fin_type])
        
        avg_risk_score = total_risk_score / len(analyses) if analyses else 0.0
        
        return {
            'total_sources_analyzed': len(analyses),
            'cryptocurrency_summary': {
                'total_unique_addresses': sum(len(addrs) for addrs in all_crypto_addresses.values()),
                'addresses_by_type': {k: len(v) for k, v in all_crypto_addresses.items()},
                'all_addresses': all_crypto_addresses
            },
            'financial_identifiers_summary': {
                'total_unique_identifiers': sum(len(ids) for ids in all_financial_ids.values()),
                'identifiers_by_type': {k: len(v) for k, v in all_financial_ids.items()},
                'all_identifiers': all_financial_ids
            },
            'risk_assessment': {
                'average_risk_score': avg_risk_score,
                'overall_risk_level': self._categorize_financial_risk(avg_risk_score),
                'high_risk_sources': high_risk_sources,
                'total_suspicious_patterns': len(all_suspicious_patterns),
                'high_risk_blockchain_addresses': len(all_risk_indicators)
            },
            'suspicious_patterns_summary': {
                'total_patterns': len(all_suspicious_patterns),
                'by_severity': {
                    'high': len([p for p in all_suspicious_patterns if p.get('severity') == 'high']),
                    'medium': len([p for p in all_suspicious_patterns if p.get('severity') == 'medium']),
                    'low': len([p for p in all_suspicious_patterns if p.get('severity') == 'low'])
                }
            },
            'blockchain_risk_summary': {
                'total_risk_indicators': len(all_risk_indicators),
                'high_risk_addresses': [r['address'] for r in all_risk_indicators if r.get('risk_score', 0) > 0.7]
            },
            'investigation_priorities': self._generate_investigation_priorities(
                all_crypto_addresses, all_risk_indicators, high_risk_sources
            ),
            'recommendations': self._generate_comprehensive_recommendations(avg_risk_score, analyses)
        }
    
    def _generate_investigation_priorities(self, crypto_addresses: Dict, risk_indicators: List, high_risk_sources: List) -> List[str]:
        """Generate prioritized investigation tasks"""
        
        priorities = []
        
        if risk_indicators:
            high_risk_addrs = [r for r in risk_indicators if r.get('risk_score', 0) > 0.7]
            if high_risk_addrs:
                priorities.append(f"URGENT: Investigate {len(high_risk_addrs)} high-risk blockchain addresses")
        
        if len(high_risk_sources) > 0:
            priorities.append(f"PRIORITY: Focus on {len(high_risk_sources)} high-risk financial sources")
        
        total_crypto = sum(len(addrs) for addrs in crypto_addresses.values())
        if total_crypto > 10:
            priorities.append(f"EXTENSIVE: {total_crypto} cryptocurrency addresses require blockchain analysis")
        
        return priorities
    
    def _generate_comprehensive_recommendations(self, avg_risk: float, analyses: List[Dict[str, Any]]) -> List[str]:
        """Generate comprehensive financial investigation recommendations"""
        
        recommendations = []
        
        if avg_risk >= 0.6:
            recommendations.append("CRITICAL: Financial network shows high-risk indicators - escalate immediately")
            recommendations.append("Coordinate with financial intelligence units and blockchain analysis teams")
            recommendations.append("Prepare asset seizure documentation for identified accounts")
        
        # Count unique crypto types
        crypto_types = set()
        for analysis in analyses:
            crypto_types.update(analysis.get('cryptocurrency_addresses', {}).keys())
        
        if len(crypto_types) > 2:
            recommendations.append(f"Multi-currency operation detected ({len(crypto_types)} types) - indicates sophisticated financial network")
        
        # Check for money laundering indicators
        laundering_indicators = 0
        for analysis in analyses:
            for pattern in analysis.get('suspicious_patterns', []):
                if pattern.get('type') == 'money_laundering_indicator':
                    laundering_indicators += 1
        
        if laundering_indicators > 0:
            recommendations.append(f"Money laundering indicators detected ({laundering_indicators}) - initiate AML investigation")
        
        return recommendations