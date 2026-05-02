"""
Cryptocurrency Intelligence Engine - Blockchain Address Analysis
Bitcoin, Ethereum, Monero, Litecoin + Wallet tracking + ML
"""
import sys
import os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
import requests
from typing import Dict

class CryptocurrencyEngine:
    def __init__(self):
        self.free_apis = {
            'blockchain_info': 'https://blockchain.info/rawaddr',
            'blockchair': 'https://api.blockchair.com',
            'etherscan': 'https://api.etherscan.io/api',
            'blockcypher': 'https://api.blockcypher.com/v1',
            'whale_alert': 'https://api.whale-alert.io/v1/transaction',
            'bitcoinabuse': 'https://www.bitcoinabuse.com/api/reports/check'
        }
        self.paid_apis = {
            'etherscan_key': os.getenv('ETHERSCAN_API_KEY', ''),
            'whale_alert_key': os.getenv('WHALE_ALERT_API_KEY', '')
        }
    
    def investigate(self, address: str) -> Dict:
        """Deep cryptocurrency address investigation"""
        results = {
            'address': address,
            'crypto_type': self._detect_crypto_type(address),
            'sources': [],
            'balance': 0.0,
            'balance_usd': 0.0,
            'total_received': 0.0,
            'total_sent': 0.0,
            'transaction_count': 0,
            'first_seen': None,
            'last_seen': None,
            'transactions': [],
            'related_addresses': [],
            'tags': [],
            'abuse_reports': [],
            'whale_activity': False,
            'exchange_deposit': False,
            'mixer_usage': False,
            'risk_score': 0.0,
            'reputation': {}
        }
        
        crypto_type = results['crypto_type']
        
        # === BITCOIN ===
        if crypto_type == 'bitcoin':
            # 1. Blockchain.info - Free Bitcoin API
            try:
                r = requests.get(f"{self.free_apis['blockchain_info']}/{address}", timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    results['balance'] = data.get('final_balance', 0) / 100000000  # Satoshi to BTC
                    results['total_received'] = data.get('total_received', 0) / 100000000
                    results['total_sent'] = data.get('total_sent', 0) / 100000000
                    results['transaction_count'] = data.get('n_tx', 0)
                    
                    # Recent transactions
                    for tx in data.get('txs', [])[:10]:
                        results['transactions'].append({
                            'hash': tx.get('hash'),
                            'time': tx.get('time'),
                            'value': sum([out.get('value', 0) for out in tx.get('out', [])]) / 100000000,
                            'confirmations': tx.get('block_height')
                        })
                    
                    results['sources'].append('blockchain_info')
            except: pass
            
            # 2. Blockchair - Multi-blockchain explorer
            try:
                r = requests.get(f"{self.free_apis['blockchair']}/bitcoin/dashboards/address/{address}", timeout=10)
                if r.status_code == 200:
                    data = r.json().get('data', {}).get(address, {})
                    if data:
                        addr_data = data.get('address', {})
                        results['balance'] = addr_data.get('balance', 0) / 100000000
                        results['transaction_count'] = addr_data.get('transaction_count', 0)
                        results['first_seen'] = addr_data.get('first_seen_receiving')
                        results['last_seen'] = addr_data.get('last_seen_receiving')
                        results['sources'].append('blockchair')
            except: pass
            
            # 3. BitcoinAbuse - Scam/abuse reports
            try:
                r = requests.get(f"{self.free_apis['bitcoinabuse']}", params={'address': address}, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    if data.get('count', 0) > 0:
                        results['abuse_reports'] = [{
                            'count': data.get('count'),
                            'recent': data.get('recent', [])[:5]
                        }]
                        results['sources'].append('bitcoinabuse')
            except: pass
        
        # === ETHEREUM ===
        elif crypto_type == 'ethereum':
            # 4. Etherscan - Ethereum blockchain explorer
            if self.paid_apis['etherscan_key']:
                try:
                    # Balance
                    r = requests.get(self.free_apis['etherscan'],
                                   params={'module': 'account', 'action': 'balance',
                                          'address': address, 'apikey': self.paid_apis['etherscan_key']},
                                   timeout=10)
                    if r.status_code == 200:
                        data = r.json()
                        if data.get('status') == '1':
                            results['balance'] = int(data.get('result', 0)) / 1e18  # Wei to ETH
                    
                    # Transaction count
                    r = requests.get(self.free_apis['etherscan'],
                                   params={'module': 'proxy', 'action': 'eth_getTransactionCount',
                                          'address': address, 'apikey': self.paid_apis['etherscan_key']},
                                   timeout=10)
                    if r.status_code == 200:
                        data = r.json()
                        results['transaction_count'] = int(data.get('result', '0x0'), 16)
                    
                    # Recent transactions
                    r = requests.get(self.free_apis['etherscan'],
                                   params={'module': 'account', 'action': 'txlist',
                                          'address': address, 'startblock': 0, 'endblock': 99999999,
                                          'sort': 'desc', 'apikey': self.paid_apis['etherscan_key']},
                                   timeout=10)
                    if r.status_code == 200:
                        data = r.json()
                        if data.get('status') == '1':
                            for tx in data.get('result', [])[:10]:
                                results['transactions'].append({
                                    'hash': tx.get('hash'),
                                    'from': tx.get('from'),
                                    'to': tx.get('to'),
                                    'value': int(tx.get('value', 0)) / 1e18,
                                    'timestamp': tx.get('timeStamp')
                                })
                                
                                # Collect related addresses
                                if tx.get('from') != address:
                                    results['related_addresses'].append(tx['from'])
                                if tx.get('to') != address:
                                    results['related_addresses'].append(tx['to'])
                    
                    results['sources'].append('etherscan')
                except: pass
            
            # 5. Blockchair Ethereum
            try:
                r = requests.get(f"{self.free_apis['blockchair']}/ethereum/dashboards/address/{address}", timeout=10)
                if r.status_code == 200:
                    data = r.json().get('data', {}).get(address, {})
                    if data:
                        addr_data = data.get('address', {})
                        results['balance'] = float(addr_data.get('balance', 0)) / 1e18
                        results['transaction_count'] = addr_data.get('transaction_count', 0)
                        results['sources'].append('blockchair_eth')
            except: pass
        
        # === WHALE ALERT ===
        if self.paid_apis['whale_alert_key']:
            try:
                # Check for large transactions (whale activity)
                for tx in results['transactions'][:5]:
                    if tx.get('value', 0) > 100:  # > 100 BTC/ETH
                        results['whale_activity'] = True
                        results['tags'].append('whale')
                        break
            except: pass
        
        # === ANALYSIS ===
        
        # Detect exchange deposits
        known_exchanges = ['binance', 'coinbase', 'kraken', 'bitfinex', 'huobi']
        for tag in results['tags']:
            if any(exchange in tag.lower() for exchange in known_exchanges):
                results['exchange_deposit'] = True
                break
        
        # Detect mixer usage (privacy coins)
        mixer_patterns = ['mixer', 'tumbler', 'wasabi', 'samourai']
        for tag in results['tags']:
            if any(pattern in tag.lower() for pattern in mixer_patterns):
                results['mixer_usage'] = True
                break
        
        # === ML ANALYSIS ===
        
        try:
            from modules.ml_engine.trainer import ModelTrainer
            trainer = ModelTrainer()
            
            threat_text = f"""
            cryptocurrency: {crypto_type}
            address: {address}
            balance: {results['balance']}
            transaction_count: {results['transaction_count']}
            abuse_reports: {len(results['abuse_reports'])}
            whale_activity: {results['whale_activity']}
            mixer_usage: {results['mixer_usage']}
            exchange_deposit: {results['exchange_deposit']}
            """
            
            ml_pred = trainer.predict_threat(threat_text)
            risk_map = {'LOW': 0.2, 'MEDIUM': 0.5, 'HIGH': 0.75, 'CRITICAL': 1.0}
            results['risk_score'] = risk_map.get(ml_pred.get('label', 'LOW'), 0.0)
            
            # Increase risk if abuse reports
            if results['abuse_reports']:
                results['risk_score'] = max(results['risk_score'], 0.75)
            
            results['ml_prediction'] = ml_pred
            results['sources'].append('sentinelnet_ml')
        except: pass
        
        # === GROQ CRYPTO FORENSICS ===
        
        try:
            from modules.ml_engine.groq_llm import get_groq
            import time
            groq = get_groq()
            
            if groq and groq.is_ready:
                tags_str = ', '.join(results['tags'][:10]) if results['tags'] else 'None'
                abuse_str = ', '.join([f"{a.get('reporter', 'Unknown')}: {a.get('description', 'N/A')[:50]}" for a in results['abuse_reports'][:3]])
                
                context = f"""
Cryptocurrency Intelligence Summary:
- Type: {crypto_type.upper()}
- Address: {address}
- Balance: {results['balance']} {crypto_type.upper()}
- Total Transactions: {results['transaction_count']}
- First Seen: {results.get('first_seen', 'Unknown')}
- Last Seen: {results.get('last_seen', 'Unknown')}
- Related Addresses: {len(results['related_addresses'])}
- Exchange Tags: {tags_str}
- Whale Activity: {results['whale_activity']}
- Mixer Usage: {results['mixer_usage']}
- Exchange Deposit: {results['exchange_deposit']}
- Abuse Reports: {len(results['abuse_reports'])}
- ML Risk Score: {results['risk_score']:.0%}

Abuse Reports:
{abuse_str if abuse_str else 'None'}
"""
                
                prompt = f"""Analyze this cryptocurrency address:

1. **Wallet Type Classification**: Is this personal, exchange, mixer, or other?
2. **Transaction Pattern Analysis**: What patterns emerge from transaction history?
3. **Money Laundering Risk Indicators**: Any red flags for illicit activity?
4. **Related Entity Identification**: Who likely controls this address?
5. **Investigation Recommendations**: Next steps for blockchain forensics

{context}

Provide detailed professional crypto forensics analysis."""
                
                groq_response = groq.ask(prompt, max_tokens=500)
                
                results['groq_analysis'] = {
                    'assessment': groq_response,
                    'timestamp': time.time(),
                    'model': groq.MODEL
                }
                results['sources'].append('groq_llm')
        except Exception as e:
            pass
        
        # Deduplicate related addresses
        results['related_addresses'] = list(set(results['related_addresses']))[:50]
        
        return results
    
    def _detect_crypto_type(self, address: str) -> str:
        """Detect cryptocurrency type from address format"""
        if address.startswith('1') or address.startswith('3') or address.startswith('bc1'):
            return 'bitcoin'
        elif address.startswith('0x') and len(address) == 42:
            return 'ethereum'
        elif address.startswith('L') or address.startswith('M'):
            return 'litecoin'
        elif address.startswith('4') or address.startswith('8'):
            return 'monero'
        elif address.startswith('D'):
            return 'dogecoin'
        elif address.startswith('X'):
            return 'dash'
        elif address.startswith('r'):
            return 'ripple'
        else:
            return 'unknown'
