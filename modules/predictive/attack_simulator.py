"""
Attack Simulator
RL-based attack simulation to identify weak points and optimize attack paths
"""

import random
import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Any, Tuple
from datetime import datetime
from collections import defaultdict
import numpy as np

class AttackSimulator:
    """Simulate attacks using reinforcement learning"""
    
    def __init__(self, db_path: str = "data/attack_simulations.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        
        # Attack techniques (MITRE ATT&CK inspired)
        self.techniques = {
            'reconnaissance': {
                'port_scan': {'success_rate': 0.95, 'detection_rate': 0.3, 'impact': 1},
                'subdomain_enum': {'success_rate': 0.90, 'detection_rate': 0.2, 'impact': 1},
                'whois_lookup': {'success_rate': 0.99, 'detection_rate': 0.1, 'impact': 1},
            },
            'initial_access': {
                'phishing': {'success_rate': 0.15, 'detection_rate': 0.4, 'impact': 8},
                'exploit_public': {'success_rate': 0.30, 'detection_rate': 0.6, 'impact': 9},
                'brute_force': {'success_rate': 0.10, 'detection_rate': 0.8, 'impact': 7},
            },
            'execution': {
                'command_injection': {'success_rate': 0.25, 'detection_rate': 0.7, 'impact': 9},
                'script_execution': {'success_rate': 0.40, 'detection_rate': 0.5, 'impact': 7},
            },
            'persistence': {
                'create_account': {'success_rate': 0.50, 'detection_rate': 0.6, 'impact': 8},
                'scheduled_task': {'success_rate': 0.60, 'detection_rate': 0.4, 'impact': 7},
            },
            'privilege_escalation': {
                'exploit_vuln': {'success_rate': 0.35, 'detection_rate': 0.7, 'impact': 9},
                'sudo_abuse': {'success_rate': 0.20, 'detection_rate': 0.5, 'impact': 8},
            },
            'defense_evasion': {
                'obfuscation': {'success_rate': 0.70, 'detection_rate': 0.3, 'impact': 5},
                'disable_security': {'success_rate': 0.30, 'detection_rate': 0.9, 'impact': 9},
            },
            'credential_access': {
                'credential_dump': {'success_rate': 0.40, 'detection_rate': 0.8, 'impact': 9},
                'keylogging': {'success_rate': 0.50, 'detection_rate': 0.6, 'impact': 8},
            },
            'lateral_movement': {
                'remote_services': {'success_rate': 0.45, 'detection_rate': 0.6, 'impact': 8},
                'pass_the_hash': {'success_rate': 0.35, 'detection_rate': 0.7, 'impact': 9},
            },
            'exfiltration': {
                'data_transfer': {'success_rate': 0.60, 'detection_rate': 0.5, 'impact': 9},
                'exfil_over_c2': {'success_rate': 0.55, 'detection_rate': 0.6, 'impact': 8},
            },
        }
        
        # Q-table for RL
        self.q_table = {}
        self.alpha = 0.1  # Learning rate
        self.gamma = 0.9  # Discount factor
        self.epsilon = 0.2  # Exploration rate
        
        # Load existing Q-table
        self._load_q_table()
    
    def _init_db(self):
        """Initialize simulations database"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS simulations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                attack_path TEXT NOT NULL,
                success INTEGER NOT NULL,
                detected INTEGER NOT NULL,
                total_impact INTEGER,
                duration_seconds REAL,
                techniques_used TEXT,
                weak_points TEXT,
                simulated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS q_table (
                state TEXT PRIMARY KEY,
                action TEXT NOT NULL,
                q_value REAL NOT NULL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def simulate_attack(self, target: str, defense_level: str = 'medium',
                       max_steps: int = 10) -> Dict[str, Any]:
        """Simulate a complete attack chain"""
        
        # Initialize state
        state = {
            'phase': 'reconnaissance',
            'access_level': 'none',
            'detected': False,
            'data_exfiltrated': False
        }
        
        attack_path = []
        total_impact = 0
        weak_points = []
        
        # Simulate attack chain
        for step in range(max_steps):
            if state['detected']:
                break
            
            # Choose action (technique)
            action = self._choose_action(state)
            
            if not action:
                break
            
            # Execute technique
            result = self._execute_technique(action, defense_level)
            
            attack_path.append({
                'step': step + 1,
                'phase': state['phase'],
                'technique': action,
                'success': result['success'],
                'detected': result['detected'],
                'impact': result['impact']
            })
            
            # Update state
            if result['success']:
                total_impact += result['impact']
                state = self._update_state(state, action)
                
                if result['impact'] >= 8:
                    weak_points.append({
                        'technique': action,
                        'phase': state['phase'],
                        'impact': result['impact']
                    })
            
            if result['detected']:
                state['detected'] = True
            
            # Update Q-table
            self._update_q_table(state, action, result)
        
        # Calculate success probability
        success_prob = self._calculate_success_probability(attack_path)
        
        # Determine overall success
        overall_success = (
            not state['detected'] and
            state['access_level'] in ('user', 'admin') and
            total_impact >= 20
        )
        
        simulation = {
            'target': target,
            'defense_level': defense_level,
            'attack_path': attack_path,
            'overall_success': overall_success,
            'success_probability': success_prob,
            'detected': state['detected'],
            'total_impact': total_impact,
            'total_steps': len(attack_path),
            'weak_points': weak_points,
            'final_state': state,
            'simulated_at': datetime.now().isoformat()
        }
        
        # Store simulation
        self._store_simulation(simulation)
        
        return simulation
    
    def _choose_action(self, state: Dict) -> str:
        """Choose next technique using epsilon-greedy"""
        phase = state['phase']
        
        if phase not in self.techniques:
            return None
        
        available_actions = list(self.techniques[phase].keys())
        
        # Epsilon-greedy
        if random.random() < self.epsilon:
            # Explore: random action
            return random.choice(available_actions)
        else:
            # Exploit: best Q-value
            state_key = self._state_to_key(state)
            best_action = None
            best_q = float('-inf')
            
            for action in available_actions:
                q_key = f"{state_key}_{action}"
                q_value = self.q_table.get(q_key, 0.0)
                
                if q_value > best_q:
                    best_q = q_value
                    best_action = action
            
            return best_action if best_action else random.choice(available_actions)
    
    def _execute_technique(self, technique: str, defense_level: str) -> Dict[str, Any]:
        """Execute a technique and return result"""
        
        # Find technique in all phases
        tech_info = None
        for phase, techniques in self.techniques.items():
            if technique in techniques:
                tech_info = techniques[technique]
                break
        
        if not tech_info:
            return {'success': False, 'detected': False, 'impact': 0}
        
        # Adjust rates based on defense level
        defense_multipliers = {
            'low': {'success': 1.2, 'detection': 0.7},
            'medium': {'success': 1.0, 'detection': 1.0},
            'high': {'success': 0.7, 'detection': 1.3},
            'critical': {'success': 0.5, 'detection': 1.5}
        }
        
        mult = defense_multipliers.get(defense_level, defense_multipliers['medium'])
        
        success_rate = min(tech_info['success_rate'] * mult['success'], 0.99)
        detection_rate = min(tech_info['detection_rate'] * mult['detection'], 0.99)
        
        # Simulate
        success = random.random() < success_rate
        detected = random.random() < detection_rate if success else False
        
        return {
            'success': success,
            'detected': detected,
            'impact': tech_info['impact'] if success else 0
        }
    
    def _update_state(self, state: Dict, action: str) -> Dict:
        """Update state based on successful action"""
        new_state = state.copy()
        
        # Phase progression
        phase_order = [
            'reconnaissance', 'initial_access', 'execution',
            'persistence', 'privilege_escalation', 'defense_evasion',
            'credential_access', 'lateral_movement', 'exfiltration'
        ]
        
        current_idx = phase_order.index(state['phase'])
        if current_idx < len(phase_order) - 1:
            new_state['phase'] = phase_order[current_idx + 1]
        
        # Access level progression
        if action in ['exploit_public', 'brute_force', 'phishing']:
            new_state['access_level'] = 'user'
        elif action in ['exploit_vuln', 'sudo_abuse']:
            new_state['access_level'] = 'admin'
        
        # Data exfiltration
        if action in ['data_transfer', 'exfil_over_c2']:
            new_state['data_exfiltrated'] = True
        
        return new_state
    
    def _update_q_table(self, state: Dict, action: str, result: Dict):
        """Update Q-table using Q-learning"""
        state_key = self._state_to_key(state)
        q_key = f"{state_key}_{action}"
        
        # Calculate reward
        reward = 0
        if result['success']:
            reward += result['impact']
        if result['detected']:
            reward -= 10
        
        # Current Q-value
        current_q = self.q_table.get(q_key, 0.0)
        
        # Max future Q-value (simplified)
        max_future_q = max(self.q_table.values()) if self.q_table else 0.0
        
        # Q-learning update
        new_q = current_q + self.alpha * (reward + self.gamma * max_future_q - current_q)
        
        self.q_table[q_key] = new_q
    
    def _state_to_key(self, state: Dict) -> str:
        """Convert state to string key"""
        return f"{state['phase']}_{state['access_level']}_{state['detected']}"
    
    def _calculate_success_probability(self, attack_path: List[Dict]) -> float:
        """Calculate overall success probability"""
        if not attack_path:
            return 0.0
        
        successful_steps = sum(1 for step in attack_path if step['success'])
        total_steps = len(attack_path)
        
        return successful_steps / total_steps
    
    def _store_simulation(self, simulation: Dict):
        """Store simulation in database"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''
            INSERT INTO simulations 
            (target, attack_path, success, detected, total_impact, 
             duration_seconds, techniques_used, weak_points)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            simulation['target'],
            json.dumps(simulation['attack_path']),
            1 if simulation['overall_success'] else 0,
            1 if simulation['detected'] else 0,
            simulation['total_impact'],
            simulation['total_steps'] * 2.5,  # Estimated duration
            json.dumps([s['technique'] for s in simulation['attack_path']]),
            json.dumps(simulation['weak_points'])
        ))
        
        conn.commit()
        conn.close()
    
    def _load_q_table(self):
        """Load Q-table from database"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('SELECT state, action, q_value FROM q_table')
        
        for row in c.fetchall():
            q_key = f"{row[0]}_{row[1]}"
            self.q_table[q_key] = row[2]
        
        conn.close()
    
    def save_q_table(self):
        """Save Q-table to database"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        for q_key, q_value in self.q_table.items():
            parts = q_key.rsplit('_', 1)
            if len(parts) == 2:
                state, action = parts
                
                c.execute('''
                    INSERT OR REPLACE INTO q_table (state, action, q_value)
                    VALUES (?, ?, ?)
                ''', (state, action, q_value))
        
        conn.commit()
        conn.close()
    
    def optimize_attack_path(self, target: str, defense_level: str = 'medium',
                            simulations: int = 100) -> Dict[str, Any]:
        """Run multiple simulations to find optimal attack path"""
        
        print(f"[*] Running {simulations} attack simulations...")
        
        results = []
        for i in range(simulations):
            result = self.simulate_attack(target, defense_level, max_steps=10)
            results.append(result)
            
            if (i + 1) % 20 == 0:
                print(f"  Progress: {i + 1}/{simulations}")
        
        # Save learned Q-table
        self.save_q_table()
        
        # Analyze results
        successful = [r for r in results if r['overall_success']]
        detected = [r for r in results if r['detected']]
        
        # Find best path
        best_path = max(results, key=lambda x: x['total_impact'])
        
        # Identify common weak points
        all_weak_points = []
        for r in results:
            all_weak_points.extend(r['weak_points'])
        
        weak_point_counts = defaultdict(int)
        for wp in all_weak_points:
            weak_point_counts[wp['technique']] += 1
        
        top_weak_points = sorted(
            weak_point_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        return {
            'target': target,
            'defense_level': defense_level,
            'total_simulations': simulations,
            'success_rate': len(successful) / simulations,
            'detection_rate': len(detected) / simulations,
            'avg_impact': sum(r['total_impact'] for r in results) / simulations,
            'best_attack_path': best_path['attack_path'],
            'best_impact': best_path['total_impact'],
            'top_weak_points': [
                {'technique': tech, 'exploited_count': count}
                for tech, count in top_weak_points
            ],
            'recommendations': self._generate_recommendations(results, top_weak_points)
        }
    
    def _generate_recommendations(self, results: List[Dict], 
                                 weak_points: List[Tuple]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Check success rate
        success_rate = sum(1 for r in results if r['overall_success']) / len(results)
        if success_rate > 0.3:
            recommendations.append(
                f"High attack success rate ({success_rate:.0%}). Strengthen overall defenses."
            )
        
        # Check detection rate
        detection_rate = sum(1 for r in results if r['detected']) / len(results)
        if detection_rate < 0.5:
            recommendations.append(
                f"Low detection rate ({detection_rate:.0%}). Improve monitoring and alerting."
            )
        
        # Check weak points
        if weak_points:
            top_weak = weak_points[0]
            recommendations.append(
                f"Most exploited technique: {top_weak[0]} ({top_weak[1]} times). "
                f"Prioritize patching this vulnerability."
            )
        
        # Check phases
        phase_counts = defaultdict(int)
        for r in results:
            for step in r['attack_path']:
                if step['success']:
                    phase_counts[step['phase']] += 1
        
        if phase_counts:
            weakest_phase = max(phase_counts.items(), key=lambda x: x[1])
            recommendations.append(
                f"Weakest phase: {weakest_phase[0]}. Focus hardening efforts here."
            )
        
        return recommendations


if __name__ == "__main__":
    import sys
    
    simulator = AttackSimulator()
    
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    defense = sys.argv[2] if len(sys.argv) > 2 else "medium"
    
    print(f"[*] Attack Simulation: {target}")
    print(f"[*] Defense Level: {defense}\n")
    
    # Single simulation
    print("[*] Running single simulation...")
    result = simulator.simulate_attack(target, defense)
    
    print(f"\n✓ Simulation Complete")
    print(f"  Success: {'Yes' if result['overall_success'] else 'No'}")
    print(f"  Detected: {'Yes' if result['detected'] else 'No'}")
    print(f"  Total Impact: {result['total_impact']}")
    print(f"  Steps: {result['total_steps']}")
    
    if result['weak_points']:
        print(f"\n  Weak Points:")
        for wp in result['weak_points']:
            print(f"    • {wp['technique']} (impact: {wp['impact']})")
    
    # Optimization
    print(f"\n[*] Optimizing attack path (100 simulations)...")
    optimization = simulator.optimize_attack_path(target, defense, simulations=100)
    
    print(f"\n✓ Optimization Complete")
    print(f"  Success Rate: {optimization['success_rate']:.0%}")
    print(f"  Detection Rate: {optimization['detection_rate']:.0%}")
    print(f"  Avg Impact: {optimization['avg_impact']:.1f}")
    
    print(f"\n  Top Weak Points:")
    for wp in optimization['top_weak_points']:
        print(f"    • {wp['technique']}: exploited {wp['exploited_count']} times")
    
    print(f"\n  Recommendations:")
    for rec in optimization['recommendations']:
        print(f"    • {rec}")
