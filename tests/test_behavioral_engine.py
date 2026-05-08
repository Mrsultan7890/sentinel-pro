#!/usr/bin/env python3
"""
Test BehavioralEngine - AI Attack Detection
"""
import sys
sys.path.insert(0, '/home/kali/osints')

from sentinel_brain.engines import BehavioralEngine
from datetime import datetime
import time

def test_normal_traffic():
    print("\n=== Test 1: Normal Human Traffic ===")
    engine = BehavioralEngine()
    
    # Simulate normal human browsing
    for i in range(5):
        request = {
            'method': 'GET',
            'url': f'https://example.com/page{i}',
            'status_code': 200,
            'response_time': 0.5 + (i * 0.1),
            'request_size': 500,
            'response_size': 2000,
            'headers': {'User-Agent': 'Mozilla/5.0'},
            'user_agent': 'Mozilla/5.0',
            'ip_address': '192.168.1.100',
            'session_id': 'human_session_1',
        }
        is_ai, conf, reason = engine.analyze_request(request)
        print(f"Request {i+1}: AI={is_ai}, Confidence={conf:.2f}, Reason={reason}")
        time.sleep(0.5)
    
    engine.close()

def test_ai_attack():
    print("\n=== Test 2: AI-Powered Attack ===")
    engine = BehavioralEngine()
    
    urls = [
        'https://target.com/admin',
        'https://target.com/login?user=admin',
        'https://target.com/api/users',
        'https://target.com/config.php',
        'https://target.com/backup.sql',
        'https://target.com/.env',
        'https://target.com/api/v1/auth',
        'https://target.com/graphql',
        'https://target.com/admin/dashboard',
        'https://target.com/api/internal',
    ]
    
    for i, url in enumerate(urls):
        request = {
            'method': 'GET',
            'url': url,
            'status_code': 403 if i < 3 else 200,
            'response_time': 0.15,
            'request_size': 300,
            'response_size': 1500,
            'headers': {'User-Agent': 'python-requests/2.28.0'},
            'user_agent': 'python-requests/2.28.0',
            'ip_address': '10.0.0.50',
            'session_id': 'ai_session_1',
        }
        is_ai, conf, reason = engine.analyze_request(request)
        print(f"Request {i+1}: AI={is_ai}, Confidence={conf:.2f}")
        if is_ai:
            print(f"  🚨 DETECTED: {reason}")
        time.sleep(0.1)
    
    stats = engine.get_session_stats('ai_session_1')
    print(f"\n📊 Session Stats:")
    print(f"  Total Requests: {stats['total_requests']}")
    print(f"  Diversity: {stats['diversity']:.2f}")
    print(f"  Timing Consistency: {stats['timing_consistency']:.2f}")
    print(f"  Adaptation: {stats['adaptation']:.2f}")
    
    engine.close()

def test_detections():
    print("\n=== Test 3: View Detections ===")
    engine = BehavioralEngine()
    
    detections = engine.get_recent_detections(limit=10)
    print(f"Found {len(detections)} AI attack detections:")
    for det in detections[:5]:
        print(f"  - {det[1]} | {det[2]} | Confidence: {det[4]:.2f}")
        print(f"    Reason: {det[5]}")
    
    engine.close()

if __name__ == '__main__':
    print("🧠 Behavioral Intelligence Engine - Test Suite")
    print("=" * 60)
    
    test_normal_traffic()
    test_ai_attack()
    test_detections()
    
    print("\n✅ Tests complete! Check data/behavioral_data.db for logs")
