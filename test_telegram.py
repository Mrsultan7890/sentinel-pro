#!/usr/bin/env python3
# ============================================================================
# Sentinel Pro v3.0 — Professional OSINT & Bug Bounty Platform
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
#
# Unauthorized copying, distribution, or modification of this software,
# via any medium, is strictly prohibited without written permission.
#
# Licensed users may use this software under the terms of their license.
# For licensing: https://github.com/Mrsultan7890/osints
# ============================================================================

"""
Telegram Notification Debug & Test Script
Check karo ki Telegram notifications properly work kar rahi hain ya nahi
"""

import sys
import os
import json
import requests
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

import config
from modules.notifications import TelegramNotifier

def test_telegram_api():
    """Direct Telegram API test karo."""
    print("🔍 Testing Telegram API directly...")
    
    token = config.TELEGRAM_BOT_TOKEN
    chat_id = config.TELEGRAM_CHAT_ID
    
    if not token or not chat_id:
        print("❌ TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not configured in .env")
        return False
    
    print(f"📱 Bot Token: {token[:10]}...{token[-10:]}")
    print(f"💬 Chat ID: {chat_id}")
    
    # Test 1: Get bot info
    try:
        response = requests.get(f"https://api.telegram.org/bot{token}/getMe", timeout=10)
        if response.status_code == 200:
            bot_info = response.json()
            if bot_info.get('ok'):
                bot_name = bot_info['result']['username']
                print(f"✅ Bot connected: @{bot_name}")
            else:
                print(f"❌ Bot API error: {bot_info}")
                return False
        else:
            print(f"❌ Bot API HTTP error: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Bot API connection error: {e}")
        return False
    
    # Test 2: Send test message
    try:
        test_message = f"""🧪 TELEGRAM TEST MESSAGE

🤖 Bot: @{bot_name}
💬 Chat ID: {chat_id}
🕐 Time: {os.popen('date').read().strip()}
🔧 Test: Direct API call

✅ Telegram notifications are working!

Sentinel Pro — @who_is_the_black_hat"""
        
        response = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": test_message},
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('ok'):
                print("✅ Test message sent successfully!")
                return True
            else:
                print(f"❌ Message send error: {result}")
                return False
        else:
            print(f"❌ Message send HTTP error: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Message send error: {e}")
        return False

def test_notifier_class():
    """TelegramNotifier class test karo."""
    print("\n🔍 Testing TelegramNotifier class...")
    
    notifier = TelegramNotifier(config.TELEGRAM_BOT_TOKEN, config.TELEGRAM_CHAT_ID)
    
    if not notifier.enabled:
        print("❌ TelegramNotifier not enabled (missing token/chat_id)")
        return False
    
    print(f"✅ TelegramNotifier enabled")
    
    # Test basic send
    success = notifier.test()
    if success:
        print("✅ TelegramNotifier.test() successful")
    else:
        print("❌ TelegramNotifier.test() failed")
        return False
    
    # Test custom message
    custom_success = notifier.send("""🔔 CUSTOM TEST MESSAGE

This is a test from TelegramNotifier class.
If you see this, the notification system is working!

Sentinel Pro — @who_is_the_black_hat""")
    
    if custom_success:
        print("✅ Custom message sent successfully")
    else:
        print("❌ Custom message send failed")
        return False
    
    return True

def test_monitoring_alerts():
    """Monitoring alerts test karo."""
    print("\n🔍 Testing monitoring alert formats...")
    
    notifier = TelegramNotifier(config.TELEGRAM_BOT_TOKEN, config.TELEGRAM_CHAT_ID)
    
    # Test bug bounty alert
    fake_bugbounty_data = {
        'cves': {
            'cves': [
                {'severity': 'CRITICAL', 'cve_id': 'CVE-2024-TEST', 'tech': 'Apache'}
            ]
        },
        'takeover': {
            'vulnerable': [
                {'subdomain': 'test.example.com', 'service': 'GitHub Pages'}
            ]
        },
        'nuclei': {
            'findings': [
                {'severity': 'HIGH', 'name': 'SQL Injection Test'}
            ]
        }
    }
    
    print("📤 Sending bug bounty alert test...")
    bb_success = notifier.alert_bugbounty("test.example.com", fake_bugbounty_data)
    if bb_success:
        print("✅ Bug bounty alert sent")
    else:
        print("❌ Bug bounty alert failed")
    
    # Test breach alert
    fake_breach_data = {
        'risk_level': 'CRITICAL',
        'total_breaches': 5,
        'total_stealer_logs': 2
    }
    
    print("📤 Sending breach alert test...")
    breach_success = notifier.alert_breach("test@example.com", fake_breach_data)
    if breach_success:
        print("✅ Breach alert sent")
    else:
        print("❌ Breach alert failed")
    
    return bb_success and breach_success

def test_monitor_integration():
    """Monitor integration test karo."""
    print("\n🔍 Testing monitor integration...")
    
    try:
        from sentinel_brain.monitor import SentinelMonitor
        from sentinel_brain.brain import SentinelBrain
        
        # Create mock brain and monitor
        brain = SentinelBrain(console=print)
        monitor = SentinelMonitor(brain, interval=60)
        
        # Test alert method directly
        fake_findings = [
            {
                'severity': 'CRITICAL',
                'title': 'SQL Injection Found',
                'detail': 'Parameter "id" is vulnerable to SQL injection'
            },
            {
                'severity': 'HIGH', 
                'title': 'XSS Vulnerability',
                'detail': 'Reflected XSS in search parameter'
            }
        ]
        
        print("📤 Sending monitor alert test...")
        monitor._alert("test.example.com", fake_findings)
        print("✅ Monitor alert sent (check Telegram)")
        
        return True
        
    except Exception as e:
        print(f"❌ Monitor integration test failed: {e}")
        return False

def debug_network():
    """Network connectivity debug karo."""
    print("\n🔍 Debugging network connectivity...")
    
    # Test internet connectivity
    try:
        response = requests.get("https://httpbin.org/ip", timeout=5)
        if response.status_code == 200:
            ip_info = response.json()
            print(f"✅ Internet connected - IP: {ip_info.get('origin', 'unknown')}")
        else:
            print("❌ Internet connectivity issue")
            return False
    except Exception as e:
        print(f"❌ Internet connectivity error: {e}")
        return False
    
    # Test Telegram API reachability
    try:
        response = requests.get("https://api.telegram.org", timeout=5)
        if response.status_code in [200, 404]:  # 404 is normal for root endpoint
            print("✅ Telegram API reachable")
        else:
            print(f"❌ Telegram API unreachable: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Telegram API connectivity error: {e}")
        return False
    
    # Test Tor status
    if config.is_tor_active():
        print("🧅 Tor is ACTIVE - testing through proxy...")
        try:
            proxies = config.get_proxies()
            response = requests.get("https://httpbin.org/ip", proxies=proxies, timeout=10)
            if response.status_code == 200:
                tor_ip = response.json().get('origin', 'unknown')
                print(f"✅ Tor working - Exit IP: {tor_ip}")
            else:
                print("❌ Tor proxy not working")
                return False
        except Exception as e:
            print(f"❌ Tor proxy error: {e}")
            return False
    else:
        print("🔓 Tor is INACTIVE - using direct connection")
    
    return True

def main():
    print("🚀 TELEGRAM NOTIFICATION DEBUG & TEST")
    print("=" * 50)
    
    # Step 1: Network debug
    if not debug_network():
        print("\n❌ Network issues detected. Fix network connectivity first.")
        return
    
    # Step 2: Direct API test
    if not test_telegram_api():
        print("\n❌ Direct Telegram API test failed. Check bot token and chat ID.")
        return
    
    # Step 3: Notifier class test
    if not test_notifier_class():
        print("\n❌ TelegramNotifier class test failed.")
        return
    
    # Step 4: Alert format tests
    if not test_monitoring_alerts():
        print("\n❌ Monitoring alert tests failed.")
        return
    
    # Step 5: Monitor integration test
    if not test_monitor_integration():
        print("\n❌ Monitor integration test failed.")
        return
    
    print("\n" + "=" * 50)
    print("✅ ALL TESTS PASSED!")
    print("🎉 Telegram notifications are working correctly!")
    print("\n💡 If you're still not receiving monitoring alerts:")
    print("   1. Make sure monitoring is running: monitor status")
    print("   2. Check if targets have new findings: monitor add <target>")
    print("   3. Verify scan intervals: monitor interval 300")
    print("   4. Check logs: tail -f logs/sentinel.log")

if __name__ == "__main__":
    main()