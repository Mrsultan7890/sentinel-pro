#!/usr/bin/env python3
"""
Monitoring Notification Test
Simulate monitoring findings aur Telegram notifications test karo
"""

import sys
import time
from pathlib import Path
from datetime import datetime

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

import config
from sentinel_brain.monitor import SentinelMonitor
from sentinel_brain.brain import SentinelBrain
from sentinel_brain.memory import Memory

def test_monitoring_notifications():
    """Monitoring notifications ka complete test karo."""
    print("🔔 MONITORING NOTIFICATION TEST")
    print("=" * 40)
    
    # Step 1: Create brain and monitor
    print("🧠 Creating SentinelBrain...")
    brain = SentinelBrain(console=print)
    
    print("📡 Creating SentinelMonitor...")
    monitor = SentinelMonitor(brain, interval=60)
    
    # Step 2: Add test target
    test_target = "test.example.com"
    print(f"🎯 Adding test target: {test_target}")
    monitor.add_target(test_target, "full")
    
    # Step 3: Simulate some findings in memory
    print("💾 Adding fake findings to memory...")
    memory = Memory()
    
    # Add some fake findings
    fake_findings = [
        {
            'severity': 'CRITICAL',
            'title': 'SQL Injection Vulnerability',
            'detail': 'Parameter "id" in /login.php is vulnerable to SQL injection',
            'fix': 'Use parameterized queries'
        },
        {
            'severity': 'HIGH',
            'title': 'Cross-Site Scripting (XSS)',
            'detail': 'Reflected XSS in search parameter',
            'fix': 'Sanitize user input'
        },
        {
            'severity': 'MEDIUM',
            'title': 'Missing Security Headers',
            'detail': 'X-Frame-Options header not set',
            'fix': 'Add security headers'
        }
    ]
    
    for finding in fake_findings:
        memory.remember_finding(
            target=test_target,
            agent="test_agent",
            severity=finding['severity'],
            title=finding['title'],
            detail=finding['detail'],
            fix=finding['fix']
        )
        print(f"  ✅ Added {finding['severity']} finding: {finding['title']}")
    
    # Step 4: Test alert method directly
    print("\n📤 Testing monitor alert method...")
    monitor._alert(test_target, fake_findings)
    print("✅ Alert sent! Check your Telegram.")
    
    # Step 5: Test the "new findings" detection logic
    print("\n🔍 Testing new findings detection...")
    
    # Clear seen findings to simulate fresh scan
    monitor._seen[test_target] = set()
    
    # Simulate what happens during a real scan
    findings = memory.recall_findings(test_target)
    new_findings = []
    
    for f in findings:
        key = f"{f['severity']}:{f['title']}"
        if key not in monitor._seen.get(test_target, set()):
            new_findings.append(f)
            monitor._seen.setdefault(test_target, set()).add(key)
    
    print(f"📊 Found {len(new_findings)} new findings")
    
    if new_findings:
        print("📤 Sending new findings alert...")
        monitor._alert(test_target, new_findings)
        print("✅ New findings alert sent!")
    else:
        print("ℹ️  No new findings to alert")
    
    # Step 6: Test duplicate detection
    print("\n🔄 Testing duplicate detection...")
    
    # Try to alert same findings again
    duplicate_findings = memory.recall_findings(test_target)
    new_after_seen = []
    
    for f in duplicate_findings:
        key = f"{f['severity']}:{f['title']}"
        if key not in monitor._seen.get(test_target, set()):
            new_after_seen.append(f)
    
    if new_after_seen:
        print(f"❌ Duplicate detection failed - {len(new_after_seen)} duplicates found")
    else:
        print("✅ Duplicate detection working - no duplicate alerts")
    
    # Step 7: Add one more finding to test incremental alerts
    print("\n➕ Adding one more finding...")
    
    new_finding = {
        'severity': 'CRITICAL',
        'title': 'Remote Code Execution',
        'detail': 'RCE vulnerability in file upload',
        'fix': 'Validate file uploads'
    }
    
    memory.remember_finding(
        target=test_target,
        agent="test_agent_2",
        severity=new_finding['severity'],
        title=new_finding['title'],
        detail=new_finding['detail'],
        fix=new_finding['fix']
    )
    
    # Check for new findings again
    all_findings = memory.recall_findings(test_target)
    incremental_new = []
    
    for f in all_findings:
        key = f"{f['severity']}:{f['title']}"
        if key not in monitor._seen.get(test_target, set()):
            incremental_new.append(f)
            monitor._seen.setdefault(test_target, set()).add(key)
    
    if incremental_new:
        print(f"📤 Sending incremental alert for {len(incremental_new)} new finding(s)...")
        monitor._alert(test_target, incremental_new)
        print("✅ Incremental alert sent!")
    
    print("\n" + "=" * 40)
    print("🎉 MONITORING NOTIFICATION TEST COMPLETE!")
    print("\n💡 What was tested:")
    print("   ✅ Monitor creation and target addition")
    print("   ✅ Fake findings injection")
    print("   ✅ Direct alert method")
    print("   ✅ New findings detection logic")
    print("   ✅ Duplicate prevention")
    print("   ✅ Incremental alerts")
    print("\n📱 Check your Telegram for multiple test messages!")

def test_real_monitoring_flow():
    """Real monitoring flow test karo."""
    print("\n🔄 REAL MONITORING FLOW TEST")
    print("=" * 40)
    
    # Create monitor
    brain = SentinelBrain(console=print)
    monitor = SentinelMonitor(brain, interval=10)  # 10 second interval for testing
    
    # Add target
    test_target = "httpbin.org"  # Safe test target
    monitor.add_target(test_target, "recon")
    
    print(f"🎯 Added target: {test_target}")
    print("⏰ Starting monitor with 10-second interval...")
    print("🛑 This will run for 30 seconds then stop")
    
    # Start monitoring
    monitor.start()
    
    # Let it run for 30 seconds
    time.sleep(30)
    
    # Stop monitoring
    monitor.stop()
    
    print("✅ Real monitoring flow test complete!")
    print("📱 Check Telegram for any alerts from real scan")

if __name__ == "__main__":
    # Test 1: Simulated notifications
    test_monitoring_notifications()
    
    # Test 2: Real monitoring flow (optional)
    print("\n" + "=" * 50)
    response = input("🤔 Do you want to test real monitoring flow? (y/N): ")
    if response.lower() in ['y', 'yes']:
        test_real_monitoring_flow()
    else:
        print("⏭️  Skipping real monitoring flow test")
    
    print("\n🏁 All tests complete!")