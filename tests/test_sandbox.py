#!/usr/bin/env python3
"""
Test Autonomous Sandbox Engine
"""
import sys
sys.path.insert(0, '/home/kali/osints')

from sentinel_brain.engines import SandboxManager, RiskAssessor, RiskLevel

def test_risk_assessment():
    print("\n=== Test 1: Risk Assessment ===")
    assessor = RiskAssessor()
    
    tests = [
        ("ls -la", RiskLevel.LOW),
        ("nmap -sV target.com", RiskLevel.HIGH),
        ("sqlmap -u http://target.com", RiskLevel.CRITICAL),
        ("rm -rf /", RiskLevel.CRITICAL),
        ("curl http://example.com", RiskLevel.MEDIUM),
    ]
    
    for cmd, expected in tests:
        risk = assessor.assess_command(cmd)
        status = "✅" if risk == expected else "❌"
        print(f"{status} {cmd[:40]:40} -> {risk.name:10} (expected {expected.name})")

def test_sandbox_execution():
    print("\n=== Test 2: Sandbox Execution ===")
    manager = SandboxManager()
    
    # Test LOW risk
    print("\n[LOW] echo test")
    success, out, err = manager.execute("echo 'Hello from sandbox'", RiskLevel.LOW)
    print(f"  Success: {success}, Output: {out.strip()}")
    
    # Test MEDIUM risk
    print("\n[MEDIUM] ls command")
    success, out, err = manager.execute("ls /tmp", RiskLevel.MEDIUM)
    print(f"  Success: {success}, Output lines: {len(out.splitlines())}")
    
    # Test HIGH risk (container)
    print("\n[HIGH] Container isolation")
    success, out, err = manager.execute("whoami", RiskLevel.HIGH)
    print(f"  Success: {success}, Output: {out.strip()}")
    if not success:
        print(f"  Note: {err.strip()[:100]}")
    
    # Test timeout
    print("\n[TIMEOUT] Sleep 10s with 2s timeout")
    success, out, err = manager.execute("sleep 10", RiskLevel.LOW, timeout=2)
    print(f"  Success: {success}, Error: {err.strip()}")

def test_dangerous_commands():
    print("\n=== Test 3: Dangerous Command Blocking ===")
    manager = SandboxManager()
    
    dangerous = [
        "rm -rf /",
        "dd if=/dev/zero of=/dev/sda",
        ":(){ :|:& };:",
    ]
    
    for cmd in dangerous:
        risk = manager.risk_assessor.assess_command(cmd)
        print(f"  {cmd[:40]:40} -> {risk.name} (CRITICAL expected)")

def test_status():
    print("\n=== Test 4: Sandbox Status ===")
    manager = SandboxManager()
    status = manager.get_status()
    print(f"  Active sandboxes: {status['active_sandboxes']}")
    print(f"  Sandbox dir: {status['sandbox_dir']}")
    print(f"  Container runtime: {status['container_runtime'] or 'None'}")

if __name__ == '__main__':
    print("🔒 Autonomous Sandbox Engine - Test Suite")
    print("=" * 60)
    
    test_risk_assessment()
    test_sandbox_execution()
    test_dangerous_commands()
    test_status()
    
    print("\n✅ Tests complete!")
