"""
Safe Data Extraction Utilities
================================
Prevents hardcoded key assumptions and handles missing/malformed data gracefully.

Author: @who_is_the_black_hat
"""


def safe_get_count(data, *keys, default=0):
    """
    Safely extract count from nested dict.
    
    Examples:
        safe_get_count(result, 'github_dorks', 'total_secrets')
        safe_get_count(result, 'nmap', 'total')
    
    Returns default if key missing or value is not numeric.
    """
    if not isinstance(data, dict):
        return default
    
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    
    # Ensure it's a number
    try:
        return int(current) if current is not None else default
    except (ValueError, TypeError):
        return default


def safe_get_nested(data, *keys, default=None):
    """
    Safely extract value from nested dict.
    
    Examples:
        safe_get_nested(result, 'findings', 0, 'severity')
        safe_get_nested(result, 'config', 'timeout')
    """
    if not isinstance(data, dict):
        return default
    
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        elif isinstance(current, list) and isinstance(key, int):
            try:
                current = current[key]
            except (IndexError, TypeError):
                return default
        else:
            return default
        
        if current is None:
            return default
    
    return current


def has_findings(data, *keys):
    """
    Check if data has actual findings (count > 0).
    
    Examples:
        has_findings(result, 'github_dorks', 'total_secrets')
        has_findings(result, 'vulns', 'total')
    """
    count = safe_get_count(data, *keys)
    return count > 0


def get_risk_level(data, key='risk_level', default='LOW'):
    """
    Safely extract risk level from various possible keys.
    Handles: risk_level, risk, _risk, severity
    """
    if not isinstance(data, dict):
        return default
    
    # Try common risk key names
    for risk_key in [key, 'risk', '_risk', 'severity', 'risk_score']:
        value = data.get(risk_key)
        if value and isinstance(value, str) and value.upper() in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'):
            return value.upper()
    
    return default


def summarize_scan_result(result, scan_type='scan'):
    """
    Generate human-readable summary from scan result.
    Handles various result formats gracefully.
    
    Returns: (summary_string, risk_level)
    """
    if not isinstance(result, dict):
        return f"{scan_type} completed", "LOW"
    
    parts = []
    risk = get_risk_level(result, default='LOW')
    
    # Common patterns
    if has_findings(result, 'github_dorks', 'total_secrets'):
        count = safe_get_count(result, 'github_dorks', 'total_secrets')
        parts.append(f"{count} GitHub secrets")
    
    if has_findings(result, 'cloud_assets', 'total'):
        count = safe_get_count(result, 'cloud_assets', 'total')
        parts.append(f"{count} cloud assets")
    
    if has_findings(result, 'nmap', 'total'):
        count = safe_get_count(result, 'nmap', 'total')
        parts.append(f"{count} open ports")
    
    if has_findings(result, 'subdomains', 'total_found'):
        count = safe_get_count(result, 'subdomains', 'total_found')
        parts.append(f"{count} subdomains")
    
    if has_findings(result, 'vulns', 'total'):
        count = safe_get_count(result, 'vulns', 'total')
        parts.append(f"{count} vulnerabilities")
    
    # Findings array
    if has_findings(result, 'total'):
        count = safe_get_count(result, 'total')
        parts.append(f"{count} findings")
    
    if parts:
        return f"{scan_type}: " + ", ".join(parts), risk
    
    # Fallback
    total = safe_get_count(result, 'total')
    return f"{scan_type} completed: {total} items found", risk


# Backward compatibility aliases
def get_github_secrets_count(data):
    """Get GitHub secrets count safely."""
    return safe_get_count(data, 'github_dorks', 'total_secrets')


def get_cloud_assets_count(data):
    """Get cloud assets count safely."""
    return safe_get_count(data, 'cloud_assets', 'total')


def get_subdomain_count(data):
    """Get subdomain count safely."""
    return safe_get_count(data, 'subdomains', 'total_found')


def get_port_count(data):
    """Get open ports count safely."""
    return safe_get_count(data, 'nmap', 'total')
