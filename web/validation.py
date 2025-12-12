"""
Input validation utilities for web interface
Provides validation for domains, IPs, CIDR notation, and other user inputs
"""

import re
import ipaddress
from typing import List, Tuple

def validate_domain(domain: str) -> Tuple[bool, str]:
    """
    Validate domain name format
    
    Args:
        domain: Domain name to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not domain or not isinstance(domain, str):
        return False, "Domain cannot be empty"
    
    # Remove whitespace
    domain = domain.strip()
    
    # Check length
    if len(domain) > 253:
        return False, "Domain name too long (max 253 characters)"
    
    # Domain regex pattern
    # Allows alphanumeric, hyphens, dots, and underscores (for AD)
    pattern = r'^(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)*[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?$'
    
    if not re.match(pattern, domain):
        return False, "Invalid domain name format"
    
    return True, ""

def validate_ip(ip: str) -> Tuple[bool, str]:
    """
    Validate IPv4 or IPv6 address
    
    Args:
        ip: IP address to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not ip or not isinstance(ip, str):
        return False, "IP address cannot be empty"
    
    ip = ip.strip()
    
    try:
        ipaddress.ip_address(ip)
        return True, ""
    except ValueError:
        return False, "Invalid IP address format"

def validate_cidr(cidr: str) -> Tuple[bool, str]:
    """
    Validate CIDR notation (e.g., 192.168.1.0/24)
    
    Args:
        cidr: CIDR notation to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not cidr or not isinstance(cidr, str):
        return False, "CIDR notation cannot be empty"
    
    cidr = cidr.strip()
    
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True, ""
    except ValueError as e:
        return False, f"Invalid CIDR notation: {str(e)}"

def validate_targets(targets: List[str]) -> Tuple[bool, str]:
    """
    Validate list of targets (domains, IPs, or CIDR)
    
    Args:
        targets: List of target strings
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not targets:
        return False, "At least one target is required"
    
    if not isinstance(targets, list):
        return False, "Targets must be a list"
    
    if len(targets) > 100:
        return False, "Too many targets (max 100)"
    
    for i, target in enumerate(targets):
        if not isinstance(target, str):
            return False, f"Target {i+1} must be a string"
        
        target = target.strip()
        
        # Try validating as domain, IP, or CIDR
        is_domain, _ = validate_domain(target)
        is_ip, _ = validate_ip(target)
        is_cidr, _ = validate_cidr(target)
        
        if not (is_domain or is_ip or is_cidr):
            return False, f"Target '{target}' is not a valid domain, IP, or CIDR"
    
    return True, ""

def validate_campaign_name(name: str) -> Tuple[bool, str]:
    """
    Validate campaign name
    
    Args:
        name: Campaign name to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not name or not isinstance(name, str):
        return False, "Campaign name cannot be empty"
    
    name = name.strip()
    
    if len(name) < 3:
        return False, "Campaign name must be at least 3 characters"
    
    if len(name) > 100:
        return False, "Campaign name too long (max 100 characters)"
    
    # Allow alphanumeric, spaces, hyphens, underscores
    if not re.match(r'^[a-zA-Z0-9_ -]+$', name):return False, "Campaign name contains invalid characters (only alphanumeric, spaces, hyphens, underscores allowed)"
    
    return True, ""

def validate_username(username: str) -> Tuple[bool, str]:
    """
    Validate username format
    
    Args:
        username: Username to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not username or not isinstance(username, str):
        # Username is optional
        return True, ""
    
    username = username.strip()
    
    if len(username) > 256:
        return False, "Username too long (max 256 characters)"
    
    # Basic username validation (alphanumeric, @, ., -, _)
    if not re.match(r'^[a-zA-Z0-9@._-]+$', username):
        return False, "Username contains invalid characters"
    
    return True, ""

def sanitize_string(value: str, max_length: int = 1000) -> str:
    """
    Sanitize string input by removing/escaping dangerous characters
    
    Args:
        value: String to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized string
    """
    if not isinstance(value, str):
        return ""
    
    # Remove control characters
    value = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', value)
    
    # Limit length
    value = value[:max_length]
    
    # Strip whitespace
    value = value.strip()
    
    return value

def validate_email(email: str) -> Tuple[bool, str]:
    """
    Validate email address format
    
    Args:
        email: Email address to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not email or not isinstance(email, str):
        # Email is optional
        return True, ""
    
    email = email.strip()
    
    # Basic email regex
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if not re.match(pattern, email):
        return False, "Invalid email address format"
    
    return True, ""
