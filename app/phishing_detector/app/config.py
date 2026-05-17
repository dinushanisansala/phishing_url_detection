# app/config.py

# KNOWN_TLDS
KNOWN_TLDS = {
    'generic': ['com', 'org', 'net', 'int', 'edu', 'gov', 'mil', 'arpa', 'biz', 'info', 'name', 'pro', 'aero', 'coop', 'museum'],
    'country_code': ['us', 'uk', 'ca', 'fr', 'de', 'jp', 'in', 'cn', 'au', 'br'],
    'sponsored': ['xxx', 'biz', 'aero', 'cat', 'coop', 'museum', 'travel', 'jobs']
}

def load_common_tlds():
    """
    Retrieves all common top-level domains (TLDs) from KNOWN_TLDS.

    This function concatenates all TLD lists ('generic', 'country_code', 'sponsored') 
    from the KNOWN_TLDS dictionary into a single list of common TLDs.

    Returns:
    list: A list of all common TLDs.
    """
    common_tlds = []
    
    # Iterate over values in KNOWN_TLDS dictionary
    for tld_list in KNOWN_TLDS.values():
        common_tlds.extend(tld_list)
    
    return common_tlds


# BRAND_NAMES
BRAND_NAMES = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'netflix', 'alibaba']

def load_brand_names():
    """
    Load the brand names.

    This function retrieves a list of brand names from an external source or file,
    or uses a static list defined in config.py if no external source is specified.

    Returns:
    list: A list of brand names.
    """
    # Replace with logic to load from external source or file if needed
    return BRAND_NAMES

# SENSITIVE_WORDS
SENSITIVE_WORDS = [
    'wp', 'login', 'includes', 'admin', 'content', 'site',
    'images', 'js', 'css', 'myaccount',
    'dropbox', 'themes', 'plugins', 'signin', 'view',
    'username', 'userid', 'passwd', 'password'
]

def load_sensitive_words():
    """
    Load the sensitive words.

    This function retrieves a list of sensitive words from an external source or file,
    or uses a static list defined in config.py if no external source is specified.

    Returns:
    list: A list of sensitive words.
    """
    # Replace with logic to load from external source or file if needed
    return SENSITIVE_WORDS

# STANDARD_PROTOCOLS
STANDARD_PROTOCOLS = ["http://", "https://", "ftp://", "ftps://", "sftp://", "ssh://"]

def load_standard_protocols():
    """
    Load the standard protocols.

    This function retrieves a list of standard protocols from an external source or file,
    or uses a static list defined in config.py if no external source is specified.

    Returns:
    list: A list of standard protocols.
    """
    # Replace with logic to load from external source or file if needed
    return STANDARD_PROTOCOLS

# RELIABLE_PORTS
RELIABLE_PORTS = {21, 70, 80, 443, 1080, 8080}

def load_reliable_ports():
    """
    Load the reliable ports.

    This function retrieves a set of reliable ports from an external source or file,
    or uses a static set defined in config.py if no external source is specified.

    Returns:
    set: A set of reliable ports.
    """
    # Replace with logic to load from external source or file if needed
    return RELIABLE_PORTS

# SHORTENING_DOMAINS
SHORTENING_DOMAINS = [
    "bit.ly", "tinyurl.com", "ow.ly", "t.co", "goo.gl", "is.gd",
    "buff.ly", "fb.me", "rebrand.ly", "shorte.st", "bc.vc", "mcaf.ee",
    "adf.ly", "tiny.cc", "smarturl.it"
]

def load_shortening_domains():
    """
    Load the shortening domains.

    This function retrieves a list of shortening domains from an external source or file,
    or uses a static list defined in config.py if no external source is specified.

    Returns:
    list: A list of shortening domains.
    """
    # Replace with logic to load from external source or file if needed
    return SHORTENING_DOMAINS

# REDIRECT_PATTERNS
REDIRECT_PATTERNS = [
    r"https?://", r"redirect", r"goto", r"forward", r"url=",
    r"target", r"destination", r"redir", r"click", r"r=", r"goto=",
    r"out=", r"out.aspx?", r"link=", r"next=", r"u=", r"open=",
    r"continue=", r"navigation=", r"navto=", r"\.\.", r"%[0-9a-fA-F]{2}",
    r"%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}"
]

def load_redirect_patterns():
    """
    Load the redirect patterns.

    This function retrieves a list of redirect patterns from an external source or file,
    or uses a static list defined in config.py if no external source is specified.

    Returns:
    list: A list of redirect patterns.
    """
    # Replace with logic to load from external source or file if needed
    return REDIRECT_PATTERNS

# Define __all__ to specify the public symbols
__all__ = [
    'KNOWN_TLDS',
    'BRAND_NAMES',
    'SENSITIVE_WORDS',
    'STANDARD_PROTOCOLS',
    'RELIABLE_PORTS',
    'SHORTENING_DOMAINS',
    'REDIRECT_PATTERNS',
    'load_common_tlds',
    'load_brand_names',
    'load_sensitive_words',
    'load_standard_protocols',
    'load_reliable_ports',
    'load_shortening_domains',
    'load_redirect_patterns'
]

