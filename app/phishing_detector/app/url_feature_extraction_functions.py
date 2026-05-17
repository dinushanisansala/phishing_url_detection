# app/url_feature_extraction_functions.py



import socket
import struct
import re
import validators
import math
from urllib.parse import urlparse, parse_qs, unquote
from collections import defaultdict
import pandas as pd


# Import functions and constants from config.py
from .config import *


def is_valid_url(url):
    """
    Validate if a given string is a valid URL.

    Parameters:
    url (str): The URL to validate.

    Returns:
    bool: True if the URL is valid, False otherwise.
    """
    return validators.url(url)


def is_valid_ip(ip):
    """
    Validate if a given string is a valid IPv4 or IPv6 address.

    Parameters:
    ip (str): The IP address to validate.

    Returns:
    bool: True if the IP address is valid, False otherwise.
    """
    try:
        # Check for IPv4
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        pass

    try:
        # Check for IPv6
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except socket.error:
        pass

    return False


def detect_ip(hostname):
    """
    Detects the presence of an IP address (IPv4 or IPv6) in the hostname.

    Parameters:
    hostname (str): The hostname to analyze.

    Returns:
    int: 1 if an IP address is detected, 0 otherwise.
    """
    if is_valid_ip(hostname):
        return 1

    # Check for dotless IPv4 address
    if hostname.isdigit():
        try:
            # Convert dotless IP to integer and back to dotted notation
            ip = socket.inet_ntoa(struct.pack('!I', int(hostname)))
            if is_valid_ip(ip):
                return 1
        except:
            pass

    # Check for hexadecimal IPv4 address
    if hostname.startswith('0x'):
        try:
            # Convert hex to integer and then to dotted notation
            ip = socket.inet_ntoa(struct.pack('!I', int(hostname, 16)))
            if is_valid_ip(ip):
                return 1
        except:
            pass

    return 0



def count_common_tlds_in_path(path):
    """
    Count occurrences of common top-level domains (TLDs) in the given path.

    Parameters:
    path (str): The path to analyze.

    Returns:
    int: Number of common TLDs found in the path, or -1 if path is None.
    """
    common_tlds = load_common_tlds()

    if path is None:
        return -1

    # Regular expression to match common TLDs
    tld_pattern = re.compile(r'\b(' + '|'.join(re.escape(tld) for tld in common_tlds) + r')\b')

    # Find all TLDs in the path
    tlds_in_path = tld_pattern.findall(path)
    
    if tlds_in_path:
        return 1
    else:
        return 0


def count_common_tlds_in_subdomain(subdomain):
    """
    Count occurrences of common top-level domains (TLDs) in the given subdomain.

    Parameters:
    subdomain (str): The subdomain to analyze.

    Returns:
    int: Number of common TLDs found in the subdomain, or -1 if subdomain is None.
    """
    common_tlds = load_common_tlds()

    if subdomain is None:
        return -1

    # Regular expression to match common TLDs
    tld_pattern = re.compile(r'\b(' + '|'.join(re.escape(tld) for tld in common_tlds) + r')\b')

    # Find all TLDs in the subdomain
    tlds_in_subdomain = tld_pattern.findall(subdomain)
    if tlds_in_subdomain:
        return len(tlds_in_subdomain)
    else:
        return 0


def get_url_segments(url):
    """
    Parse the given URL and extract its components.

    Parameters:
    url (str): The URL to parse.

    Returns:
    dict: A dictionary containing parsed components of the URL.
    """
    common_tlds = load_common_tlds()

    # Parse the URL
    parsed_url = urlparse(url)

    # Assign components, ensuring None for missing values
    scheme = parsed_url.scheme
    netloc = parsed_url.netloc
    path = parsed_url.path
    params = parsed_url.params
    query = parsed_url.query
    fragment = parsed_url.fragment
    query_dict = parse_qs(parsed_url.query)

    # Extract subdomain, domain, SLD, TLD, and port from netloc
    if netloc:
        if ':' in netloc:
            hostname, port = netloc.split(':')
            port = int(port) if port.isdigit() else None
        else:
            hostname = netloc
            port = None

        if detect_ip(hostname):
            domain_parts = []
        else:
            domain_parts = hostname.split('.')

        if len(domain_parts) > 2:
            subdomain = '.'.join(domain_parts[:-2])
            num_subdomain = len(domain_parts) - 2
            domain = '.'.join(domain_parts[-2:])
            sld = domain_parts[-2]
            tld = domain_parts[-1]
        elif len(domain_parts) == 2:
            subdomain = None
            num_subdomain = 0
            domain = '.'.join(domain_parts)
            sld = domain_parts[-2]
            tld = domain_parts[-1]
        else:
            subdomain = None
            num_subdomain = 0
            domain = hostname
            sld = None
            tld = None
    else:
        subdomain = domain = sld = tld = port = None
        num_subdomain = -1

    # Count common TLDs in subdomain and path
    subdomain_common_tld_count = count_common_tlds_in_subdomain(subdomain)
    path_common_tld_count = count_common_tlds_in_path(path)

    segments = {
        'scheme': scheme,
        'netloc': netloc,
        'hostname': hostname,
        'port': port,
        'subdomain': subdomain,
        'num_subdomain': num_subdomain,
        'domain': domain,
        'sld': sld,
        'tld': tld,
        'path': path,
        'params': params,
        'query': query,
        'fragment': fragment,
        'query_dict': query_dict,
        'path_common_tld_count': path_common_tld_count,
        'subdomain_common_tld_count': subdomain_common_tld_count
    }

    return segments


def count_length(string):
    """
    Calculate the length of the given String.

    Parameters:
    string (str): The String to be calculated.

    Returns:
    int: The length of the String, or 0 if the input string is None.
    """
    if string is None:
        return 0
    return len(string)


def check_standard_protocol(protocol):
    """
    Checks if a given protocol is a standard protocol.

    Parameters:
    protocol (str): The protocol to be checked.

    Returns:
    int: Returns 1 if the protocol is a standard protocol, otherwise returns 0.
    """
    # Load the list of standard protocols
    standard_protocols = load_standard_protocols()

    # Check if the given protocol is in the list of standard protocols
    if protocol in standard_protocols:
        return 1  # Return 1 if it is a standard protocol
    else:
        return 0  # Return 0 if it is not a standard protocol



def count_special_char(component, component_type):
    """
    Counts the occurrences of each special character in the given input string
    and assigns the results to attributes with names based on the category.

    Parameters:
    component (str): The input component to be analyzed.
    component_type (str): The component type.

    Returns:
    dict: A dictionary with the counts of each special character in the input string.
    """
    # Define special characters and their corresponding names
    special_characters = ".-_:;/?@&=+$,{}|\\^~`[]'\"()#*%! ‘’<>"
    special_characters_names = {
        ".": "dot", "-": "hyphen", "_": "underscore", "!": "exclamation_mark",
        "$": "dollar_sign", "(": "left_parenthesis", ")": "right_parenthesis",
        "*": "asterisk", ",": "comma", "'": "single_quote", "+": "plus_sign",
        ":": "colon", ";": "semicolon", "/": "slash", "?": "question_mark",
        "@": "at_sign", "&": "ampersand", "=": "equal_sign", "{": "left_curly_brace",
        "}": "right_curly_brace", "|": "vertical_bar", "\\": "backslash",
        "^": "caret", "~": "tilde", "`": "backtick", "[": "left_square_bracket",
        "]": "right_square_bracket", "<": "less_than_sign", ">": "greater_than_sign",
        "#": "hash", "%": "percent", "\"": "double_quote", " ": "space",
        "<": "less_than", ">" : "greater_than" , "‘" : "open_quotation", "’" : "close_quotation"
    }
    
    if component is not None:
        # Initialize counts dictionary with special character names
        counts = {f"{component_type}_{special_characters_names[char]}_char_count": 0 for char in special_characters}
        
        # Add key for counting double slashes
        counts[f"{component_type}_double_slash_char_count"] = 0

        # Count occurrences of each special character
        i = 0
        while i < len(component):
            char = component[i]
            if char in special_characters:
                char_name = special_characters_names[char]
                # Check for double slash if current character is a slash
                if char == "/" and i < len(component) - 1 and component[i + 1] == "/":
                    counts[f"{component_type}_double_slash_char_count"] += 1
                    i += 1  # Skip the next character as it is part of the double slash
                else:
                    # Increment count for current character
                    counts[f"{component_type}_{char_name}_char_count"] += 1
            i += 1
        # Calculate the total count of special characters
        #total_special_char_count = sum(counts[key] for key in counts if key != f"{component_type}_double_slash_char_count")
        total_special_char_count = sum(counts[key]for key in counts)
        counts[f"{component_type}_special_characters_char_count"] = total_special_char_count
    else:
        # If input_string is None, return -1 for all counts
        counts = {f"{component_type}_{special_characters_names[char]}_char_count": -1 for char in special_characters}
        counts[f"{component_type}_double_slash_char_count"] = -1  # Double slash count set to -1
        counts[f"{component_type}_special_characters_char_count"] = -1  # Total special characters count set to -1
    return counts


def is_shortened_url(url):
    """
    Detects if the given URL is a shortened URL.

    Parameters:
    url (str): The URL to be checked.

    Returns:
    int: 1 if a shortened URL is detected, 0 otherwise.
    """
    # List of known URL shortening service domains
    shortening_domains = load_shortening_domains()

    # Regular expression pattern to match shortened URL domains
    pattern = r"https?://(?:www\.)?(" + "|".join(shortening_domains) + r")/"

    # Check if the URL matches the pattern
    if re.match(pattern, url):
        return 1  # Return 1 if shortened URL is detected
    else:
        return 0  # Return 0 if not a shortened URL


def detect_https(scheme):
    """
    Detects if the HTTPS protocol is present in the given URL scheme.

    Parameters:
    scheme (str): The scheme part of the URL.

    Returns:
    int: 1 if HTTPS protocol detected, 0 if HTTPS protocol not detected, -1 if no scheme in the URL.
    """
    if not scheme:
        return -1  # No scheme in the URL
    if scheme.lower() == "https":
        return 1  # HTTPS protocol detected
    else:
        return 0  # No HTTPS scheme detected


def count_special_str_in_url(url, string):
    """
    Counts the occurrences of 'string' in the given URL.

    Parameters:
    url (str): The URL to be analyzed.
    string (str): The string to count occurrences of.

    Returns:
    int: The number of occurrences of 'string' in the URL.
    """
    return url.lower().count(string.lower())


def count_digit_in_string(s):
    """
    Counts the number of digits in the given string.

    Parameters:
    s (str): The string to be analyzed.

    Returns:
    int: The number of digits in the string.
    """
    return sum(char.isdigit() for char in s)


def get_ratios_of_digits_in_string(s):
    """
    Calculates the ratio of digits in the s.

    Parameters:
    s (str): The String to be analyzed.

    Returns:
    tuple: A tuple containing the ratio of digits in the s.
    """

    # Calculate the total lengths
    total_length = len(s)
    number_of_digits = count_digit_in_string(s)

    # Calculate the ratios
    ratio_digits = number_of_digits / total_length if total_length else 0

    return ratio_digits


def get_ratios_of_special_char_in_string(s):
    """
    Calculates the ratio of special characters in the given string.

    Parameters:
    s (str): The String to be analyzed.

    Returns:
    float: The ratio of special characters in the string.
    """
    # Define the special characters (correctly escaping backslashes)
    special_chars_pattern = re.compile(r'[.\-_:;/?@&=+$,{}|\\^~`[\]\'()"#*%!‘’<>\\ ]')

    # Count the total number of special characters in s
    special_char_count = len(special_chars_pattern.findall(s))

    # Get the total length of the s
    s_length = len(s)

    # Calculate the ratio of special characters to the total length of s
    if s_length == 0:  # To handle the case of empty s
        return 0.0
    
    special_char_ratio = special_char_count / s_length
    
    return special_char_ratio


def contains_punycode(s):
    """
    Checks if the given URL contains punycode.

    Parameters:
    s (str): The URL to be analyzed.

    Returns:
    int: 1 if the URL contains punycode, 0 otherwise.
    """
    return 1 if 'xn--' in s else 0


def phishing_pattern_in_subdomain(subdomain):
    """
    Checks if the URL's subdomain matches a phishing pattern like 'w[w]?[0-9]*'.

    Parameters:
    subdomain (str): The subdomain to be analyzed.

    Returns:
    int: 1 if the subdomain matches the phishing pattern, 0 if it doesn't match the pattern,
         or -1 if subdomain is None.
    """
    if subdomain is None:
        return -1
    
    # Pattern to match 'w[w]?[0-9]*'
    phishing_pattern = re.compile(r'^w[w]?[0-9]*$')
    
    # Split the subdomain by dots and check each part
    subdomain_parts = subdomain.split('.')
    for part in subdomain_parts:
        if phishing_pattern.match(part):
            return 1
    
    return 0


def calculate_entropy(s):
    """
    Calculate the entropy of a string.

    Parameters:
    s (str): The string for which to calculate entropy.

    Returns:
    float: The entropy of the string.
    """
    # Count occurrences of each character
    char_count = {}
    for char in s:
        char_count[char] = char_count.get(char, 0) + 1
    
    # Calculate entropy
    entropy = 0
    total_chars = len(s)
    for count in char_count.values():
        probability = count / total_chars
        entropy -= probability * math.log2(probability)
    
    return entropy



def is_domain_random(domain):
    """
    Checks if a domain name appears to be random.

    Parameters:
    domain (str): The domain name to check.

    Returns:
    int: 1 if the domain appears to be random, 0 otherwise.
    """
    # Calculate entropy of the domain name
    entropy = calculate_entropy(domain)
    
    # If entropy is above a certain threshold, consider it random
    threshold = 3.0  # Adjust this threshold based on analysis
    return int(entropy > threshold)


def malicious_extension_in_path(path):
    """
    Checks if the given URL contains malicious file extensions in its path.

    Parameters:
    path (str): The path to be checked.

    Returns:
    int: 1 if the path contains malicious file extensions, 0 if it doesn't contain any,
         or -1 if path is None.
    """
    if path is None:
        return -1
    
    # List of malicious file extensions
    malicious_extensions = ['.txt', '.exe', '.js']

    # Check if any malicious extension exists in the path
    for extension in malicious_extensions:
        if extension in path:
            return 1

    return 0


def check_redirect_patterns(text):
    """
    Analyzes the given text for redirect patterns.

    Parameters:
    text (str): The text to be analyzed.

    Returns:
    int: 
        - 1 if any redirect pattern is found in text.
        - 0 if no redirect patterns are detected.
        - -1 if the text is None.
    """
    if text is None:
        return -1
    else:
        # Load redirect patterns
        redirect_patterns = load_redirect_patterns()
        
        # Check for redirect patterns in text
        if any(pattern in text.lower() for pattern in redirect_patterns):
            return 1
        
        # If no redirect patterns found
        else:
            return 0


def count_sensitive_words(url):
    """
    Counts the occurrences of sensitive words in the given URL.

    Parameters:
    url (str): The URL to be analyzed.

    Returns:
    int: The total count of sensitive words found in the URL.
    """
    sensitive_words = load_sensitive_words()  # Load sensitive words
    
    # Normalize the URL to lowercase to ensure case-insensitive matching
    normalized_url = url.lower()
    
    # Initialize the counter for sensitive words
    word_count = 0
    
    # Check each sensitive word in the URL
    for word in sensitive_words:
        word_count += len(re.findall(word, normalized_url))
    
    return word_count


def check_brand_names(text):
    """
    Checks if the given text contains any brand names.

    Parameters:
    text (str): The text to be analyzed.

    Returns:
    int: 
        - 1 if a brand name is found in the text,
        - 0 if no brand names are found,
        - -1 if text is None.
    """
    if text is None:
        return -1
    
    brand_names = load_brand_names()  # Load brand names
    
    # Check for each brand name in the text
    for brand in brand_names:
        if brand in text:
            return 1
    
    return 0


def count_common_tlds_in_path(path):
    """
    Counts occurrences of common top-level domains (TLDs) in the given path.

    Parameters:
    path (str): The path to be analyzed.

    Returns:
    int: 
        - Number of common TLDs found in the path,
        - or -1 if path is None.
    """
    if path is None:
        return -1
    
    common_tlds = load_common_tlds()  # Load common TLDs
    
    # Regular expression pattern to match TLDs in the path
    tld_pattern = re.compile(r'\b(' + '|'.join(re.escape(tld) for tld in common_tlds) + r')\b')
    
    # Find all TLDs in the path
    tlds_in_path = tld_pattern.findall(path)
    
    return len(tlds_in_path)


def check_port_reliability(port):
    """
    Checks if the port is in the list of reliable ports.

    Parameters:
    port (int): The port number to check.

    Returns:
    int: 
        - 1 if the port is reliable,
        - 0 if not,
        - -1 if no port is specified.
    """
    reliable_ports = load_reliable_ports()  # Load reliable ports
    
    if port is not None:
        return 1 if port in reliable_ports else 0
    
    return -1

def check_email_submission_patterns_in_query(query):
    """
    Checks if the query parameters contain email submission patterns.

    Parameters:
    query (dict or None): A dictionary of query parameters where keys are strings and values are lists of strings.

    Returns:
    int: 
        - 1 if an email-related keyword is found in any key or if any value matches the email address pattern,
        - 0 if no email submission patterns are detected,
        - -1 if query is None.
    """
    if query is None:
        return -1
    
    # Check if any query parameter key contains an email related word
    for key in query:
        if any(word in key.lower() for word in ['email', 'user', 'username', 'mail']):
            return 1
        
        # Check if any query parameter value looks like an email address
        for value in query[key]:
            if re.match(r"[^@]+@[^@]+\.[^@]+", value):
                return 1
    
    return 0


def check_iframe_patterns(url):
    """
    Checks if the URL contains any "iframe" patterns, including encoded forms.

    Parameters:
    url (str): The URL to be analyzed.

    Returns:
    int: 
        - 1 if "iframe" patterns are found,
        - 0 otherwise.
    """
    # Regular expression pattern to match variations of "iframe"
    iframe_pattern = re.compile(r'\biframe\b|\bIFRAME\b|\bi_frame\b|\biframe_')

    # Decode the URL-encoded text
    decoded_url = unquote(url)

    # Search for the pattern in both original and decoded text
    if iframe_pattern.search(url) or iframe_pattern.search(decoded_url):
        return 1
    else:
        return 0

def extract_features(url):
    """
    Extracts features from a given URL.

    Parameters:
    url (str): The URL to extract features from.

    Returns:
    pd.Series: A pandas Series containing extracted features.
    """
    # Parse the URL segments
    segments = get_url_segments(url)
    
    # Check if URL is valid
    url_is_valid = 1 if is_valid_url(url) else 0
    
    # URL length
    url_length = len(url)
    
    # Detect if URL has IP address
    url_has_ip = detect_ip(segments.get('hostname'))
    
    # Detect if URL is shortened
    url_shortened = is_shortened_url(url)
    
    # Detect if URL has hostname
    url_has_hostname = 1 if segments.get('hostname') else 0
    
    # Detect if URL has domain
    url_has_domain = 1 if segments.get('domain') else 0
    
    # Detect if URL has subdomain
    url_has_subdomain = 1 if segments.get('subdomain') else 0
    
    # Detect if URL has port
    url_has_port = 1 if segments.get('port') else 0
    
    # Check reliability of the port
    url_has_reliable_port = check_port_reliability(segments.get('port'))
    
    # Detect if URL has TLD
    url_has_tld = 1 if segments.get('tld') else 0
    
    # Detect if URL has SLD
    url_has_sld = 1 if segments.get('sld') else 0
    
    # Detect if URL has path (excluding root path '/')
    url_has_path = 1 if segments.get('path') and segments.get('path') != '/' else 0
    
    # Detect if URL has query
    url_has_query = 1 if segments.get('query') else 0
    
    # Detect if URL has fragment
    url_has_fragment = 1 if segments.get('fragment') else 0
    
    # Detect if URL uses HTTPS
    url_has_https = detect_https(segments.get('scheme'))
    
    # Count occurrences of 'www' in URL
    url_www_count = count_special_str_in_url(url, "www")
    
    # Count occurrences of '.com' in URL
    url_com_count = count_special_str_in_url(url, ".com")
    
    # Count occurrences of 'http' in URL
    url_http_count = count_special_str_in_url(url, "http")
    
    # Detect if URL has iframe patterns
    url_has_iframe_patterns = check_iframe_patterns(url)
    
    # Detect if URL has redirect patterns
    url_has_redirect_patterns = check_redirect_patterns(url)
    
    # Get ratio of digits in URL
    url_ratio_digits = get_ratios_of_digits_in_string(url)

    # Get ratio of special chars in URL
    url_ratio_special_char = get_ratios_of_special_char_in_string(url)
    
    # Count sensitive words in URL
    url_num_sensitive_words = count_sensitive_words(url)
    
    # Count digits in URL
    url_digit_char_count = count_digit_in_string(url)
    
    # Count special characters in URL
    url_special_char_counts = count_special_char(url,"url")
    
    # Length of scheme
    scheme_length = count_length(segments.get('scheme'))
    
    # Check if scheme uses standard protocol (http, https, ftp, etc.)
    scheme_has_standard_protocol = check_standard_protocol(segments.get('scheme'))
    
    # Length of netloc
    netloc_length = count_length(segments.get('netloc'))
    
    # Length of domain
    domain_length = count_length(segments.get('domain'))

    # Get ratio of digits in domain
    domain_ratio_digits = get_ratios_of_digits_in_string(segments.get('domain'))

    # Get ratio of special chars in domain
    domain_ratio_special_char = get_ratios_of_special_char_in_string(segments.get('domain'))
    
    # Count digits in Domain
    domain_digit_char_count = count_digit_in_string(segments.get('domain'))
    
    # Count special characters in domain
    domain_special_char_counts = count_special_char(segments.get('domain'), "domain")
    
    # Check if domain uses punycode
    domain_has_punycode = 1 if contains_punycode(segments.get('domain')) else 0
    
    # Check if domain is randomly generated
    domain_is_random = is_domain_random(segments.get('domain'))
    
    # Check if domain contains brand names
    domain_has_brandnames = 1 if check_brand_names(segments.get('domain')) else 0
    
    # Length of subdomain
    subdomain_length = count_length(segments.get('subdomain'))
    
    # Number of subdomains
    subdomain_count = segments.get('num_subdomain')
    
    # Count common TLDs in subdomain
    subdomain_common_tld_count = segments.get('subdomain_common_tld_count')
    
    # Check for phishing patterns in subdomain
    subdomain_has_phishing_pattern = 1 if phishing_pattern_in_subdomain(segments.get('subdomain')) else 0
    
    # Check if subdomain contains brand names
    subdomain_has_brandnames = 1 if check_brand_names(segments.get('subdomain')) else 0
    
    # Length of path
    path_length = count_length(segments.get('path'))
    
    # Count common TLDs in path
    path_common_tld_count = segments.get('path_common_tld_count')
    
    # Detect if path has redirect patterns
    path_has_redirect_patterns = check_redirect_patterns(segments.get('path'))
    
    # Check for malicious extensions in path
    path_has_malicious_extension = 1 if malicious_extension_in_path(segments.get('path')) else 0
    
    # Check if path contains brand names
    path_has_brandnames = 1 if check_brand_names(segments.get('path')) else 0

    # Get ratio of digits in path
    path_ratio_digits = get_ratios_of_digits_in_string(segments.get('path'))

    # Get ratio of special chars in path
    path_ratio_special_char = get_ratios_of_special_char_in_string(segments.get('path'))
    
    # Count digits in Path
    path_digit_char_count = count_digit_in_string(segments.get('path'))
    
    # Count special characters in path
    path_special_char_counts = count_special_char(segments.get('path'), "path")
    
    # Length of query
    query_length = count_length(segments.get('query'))
    
    # Detect if query has redirect patterns
    query_has_redirect_patterns = check_redirect_patterns(segments.get('query'))
    
    # Check for email submission patterns in query
    query_has_email_submission_patterns = check_email_submission_patterns_in_query(segments.get('query_dict'))
    
    # Get ratio of digits in query
    query_ratio_digits = get_ratios_of_digits_in_string(segments.get('query'))

    # Get ratio of special chars in query
    query_ratio_special_char = get_ratios_of_special_char_in_string(segments.get('query'))
    
    # Count digits in query
    query_digit_char_count = count_digit_in_string(segments.get('query'))
    
    # Count special characters in query
    query_special_char_counts = count_special_char(segments.get('query'), "query")
    
    # Length of fragment
    fragment_length = count_length(segments.get('fragment'))
    
    # Detect if fragment has redirect patterns
    fragment_has_redirect_patterns = check_redirect_patterns(segments.get('fragment'))

    # Get ratio of digits in fragment
    fragment_ratio_digits = get_ratios_of_digits_in_string(segments.get('fragment'))

    # Get ratio of special chars in fragment
    fragment_ratio_special_char = get_ratios_of_special_char_in_string(segments.get('fragment'))
    
    # Count special characters in fragment
    fragment_special_char_counts = count_special_char(segments.get('fragment'), "fragment")
    
    # Count digits in query
    fragment_digit_char_count = count_digit_in_string(segments.get('fragment'))
    
    # Construct a dictionary with extracted features
    features = {
        'url_is_valid': url_is_valid,
        'url_length': url_length,
        'url_has_ip': url_has_ip,
        'url_shortened': url_shortened,
        'url_has_hostname': url_has_hostname,
        'url_has_domain': url_has_domain,
        'url_has_subdomain': url_has_subdomain,
        'url_has_port': url_has_port,
        'url_has_redirect_patterns': url_has_redirect_patterns,
        'url_has_reliable_port': url_has_reliable_port,
        'url_has_tld': url_has_tld,
        'url_has_sld': url_has_sld,
        'url_has_path': url_has_path,
        'url_has_query': url_has_query,
        'url_has_fragment': url_has_fragment,
        'url_has_https': url_has_https,
        'url_has_iframe_patterns': url_has_iframe_patterns,
        'url_www_count': url_www_count,
        'url_com_count': url_com_count,
        'url_http_count': url_http_count,
        'url_ratio_digits': url_ratio_digits,
        'url_ratio_special_char': url_ratio_special_char,
        'url_num_sensitive_words': url_num_sensitive_words,
        'url_digit_char_count':url_digit_char_count,
        **url_special_char_counts,
        'scheme_length': scheme_length,
        'scheme_has_standard_protocol': scheme_has_standard_protocol,
        'netloc_length': netloc_length,
        'domain_length': domain_length,
        'domain_has_punycode': domain_has_punycode,
        'domain_is_random': domain_is_random,
        'domain_has_brandnames': domain_has_brandnames,
        'domain_ratio_digits': domain_ratio_digits,
        'domain_ratio_special_char': domain_ratio_special_char,
        'domain_digit_char_count':domain_digit_char_count,
        **domain_special_char_counts,
        'subdomain_length': subdomain_length,
        'subdomain_count': subdomain_count,
        'subdomain_common_tld_count':subdomain_common_tld_count,
        'subdomain_has_phishing_pattern': subdomain_has_phishing_pattern,
        'subdomain_has_brandnames': subdomain_has_brandnames,
        'path_length': path_length,
        'path_common_tld_count':path_common_tld_count,
        'path_has_redirect_patterns': path_has_redirect_patterns,
        'path_has_malicious_extension': path_has_malicious_extension,
        'path_has_brandnames': path_has_brandnames,
        'path_ratio_digits':path_ratio_digits,
        'path_ratio_special_char':path_ratio_special_char,
        'path_digit_char_count':path_digit_char_count,
        **path_special_char_counts,
        'query_length': query_length,
        'query_has_redirect_patterns': query_has_redirect_patterns,
        'query_ratio_digits':query_ratio_digits,
        'query_ratio_special_char':query_ratio_special_char,
        'query_has_email_submission_patterns':query_has_email_submission_patterns,
        'query_digit_char_count':query_digit_char_count,
        **query_special_char_counts,
        'fragment_length': fragment_length,
        'fragment_has_redirect_patterns': fragment_has_redirect_patterns,
        'fragment_ratio_digits':fragment_ratio_digits,
        'fragment_ratio_special_char':fragment_ratio_special_char,
        'fragment_digit_char_count':fragment_digit_char_count,
        **fragment_special_char_counts
    }
    
    return pd.Series(features)

