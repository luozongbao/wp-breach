<?php

/**
 * General vulnerability patterns for WP Breach.
 *
 * This file contains regex patterns and signatures for detecting
 * various types of vulnerabilities in WordPress code.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/detection/patterns
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * General Vulnerability Patterns
 *
 * Patterns are organized by category and include:
 * - pattern: Regex pattern for detection
 * - severity: Vulnerability severity level
 * - confidence: Detection confidence (0.0-1.0)
 * - description: Human-readable description
 * - cwe_id: Common Weakness Enumeration ID
 * - references: Additional information sources
 */
return array(
    'code_injection' => array(
        'eval_user_input' => array(
            'pattern' => '/eval\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'critical',
            'confidence' => 0.95,
            'description' => 'eval() with user input - code injection',
            'cwe_id' => 'CWE-94',
            'references' => array(
                'https://owasp.org/www-community/attacks/Code_Injection',
                'https://wordpress.org/support/article/hardening-wordpress/'
            )
        ),
        'create_function_injection' => array(
            'pattern' => '/create_function\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'critical',
            'confidence' => 0.9,
            'description' => 'create_function() with user input',
            'cwe_id' => 'CWE-94',
            'references' => array()
        ),
        'preg_replace_e_modifier' => array(
            'pattern' => '/preg_replace\s*\([^,]*\/[^\/]*e[^\/]*\/[^,]*,\s*[^,]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'critical',
            'confidence' => 0.9,
            'description' => 'preg_replace /e modifier with user input',
            'cwe_id' => 'CWE-94',
            'references' => array()
        ),
        'assert_injection' => array(
            'pattern' => '/assert\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'critical',
            'confidence' => 0.9,
            'description' => 'assert() with user input',
            'cwe_id' => 'CWE-94',
            'references' => array()
        )
    ),

    'command_injection' => array(
        'shell_exec' => array(
            'pattern' => '/(?:shell_exec|exec|system|passthru|popen|proc_open)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'critical',
            'confidence' => 0.95,
            'description' => 'Command execution with user input',
            'cwe_id' => 'CWE-78',
            'references' => array(
                'https://owasp.org/www-community/attacks/Command_Injection'
            )
        ),
        'backtick_execution' => array(
            'pattern' => '/`[^`]*\$_(?:GET|POST|REQUEST|COOKIE)[^`]*`/i',
            'severity' => 'critical',
            'confidence' => 0.9,
            'description' => 'Backtick command execution with user input',
            'cwe_id' => 'CWE-78',
            'references' => array()
        ),
        'wp_filesystem_commands' => array(
            'pattern' => '/WP_Filesystem.*?(?:put_contents|chmod|chown)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'WP_Filesystem operations with user input',
            'cwe_id' => 'CWE-78',
            'references' => array()
        )
    ),

    'file_upload' => array(
        'unrestricted_upload' => array(
            'pattern' => '/move_uploaded_file\s*\([^)]*\$_FILES(?![^)]*(?:pathinfo|wp_check_filetype))/i',
            'severity' => 'critical',
            'confidence' => 0.8,
            'description' => 'File upload without type validation',
            'cwe_id' => 'CWE-434',
            'references' => array(
                'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload'
            )
        ),
        'dangerous_file_types' => array(
            'pattern' => '/\$_FILES\[.*?\]\[["\']type["\']\].*?(?:php|phtml|php3|php4|php5|exe|asp|jsp|sh|pl|py)/i',
            'severity' => 'high',
            'confidence' => 0.7,
            'description' => 'Upload allowing dangerous file types',
            'cwe_id' => 'CWE-434',
            'references' => array()
        ),
        'wp_handle_upload_bypass' => array(
            'pattern' => '/wp_handle_upload\s*\([^)]*["\']test_form["\']\s*=>\s*false/i',
            'severity' => 'medium',
            'confidence' => 0.6,
            'description' => 'wp_handle_upload with form test disabled',
            'cwe_id' => 'CWE-434',
            'references' => array()
        )
    ),

    'path_traversal' => array(
        'directory_traversal' => array(
            'pattern' => '/(?:file_get_contents|fopen|readfile|include|require)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE).*?\.\.(?:\/|\\\\)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'Path traversal in file operations',
            'cwe_id' => 'CWE-22',
            'references' => array(
                'https://owasp.org/www-community/attacks/Path_Traversal'
            )
        ),
        'unvalidated_file_path' => array(
            'pattern' => '/(?:file_get_contents|fopen|readfile)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)(?![^)]*(?:basename|realpath|wp_normalize_path))/i',
            'severity' => 'medium',
            'confidence' => 0.6,
            'description' => 'File operation with unvalidated user path',
            'cwe_id' => 'CWE-22',
            'references' => array()
        ),
        'wp_upload_dir_traversal' => array(
            'pattern' => '/wp_upload_dir\(\)[^;]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'medium',
            'confidence' => 0.5,
            'description' => 'User input in upload directory path',
            'cwe_id' => 'CWE-22',
            'references' => array()
        )
    ),

    'deserialization' => array(
        'unsafe_unserialize' => array(
            'pattern' => '/unserialize\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'critical',
            'confidence' => 0.9,
            'description' => 'Unsafe deserialization of user input',
            'cwe_id' => 'CWE-502',
            'references' => array(
                'https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection'
            )
        ),
        'maybe_unserialize_user_input' => array(
            'pattern' => '/maybe_unserialize\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'maybe_unserialize with user input',
            'cwe_id' => 'CWE-502',
            'references' => array()
        ),
        'wp_cache_deserialization' => array(
            'pattern' => '/wp_cache_(?:get|set)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'medium',
            'confidence' => 0.5,
            'description' => 'Cache operations with user input (potential deserialization)',
            'cwe_id' => 'CWE-502',
            'references' => array()
        )
    ),

    'information_disclosure' => array(
        'error_display' => array(
            'pattern' => '/(?:ini_set|error_reporting)\s*\([^)]*["\'](?:display_errors|E_ALL)["\'].*?(?:1|true|On)/i',
            'severity' => 'medium',
            'confidence' => 0.6,
            'description' => 'Error display enabled (information disclosure)',
            'cwe_id' => 'CWE-200',
            'references' => array()
        ),
        'debug_output' => array(
            'pattern' => '/(?:var_dump|print_r|var_export)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE|SESSION)/i',
            'severity' => 'medium',
            'confidence' => 0.7,
            'description' => 'Debug output with user/session data',
            'cwe_id' => 'CWE-200',
            'references' => array()
        ),
        'phpinfo_exposure' => array(
            'pattern' => '/phpinfo\s*\(\s*\)/i',
            'severity' => 'medium',
            'confidence' => 0.8,
            'description' => 'phpinfo() call (information disclosure)',
            'cwe_id' => 'CWE-200',
            'references' => array()
        ),
        'wp_debug_enabled' => array(
            'pattern' => '/define\s*\(\s*["\']WP_DEBUG["\'],\s*true\s*\)/i',
            'severity' => 'low',
            'confidence' => 0.5,
            'description' => 'WordPress debug mode enabled',
            'cwe_id' => 'CWE-200',
            'references' => array()
        )
    ),

    'weak_cryptography' => array(
        'md5_hashing' => array(
            'pattern' => '/md5\s*\([^)]*(?:password|pass|pwd|secret)/i',
            'severity' => 'medium',
            'confidence' => 0.7,
            'description' => 'MD5 used for password hashing (weak)',
            'cwe_id' => 'CWE-327',
            'references' => array(
                'https://owasp.org/www-community/vulnerabilities/Use_of_a_Broken_or_Risky_Cryptographic_Algorithm'
            )
        ),
        'sha1_hashing' => array(
            'pattern' => '/sha1\s*\([^)]*(?:password|pass|pwd|secret)/i',
            'severity' => 'medium',
            'confidence' => 0.7,
            'description' => 'SHA1 used for password hashing (weak)',
            'cwe_id' => 'CWE-327',
            'references' => array()
        ),
        'weak_random' => array(
            'pattern' => '/(?:rand|mt_rand|srand)\s*\(\s*\).*?(?:password|token|secret|key|nonce)/i',
            'severity' => 'medium',
            'confidence' => 0.6,
            'description' => 'Weak random number generation for security',
            'cwe_id' => 'CWE-338',
            'references' => array()
        ),
        'hardcoded_secrets' => array(
            'pattern' => '/(?:password|secret|key|token)\s*=\s*["\'][a-zA-Z0-9]{8,}["\']/i',
            'severity' => 'high',
            'confidence' => 0.6,
            'description' => 'Hardcoded secret/password detected',
            'cwe_id' => 'CWE-798',
            'references' => array()
        )
    ),

    'open_redirect' => array(
        'redirect_user_input' => array(
            'pattern' => '/(?:wp_redirect|header\s*\(\s*["\']Location:)\s*[^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'medium',
            'confidence' => 0.8,
            'description' => 'Open redirect with user input',
            'cwe_id' => 'CWE-601',
            'references' => array(
                'https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards'
            )
        ),
        'wp_safe_redirect_bypass' => array(
            'pattern' => '/wp_redirect\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)(?![^)]*wp_validate_redirect)/i',
            'severity' => 'medium',
            'confidence' => 0.7,
            'description' => 'wp_redirect without validation (prefer wp_safe_redirect)',
            'cwe_id' => 'CWE-601',
            'references' => array()
        )
    ),

    'xml_external_entity' => array(
        'libxml_external_entities' => array(
            'pattern' => '/libxml_disable_entity_loader\s*\(\s*false\s*\)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'XML external entity loading enabled',
            'cwe_id' => 'CWE-611',
            'references' => array(
                'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing'
            )
        ),
        'simplexml_load_string' => array(
            'pattern' => '/simplexml_load_string\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'medium',
            'confidence' => 0.7,
            'description' => 'XML parsing with user input (potential XXE)',
            'cwe_id' => 'CWE-611',
            'references' => array()
        ),
        'domdocument_load' => array(
            'pattern' => '/DOMDocument.*?(?:load|loadXML)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'medium',
            'confidence' => 0.7,
            'description' => 'DOMDocument XML loading with user input',
            'cwe_id' => 'CWE-611',
            'references' => array()
        )
    ),

    'ldap_injection' => array(
        'ldap_search_injection' => array(
            'pattern' => '/ldap_search\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'LDAP search with user input',
            'cwe_id' => 'CWE-90',
            'references' => array()
        ),
        'ldap_bind_injection' => array(
            'pattern' => '/ldap_bind\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'LDAP bind with user input',
            'cwe_id' => 'CWE-90',
            'references' => array()
        )
    ),

    'session_fixation' => array(
        'session_id_user_input' => array(
            'pattern' => '/session_id\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'Session ID set from user input (session fixation)',
            'cwe_id' => 'CWE-384',
            'references' => array()
        ),
        'missing_session_regenerate' => array(
            'pattern' => '/wp_login\|login.*?(?!session_regenerate_id)/s',
            'severity' => 'medium',
            'confidence' => 0.4,
            'description' => 'Login without session regeneration',
            'cwe_id' => 'CWE-384',
            'references' => array()
        )
    ),

    'insecure_randomness' => array(
        'predictable_tokens' => array(
            'pattern' => '/(?:nonce|token|csrf)\s*=\s*(?:md5|sha1)\s*\([^)]*(?:time|date|microtime)/i',
            'severity' => 'medium',
            'confidence' => 0.6,
            'description' => 'Predictable token generation',
            'cwe_id' => 'CWE-330',
            'references' => array()
        ),
        'weak_wp_nonce' => array(
            'pattern' => '/wp_create_nonce\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'low',
            'confidence' => 0.5,
            'description' => 'wp_create_nonce with user input',
            'cwe_id' => 'CWE-330',
            'references' => array()
        )
    ),

    'race_conditions' => array(
        'file_race_condition' => array(
            'pattern' => '/(?:file_exists|is_file)\s*\([^)]*\).*?(?:fopen|file_get_contents)\s*\([^)]*\)/s',
            'severity' => 'medium',
            'confidence' => 0.4,
            'description' => 'Potential TOCTOU race condition',
            'cwe_id' => 'CWE-367',
            'references' => array()
        )
    ),

    'server_side_request_forgery' => array(
        'curl_user_url' => array(
            'pattern' => '/(?:curl_setopt|wp_remote_(?:get|post|request))\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'HTTP request with user-controlled URL (SSRF)',
            'cwe_id' => 'CWE-918',
            'references' => array(
                'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery'
            )
        ),
        'file_get_contents_url' => array(
            'pattern' => '/file_get_contents\s*\([^)]*(?:https?:|ftp:)[^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'file_get_contents with user URL (SSRF)',
            'cwe_id' => 'CWE-918',
            'references' => array()
        )
    ),

    'business_logic' => array(
        'price_manipulation' => array(
            'pattern' => '/(?:price|cost|amount|total)\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'high',
            'confidence' => 0.6,
            'description' => 'Price/amount set from user input',
            'cwe_id' => 'CWE-840',
            'references' => array()
        ),
        'quantity_manipulation' => array(
            'pattern' => '/(?:quantity|qty|count)\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE)(?![^;]*(?:intval|absint))/i',
            'severity' => 'medium',
            'confidence' => 0.5,
            'description' => 'Quantity without validation',
            'cwe_id' => 'CWE-840',
            'references' => array()
        )
    ),

    'wordpress_core_bypass' => array(
        'capability_bypass' => array(
            'pattern' => '/\$current_user->allcaps\[.*?\]\s*=\s*true/i',
            'severity' => 'critical',
            'confidence' => 0.9,
            'description' => 'Direct capability manipulation',
            'cwe_id' => 'CWE-269',
            'references' => array()
        ),
        'role_manipulation' => array(
            'pattern' => '/\$current_user->roles\[\d+\]\s*=\s*["\']administrator["\']/i',
            'severity' => 'critical',
            'confidence' => 0.9,
            'description' => 'Direct role manipulation to administrator',
            'cwe_id' => 'CWE-269',
            'references' => array()
        ),
        'wp_die_bypass' => array(
            'pattern' => '/wp_die\s*\(\s*["\']["\']\s*\)/i',
            'severity' => 'low',
            'confidence' => 0.3,
            'description' => 'Empty wp_die() call',
            'cwe_id' => 'CWE-754',
            'references' => array()
        )
    )
);
