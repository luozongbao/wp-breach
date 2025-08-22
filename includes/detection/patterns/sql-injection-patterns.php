<?php

/**
 * SQL Injection vulnerability patterns for WP Breach.
 *
 * This file contains regex patterns and signatures for detecting
 * SQL injection vulnerabilities in WordPress code.
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
 * SQL Injection Patterns
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
    'basic_injection' => array(
        'user_input_in_query' => array(
            'pattern' => '/\$wpdb->(?:query|get_(?:var|row|col|results))\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'critical',
            'confidence' => 0.9,
            'description' => 'Direct user input in SQL query',
            'cwe_id' => 'CWE-89',
            'references' => array(
                'https://wordpress.org/support/article/hardening-wordpress/#securing-wp-config-php',
                'https://developer.wordpress.org/apis/handbook/database/'
            )
        ),
        'concatenated_user_input' => array(
            'pattern' => '/\$wpdb->(?:query|get_(?:var|row|col|results))\s*\([^)]*["\'].*?\$_(?:GET|POST|REQUEST)/i',
            'severity' => 'critical',
            'confidence' => 0.85,
            'description' => 'User input concatenated into SQL query',
            'cwe_id' => 'CWE-89',
            'references' => array()
        ),
        'dynamic_table_names' => array(
            'pattern' => '/\$wpdb->(?:query|get_(?:var|row|col|results))\s*\([^)]*FROM\s+["\']?\$\w+["\']?/i',
            'severity' => 'high',
            'confidence' => 0.7,
            'description' => 'Dynamic table name in SQL query',
            'cwe_id' => 'CWE-89',
            'references' => array()
        ),
        'unescaped_variables' => array(
            'pattern' => '/\$wpdb->(?:query|get_(?:var|row|col|results))\s*\([^)]*["\'][^"\']*\$\w+[^"\']*["\'][^)]*\)/i',
            'severity' => 'high',
            'confidence' => 0.6,
            'description' => 'Potentially unescaped variable in SQL query',
            'cwe_id' => 'CWE-89',
            'references' => array()
        )
    ),

    'wordpress_specific' => array(
        'missing_prepare' => array(
            'pattern' => '/\$wpdb->(?:query|get_(?:var|row|col|results))\s*\(\s*["\'][^"\']*%[sd][^"\']*["\'](?!\s*,\s*\$wpdb->prepare)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'SQL query with placeholders but no prepare() call',
            'cwe_id' => 'CWE-89',
            'references' => array(
                'https://developer.wordpress.org/reference/classes/wpdb/prepare/'
            )
        ),
        'improper_prepare_usage' => array(
            'pattern' => '/\$wpdb->prepare\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'medium',
            'confidence' => 0.7,
            'description' => 'User input passed directly to wpdb::prepare()',
            'cwe_id' => 'CWE-89',
            'references' => array()
        ),
        'custom_sql_functions' => array(
            'pattern' => '/(?:mysql_query|mysqli_query|pg_query)\s*\([^)]*\$_(?:GET|POST|REQUEST)/i',
            'severity' => 'critical',
            'confidence' => 0.95,
            'description' => 'Raw SQL function with user input',
            'cwe_id' => 'CWE-89',
            'references' => array()
        ),
        'meta_query_injection' => array(
            'pattern' => '/(?:meta_(?:key|value|query)|get_(?:user|post)_meta)\s*\([^)]*\$_(?:GET|POST|REQUEST)/i',
            'severity' => 'high',
            'confidence' => 0.7,
            'description' => 'User input in meta query without sanitization',
            'cwe_id' => 'CWE-89',
            'references' => array()
        )
    ),

    'advanced_patterns' => array(
        'blind_injection' => array(
            'pattern' => '/\$wpdb->(?:query|get_(?:var|row|col|results))\s*\([^)]*(?:SLEEP|BENCHMARK|WAITFOR)\s*\(/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'Time-based blind SQL injection pattern',
            'cwe_id' => 'CWE-89',
            'references' => array()
        ),
        'union_injection' => array(
            'pattern' => '/\$wpdb->(?:query|get_(?:var|row|col|results))\s*\([^)]*UNION(?:\s+ALL)?\s+SELECT/i',
            'severity' => 'high',
            'confidence' => 0.75,
            'description' => 'UNION-based SQL injection pattern',
            'cwe_id' => 'CWE-89',
            'references' => array()
        ),
        'error_based_injection' => array(
            'pattern' => '/\$wpdb->(?:query|get_(?:var|row|col|results))\s*\([^)]*(?:extractvalue|updatexml|exp)\s*\(/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'Error-based SQL injection pattern',
            'cwe_id' => 'CWE-89',
            'references' => array()
        ),
        'order_by_injection' => array(
            'pattern' => '/ORDER\s+BY\s+["\']?\$\w+["\']?(?!\s+(?:ASC|DESC))/i',
            'severity' => 'medium',
            'confidence' => 0.6,
            'description' => 'Potential ORDER BY injection',
            'cwe_id' => 'CWE-89',
            'references' => array()
        )
    ),

    'filter_evasion' => array(
        'comment_evasion' => array(
            'pattern' => '/\$wpdb->(?:query|get_(?:var|row|col|results))\s*\([^)]*\/\*.*?\*\//s',
            'severity' => 'medium',
            'confidence' => 0.6,
            'description' => 'SQL comment in query (potential evasion)',
            'cwe_id' => 'CWE-89',
            'references' => array()
        ),
        'encoded_input' => array(
            'pattern' => '/(?:urldecode|base64_decode|hex2bin)\s*\(\s*\$_(?:GET|POST|REQUEST)/i',
            'severity' => 'medium',
            'confidence' => 0.5,
            'description' => 'Decoded user input may bypass filters',
            'cwe_id' => 'CWE-89',
            'references' => array()
        ),
        'case_manipulation' => array(
            'pattern' => '/(?:strtoupper|strtolower)\s*\(\s*\$_(?:GET|POST|REQUEST)/i',
            'severity' => 'low',
            'confidence' => 0.4,
            'description' => 'Case manipulation may bypass filters',
            'cwe_id' => 'CWE-89',
            'references' => array()
        )
    ),

    'dangerous_functions' => array(
        'eval_with_sql' => array(
            'pattern' => '/eval\s*\([^)]*\$wpdb/i',
            'severity' => 'critical',
            'confidence' => 0.9,
            'description' => 'eval() with database operations',
            'cwe_id' => 'CWE-94',
            'references' => array()
        ),
        'create_function_sql' => array(
            'pattern' => '/create_function\s*\([^)]*\$wpdb/i',
            'severity' => 'critical',
            'confidence' => 0.9,
            'description' => 'create_function() with database operations',
            'cwe_id' => 'CWE-94',
            'references' => array()
        ),
        'preg_replace_e_sql' => array(
            'pattern' => '/preg_replace\s*\([^,]*\/[^\/]*e[^\/]*\/[^,]*,[^,]*\$wpdb/i',
            'severity' => 'critical',
            'confidence' => 0.85,
            'description' => 'preg_replace /e modifier with database operations',
            'cwe_id' => 'CWE-94',
            'references' => array()
        )
    ),

    'sanitization_bypass' => array(
        'incomplete_sanitization' => array(
            'pattern' => '/(?:stripslashes|addslashes)\s*\(\s*\$_(?:GET|POST|REQUEST)[^)]*\).*?\$wpdb/i',
            'severity' => 'medium',
            'confidence' => 0.6,
            'description' => 'Weak sanitization before database operation',
            'cwe_id' => 'CWE-89',
            'references' => array()
        ),
        'double_sanitization' => array(
            'pattern' => '/(?:sanitize_\w+|esc_sql)\s*\(\s*(?:sanitize_\w+|esc_sql)\s*\(/i',
            'severity' => 'low',
            'confidence' => 0.3,
            'description' => 'Double sanitization may indicate confusion',
            'cwe_id' => 'CWE-89',
            'references' => array()
        ),
        'wrong_sanitization' => array(
            'pattern' => '/(?:sanitize_email|sanitize_url)\s*\([^)]*\).*?\$wpdb->.*?WHERE.*?LIKE/i',
            'severity' => 'medium',
            'confidence' => 0.5,
            'description' => 'Wrong sanitization function for SQL context',
            'cwe_id' => 'CWE-89',
            'references' => array()
        )
    ),

    'context_specific' => array(
        'search_injection' => array(
            'pattern' => '/\$wpdb->(?:query|get_(?:var|row|col|results))\s*\([^)]*LIKE\s*["\']%[^"\']*\$_(?:GET|POST|REQUEST)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'User input in LIKE clause without escaping',
            'cwe_id' => 'CWE-89',
            'references' => array()
        ),
        'limit_injection' => array(
            'pattern' => '/\$wpdb->(?:query|get_(?:var|row|col|results))\s*\([^)]*LIMIT\s+\$_(?:GET|POST|REQUEST)/i',
            'severity' => 'medium',
            'confidence' => 0.7,
            'description' => 'User input in LIMIT clause',
            'cwe_id' => 'CWE-89',
            'references' => array()
        ),
        'where_injection' => array(
            'pattern' => '/\$wpdb->(?:query|get_(?:var|row|col|results))\s*\([^)]*WHERE\s+[^=]*=\s*["\']?\$_(?:GET|POST|REQUEST)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'User input in WHERE clause without preparation',
            'cwe_id' => 'CWE-89',
            'references' => array()
        )
    ),

    'stored_procedures' => array(
        'procedure_call' => array(
            'pattern' => '/\$wpdb->(?:query|get_(?:var|row|col|results))\s*\([^)]*(?:CALL|EXEC)\s+\w+\s*\([^)]*\$_(?:GET|POST|REQUEST)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'User input in stored procedure call',
            'cwe_id' => 'CWE-89',
            'references' => array()
        )
    ),

    'second_order' => array(
        'stored_user_input' => array(
            'pattern' => '/get_(?:option|user_meta|post_meta)\s*\([^)]*\).*?\$wpdb->(?:query|get_(?:var|row|col|results))/s',
            'severity' => 'medium',
            'confidence' => 0.4,
            'description' => 'Stored user data used in SQL query (potential second-order injection)',
            'cwe_id' => 'CWE-89',
            'references' => array()
        ),
        'session_data_in_sql' => array(
            'pattern' => '/\$_SESSION\s*\[[^\]]*\].*?\$wpdb->(?:query|get_(?:var|row|col|results))/s',
            'severity' => 'medium',
            'confidence' => 0.5,
            'description' => 'Session data used in SQL query without validation',
            'cwe_id' => 'CWE-89',
            'references' => array()
        )
    ),

    'wordpress_queries' => array(
        'wp_query_injection' => array(
            'pattern' => '/new\s+WP_Query\s*\([^)]*\$_(?:GET|POST|REQUEST)/i',
            'severity' => 'medium',
            'confidence' => 0.6,
            'description' => 'User input in WP_Query without sanitization',
            'cwe_id' => 'CWE-89',
            'references' => array()
        ),
        'get_posts_injection' => array(
            'pattern' => '/get_posts\s*\([^)]*\$_(?:GET|POST|REQUEST)/i',
            'severity' => 'medium',
            'confidence' => 0.6,
            'description' => 'User input in get_posts() without sanitization',
            'cwe_id' => 'CWE-89',
            'references' => array()
        ),
        'custom_post_query' => array(
            'pattern' => '/\$wpdb->posts.*?WHERE.*?\$_(?:GET|POST|REQUEST)/i',
            'severity' => 'high',
            'confidence' => 0.7,
            'description' => 'User input in direct posts table query',
            'cwe_id' => 'CWE-89',
            'references' => array()
        )
    ),

    'numeric_injection' => array(
        'untyped_numeric' => array(
            'pattern' => '/\$wpdb->(?:query|get_(?:var|row|col|results))\s*\([^)]*=\s*\$_(?:GET|POST|REQUEST)\s*[^)]*\)/i',
            'severity' => 'medium',
            'confidence' => 0.5,
            'description' => 'Numeric user input without type casting',
            'cwe_id' => 'CWE-89',
            'references' => array()
        ),
        'missing_intval' => array(
            'pattern' => '/\$wpdb->(?:query|get_(?:var|row|col|results))\s*\([^)]*(?:user_id|post_id|term_id)\s*=\s*\$_(?:GET|POST|REQUEST)(?![^)]*(?:intval|absint|\(int\)))/i',
            'severity' => 'medium',
            'confidence' => 0.7,
            'description' => 'ID parameter without integer validation',
            'cwe_id' => 'CWE-89',
            'references' => array()
        )
    )
);
