<?php

/**
 * Cross-Site Scripting (XSS) vulnerability patterns for WP Breach.
 *
 * This file contains regex patterns and signatures for detecting
 * XSS vulnerabilities in WordPress code.
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
 * XSS Patterns
 *
 * Patterns are organized by category and include:
 * - pattern: Regex pattern for detection
 * - severity: Vulnerability severity level
 * - confidence: Detection confidence (0.0-1.0)
 * - description: Human-readable description
 * - cwe_id: Common Weakness Enumeration ID
 * - context: Expected output context (html, js, css, url)
 * - references: Additional information sources
 */
return array(
    'reflected_xss' => array(
        'direct_echo' => array(
            'pattern' => '/echo\s+\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i',
            'severity' => 'high',
            'confidence' => 0.9,
            'description' => 'Direct echo of user input without escaping',
            'cwe_id' => 'CWE-79',
            'context' => 'html',
            'references' => array(
                'https://developer.wordpress.org/plugins/security/securing-output/',
                'https://wordpress.org/support/article/hardening-wordpress/'
            )
        ),
        'print_user_input' => array(
            'pattern' => '/(?:print|printf)\s*\(\s*[^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'high',
            'confidence' => 0.9,
            'description' => 'Print statement with user input without escaping',
            'cwe_id' => 'CWE-79',
            'context' => 'html',
            'references' => array()
        ),
        'html_concatenation' => array(
            'pattern' => '/["\']<[^>]*["\']\.?\s*\$_(?:GET|POST|REQUEST|COOKIE)|["\']<[^>]*["\']\.?\s*\$\w+.*?\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'HTML concatenation with user input',
            'cwe_id' => 'CWE-79',
            'context' => 'html',
            'references' => array()
        ),
        'shortcode_output' => array(
            'pattern' => '/add_shortcode\s*\([^,]*,[^}]*\$_(?:GET|POST|REQUEST|COOKIE)(?![^}]*esc_)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'Shortcode outputs user input without escaping',
            'cwe_id' => 'CWE-79',
            'context' => 'html',
            'references' => array()
        )
    ),

    'stored_xss' => array(
        'unescaped_option' => array(
            'pattern' => '/echo\s+get_option\s*\([^)]*\)(?!\s*\)|[^}]*esc_)/i',
            'severity' => 'medium',
            'confidence' => 0.6,
            'description' => 'Unescaped option output (potential stored XSS)',
            'cwe_id' => 'CWE-79',
            'context' => 'html',
            'references' => array()
        ),
        'unescaped_meta' => array(
            'pattern' => '/echo\s+(?:get_(?:user|post)_meta|get_metadata)\s*\([^)]*\)(?![^}]*esc_)/i',
            'severity' => 'medium',
            'confidence' => 0.6,
            'description' => 'Unescaped metadata output (potential stored XSS)',
            'cwe_id' => 'CWE-79',
            'context' => 'html',
            'references' => array()
        ),
        'comment_content' => array(
            'pattern' => '/echo\s+(?:\$comment->comment_content|get_comment_text)\s*\([^)]*\)(?![^}]*esc_)/i',
            'severity' => 'high',
            'confidence' => 0.7,
            'description' => 'Unescaped comment content output',
            'cwe_id' => 'CWE-79',
            'context' => 'html',
            'references' => array()
        ),
        'post_content' => array(
            'pattern' => '/echo\s+(?:\$post->post_content|get_the_content)\s*\([^)]*\)(?![^}]*esc_)/i',
            'severity' => 'medium',
            'confidence' => 0.5,
            'description' => 'Unescaped post content (may contain user data)',
            'cwe_id' => 'CWE-79',
            'context' => 'html',
            'references' => array()
        )
    ),

    'javascript_context' => array(
        'js_variable_injection' => array(
            'pattern' => '/(?:var|let|const)\s+\w+\s*=\s*["\'][^"\']*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'User input in JavaScript variable without escaping',
            'cwe_id' => 'CWE-79',
            'context' => 'js',
            'references' => array()
        ),
        'js_function_call' => array(
            'pattern' => '/(?:alert|confirm|prompt|eval|setTimeout|setInterval)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'critical',
            'confidence' => 0.9,
            'description' => 'User input in dangerous JavaScript function',
            'cwe_id' => 'CWE-79',
            'context' => 'js',
            'references' => array()
        ),
        'dom_manipulation' => array(
            'pattern' => '/(?:innerHTML|outerHTML|insertAdjacentHTML)\s*[+]?=\s*[^;]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'User input in DOM manipulation without escaping',
            'cwe_id' => 'CWE-79',
            'context' => 'js',
            'references' => array()
        ),
        'wp_localize_script' => array(
            'pattern' => '/wp_localize_script\s*\([^,]*,[^,]*,[^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'medium',
            'confidence' => 0.7,
            'description' => 'User input in wp_localize_script without escaping',
            'cwe_id' => 'CWE-79',
            'context' => 'js',
            'references' => array()
        )
    ),

    'attribute_context' => array(
        'unescaped_attributes' => array(
            'pattern' => '/(?:href|src|onclick|onload|onerror|style|class|id)\s*=\s*["\'][^"\']*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'User input in HTML attribute without escaping',
            'cwe_id' => 'CWE-79',
            'context' => 'attr',
            'references' => array()
        ),
        'data_attributes' => array(
            'pattern' => '/data-[^=]*=\s*["\'][^"\']*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'medium',
            'confidence' => 0.6,
            'description' => 'User input in data attribute without escaping',
            'cwe_id' => 'CWE-79',
            'context' => 'attr',
            'references' => array()
        ),
        'event_attributes' => array(
            'pattern' => '/on\w+\s*=\s*["\'][^"\']*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'critical',
            'confidence' => 0.9,
            'description' => 'User input in event attribute (critical XSS)',
            'cwe_id' => 'CWE-79',
            'context' => 'attr',
            'references' => array()
        )
    ),

    'css_context' => array(
        'style_injection' => array(
            'pattern' => '/style\s*=\s*["\'][^"\']*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'medium',
            'confidence' => 0.7,
            'description' => 'User input in style attribute',
            'cwe_id' => 'CWE-79',
            'context' => 'css',
            'references' => array()
        ),
        'css_property_injection' => array(
            'pattern' => '/(?:background|background-image|content)\s*:\s*[^;]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'medium',
            'confidence' => 0.6,
            'description' => 'User input in CSS property value',
            'cwe_id' => 'CWE-79',
            'context' => 'css',
            'references' => array()
        )
    ),

    'url_context' => array(
        'unescaped_url' => array(
            'pattern' => '/(?:href|src|action)\s*=\s*["\'][^"\']*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'medium',
            'confidence' => 0.7,
            'description' => 'User input in URL without validation',
            'cwe_id' => 'CWE-79',
            'context' => 'url',
            'references' => array()
        ),
        'redirect_injection' => array(
            'pattern' => '/(?:wp_redirect|header\s*\(\s*["\']Location:)\s*[^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'medium',
            'confidence' => 0.8,
            'description' => 'User input in redirect without validation',
            'cwe_id' => 'CWE-601',
            'context' => 'url',
            'references' => array()
        )
    ),

    'wordpress_specific' => array(
        'wp_die_message' => array(
            'pattern' => '/wp_die\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'medium',
            'confidence' => 0.6,
            'description' => 'User input in wp_die message without escaping',
            'cwe_id' => 'CWE-79',
            'context' => 'html',
            'references' => array()
        ),
        'admin_notice' => array(
            'pattern' => '/add_action\s*\(\s*["\']admin_notices["\'].*?echo\s*[^;]*\$_(?:GET|POST|REQUEST|COOKIE)/is',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'User input in admin notice without escaping',
            'cwe_id' => 'CWE-79',
            'context' => 'html',
            'references' => array()
        ),
        'wp_mail_html' => array(
            'pattern' => '/wp_mail\s*\([^)]*["\']text\/html["\'][^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'medium',
            'confidence' => 0.6,
            'description' => 'User input in HTML email without escaping',
            'cwe_id' => 'CWE-79',
            'context' => 'html',
            'references' => array()
        ),
        'widget_output' => array(
            'pattern' => '/(?:widget|before_widget|after_widget)\s*[^;]*echo\s*[^;]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'high',
            'confidence' => 0.7,
            'description' => 'User input in widget output without escaping',
            'cwe_id' => 'CWE-79',
            'context' => 'html',
            'references' => array()
        )
    ),

    'filter_bypass' => array(
        'incomplete_escaping' => array(
            'pattern' => '/htmlspecialchars\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)[^)]*\)(?![^)]*ENT_QUOTES)/i',
            'severity' => 'medium',
            'confidence' => 0.5,
            'description' => 'Incomplete HTML escaping (missing ENT_QUOTES)',
            'cwe_id' => 'CWE-79',
            'context' => 'html',
            'references' => array()
        ),
        'strip_tags_bypass' => array(
            'pattern' => '/strip_tags\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'medium',
            'confidence' => 0.4,
            'description' => 'strip_tags() used for XSS prevention (bypassable)',
            'cwe_id' => 'CWE-79',
            'context' => 'html',
            'references' => array()
        ),
        'wrong_escaping_context' => array(
            'pattern' => '/esc_html\s*\([^)]*\).*?(?:href|src|onclick)\s*=/i',
            'severity' => 'medium',
            'confidence' => 0.6,
            'description' => 'Wrong escaping function for context',
            'cwe_id' => 'CWE-79',
            'context' => 'mixed',
            'references' => array()
        )
    ),

    'template_injection' => array(
        'include_user_input' => array(
            'pattern' => '/(?:include|require)(?:_once)?\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'critical',
            'confidence' => 0.9,
            'description' => 'File inclusion with user input (template injection)',
            'cwe_id' => 'CWE-98',
            'context' => 'file',
            'references' => array()
        ),
        'get_template_part_injection' => array(
            'pattern' => '/get_template_part\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'User input in get_template_part()',
            'cwe_id' => 'CWE-98',
            'context' => 'file',
            'references' => array()
        ),
        'load_template_injection' => array(
            'pattern' => '/load_template\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'User input in load_template()',
            'cwe_id' => 'CWE-98',
            'context' => 'file',
            'references' => array()
        )
    ),

    'dom_xss' => array(
        'document_write' => array(
            'pattern' => '/document\.write\s*\([^)]*(?:location\.|window\.location|document\.URL)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'document.write with location data (DOM XSS)',
            'cwe_id' => 'CWE-79',
            'context' => 'js',
            'references' => array()
        ),
        'location_hash' => array(
            'pattern' => '/(?:innerHTML|outerHTML|insertAdjacentHTML)\s*[+]?=\s*[^;]*(?:location\.hash|window\.location\.hash)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'DOM manipulation with location.hash (DOM XSS)',
            'cwe_id' => 'CWE-79',
            'context' => 'js',
            'references' => array()
        ),
        'url_parameters' => array(
            'pattern' => '/(?:innerHTML|outerHTML|insertAdjacentHTML)\s*[+]?=\s*[^;]*(?:URLSearchParams|new URL)/i',
            'severity' => 'medium',
            'confidence' => 0.6,
            'description' => 'DOM manipulation with URL parameters',
            'cwe_id' => 'CWE-79',
            'context' => 'js',
            'references' => array()
        )
    ),

    'ajax_xss' => array(
        'ajax_response_html' => array(
            'pattern' => '/wp_ajax_\w+[^}]*echo\s*[^;]*\$_(?:GET|POST|REQUEST|COOKIE)/s',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'AJAX response with unescaped user input',
            'cwe_id' => 'CWE-79',
            'context' => 'html',
            'references' => array()
        ),
        'json_response_html' => array(
            'pattern' => '/wp_send_json(?:_success|_error)?\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'medium',
            'confidence' => 0.6,
            'description' => 'JSON response with user input (potential XSS)',
            'cwe_id' => 'CWE-79',
            'context' => 'json',
            'references' => array()
        )
    ),

    'xml_xss' => array(
        'xml_output' => array(
            'pattern' => '/(?:header\s*\(\s*["\']Content-Type:\s*text\/xml|<?xml)[^>]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'medium',
            'confidence' => 0.7,
            'description' => 'User input in XML output without escaping',
            'cwe_id' => 'CWE-79',
            'context' => 'xml',
            'references' => array()
        ),
        'rss_feed' => array(
            'pattern' => '/(?:rss|feed|xml)[^}]*echo\s*[^;]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'medium',
            'confidence' => 0.6,
            'description' => 'User input in RSS/XML feed without escaping',
            'cwe_id' => 'CWE-79',
            'context' => 'xml',
            'references' => array()
        )
    ),

    'svg_xss' => array(
        'svg_content' => array(
            'pattern' => '/(?:header\s*\(\s*["\']Content-Type:\s*image\/svg|<svg)[^>]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'User input in SVG content (XSS via SVG)',
            'cwe_id' => 'CWE-79',
            'context' => 'svg',
            'references' => array()
        )
    ),

    'serialization_xss' => array(
        'unserialize_output' => array(
            'pattern' => '/echo\s*[^;]*unserialize\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'critical',
            'confidence' => 0.9,
            'description' => 'Unserialize with user input and output (critical)',
            'cwe_id' => 'CWE-502',
            'context' => 'mixed',
            'references' => array()
        ),
        'maybe_unserialize_output' => array(
            'pattern' => '/echo\s*[^;]*maybe_unserialize\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'severity' => 'high',
            'confidence' => 0.8,
            'description' => 'maybe_unserialize with user input and output',
            'cwe_id' => 'CWE-502',
            'context' => 'mixed',
            'references' => array()
        )
    )
);
