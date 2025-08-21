<?php
/**
 * Scanner Test File
 *
 * Test the scanner implementation to verify Issue #003 functionality.
 *
 * @package WP_Breach
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Only run in debug mode
if (!defined('WP_DEBUG') || !WP_DEBUG) {
    return;
}

/**
 * Test Scanner Implementation
 */
function wp_breach_test_scanner() {
    error_log('WP Breach: Testing Scanner Implementation');
    
    try {
        // Test 1: Scanner Factory
        echo "<h3>Testing Scanner Factory</h3>";
        
        $available_types = WP_Breach_Scanner_Factory::get_available_types();
        echo "<p>Available scanner types: " . implode(', ', $available_types) . "</p>";
        
        // Test 2: Create Core Scanner
        echo "<h3>Testing Core Scanner Creation</h3>";
        
        $core_scanner = WP_Breach_Scanner_Factory::create('core');
        if (is_wp_error($core_scanner)) {
            echo "<p style='color: red;'>Error creating core scanner: " . $core_scanner->get_error_message() . "</p>";
        } else {
            echo "<p style='color: green;'>Core scanner created successfully</p>";
            echo "<p>Scanner metadata: " . print_r($core_scanner->get_metadata(), true) . "</p>";
        }
        
        // Test 3: Create Plugin Scanner
        echo "<h3>Testing Plugin Scanner Creation</h3>";
        
        $plugin_scanner = WP_Breach_Scanner_Factory::create('plugin');
        if (is_wp_error($plugin_scanner)) {
            echo "<p style='color: red;'>Error creating plugin scanner: " . $plugin_scanner->get_error_message() . "</p>";
        } else {
            echo "<p style='color: green;'>Plugin scanner created successfully</p>";
            echo "<p>Supported vulnerabilities: " . implode(', ', $plugin_scanner->get_supported_vulnerabilities()) . "</p>";
        }
        
        // Test 4: Main Scanner
        echo "<h3>Testing Main Scanner</h3>";
        
        $main_scanner = new WP_Breach_Scanner();
        $init_result = $main_scanner->initialize(array(
            'scanner_types' => array('core', 'plugin'),
            'enable_progress_tracking' => true,
            'enable_detailed_logging' => true
        ));
        
        if ($init_result) {
            echo "<p style='color: green;'>Main scanner initialized successfully</p>";
            echo "<p>Scanner status: " . $main_scanner->get_status() . "</p>";
        } else {
            echo "<p style='color: red;'>Failed to initialize main scanner</p>";
        }
        
        // Test 5: SQL Injection Detector
        echo "<h3>Testing SQL Injection Detector</h3>";
        
        $sql_detector = new WP_Breach_SQL_Injection_Detector();
        $test_code = 'echo "SELECT * FROM table WHERE id = " . $_GET["id"];';
        $vulnerabilities = $sql_detector->detect($test_code, 'test.php');
        
        echo "<p>Test code: <code>" . esc_html($test_code) . "</code></p>";
        echo "<p>Vulnerabilities found: " . count($vulnerabilities) . "</p>";
        
        if (!empty($vulnerabilities)) {
            echo "<pre>" . print_r($vulnerabilities[0], true) . "</pre>";
        }
        
        // Test 6: XSS Detector
        echo "<h3>Testing XSS Detector</h3>";
        
        $xss_detector = new WP_Breach_XSS_Detector();
        $test_code = 'echo $_GET["message"];';
        $vulnerabilities = $xss_detector->detect($test_code, 'test.php');
        
        echo "<p>Test code: <code>" . esc_html($test_code) . "</code></p>";
        echo "<p>Vulnerabilities found: " . count($vulnerabilities) . "</p>";
        
        if (!empty($vulnerabilities)) {
            echo "<pre>" . print_r($vulnerabilities[0], true) . "</pre>";
        }
        
        echo "<h3>Scanner Tests Completed Successfully!</h3>";
        
    } catch (Exception $e) {
        echo "<p style='color: red;'>Scanner test error: " . esc_html($e->getMessage()) . "</p>";
        error_log('WP Breach Scanner Test Error: ' . $e->getMessage());
    }
}

// Add admin page for testing
add_action('admin_menu', function() {
    add_submenu_page(
        'wp-breach',
        'Scanner Test',
        'Scanner Test',
        'manage_options',
        'wp-breach-scanner-test',
        'wp_breach_test_scanner'
    );
});
