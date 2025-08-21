<?php
/**
 * WP-Breach Database Test Script
 * 
 * This script helps test the database implementation.
 * Place this file in wp-content/plugins/wp-breach/ and run it via WordPress admin.
 */

// Exit if not in WordPress environment
if ( ! defined( 'WPINC' ) ) {
    die( 'Direct access denied.' );
}

/**
 * Test WP-Breach database implementation
 */
function wp_breach_test_database() {
    // Load the database class
    require_once WP_BREACH_PLUGIN_DIR . 'includes/class-wp-breach-database.php';
    
    $database = new WP_Breach_Database();
    
    echo "<h2>WP-Breach Database Test Results</h2>";
    
    // Test 1: Check if tables can be created
    echo "<h3>1. Database Table Creation Test</h3>";
    $tables_created = $database->create_tables();
    if ( $tables_created ) {
        echo "<p style='color: green;'>✅ Database tables created successfully!</p>";
    } else {
        echo "<p style='color: red;'>❌ Failed to create database tables.</p>";
        return;
    }
    
    // Test 2: Check table statistics
    echo "<h3>2. Table Statistics</h3>";
    $stats = $database->get_table_stats();
    echo "<table border='1' style='border-collapse: collapse;'>";
    echo "<tr><th>Table</th><th>Count</th></tr>";
    foreach ( $stats as $table => $data ) {
        echo "<tr><td>{$data['label']}</td><td>{$data['count']}</td></tr>";
    }
    echo "</table>";
    
    // Test 3: Test model loading
    echo "<h3>3. Model Loading Test</h3>";
    try {
        $scan_model = $database->get_scan_model();
        echo "<p style='color: green;'>✅ Scan model loaded successfully</p>";
        
        $vuln_model = $database->get_vulnerability_model();
        echo "<p style='color: green;'>✅ Vulnerability model loaded successfully</p>";
        
        $fix_model = $database->get_fix_model();
        echo "<p style='color: green;'>✅ Fix model loaded successfully</p>";
        
        $settings_model = $database->get_settings_model();
        echo "<p style='color: green;'>✅ Settings model loaded successfully</p>";
        
        $alert_model = $database->get_alert_model();
        echo "<p style='color: green;'>✅ Alert model loaded successfully</p>";
        
    } catch ( Exception $e ) {
        echo "<p style='color: red;'>❌ Model loading failed: " . $e->getMessage() . "</p>";
    }
    
    // Test 4: Test basic CRUD operations
    echo "<h3>4. Basic CRUD Operations Test</h3>";
    try {
        // Test settings
        $settings_model = $database->get_settings_model();
        $test_set = $settings_model->set_setting( 'test', 'database_test', 'working', 'string', 'Database test setting' );
        $test_get = $settings_model->get_setting( 'test', 'database_test' );
        
        if ( $test_set && $test_get === 'working' ) {
            echo "<p style='color: green;'>✅ Settings CRUD operations working</p>";
        } else {
            echo "<p style='color: red;'>❌ Settings CRUD operations failed</p>";
        }
        
        // Test scan creation
        $scan_model = $database->get_scan_model();
        $scan_id = $scan_model->create_scan( array(
            'scan_type' => 'quick',
            'status' => 'pending',
            'created_by' => get_current_user_id()
        ) );
        
        if ( $scan_id ) {
            echo "<p style='color: green;'>✅ Scan creation working (ID: {$scan_id})</p>";
            
            // Test scan retrieval
            $scan = $scan_model->get( $scan_id );
            if ( $scan && $scan->scan_type === 'quick' ) {
                echo "<p style='color: green;'>✅ Scan retrieval working</p>";
            } else {
                echo "<p style='color: red;'>❌ Scan retrieval failed</p>";
            }
        } else {
            echo "<p style='color: red;'>❌ Scan creation failed</p>";
        }
        
    } catch ( Exception $e ) {
        echo "<p style='color: red;'>❌ CRUD operations failed: " . $e->getMessage() . "</p>";
    }
    
    // Test 5: Database version
    echo "<h3>5. Database Version Test</h3>";
    $db_version = $database->get_db_version();
    $migration_version = $database->get_migration_version();
    echo "<p>Current DB Version: <strong>{$db_version}</strong></p>";
    echo "<p>Migration Version: <strong>{$migration_version}</strong></p>";
    
    if ( version_compare( $migration_version, $db_version, '>=' ) ) {
        echo "<p style='color: green;'>✅ Database is up to date</p>";
    } else {
        echo "<p style='color: orange;'>⚠️ Database migration may be needed</p>";
    }
}

// Add admin page for testing
function wp_breach_add_test_page() {
    add_management_page(
        'WP-Breach DB Test',
        'WP-Breach DB Test',
        'manage_options',
        'wp-breach-db-test',
        'wp_breach_test_database'
    );
}

// Only add the test page if WP-Breach constants are defined
if ( defined( 'WP_BREACH_VERSION' ) ) {
    add_action( 'admin_menu', 'wp_breach_add_test_page' );
}
