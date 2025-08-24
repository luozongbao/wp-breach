<?php
/**
 * User Management System Test File
 * 
 * This file tests the functionality of Issue #010 - User Management and Permissions System
 * Run this file to verify that all components are working correctly.
 *
 * @package WP_Breach
 * @since   1.0.0
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Test class for User Management System
 */
class WP_Breach_User_Management_Test {

	/**
	 * Run all tests
	 */
	public static function run_tests() {
		echo "<h2>WP-Breach User Management System Tests</h2>";
		
		// Test 1: Check if classes are loaded
		self::test_classes_loaded();
		
		// Test 2: Check if database tables exist
		self::test_database_tables();
		
		// Test 3: Check if custom roles exist
		self::test_custom_roles();
		
		// Test 4: Check if capabilities are working
		self::test_capabilities();
		
		// Test 5: Test audit logging
		self::test_audit_logging();
		
		// Test 6: Test permission checking
		self::test_permission_checking();
		
		echo "<h3>✅ All tests completed!</h3>";
	}

	/**
	 * Test if all required classes are loaded
	 */
	private static function test_classes_loaded() {
		echo "<h3>Test 1: Checking if classes are loaded...</h3>";
		
		$required_classes = array(
			'WP_Breach_Permissions_Manager',
			'WP_Breach_Audit_Logger', 
			'WP_Breach_Capability_Checker',
			'WP_Breach_User_Management_Admin'
		);
		
		foreach ( $required_classes as $class ) {
			if ( class_exists( $class ) ) {
				echo "✅ {$class} - Loaded<br>";
			} else {
				echo "❌ {$class} - Not loaded<br>";
			}
		}
	}

	/**
	 * Test if database tables exist
	 */
	private static function test_database_tables() {
		global $wpdb;
		
		echo "<h3>Test 2: Checking database tables...</h3>";
		
		$required_tables = array(
			$wpdb->prefix . 'wp_breach_audit_logs',
			$wpdb->prefix . 'wp_breach_delegations',
			$wpdb->prefix . 'wp_breach_user_sessions'
		);
		
		foreach ( $required_tables as $table ) {
			$table_exists = $wpdb->get_var( $wpdb->prepare(
				"SHOW TABLES LIKE %s",
				$table
			) ) === $table;
			
			if ( $table_exists ) {
				echo "✅ {$table} - Exists<br>";
			} else {
				echo "❌ {$table} - Missing<br>";
			}
		}
	}

	/**
	 * Test if custom roles exist
	 */
	private static function test_custom_roles() {
		echo "<h3>Test 3: Checking custom roles...</h3>";
		
		$custom_roles = array(
			'wp_breach_security_admin',
			'wp_breach_security_manager',
			'wp_breach_security_analyst',
			'wp_breach_security_viewer'
		);
		
		foreach ( $custom_roles as $role_name ) {
			$role = get_role( $role_name );
			if ( $role ) {
				echo "✅ {$role_name} - Exists<br>";
			} else {
				echo "❌ {$role_name} - Missing<br>";
			}
		}
	}

	/**
	 * Test capabilities functionality
	 */
	private static function test_capabilities() {
		echo "<h3>Test 4: Testing capabilities...</h3>";
		
		if ( class_exists( 'WP_Breach_Capability_Checker' ) ) {
			$capability_checker = new WP_Breach_Capability_Checker();
			
			// Test with current user
			$current_user = wp_get_current_user();
			
			if ( $current_user && $current_user->ID > 0 ) {
				$test_capabilities = array(
					'wp_breach_run_scans',
					'wp_breach_manage_users',
					'wp_breach_view_reports'
				);
				
				foreach ( $test_capabilities as $capability ) {
					$has_capability = $capability_checker->user_can( $current_user->ID, $capability );
					$status = $has_capability ? "✅" : "⚠️";
					echo "{$status} User {$current_user->user_login} - {$capability}<br>";
				}
			} else {
				echo "⚠️ No user logged in to test capabilities<br>";
			}
		} else {
			echo "❌ WP_Breach_Capability_Checker class not available<br>";
		}
	}

	/**
	 * Test audit logging functionality
	 */
	private static function test_audit_logging() {
		echo "<h3>Test 5: Testing audit logging...</h3>";
		
		if ( class_exists( 'WP_Breach_Audit_Logger' ) ) {
			$audit_logger = new WP_Breach_Audit_Logger();
			
			// Test logging an action
			$test_logged = $audit_logger->log_action(
				get_current_user_id(),
				'test_action',
				get_current_user_id(),
				array( 'test' => 'User Management System Test' )
			);
			
			if ( $test_logged ) {
				echo "✅ Audit logging - Working<br>";
			} else {
				echo "❌ Audit logging - Failed<br>";
			}
		} else {
			echo "❌ WP_Breach_Audit_Logger class not available<br>";
		}
	}

	/**
	 * Test permission checking functionality
	 */
	private static function test_permission_checking() {
		echo "<h3>Test 6: Testing permission checking...</h3>";
		
		if ( class_exists( 'WP_Breach_Permissions_Manager' ) ) {
			$permissions_manager = new WP_Breach_Permissions_Manager();
			
			// Test getting user roles
			$current_user = wp_get_current_user();
			if ( $current_user && $current_user->ID > 0 ) {
				$user_roles = $permissions_manager->get_user_wp_breach_roles( $current_user->ID );
				
				if ( is_array( $user_roles ) ) {
					echo "✅ Permission checking - Working<br>";
					echo "   User roles: " . implode( ', ', $user_roles ) . "<br>";
				} else {
					echo "❌ Permission checking - Failed to get user roles<br>";
				}
			} else {
				echo "⚠️ No user logged in to test permission checking<br>";
			}
		} else {
			echo "❌ WP_Breach_Permissions_Manager class not available<br>";
		}
	}
}

// Run tests if this file is accessed directly in debug mode
if ( defined( 'WP_DEBUG' ) && WP_DEBUG && isset( $_GET['test_user_management'] ) ) {
	// Make sure WordPress is loaded
	if ( function_exists( 'wp_get_current_user' ) ) {
		WP_Breach_User_Management_Test::run_tests();
	} else {
		echo "WordPress not loaded. Cannot run tests.";
	}
}
