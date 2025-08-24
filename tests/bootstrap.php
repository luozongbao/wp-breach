<?php
/**
 * PHPUnit bootstrap file for WP-Breach plugin testing.
 *
 * This file sets up the WordPress testing environment and loads
 * the plugin for comprehensive testing.
 *
 * @package WP_Breach
 * @subpackage Tests
 */

// Enable error reporting for testing
error_reporting( E_ALL );
ini_set( 'display_errors', 1 );

// Define testing environment
if ( ! defined( 'WP_BREACH_TESTING' ) ) {
	define( 'WP_BREACH_TESTING', true );
}

// WordPress tests directory
$_tests_dir = getenv( 'WP_TESTS_DIR' );
if ( ! $_tests_dir ) {
	$_tests_dir = '/tmp/wordpress-tests-lib';
}

// WordPress core directory
$_core_dir = getenv( 'WP_CORE_DIR' );
if ( ! $_core_dir ) {
	$_core_dir = '/tmp/wordpress/';
}

// Plugin directory
$_plugin_dir = dirname( dirname( __FILE__ ) );

// Load WordPress test functions
require_once $_tests_dir . '/includes/functions.php';

/**
 * Manually load the plugin being tested.
 */
function _manually_load_plugin() {
	global $_plugin_dir;
	require $_plugin_dir . '/wp-breach.php';
}
tests_add_filter( 'muplugins_loaded', '_manually_load_plugin' );

/**
 * Set up testing database and configuration
 */
function _setup_test_environment() {
	// Create test database tables
	if ( class_exists( 'WP_Breach_Activator' ) ) {
		WP_Breach_Activator::activate();
	}
	
	// Set up test data
	_create_test_data();
	
	// Initialize performance monitoring for tests
	if ( class_exists( 'WP_Breach_Performance_Monitor' ) ) {
		$performance_monitor = new WP_Breach_Performance_Monitor();
		$performance_monitor->init();
	}
}
tests_add_filter( 'wp_install', '_setup_test_environment' );

/**
 * Create test data for testing scenarios
 */
function _create_test_data() {
	// Create test users with different roles
	$admin_user = wp_create_user( 'test_admin', 'test_password', 'admin@test.com' );
	$editor_user = wp_create_user( 'test_editor', 'test_password', 'editor@test.com' );
	$subscriber_user = wp_create_user( 'test_subscriber', 'test_password', 'subscriber@test.com' );
	
	// Assign roles
	$admin = new WP_User( $admin_user );
	$admin->set_role( 'administrator' );
	
	$editor = new WP_User( $editor_user );
	$editor->set_role( 'editor' );
	
	$subscriber = new WP_User( $subscriber_user );
	$subscriber->set_role( 'subscriber' );
	
	// Create test posts and pages
	wp_insert_post( array(
		'post_title' => 'Test Post',
		'post_content' => 'This is a test post for WP-Breach testing.',
		'post_status' => 'publish',
		'post_type' => 'post',
		'post_author' => $admin_user
	) );
	
	wp_insert_post( array(
		'post_title' => 'Test Page',
		'post_content' => 'This is a test page for WP-Breach testing.',
		'post_status' => 'publish',
		'post_type' => 'page',
		'post_author' => $admin_user
	) );
	
	// Set up test options
	update_option( 'wp_breach_test_environment', true );
	update_option( 'wp_breach_test_data_created', time() );
}

/**
 * Custom assertion functions for WP-Breach testing
 */
class WP_Breach_Test_Assertions {
	
	/**
	 * Assert that a vulnerability scan result is valid
	 *
	 * @param array $scan_result Scan result to validate
	 */
	public static function assertValidScanResult( $scan_result ) {
		PHPUnit\Framework\Assert::assertIsArray( $scan_result );
		PHPUnit\Framework\Assert::assertArrayHasKey( 'scan_id', $scan_result );
		PHPUnit\Framework\Assert::assertArrayHasKey( 'status', $scan_result );
		PHPUnit\Framework\Assert::assertArrayHasKey( 'vulnerabilities', $scan_result );
		PHPUnit\Framework\Assert::assertIsArray( $scan_result['vulnerabilities'] );
	}
	
	/**
	 * Assert that performance metrics are within acceptable ranges
	 *
	 * @param array $metrics Performance metrics
	 * @param array $thresholds Acceptable thresholds
	 */
	public static function assertPerformanceWithinThresholds( $metrics, $thresholds = array() ) {
		$default_thresholds = array(
			'max_execution_time' => 30,  // 30 seconds
			'max_memory_usage' => 128 * 1024 * 1024,  // 128MB
			'max_db_queries' => 100
		);
		
		$thresholds = array_merge( $default_thresholds, $thresholds );
		
		if ( isset( $metrics['execution_time'] ) ) {
			PHPUnit\Framework\Assert::assertLessThan(
				$thresholds['max_execution_time'],
				$metrics['execution_time'],
				'Execution time exceeds threshold'
			);
		}
		
		if ( isset( $metrics['memory_usage'] ) ) {
			PHPUnit\Framework\Assert::assertLessThan(
				$thresholds['max_memory_usage'],
				$metrics['memory_usage'],
				'Memory usage exceeds threshold'
			);
		}
		
		if ( isset( $metrics['db_queries'] ) ) {
			PHPUnit\Framework\Assert::assertLessThan(
				$thresholds['max_db_queries'],
				$metrics['db_queries'],
				'Database queries exceed threshold'
			);
		}
	}
	
	/**
	 * Assert that cache is working properly
	 *
	 * @param string $cache_key Cache key to test
	 * @param mixed $expected_value Expected cached value
	 */
	public static function assertCacheWorking( $cache_key, $expected_value = null ) {
		if ( function_exists( 'wp_cache_get' ) ) {
			$cached_value = wp_cache_get( $cache_key );
			
			if ( $expected_value !== null ) {
				PHPUnit\Framework\Assert::assertEquals( $expected_value, $cached_value );
			} else {
				PHPUnit\Framework\Assert::assertNotFalse( $cached_value, 'Cache miss when hit expected' );
			}
		}
	}
	
	/**
	 * Assert that database optimization is effective
	 *
	 * @param array $before_metrics Metrics before optimization
	 * @param array $after_metrics Metrics after optimization
	 */
	public static function assertDatabaseOptimizationEffective( $before_metrics, $after_metrics ) {
		// Query time should improve or stay the same
		if ( isset( $before_metrics['average_query_time'] ) && isset( $after_metrics['average_query_time'] ) ) {
			PHPUnit\Framework\Assert::assertLessThanOrEqual(
				$before_metrics['average_query_time'],
				$after_metrics['average_query_time'],
				'Database optimization did not improve query time'
			);
		}
		
		// Query count should not increase significantly
		if ( isset( $before_metrics['total_queries'] ) && isset( $after_metrics['total_queries'] ) ) {
			$query_increase = $after_metrics['total_queries'] - $before_metrics['total_queries'];
			$acceptable_increase = $before_metrics['total_queries'] * 0.1; // 10% increase max
			
			PHPUnit\Framework\Assert::assertLessThanOrEqual(
				$acceptable_increase,
				$query_increase,
				'Database optimization caused excessive query increase'
			);
		}
	}
}

/**
 * Base test case class for WP-Breach tests
 */
abstract class WP_Breach_Test_Case extends WP_UnitTestCase {
	
	/**
	 * Performance monitor for testing
	 *
	 * @var WP_Breach_Performance_Monitor
	 */
	protected $performance_monitor;
	
	/**
	 * Cache manager for testing
	 *
	 * @var WP_Breach_Cache_Manager
	 */
	protected $cache_manager;
	
	/**
	 * Set up test environment
	 */
	public function setUp(): void {
		parent::setUp();
		
		// Initialize performance monitoring
		if ( class_exists( 'WP_Breach_Performance_Monitor' ) ) {
			$this->performance_monitor = new WP_Breach_Performance_Monitor();
			$this->performance_monitor->init();
		}
		
		// Initialize cache manager
		if ( class_exists( 'WP_Breach_Cache_Manager' ) ) {
			$this->cache_manager = new WP_Breach_Cache_Manager();
		}
		
		// Clear any existing cache
		wp_cache_flush();
		
		// Start performance profiling for test
		if ( $this->performance_monitor ) {
			$this->performance_monitor->start_profiling( $this->getName() );
		}
	}
	
	/**
	 * Tear down test environment
	 */
	public function tearDown(): void {
		// End performance profiling
		if ( $this->performance_monitor ) {
			$this->performance_monitor->end_profiling( $this->getName() );
		}
		
		// Clean up cache
		wp_cache_flush();
		
		parent::tearDown();
	}
	
	/**
	 * Create test vulnerability data
	 *
	 * @param array $overrides Override default values
	 * @return array Vulnerability data
	 */
	protected function create_test_vulnerability( $overrides = array() ) {
		$defaults = array(
			'component_type' => 'plugin',
			'component_name' => 'test-plugin',
			'component_version' => '1.0.0',
			'vulnerability_type' => 'xss',
			'severity' => 'medium',
			'description' => 'Test vulnerability for unit testing',
			'status' => 'active',
			'detected_at' => current_time( 'mysql' )
		);
		
		return array_merge( $defaults, $overrides );
	}
	
	/**
	 * Create test scan data
	 *
	 * @param array $overrides Override default values
	 * @return array Scan data
	 */
	protected function create_test_scan( $overrides = array() ) {
		$defaults = array(
			'scan_type' => 'full',
			'status' => 'completed',
			'started_at' => current_time( 'mysql' ),
			'completed_at' => current_time( 'mysql' ),
			'files_scanned' => 100,
			'vulnerabilities_found' => 0,
			'created_by' => 1
		);
		
		return array_merge( $defaults, $overrides );
	}
	
	/**
	 * Create test files for scanning
	 *
	 * @param int $count Number of test files to create
	 * @return array List of created file paths
	 */
	protected function create_test_files( $count = 10 ) {
		$files = array();
		$upload_dir = wp_upload_dir();
		$test_dir = $upload_dir['basedir'] . '/wp-breach-test/';
		
		if ( ! wp_mkdir_p( $test_dir ) ) {
			return $files;
		}
		
		for ( $i = 1; $i <= $count; $i++ ) {
			$file_path = $test_dir . "test-file-{$i}.php";
			$content = "<?php\n// Test file {$i} for WP-Breach testing\necho 'Hello World {$i}';\n";
			
			if ( file_put_contents( $file_path, $content ) !== false ) {
				$files[] = $file_path;
			}
		}
		
		return $files;
	}
	
	/**
	 * Clean up test files
	 *
	 * @param array $files List of files to clean up
	 */
	protected function cleanup_test_files( $files ) {
		foreach ( $files as $file ) {
			if ( file_exists( $file ) ) {
				unlink( $file );
			}
		}
		
		// Remove test directory if empty
		$upload_dir = wp_upload_dir();
		$test_dir = $upload_dir['basedir'] . '/wp-breach-test/';
		if ( is_dir( $test_dir ) && count( scandir( $test_dir ) ) === 2 ) {
			rmdir( $test_dir );
		}
	}
	
	/**
	 * Get performance metrics for current test
	 *
	 * @return array Performance metrics
	 */
	protected function get_test_performance_metrics() {
		if ( ! $this->performance_monitor ) {
			return array();
		}
		
		return $this->performance_monitor->get_performance_metrics();
	}
	
	/**
	 * Assert test performance is acceptable
	 *
	 * @param array $custom_thresholds Custom performance thresholds
	 */
	protected function assertTestPerformanceAcceptable( $custom_thresholds = array() ) {
		$metrics = $this->get_test_performance_metrics();
		WP_Breach_Test_Assertions::assertPerformanceWithinThresholds( $metrics, $custom_thresholds );
	}
}

// Load WordPress test environment
require_once $_tests_dir . '/includes/bootstrap.php';

// Make test assertions globally available
if ( ! function_exists( 'assertValidScanResult' ) ) {
	function assertValidScanResult( $scan_result ) {
		WP_Breach_Test_Assertions::assertValidScanResult( $scan_result );
	}
}

if ( ! function_exists( 'assertPerformanceWithinThresholds' ) ) {
	function assertPerformanceWithinThresholds( $metrics, $thresholds = array() ) {
		WP_Breach_Test_Assertions::assertPerformanceWithinThresholds( $metrics, $thresholds );
	}
}

if ( ! function_exists( 'assertCacheWorking' ) ) {
	function assertCacheWorking( $cache_key, $expected_value = null ) {
		WP_Breach_Test_Assertions::assertCacheWorking( $cache_key, $expected_value );
	}
}

if ( ! function_exists( 'assertDatabaseOptimizationEffective' ) ) {
	function assertDatabaseOptimizationEffective( $before_metrics, $after_metrics ) {
		WP_Breach_Test_Assertions::assertDatabaseOptimizationEffective( $before_metrics, $after_metrics );
	}
}

// Output test environment information
echo "WP-Breach Testing Environment Initialized\n";
echo "WordPress Tests Directory: {$_tests_dir}\n";
echo "WordPress Core Directory: {$_core_dir}\n";
echo "Plugin Directory: {$_plugin_dir}\n";
echo "Testing Database: " . ( defined( 'DB_NAME' ) ? DB_NAME : 'Not Set' ) . "\n";
echo "Performance Testing: " . ( defined( 'WP_BREACH_TEST_PERFORMANCE' ) && WP_BREACH_TEST_PERFORMANCE ? 'Enabled' : 'Disabled' ) . "\n";
echo "Large Dataset Testing: " . ( defined( 'WP_BREACH_TEST_LARGE_DATASETS' ) && WP_BREACH_TEST_LARGE_DATASETS ? 'Enabled' : 'Disabled' ) . "\n\n";
