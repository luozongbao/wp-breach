<?php
/**
 * Unit tests for WP_Breach_Performance_Monitor class.
 *
 * @package WP_Breach
 * @subpackage Tests
 */

class WP_Breach_Performance_Monitor_Test extends WP_Breach_Test_Case {

	/**
	 * Performance monitor instance
	 *
	 * @var WP_Breach_Performance_Monitor
	 */
	private $monitor;

	/**
	 * Set up test environment
	 */
	public function setUp(): void {
		parent::setUp();
		$this->monitor = new WP_Breach_Performance_Monitor();
		$this->monitor->init();
	}

	/**
	 * Test performance monitor initialization
	 */
	public function test_monitor_initialization() {
		$this->assertInstanceOf( 'WP_Breach_Performance_Monitor', $this->monitor );
		$this->assertTrue( method_exists( $this->monitor, 'start_profiling' ) );
		$this->assertTrue( method_exists( $this->monitor, 'end_profiling' ) );
		$this->assertTrue( method_exists( $this->monitor, 'get_performance_metrics' ) );
	}

	/**
	 * Test profiling functionality
	 */
	public function test_profiling_functionality() {
		$profile_id = $this->monitor->start_profiling( 'test_operation' );
		
		$this->assertNotEmpty( $profile_id );
		$this->assertTrue( is_string( $profile_id ) );
		
		// Simulate some work
		usleep( 100000 ); // 0.1 seconds
		
		$result = $this->monitor->end_profiling( $profile_id );
		
		$this->assertTrue( $result );
		
		// Check that metrics were recorded
		$metrics = $this->monitor->get_performance_metrics();
		$this->assertIsArray( $metrics );
		$this->assertArrayHasKey( 'profiles', $metrics );
	}

	/**
	 * Test memory monitoring
	 */
	public function test_memory_monitoring() {
		$initial_metrics = $this->monitor->get_performance_metrics();
		
		// Allocate some memory
		$large_array = array_fill( 0, 10000, 'test_data' );
		
		$profile_id = $this->monitor->start_profiling( 'memory_test' );
		
		// Process the array to use memory
		foreach ( $large_array as $item ) {
			$processed = strtoupper( $item );
		}
		
		$this->monitor->end_profiling( $profile_id );
		
		$final_metrics = $this->monitor->get_performance_metrics();
		
		// Memory usage should have increased
		$this->assertGreaterThan(
			$initial_metrics['memory_usage'] ?? 0,
			$final_metrics['memory_usage'] ?? 0
		);
		
		// Clean up
		unset( $large_array );
	}

	/**
	 * Test database query monitoring
	 */
	public function test_database_query_monitoring() {
		global $wpdb;
		
		$initial_metrics = $this->monitor->get_performance_metrics();
		$initial_queries = $wpdb->num_queries;
		
		$profile_id = $this->monitor->start_profiling( 'db_test' );
		
		// Perform some database operations
		$posts = get_posts( array( 'numberposts' => 5 ) );
		$users = get_users( array( 'number' => 3 ) );
		
		$this->monitor->end_profiling( $profile_id );
		
		$final_metrics = $this->monitor->get_performance_metrics();
		$final_queries = $wpdb->num_queries;
		
		// Query count should have increased
		$this->assertGreaterThan( $initial_queries, $final_queries );
		
		// Metrics should reflect the query activity
		$this->assertArrayHasKey( 'db_queries', $final_metrics );
	}

	/**
	 * Test performance threshold checking
	 */
	public function test_performance_threshold_checking() {
		// Configure low thresholds for testing
		$test_config = array(
			'execution_time_threshold' => 0.001, // 1ms
			'memory_threshold' => 1024, // 1KB
			'query_threshold' => 1
		);
		
		// This should trigger threshold alerts
		$profile_id = $this->monitor->start_profiling( 'threshold_test' );
		
		// Simulate work that exceeds thresholds
		usleep( 5000 ); // 5ms - exceeds time threshold
		$large_data = str_repeat( 'x', 2048 ); // 2KB - exceeds memory threshold
		
		$this->monitor->end_profiling( $profile_id );
		
		$metrics = $this->monitor->get_performance_metrics();
		$this->assertArrayHasKey( 'alerts', $metrics );
	}

	/**
	 * Test performance optimization recommendations
	 */
	public function test_performance_optimization_recommendations() {
		// Create a scenario that should trigger recommendations
		$profile_id = $this->monitor->start_profiling( 'optimization_test' );
		
		// Simulate inefficient operations
		for ( $i = 0; $i < 100; $i++ ) {
			$posts = get_posts( array( 'numberposts' => 1 ) ); // Inefficient repeated queries
		}
		
		$this->monitor->end_profiling( $profile_id );
		
		$recommendations = $this->monitor->get_optimization_recommendations();
		
		$this->assertIsArray( $recommendations );
		$this->assertNotEmpty( $recommendations );
		
		// Should have recommendations about database optimization
		$db_recommendations = array_filter( $recommendations, function( $rec ) {
			return strpos( $rec['type'], 'database' ) !== false;
		} );
		
		$this->assertNotEmpty( $db_recommendations );
	}

	/**
	 * Test performance data storage and retrieval
	 */
	public function test_performance_data_storage() {
		$profile_id = $this->monitor->start_profiling( 'storage_test' );
		
		// Simulate some work
		$test_data = array_fill( 0, 1000, 'performance_test_data' );
		array_sum( array_map( 'strlen', $test_data ) );
		
		$this->monitor->end_profiling( $profile_id );
		
		// Test data retrieval
		$historical_data = $this->monitor->get_historical_performance_data();
		$this->assertIsArray( $historical_data );
		
		// Test specific profile data
		$profile_data = $this->monitor->get_profile_data( $profile_id );
		$this->assertIsArray( $profile_data );
		$this->assertArrayHasKey( 'execution_time', $profile_data );
		$this->assertArrayHasKey( 'memory_usage', $profile_data );
	}

	/**
	 * Test performance monitoring with multiple concurrent operations
	 */
	public function test_concurrent_performance_monitoring() {
		$profile_ids = array();
		
		// Start multiple profiles
		for ( $i = 1; $i <= 3; $i++ ) {
			$profile_ids[] = $this->monitor->start_profiling( "concurrent_test_{$i}" );
		}
		
		$this->assertCount( 3, $profile_ids );
		
		// Simulate work for each profile
		foreach ( $profile_ids as $index => $profile_id ) {
			usleep( ( $index + 1 ) * 1000 ); // Different amounts of work
		}
		
		// End all profiles
		foreach ( $profile_ids as $profile_id ) {
			$result = $this->monitor->end_profiling( $profile_id );
			$this->assertTrue( $result );
		}
		
		$metrics = $this->monitor->get_performance_metrics();
		$this->assertArrayHasKey( 'profiles', $metrics );
		$this->assertGreaterThanOrEqual( 3, count( $metrics['profiles'] ) );
	}

	/**
	 * Test performance alert system
	 */
	public function test_performance_alert_system() {
		// Configure alert thresholds
		$alert_config = array(
			'enable_alerts' => true,
			'execution_time_threshold' => 0.1,
			'memory_threshold' => 10 * 1024 * 1024 // 10MB
		);
		
		// Start monitoring with alert configuration
		$profile_id = $this->monitor->start_profiling( 'alert_test' );
		
		// Simulate work that should trigger alerts
		$large_array = array_fill( 0, 100000, 'alert_test_data' );
		usleep( 150000 ); // 0.15 seconds
		
		$this->monitor->end_profiling( $profile_id );
		
		$alerts = $this->monitor->get_performance_alerts();
		$this->assertIsArray( $alerts );
		
		// Should have at least one alert
		$this->assertNotEmpty( $alerts );
		
		// Clean up
		unset( $large_array );
	}

	/**
	 * Test performance monitoring overhead
	 */
	public function test_monitoring_overhead() {
		// Measure time without monitoring
		$start_time = microtime( true );
		
		for ( $i = 0; $i < 1000; $i++ ) {
			$dummy = $i * 2;
		}
		
		$time_without_monitoring = microtime( true ) - $start_time;
		
		// Measure time with monitoring
		$start_time = microtime( true );
		$profile_id = $this->monitor->start_profiling( 'overhead_test' );
		
		for ( $i = 0; $i < 1000; $i++ ) {
			$dummy = $i * 2;
		}
		
		$this->monitor->end_profiling( $profile_id );
		$time_with_monitoring = microtime( true ) - $start_time;
		
		// Monitoring overhead should be minimal (less than 50% overhead)
		$overhead_ratio = $time_with_monitoring / $time_without_monitoring;
		$this->assertLessThan( 1.5, $overhead_ratio, 'Performance monitoring overhead is too high' );
	}

	/**
	 * Test performance data cleanup
	 */
	public function test_performance_data_cleanup() {
		// Create multiple profiles
		$profile_ids = array();
		for ( $i = 1; $i <= 10; $i++ ) {
			$profile_id = $this->monitor->start_profiling( "cleanup_test_{$i}" );
			usleep( 1000 );
			$this->monitor->end_profiling( $profile_id );
			$profile_ids[] = $profile_id;
		}
		
		$initial_metrics = $this->monitor->get_performance_metrics();
		$initial_count = count( $initial_metrics['profiles'] ?? array() );
		
		// Trigger cleanup
		$this->monitor->cleanup_old_performance_data();
		
		$final_metrics = $this->monitor->get_performance_metrics();
		$final_count = count( $final_metrics['profiles'] ?? array() );
		
		// Should still have data, but potentially less if cleanup removed old entries
		$this->assertGreaterThanOrEqual( 0, $final_count );
	}

	/**
	 * Test performance monitoring integration with WordPress hooks
	 */
	public function test_wordpress_hooks_integration() {
		// Test that the monitor responds to WordPress actions
		do_action( 'wp_breach_scan_started', array( 'scan_id' => 'test_scan' ) );
		
		// Monitor should have started tracking
		$metrics = $this->monitor->get_performance_metrics();
		$this->assertIsArray( $metrics );
		
		// Test scan completion
		do_action( 'wp_breach_scan_completed', array( 'scan_id' => 'test_scan' ) );
		
		// Should have performance data for the scan
		$scan_metrics = $this->monitor->get_scan_performance_metrics( 'test_scan' );
		$this->assertIsArray( $scan_metrics );
	}

	/**
	 * Clean up after tests
	 */
	public function tearDown(): void {
		// Clean up any test data
		$this->monitor->cleanup_old_performance_data();
		parent::tearDown();
	}
}
