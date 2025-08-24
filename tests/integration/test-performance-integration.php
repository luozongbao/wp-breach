<?php
/**
 * Integration tests for WP-Breach performance optimization system.
 *
 * @package WP_Breach
 * @subpackage Tests
 */

class WP_Breach_Performance_Integration_Test extends WP_Breach_Test_Case {

	/**
	 * Performance monitor instance
	 *
	 * @var WP_Breach_Performance_Monitor
	 */
	private $performance_monitor;

	/**
	 * Cache manager instance
	 *
	 * @var WP_Breach_Cache_Manager
	 */
	private $cache_manager;

	/**
	 * Database optimizer instance
	 *
	 * @var WP_Breach_DB_Optimizer
	 */
	private $db_optimizer;

	/**
	 * Scan optimizer instance
	 *
	 * @var WP_Breach_Scan_Optimizer
	 */
	private $scan_optimizer;

	/**
	 * Memory manager instance
	 *
	 * @var WP_Breach_Memory_Manager
	 */
	private $memory_manager;

	/**
	 * Set up integration test environment
	 */
	public function setUp(): void {
		parent::setUp();
		
		// Initialize all performance components
		$this->performance_monitor = new WP_Breach_Performance_Monitor();
		$this->cache_manager = new WP_Breach_Cache_Manager();
		$this->db_optimizer = new WP_Breach_DB_Optimizer();
		$this->scan_optimizer = new WP_Breach_Scan_Optimizer();
		$this->memory_manager = new WP_Breach_Memory_Manager();
		
		// Initialize all components
		$this->performance_monitor->init();
		$this->db_optimizer->init();
		$this->scan_optimizer->init();
		$this->memory_manager->init();
	}

	/**
	 * Test complete scan performance optimization workflow
	 */
	public function test_complete_scan_performance_workflow() {
		// Create test files for scanning
		$test_files = $this->create_test_files( 50 );
		
		// Start performance monitoring for the entire workflow
		$workflow_profile = $this->performance_monitor->start_profiling( 'complete_scan_workflow' );
		
		// Prepare scan optimization
		$scan_data = array(
			'scan_id' => 'integration_test_scan',
			'scan_type' => 'full',
			'file_count' => count( $test_files )
		);
		
		$this->scan_optimizer->prepare_scan_optimization( $scan_data );
		
		// Optimize file list
		$optimized_files = $this->scan_optimizer->optimize_file_list( $test_files, array(
			'enable_filtering' => true,
			'enable_optimization' => true
		) );
		
		$this->assertIsArray( $optimized_files );
		$this->assertLessThanOrEqual( count( $test_files ), count( $optimized_files ) );
		
		// Calculate optimal batch size
		$batch_size = $this->scan_optimizer->calculate_optimal_batch_size( 10, array(
			'total_files' => count( $optimized_files ),
			'average_file_size' => 1024
		) );
		
		$this->assertIsInt( $batch_size );
		$this->assertGreaterThan( 0, $batch_size );
		
		// Test memory optimization during scan
		$memory_before = $this->memory_manager->get_memory_statistics();
		$this->memory_manager->optimize_memory_usage( 'conservative' );
		$memory_after = $this->memory_manager->get_memory_statistics();
		
		$this->assertLessThanOrEqual(
			$memory_before['current_usage'],
			$memory_after['current_usage']
		);
		
		// Test database optimization for scan queries
		$db_optimization_result = $this->db_optimizer->optimize_scan_queries();
		$this->assertTrue( $db_optimization_result );
		
		// Simulate scan processing with caching
		$scan_results = array();
		foreach ( array_chunk( $optimized_files, $batch_size ) as $batch_index => $batch_files ) {
			$batch_profile = $this->performance_monitor->start_profiling( "batch_{$batch_index}" );
			
			// Simulate scanning each file in the batch
			foreach ( $batch_files as $file_path ) {
				$file_hash = md5_file( $file_path );
				
				// Check cache first
				$cached_result = $this->scan_optimizer->get_cached_scan_result( $file_path, $file_hash );
				
				if ( $cached_result === false ) {
					// Simulate scan operation
					$scan_result = array(
						'file' => $file_path,
						'vulnerabilities' => array(), // No vulnerabilities in test files
						'scan_time' => microtime( true )
					);
					
					// Cache the result
					$this->scan_optimizer->implement_smart_caching( $file_path, $scan_result, $file_hash );
				} else {
					$scan_result = $cached_result;
				}
				
				$scan_results[] = $scan_result;
			}
			
			// Monitor memory usage during batch processing
			$this->memory_manager->monitor_memory_usage( "batch_{$batch_index}", 'batch_processing' );
			$this->performance_monitor->end_profiling( $batch_profile );
		}
		
		// Finalize scan optimization
		$this->scan_optimizer->finalize_scan_optimization( array(
			'scan_id' => 'integration_test_scan',
			'results' => $scan_results
		) );
		
		// End workflow monitoring
		$this->performance_monitor->end_profiling( $workflow_profile );
		
		// Verify performance metrics
		$performance_metrics = $this->performance_monitor->get_performance_metrics();
		$this->assertArrayHasKey( 'profiles', $performance_metrics );
		
		// Verify cache statistics
		$cache_stats = $this->cache_manager->get_cache_statistics();
		$this->assertArrayHasKey( 'hit_rate', $cache_stats );
		
		// Verify memory management
		$memory_stats = $this->memory_manager->get_memory_statistics();
		$this->assertArrayHasKey( 'current_usage', $memory_stats );
		
		// Clean up test files
		$this->cleanup_test_files( $test_files );
		
		// Assert overall performance is acceptable
		$this->assertTestPerformanceAcceptable( array(
			'max_execution_time' => 60,  // 60 seconds for integration test
			'max_memory_usage' => 256 * 1024 * 1024  // 256MB
		) );
	}

	/**
	 * Test performance system integration with database operations
	 */
	public function test_database_performance_integration() {
		global $wpdb;
		
		// Start monitoring database operations
		$db_profile = $this->performance_monitor->start_profiling( 'database_integration_test' );
		
		// Create test data for database operations
		$test_vulnerabilities = array();
		for ( $i = 1; $i <= 20; $i++ ) {
			$vulnerability = $this->create_test_vulnerability( array(
				'component_name' => "test-component-{$i}",
				'severity' => $i % 3 === 0 ? 'high' : ( $i % 2 === 0 ? 'medium' : 'low' )
			) );
			$test_vulnerabilities[] = $vulnerability;
		}
		
		// Test database query optimization with caching
		$query = "SELECT component_type, COUNT(*) as count FROM {$wpdb->prefix}wp_breach_vulnerabilities WHERE severity = %s GROUP BY component_type";
		
		// First query - should hit database
		$results_first = $this->db_optimizer->cache_frequent_queries(
			'vulnerability_count_by_severity',
			$query,
			array( 'high' ),
			300
		);
		
		// Second query - should hit cache
		$results_second = $this->db_optimizer->cache_frequent_queries(
			'vulnerability_count_by_severity',
			$query,
			array( 'high' ),
			300
		);
		
		$this->assertEquals( $results_first, $results_second );
		
		// Test slow query analysis
		$slow_query_analysis = $this->db_optimizer->analyze_slow_queries( 'day' );
		$this->assertIsArray( $slow_query_analysis );
		$this->assertArrayHasKey( 'total_slow_queries', $slow_query_analysis );
		
		// Test query pagination
		$paginated_results = $this->db_optimizer->implement_query_pagination(
			"SELECT * FROM {$wpdb->prefix}wp_breach_vulnerabilities ORDER BY id",
			5,  // page size
			1,  // page number
			array()
		);
		
		$this->assertArrayHasKey( 'data', $paginated_results );
		$this->assertArrayHasKey( 'pagination', $paginated_results );
		$this->assertLessThanOrEqual( 5, count( $paginated_results['data'] ) );
		
		// End database monitoring
		$this->performance_monitor->end_profiling( $db_profile );
		
		// Verify database optimization effectiveness
		$connection_performance = $this->db_optimizer->get_connection_performance();
		$this->assertIsArray( $connection_performance );
		$this->assertArrayHasKey( 'query_cache_hit_rate', $connection_performance );
	}

	/**
	 * Test cache system integration across all components
	 */
	public function test_cache_system_integration() {
		// Test cross-component cache interaction
		$scan_data = array(
			'scan_id' => 'cache_integration_test',
			'vulnerabilities' => array(
				array( 'type' => 'xss', 'severity' => 'high' ),
				array( 'type' => 'sql_injection', 'severity' => 'critical' )
			)
		);
		
		// Cache scan results
		$cache_result = $this->cache_manager->cache_scan_results( 'cache_integration_test', $scan_data );
		$this->assertTrue( $cache_result );
		
		// Test cache warming with performance monitoring
		$warm_profile = $this->performance_monitor->start_profiling( 'cache_warming' );
		
		$warm_data = array(
			'frequent_query_1' => array( 'result' => 'data1' ),
			'frequent_query_2' => array( 'result' => 'data2' ),
			'frequent_query_3' => array( 'result' => 'data3' )
		);
		
		$warm_result = $this->cache_manager->warm_cache( $warm_data, 'performance_cache' );
		$this->assertTrue( $warm_result );
		
		$this->performance_monitor->end_profiling( $warm_profile );
		
		// Test cache invalidation performance
		$invalidation_profile = $this->performance_monitor->start_profiling( 'cache_invalidation' );
		
		$invalidation_result = $this->cache_manager->clear_cache_group( 'performance_cache' );
		$this->assertTrue( $invalidation_result );
		
		$this->performance_monitor->end_profiling( $invalidation_profile );
		
		// Verify cache operations were monitored
		$metrics = $this->performance_monitor->get_performance_metrics();
		$cache_profiles = array_filter( $metrics['profiles'] ?? array(), function( $profile ) {
			return strpos( $profile['operation'] ?? '', 'cache' ) !== false;
		} );
		
		$this->assertNotEmpty( $cache_profiles );
	}

	/**
	 * Test memory management integration during intensive operations
	 */
	public function test_memory_management_integration() {
		// Start memory monitoring
		$memory_profile = $this->performance_monitor->start_profiling( 'memory_integration_test' );
		$this->memory_manager->create_memory_checkpoint( 'integration_test_start' );
		
		// Simulate memory-intensive operations
		$large_datasets = array();
		for ( $i = 1; $i <= 10; $i++ ) {
			// Create large data structures
			$large_data = array_fill( 0, 1000, "Large dataset item {$i}: " . str_repeat( 'x', 100 ) );
			$large_datasets[] = $large_data;
			
			// Monitor memory usage at each step
			$memory_status = $this->memory_manager->monitor_memory_usage( 'memory_test', "step_{$i}" );
			
			// Trigger memory optimization if usage gets high
			if ( $memory_status['usage_percentage'] > 70 ) {
				$optimization_result = $this->memory_manager->optimize_memory_usage( 'conservative' );
				$this->assertIsArray( $optimization_result );
			}
		}
		
		// Test garbage collection integration
		$gc_result = $this->memory_manager->implement_garbage_collection( true );
		$this->assertIsArray( $gc_result );
		$this->assertTrue( $gc_result['executed'] );
		
		// Test memory cleanup
		$cleanup_result = $this->memory_manager->clear_memory_allocations( array(
			'clear_temporary_data' => true,
			'unset_large_variables' => true
		) );
		$this->assertTrue( $cleanup_result );
		
		// End memory monitoring
		$this->performance_monitor->end_profiling( $memory_profile );
		
		// Verify memory management effectiveness
		$memory_stats = $this->memory_manager->get_memory_statistics();
		$this->assertLessThan( 90, $memory_stats['usage_percentage'], 'Memory usage is too high after optimization' );
		
		// Clean up large datasets
		unset( $large_datasets );
	}

	/**
	 * Test performance alerting system integration
	 */
	public function test_performance_alerting_integration() {
		// Configure alert thresholds for testing
		$alert_config = array(
			'memory_threshold' => 50,  // Low threshold for testing
			'execution_time_threshold' => 0.1,
			'db_query_threshold' => 10
		);
		
		// Start operation that should trigger alerts
		$alert_profile = $this->performance_monitor->start_profiling( 'alert_integration_test' );
		
		// Trigger memory alert
		$large_array = array_fill( 0, 100000, 'alert_test_data' );
		$memory_status = $this->memory_manager->monitor_memory_usage( 'alert_test', 'memory_spike' );
		
		// Trigger execution time alert
		usleep( 150000 ); // 0.15 seconds
		
		// Trigger database query alert
		global $wpdb;
		for ( $i = 1; $i <= 15; $i++ ) {
			$wpdb->get_var( "SELECT {$i}" );
		}
		
		$this->performance_monitor->end_profiling( $alert_profile );
		
		// Check for alerts
		$performance_alerts = $this->performance_monitor->get_performance_alerts();
		$memory_alerts = $this->memory_manager->get_memory_statistics();
		
		$this->assertIsArray( $performance_alerts );
		$this->assertArrayHasKey( 'memory_alerts', $memory_alerts );
		
		// Clean up
		unset( $large_array );
	}

	/**
	 * Test complete performance optimization cycle
	 */
	public function test_complete_optimization_cycle() {
		// Start comprehensive performance monitoring
		$cycle_profile = $this->performance_monitor->start_profiling( 'optimization_cycle_test' );
		
		// Phase 1: Baseline performance measurement
		$baseline_memory = $this->memory_manager->get_memory_statistics();
		$baseline_db = $this->db_optimizer->get_connection_performance();
		$baseline_cache = $this->cache_manager->get_cache_statistics();
		
		// Phase 2: Simulate workload
		$test_files = $this->create_test_files( 30 );
		$scan_results = array();
		
		foreach ( $test_files as $file ) {
			$file_hash = md5_file( $file );
			$scan_result = array(
				'file' => $file,
				'hash' => $file_hash,
				'vulnerabilities' => array(),
				'processed_at' => microtime( true )
			);
			
			// Cache the result
			$this->cache_manager->set_cached_data(
				"scan_result_{$file_hash}",
				$scan_result,
				300,
				'optimization_cycle'
			);
			
			$scan_results[] = $scan_result;
		}
		
		// Phase 3: Apply optimizations
		$memory_optimization = $this->memory_manager->optimize_memory_usage( 'auto' );
		$db_optimization = $this->db_optimizer->optimize_scan_queries();
		$cache_optimization = $this->cache_manager->warm_cache( array(
			'optimized_data' => $scan_results
		), 'optimization_results' );
		
		// Phase 4: Measure post-optimization performance
		$optimized_memory = $this->memory_manager->get_memory_statistics();
		$optimized_db = $this->db_optimizer->get_connection_performance();
		$optimized_cache = $this->cache_manager->get_cache_statistics();
		
		// Phase 5: Verify optimization effectiveness
		$this->assertLessThanOrEqual(
			$baseline_memory['current_usage'],
			$optimized_memory['current_usage'],
			'Memory optimization should not increase usage'
		);
		
		$this->assertTrue( $db_optimization, 'Database optimization should succeed' );
		$this->assertTrue( $cache_optimization, 'Cache optimization should succeed' );
		
		// End cycle monitoring
		$this->performance_monitor->end_profiling( $cycle_profile );
		
		// Generate comprehensive optimization report
		$optimization_report = array(
			'baseline_metrics' => array(
				'memory' => $baseline_memory,
				'database' => $baseline_db,
				'cache' => $baseline_cache
			),
			'optimized_metrics' => array(
				'memory' => $optimized_memory,
				'database' => $optimized_db,
				'cache' => $optimized_cache
			),
			'optimization_results' => array(
				'memory_optimization' => $memory_optimization,
				'db_optimization' => $db_optimization,
				'cache_optimization' => $cache_optimization
			)
		);
		
		$this->assertIsArray( $optimization_report );
		$this->assertArrayHasKey( 'baseline_metrics', $optimization_report );
		$this->assertArrayHasKey( 'optimized_metrics', $optimization_report );
		
		// Clean up
		$this->cleanup_test_files( $test_files );
		$this->cache_manager->clear_cache_group( 'optimization_cycle' );
		$this->cache_manager->clear_cache_group( 'optimization_results' );
	}

	/**
	 * Test performance system under stress conditions
	 */
	public function test_performance_system_stress_test() {
		// Only run stress test if enabled
		if ( ! defined( 'WP_BREACH_TEST_LARGE_DATASETS' ) || ! WP_BREACH_TEST_LARGE_DATASETS ) {
			$this->markTestSkipped( 'Large dataset testing is disabled' );
		}
		
		$stress_profile = $this->performance_monitor->start_profiling( 'stress_test' );
		
		// Create large number of test files
		$stress_files = $this->create_test_files( 200 );
		
		// Simulate concurrent operations
		$concurrent_operations = array();
		
		for ( $i = 1; $i <= 5; $i++ ) {
			$operation_profile = $this->performance_monitor->start_profiling( "concurrent_operation_{$i}" );
			
			// Simulate different types of stress
			switch ( $i % 3 ) {
				case 0:
					// Memory stress
					$stress_data = array_fill( 0, 10000, "stress_data_{$i}" );
					break;
				case 1:
					// Database stress
					for ( $j = 1; $j <= 50; $j++ ) {
						$this->db_optimizer->cache_frequent_queries(
							"stress_query_{$i}_{$j}",
							"SELECT {$j} as test_value",
							array(),
							60
						);
					}
					break;
				case 2:
					// Cache stress
					for ( $j = 1; $j <= 100; $j++ ) {
						$this->cache_manager->set_cached_data(
							"stress_cache_{$i}_{$j}",
							array( 'stress' => true, 'value' => $j ),
							300,
							'stress_test'
						);
					}
					break;
			}
			
			$this->performance_monitor->end_profiling( $operation_profile );
			$concurrent_operations[] = $operation_profile;
		}
		
		// Monitor system stability during stress
		$stress_memory = $this->memory_manager->get_memory_statistics();
		$this->assertLessThan( 95, $stress_memory['usage_percentage'], 'Memory usage too high during stress test' );
		
		// Apply emergency optimizations if needed
		if ( $stress_memory['usage_percentage'] > 85 ) {
			$emergency_optimization = $this->memory_manager->optimize_memory_usage( 'emergency' );
			$this->assertIsArray( $emergency_optimization );
		}
		
		$this->performance_monitor->end_profiling( $stress_profile );
		
		// Verify system recovery
		$recovery_memory = $this->memory_manager->get_memory_statistics();
		$this->assertLessThan( 80, $recovery_memory['usage_percentage'], 'System did not recover properly from stress' );
		
		// Clean up stress test data
		$this->cleanup_test_files( $stress_files );
		$this->cache_manager->clear_cache_group( 'stress_test' );
		$this->memory_manager->cleanup_old_performance_data();
	}

	/**
	 * Clean up after integration tests
	 */
	public function tearDown(): void {
		// Clean up all test data
		$this->cache_manager->clear_cache_group( 'integration_test' );
		$this->cache_manager->clear_cache_group( 'performance_cache' );
		$this->memory_manager->final_memory_cleanup();
		$this->db_optimizer->cleanup_old_performance_data();
		
		parent::tearDown();
	}
}
