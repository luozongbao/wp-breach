<?php
/**
 * Performance benchmark tests for WP-Breach plugin.
 *
 * @package WP_Breach
 * @subpackage Tests
 */

class WP_Breach_Performance_Benchmark_Test extends WP_Breach_Test_Case {

	/**
	 * Performance monitor instance
	 *
	 * @var WP_Breach_Performance_Monitor
	 */
	private $performance_monitor;

	/**
	 * Benchmark results
	 *
	 * @var array
	 */
	private $benchmark_results;

	/**
	 * Set up benchmark test environment
	 */
	public function setUp(): void {
		parent::setUp();
		$this->performance_monitor = new WP_Breach_Performance_Monitor();
		$this->performance_monitor->init();
		$this->benchmark_results = array();
	}

	/**
	 * Benchmark scan performance with different file counts
	 */
	public function test_scan_performance_benchmark() {
		$file_counts = array( 10, 50, 100, 250, 500 );
		
		foreach ( $file_counts as $file_count ) {
			$benchmark_key = "scan_performance_{$file_count}_files";
			$profile_id = $this->performance_monitor->start_profiling( $benchmark_key );
			
			// Create test files
			$test_files = $this->create_test_files( $file_count );
			
			// Benchmark scan processing
			$scan_start_time = microtime( true );
			$memory_start = memory_get_usage( true );
			
			$scan_results = array();
			foreach ( $test_files as $file_path ) {
				// Simulate vulnerability scanning
				$file_content = file_get_contents( $file_path );
				$file_hash = md5( $file_content );
				
				// Simulate pattern matching (simplified)
				$vulnerabilities = array();
				if ( strpos( $file_content, 'eval(' ) !== false ) {
					$vulnerabilities[] = array( 'type' => 'code_injection', 'severity' => 'high' );
				}
				if ( strpos( $file_content, '$_GET' ) !== false ) {
					$vulnerabilities[] = array( 'type' => 'xss', 'severity' => 'medium' );
				}
				
				$scan_results[] = array(
					'file' => $file_path,
					'hash' => $file_hash,
					'vulnerabilities' => $vulnerabilities,
					'file_size' => filesize( $file_path )
				);
			}
			
			$scan_end_time = microtime( true );
			$memory_end = memory_get_usage( true );
			
			$this->performance_monitor->end_profiling( $profile_id );
			
			// Record benchmark results
			$this->benchmark_results[ $benchmark_key ] = array(
				'file_count' => $file_count,
				'execution_time' => $scan_end_time - $scan_start_time,
				'memory_used' => $memory_end - $memory_start,
				'files_per_second' => $file_count / ( $scan_end_time - $scan_start_time ),
				'memory_per_file' => ( $memory_end - $memory_start ) / $file_count,
				'vulnerabilities_found' => array_sum( array_map( function( $result ) {
					return count( $result['vulnerabilities'] );
				}, $scan_results ) )
			);
			
			// Clean up test files
			$this->cleanup_test_files( $test_files );
			
			// Performance assertions
			$execution_time = $scan_end_time - $scan_start_time;
			$this->assertLessThan( $file_count * 0.1, $execution_time, "Scan of {$file_count} files took too long" );
			
			$memory_used_mb = ( $memory_end - $memory_start ) / ( 1024 * 1024 );
			$this->assertLessThan( 50, $memory_used_mb, "Scan of {$file_count} files used too much memory" );
		}
		
		// Analyze performance scaling
		$this->analyze_performance_scaling();
	}

	/**
	 * Benchmark database query performance
	 */
	public function test_database_query_performance_benchmark() {
		global $wpdb;
		
		$db_optimizer = new WP_Breach_DB_Optimizer();
		$db_optimizer->init();
		
		// Create test vulnerability data
		$this->create_test_vulnerability_data( 1000 );
		
		$query_types = array(
			'simple_select' => "SELECT COUNT(*) FROM {$wpdb->prefix}wp_breach_vulnerabilities",
			'filtered_select' => "SELECT * FROM {$wpdb->prefix}wp_breach_vulnerabilities WHERE severity = 'high'",
			'grouped_select' => "SELECT component_type, COUNT(*) FROM {$wpdb->prefix}wp_breach_vulnerabilities GROUP BY component_type",
			'joined_select' => "SELECT v.*, s.scan_type FROM {$wpdb->prefix}wp_breach_vulnerabilities v LEFT JOIN {$wpdb->prefix}wp_breach_scans s ON v.scan_id = s.id"
		);
		
		foreach ( $query_types as $query_name => $query ) {
			$benchmark_key = "db_query_{$query_name}";
			$profile_id = $this->performance_monitor->start_profiling( $benchmark_key );
			
			// Benchmark without caching
			$start_time = microtime( true );
			$result_without_cache = $wpdb->get_results( $query );
			$time_without_cache = microtime( true ) - $start_time;
			
			// Benchmark with caching
			$start_time = microtime( true );
			$result_with_cache = $db_optimizer->cache_frequent_queries(
				$query_name,
				$query,
				array(),
				300
			);
			$time_with_cache_miss = microtime( true ) - $start_time;
			
			// Benchmark cache hit
			$start_time = microtime( true );
			$result_cache_hit = $db_optimizer->cache_frequent_queries(
				$query_name,
				$query,
				array(),
				300
			);
			$time_with_cache_hit = microtime( true ) - $start_time;
			
			$this->performance_monitor->end_profiling( $profile_id );
			
			// Record benchmark results
			$this->benchmark_results[ $benchmark_key ] = array(
				'query_type' => $query_name,
				'time_without_cache' => $time_without_cache,
				'time_with_cache_miss' => $time_with_cache_miss,
				'time_with_cache_hit' => $time_with_cache_hit,
				'cache_hit_speedup' => $time_without_cache / $time_with_cache_hit,
				'result_count' => count( $result_without_cache )
			);
			
			// Performance assertions
			$this->assertLessThan( 1.0, $time_without_cache, "Query {$query_name} without cache took too long" );
			$this->assertLessThan( $time_without_cache, $time_with_cache_hit, "Cache hit should be faster than direct query" );
			$this->assertEquals( $result_without_cache, $result_with_cache );
		}
		
		// Test pagination performance
		$this->benchmark_pagination_performance( $db_optimizer );
	}

	/**
	 * Benchmark cache performance
	 */
	public function test_cache_performance_benchmark() {
		$cache_manager = new WP_Breach_Cache_Manager();
		
		$data_sizes = array( 1, 10, 100, 1000, 10000 ); // Number of cache entries
		$data_complexities = array( 'simple', 'complex' );
		
		foreach ( $data_complexities as $complexity ) {
			foreach ( $data_sizes as $size ) {
				$benchmark_key = "cache_performance_{$complexity}_{$size}_entries";
				$profile_id = $this->performance_monitor->start_profiling( $benchmark_key );
				
				// Generate test data
				$test_data = $this->generate_cache_test_data( $size, $complexity );
				
				// Benchmark cache writes
				$write_start_time = microtime( true );
				$write_memory_start = memory_get_usage( true );
				
				foreach ( $test_data as $key => $data ) {
					$cache_manager->set_cached_data( $key, $data, 300, 'benchmark_test' );
				}
				
				$write_end_time = microtime( true );
				$write_memory_end = memory_get_usage( true );
				
				// Benchmark cache reads
				$read_start_time = microtime( true );
				$successful_reads = 0;
				
				foreach ( array_keys( $test_data ) as $key ) {
					$cached_data = $cache_manager->get_cached_data( $key, 'benchmark_test' );
					if ( $cached_data !== false ) {
						$successful_reads++;
					}
				}
				
				$read_end_time = microtime( true );
				
				$this->performance_monitor->end_profiling( $profile_id );
				
				// Record benchmark results
				$this->benchmark_results[ $benchmark_key ] = array(
					'data_complexity' => $complexity,
					'entry_count' => $size,
					'write_time' => $write_end_time - $write_start_time,
					'read_time' => $read_end_time - $read_start_time,
					'write_memory_used' => $write_memory_end - $write_memory_start,
					'successful_reads' => $successful_reads,
					'cache_hit_rate' => ( $successful_reads / $size ) * 100,
					'writes_per_second' => $size / ( $write_end_time - $write_start_time ),
					'reads_per_second' => $size / ( $read_end_time - $read_start_time )
				);
				
				// Performance assertions
				$write_time = $write_end_time - $write_start_time;
				$read_time = $read_end_time - $read_start_time;
				
				$this->assertLessThan( $size * 0.001, $write_time, "Cache writes for {$size} {$complexity} entries took too long" );
				$this->assertLessThan( $size * 0.0005, $read_time, "Cache reads for {$size} {$complexity} entries took too long" );
				$this->assertEquals( $size, $successful_reads, "Not all cache entries were successfully read" );
				$this->assertLessThan( $write_time, $read_time, "Cache reads should be faster than writes" );
				
				// Clean up
				$cache_manager->clear_cache_group( 'benchmark_test' );
			}
		}
	}

	/**
	 * Benchmark memory management performance
	 */
	public function test_memory_management_benchmark() {
		$memory_manager = new WP_Breach_Memory_Manager();
		$memory_manager->init();
		
		$memory_scenarios = array(
			'small_allocations' => 100,
			'medium_allocations' => 1000,
			'large_allocations' => 10000
		);
		
		foreach ( $memory_scenarios as $scenario_name => $allocation_count ) {
			$benchmark_key = "memory_management_{$scenario_name}";
			$profile_id = $this->performance_monitor->start_profiling( $benchmark_key );
			
			// Create memory checkpoint
			$checkpoint_id = "benchmark_{$scenario_name}";
			$memory_manager->create_memory_checkpoint( $checkpoint_id );
			
			$memory_start = memory_get_usage( true );
			$allocation_start_time = microtime( true );
			
			// Allocate memory based on scenario
			$allocated_data = array();
			for ( $i = 1; $i <= $allocation_count; $i++ ) {
				$data_size = $scenario_name === 'large_allocations' ? 1000 : 100;
				$allocated_data[] = array_fill( 0, $data_size, "data_{$i}" );
				
				// Monitor memory usage periodically
				if ( $i % 100 === 0 ) {
					$memory_manager->monitor_memory_usage( $benchmark_key, "allocation_{$i}" );
				}
			}
			
			$allocation_end_time = microtime( true );
			$memory_after_allocation = memory_get_usage( true );
			
			// Benchmark memory optimization
			$optimization_start_time = microtime( true );
			$optimization_result = $memory_manager->optimize_memory_usage( 'auto' );
			$optimization_end_time = microtime( true );
			$memory_after_optimization = memory_get_usage( true );
			
			// Benchmark garbage collection
			$gc_start_time = microtime( true );
			$gc_result = $memory_manager->implement_garbage_collection( true );
			$gc_end_time = microtime( true );
			$memory_after_gc = memory_get_usage( true );
			
			$this->performance_monitor->end_profiling( $profile_id );
			
			// Record benchmark results
			$this->benchmark_results[ $benchmark_key ] = array(
				'scenario' => $scenario_name,
				'allocation_count' => $allocation_count,
				'allocation_time' => $allocation_end_time - $allocation_start_time,
				'optimization_time' => $optimization_end_time - $optimization_start_time,
				'gc_time' => $gc_end_time - $gc_start_time,
				'memory_allocated' => $memory_after_allocation - $memory_start,
				'memory_freed_by_optimization' => $memory_after_allocation - $memory_after_optimization,
				'memory_freed_by_gc' => $memory_after_optimization - $memory_after_gc,
				'total_memory_freed' => $memory_after_allocation - $memory_after_gc,
				'optimization_effectiveness' => ( ( $memory_after_allocation - $memory_after_gc ) / $memory_after_allocation ) * 100
			);
			
			// Performance assertions
			$this->assertLessThan( 5.0, $allocation_end_time - $allocation_start_time, "Memory allocation took too long" );
			$this->assertLessThan( 1.0, $optimization_end_time - $optimization_start_time, "Memory optimization took too long" );
			$this->assertLessThan( 0.5, $gc_end_time - $gc_start_time, "Garbage collection took too long" );
			$this->assertGreaterThan( 0, $memory_after_allocation - $memory_after_gc, "Memory management did not free any memory" );
			
			// Clean up
			unset( $allocated_data );
		}
	}

	/**
	 * Benchmark complete plugin performance under load
	 */
	public function test_complete_plugin_performance_benchmark() {
		// Only run if large dataset testing is enabled
		if ( ! defined( 'WP_BREACH_TEST_LARGE_DATASETS' ) || ! WP_BREACH_TEST_LARGE_DATASETS ) {
			$this->markTestSkipped( 'Large dataset testing is disabled' );
		}
		
		$load_scenarios = array(
			'light_load' => array( 'files' => 100, 'users' => 10, 'scans' => 5 ),
			'medium_load' => array( 'files' => 500, 'users' => 50, 'scans' => 25 ),
			'heavy_load' => array( 'files' => 1000, 'users' => 100, 'scans' => 50 )
		);
		
		foreach ( $load_scenarios as $scenario_name => $scenario_config ) {
			$benchmark_key = "complete_plugin_{$scenario_name}";
			$profile_id = $this->performance_monitor->start_profiling( $benchmark_key );
			
			$scenario_start_time = microtime( true );
			$scenario_memory_start = memory_get_usage( true );
			
			// Initialize all performance components
			$cache_manager = new WP_Breach_Cache_Manager();
			$db_optimizer = new WP_Breach_DB_Optimizer();
			$scan_optimizer = new WP_Breach_Scan_Optimizer();
			$memory_manager = new WP_Breach_Memory_Manager();
			
			$db_optimizer->init();
			$scan_optimizer->init();
			$memory_manager->init();
			
			// Create test data for the scenario
			$test_files = $this->create_test_files( $scenario_config['files'] );
			$this->create_test_vulnerability_data( $scenario_config['scans'] * 10 );
			
			// Simulate multiple concurrent scans
			$scan_results = array();
			for ( $scan_id = 1; $scan_id <= $scenario_config['scans']; $scan_id++ ) {
				$scan_start = microtime( true );
				
				// Optimize file list for scanning
				$file_batch = array_slice( $test_files, ( $scan_id - 1 ) * 20, 20 );
				$optimized_files = $scan_optimizer->optimize_file_list( $file_batch );
				
				// Process files with caching
				$scan_vulnerabilities = array();
				foreach ( $optimized_files as $file ) {
					$file_hash = md5_file( $file );
					$cached_result = $scan_optimizer->get_cached_scan_result( $file, $file_hash );
					
					if ( $cached_result === false ) {
						// Simulate vulnerability scan
						$scan_result = array(
							'file' => $file,
							'vulnerabilities' => array(),
							'scan_time' => microtime( true )
						);
						$scan_optimizer->implement_smart_caching( $file, $scan_result, $file_hash );
					}
				}
				
				$scan_end = microtime( true );
				$scan_results[] = array(
					'scan_id' => $scan_id,
					'duration' => $scan_end - $scan_start,
					'files_processed' => count( $optimized_files )
				);
				
				// Monitor memory during scan
				$memory_manager->monitor_memory_usage( "scan_{$scan_id}", 'processing' );
			}
			
			// Run database optimizations
			$db_optimization_start = microtime( true );
			$db_optimizer->optimize_scan_queries();
			$db_optimization_end = microtime( true );
			
			// Run memory optimization
			$memory_optimization_start = microtime( true );
			$memory_manager->optimize_memory_usage( 'auto' );
			$memory_optimization_end = microtime( true );
			
			$scenario_end_time = microtime( true );
			$scenario_memory_end = memory_get_usage( true );
			
			$this->performance_monitor->end_profiling( $profile_id );
			
			// Record comprehensive benchmark results
			$this->benchmark_results[ $benchmark_key ] = array(
				'scenario' => $scenario_name,
				'scenario_config' => $scenario_config,
				'total_duration' => $scenario_end_time - $scenario_start_time,
				'total_memory_used' => $scenario_memory_end - $scenario_memory_start,
				'scan_results' => $scan_results,
				'avg_scan_duration' => array_sum( array_column( $scan_results, 'duration' ) ) / count( $scan_results ),
				'db_optimization_time' => $db_optimization_end - $db_optimization_start,
				'memory_optimization_time' => $memory_optimization_end - $memory_optimization_start,
				'throughput_files_per_second' => $scenario_config['files'] / ( $scenario_end_time - $scenario_start_time ),
				'memory_efficiency_mb_per_file' => ( ( $scenario_memory_end - $scenario_memory_start ) / ( 1024 * 1024 ) ) / $scenario_config['files']
			);
			
			// Performance assertions for the scenario
			$total_duration = $scenario_end_time - $scenario_start_time;
			$max_duration = $scenario_config['files'] * 0.1 + $scenario_config['scans'] * 2; // Dynamic threshold
			
			$this->assertLessThan( $max_duration, $total_duration, "Complete plugin performance for {$scenario_name} exceeded threshold" );
			
			$memory_used_mb = ( $scenario_memory_end - $scenario_memory_start ) / ( 1024 * 1024 );
			$max_memory = $scenario_config['files'] * 0.1 + 100; // Dynamic memory threshold
			
			$this->assertLessThan( $max_memory, $memory_used_mb, "Memory usage for {$scenario_name} exceeded threshold" );
			
			// Clean up scenario data
			$this->cleanup_test_files( $test_files );
			$cache_manager->clear_cache_group( 'benchmark_test' );
		}
	}

	/**
	 * Generate performance report
	 */
	public function test_generate_performance_report() {
		// This test runs last to generate a comprehensive performance report
		$report = array(
			'test_environment' => array(
				'php_version' => PHP_VERSION,
				'memory_limit' => ini_get( 'memory_limit' ),
				'max_execution_time' => ini_get( 'max_execution_time' ),
				'wordpress_version' => get_bloginfo( 'version' ),
				'test_timestamp' => current_time( 'mysql' )
			),
			'benchmark_results' => $this->benchmark_results,
			'performance_summary' => $this->generate_performance_summary()
		);
		
		// Save report to file
		$report_file = WP_CONTENT_DIR . '/wp-breach-performance-report.json';
		file_put_contents( $report_file, wp_json_encode( $report, JSON_PRETTY_PRINT ) );
		
		$this->assertFileExists( $report_file );
		$this->assertNotEmpty( $this->benchmark_results );
		
		// Output summary to console
		echo "\n\n=== WP-Breach Performance Benchmark Report ===\n";
		echo "Report saved to: {$report_file}\n";
		echo "Total benchmarks run: " . count( $this->benchmark_results ) . "\n";
		
		foreach ( $this->benchmark_results as $benchmark_name => $results ) {
			if ( isset( $results['execution_time'] ) ) {
				echo "{$benchmark_name}: {$results['execution_time']}s\n";
			} elseif ( isset( $results['total_duration'] ) ) {
				echo "{$benchmark_name}: {$results['total_duration']}s\n";
			}
		}
		echo "==========================================\n\n";
	}

	/**
	 * Analyze performance scaling characteristics
	 *
	 * @access private
	 */
	private function analyze_performance_scaling() {
		$scan_benchmarks = array_filter( $this->benchmark_results, function( $key ) {
			return strpos( $key, 'scan_performance_' ) === 0;
		}, ARRAY_FILTER_USE_KEY );
		
		$file_counts = array_column( $scan_benchmarks, 'file_count' );
		$execution_times = array_column( $scan_benchmarks, 'execution_time' );
		
		// Simple linear regression to check scaling
		$n = count( $file_counts );
		$sum_x = array_sum( $file_counts );
		$sum_y = array_sum( $execution_times );
		$sum_xy = 0;
		$sum_x2 = 0;
		
		for ( $i = 0; $i < $n; $i++ ) {
			$sum_xy += $file_counts[$i] * $execution_times[$i];
			$sum_x2 += $file_counts[$i] * $file_counts[$i];
		}
		
		$slope = ( $n * $sum_xy - $sum_x * $sum_y ) / ( $n * $sum_x2 - $sum_x * $sum_x );
		
		// Slope should be reasonable (not exponential growth)
		$this->assertLessThan( 0.01, $slope, 'Performance scaling appears to be worse than linear' );
	}

	/**
	 * Benchmark pagination performance
	 *
	 * @param WP_Breach_DB_Optimizer $db_optimizer Database optimizer instance
	 * @access private
	 */
	private function benchmark_pagination_performance( $db_optimizer ) {
		global $wpdb;
		
		$page_sizes = array( 10, 25, 50, 100 );
		$base_query = "SELECT * FROM {$wpdb->prefix}wp_breach_vulnerabilities ORDER BY id";
		
		foreach ( $page_sizes as $page_size ) {
			$benchmark_key = "pagination_performance_{$page_size}_per_page";
			$profile_id = $this->performance_monitor->start_profiling( $benchmark_key );
			
			$pagination_start_time = microtime( true );
			
			// Test multiple pages
			for ( $page = 1; $page <= 5; $page++ ) {
				$paginated_results = $db_optimizer->implement_query_pagination(
					$base_query,
					$page_size,
					$page,
					array()
				);
				
				$this->assertArrayHasKey( 'data', $paginated_results );
				$this->assertArrayHasKey( 'pagination', $paginated_results );
			}
			
			$pagination_end_time = microtime( true );
			$this->performance_monitor->end_profiling( $profile_id );
			
			$this->benchmark_results[ $benchmark_key ] = array(
				'page_size' => $page_size,
				'pages_tested' => 5,
				'total_time' => $pagination_end_time - $pagination_start_time,
				'avg_time_per_page' => ( $pagination_end_time - $pagination_start_time ) / 5
			);
			
			// Performance assertion
			$avg_time = ( $pagination_end_time - $pagination_start_time ) / 5;
			$this->assertLessThan( 0.1, $avg_time, "Pagination with {$page_size} items per page is too slow" );
		}
	}

	/**
	 * Generate cache test data
	 *
	 * @param int    $count      Number of entries
	 * @param string $complexity Data complexity level
	 * @return array Generated test data
	 * @access private
	 */
	private function generate_cache_test_data( $count, $complexity ) {
		$test_data = array();
		
		for ( $i = 1; $i <= $count; $i++ ) {
			$key = "cache_test_key_{$i}";
			
			if ( $complexity === 'simple' ) {
				$test_data[ $key ] = "simple_cache_value_{$i}";
			} else {
				$test_data[ $key ] = array(
					'id' => $i,
					'data' => str_repeat( "complex_data_{$i}_", 10 ),
					'metadata' => array(
						'created' => time(),
						'type' => 'complex',
						'nested' => array(
							'level1' => array(
								'level2' => "deep_value_{$i}"
							)
						)
					),
					'large_text' => str_repeat( 'Lorem ipsum dolor sit amet. ', 50 )
				);
			}
		}
		
		return $test_data;
	}

	/**
	 * Create test vulnerability data
	 *
	 * @param int $count Number of vulnerabilities to create
	 * @access private
	 */
	private function create_test_vulnerability_data( $count ) {
		global $wpdb;
		
		$table_name = $wpdb->prefix . 'wp_breach_vulnerabilities';
		$severities = array( 'low', 'medium', 'high', 'critical' );
		$types = array( 'xss', 'sql_injection', 'file_inclusion', 'code_injection', 'csrf' );
		$components = array( 'plugin', 'theme', 'core', 'custom' );
		
		for ( $i = 1; $i <= $count; $i++ ) {
			$wpdb->insert(
				$table_name,
				array(
					'component_type' => $components[ $i % count( $components ) ],
					'component_name' => "test-component-{$i}",
					'component_version' => '1.0.0',
					'vulnerability_type' => $types[ $i % count( $types ) ],
					'severity' => $severities[ $i % count( $severities ) ],
					'description' => "Test vulnerability {$i} for performance benchmarking",
					'status' => 'active',
					'detected_at' => current_time( 'mysql' ),
					'created_at' => current_time( 'mysql' )
				),
				array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
			);
		}
	}

	/**
	 * Generate performance summary
	 *
	 * @return array Performance summary
	 * @access private
	 */
	private function generate_performance_summary() {
		$summary = array(
			'scan_performance' => array(),
			'database_performance' => array(),
			'cache_performance' => array(),
			'memory_performance' => array(),
			'overall_assessment' => 'unknown'
		);
		
		// Analyze scan performance
		$scan_results = array_filter( $this->benchmark_results, function( $key ) {
			return strpos( $key, 'scan_performance_' ) === 0;
		}, ARRAY_FILTER_USE_KEY );
		
		if ( ! empty( $scan_results ) ) {
			$avg_files_per_second = array_sum( array_column( $scan_results, 'files_per_second' ) ) / count( $scan_results );
			$summary['scan_performance'] = array(
				'average_files_per_second' => round( $avg_files_per_second, 2 ),
				'assessment' => $avg_files_per_second > 50 ? 'excellent' : ( $avg_files_per_second > 20 ? 'good' : 'needs_improvement' )
			);
		}
		
		// Analyze database performance
		$db_results = array_filter( $this->benchmark_results, function( $key ) {
			return strpos( $key, 'db_query_' ) === 0;
		}, ARRAY_FILTER_USE_KEY );
		
		if ( ! empty( $db_results ) ) {
			$avg_speedup = array_sum( array_column( $db_results, 'cache_hit_speedup' ) ) / count( $db_results );
			$summary['database_performance'] = array(
				'average_cache_speedup' => round( $avg_speedup, 2 ),
				'assessment' => $avg_speedup > 5 ? 'excellent' : ( $avg_speedup > 2 ? 'good' : 'needs_improvement' )
			);
		}
		
		// Determine overall assessment
		$assessments = array_column( $summary, 'assessment' );
		$assessments = array_filter( $assessments, function( $assessment ) {
			return $assessment !== 'unknown';
		} );
		
		if ( ! empty( $assessments ) ) {
			$excellent_count = count( array_filter( $assessments, function( $a ) { return $a === 'excellent'; } ) );
			$good_count = count( array_filter( $assessments, function( $a ) { return $a === 'good'; } ) );
			
			if ( $excellent_count > count( $assessments ) / 2 ) {
				$summary['overall_assessment'] = 'excellent';
			} elseif ( $good_count + $excellent_count > count( $assessments ) / 2 ) {
				$summary['overall_assessment'] = 'good';
			} else {
				$summary['overall_assessment'] = 'needs_improvement';
			}
		}
		
		return $summary;
	}

	/**
	 * Clean up after benchmark tests
	 */
	public function tearDown(): void {
		// Clean up any remaining test data
		global $wpdb;
		$wpdb->query( "DELETE FROM {$wpdb->prefix}wp_breach_vulnerabilities WHERE component_name LIKE 'test-component-%'" );
		
		parent::tearDown();
	}
}
