<?php
/**
 * The scan performance optimization system for WP-Breach.
 *
 * This class provides optimizations for vulnerability scanning operations,
 * including file filtering, parallel processing, and resource management.
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/performance
 */

/**
 * The scan performance optimizer class.
 *
 * This class handles optimization of scan operations including
 * file filtering, parallel processing, and memory management.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/performance
 * @author     luozongbao <luo.zongbao@outlook.com>
 */
class WP_Breach_Scan_Optimizer {

	/**
	 * Performance monitor instance
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      WP_Breach_Performance_Monitor    $performance_monitor    Performance monitor.
	 */
	private $performance_monitor;

	/**
	 * Cache manager instance
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      WP_Breach_Cache_Manager    $cache    Cache manager.
	 */
	private $cache;

	/**
	 * Optimization configuration
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      array    $config    Optimization settings.
	 */
	private $config;

	/**
	 * File filter patterns
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      array    $file_filters    File filtering patterns.
	 */
	private $file_filters;

	/**
	 * Scan statistics
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      array    $scan_stats    Current scan statistics.
	 */
	private $scan_stats;

	/**
	 * Memory usage tracker
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      array    $memory_usage    Memory usage tracking.
	 */
	private $memory_usage;

	/**
	 * Initialize the scan optimizer
	 *
	 * @since    1.0.0
	 */
	public function __construct() {
		$this->initialize_config();
		$this->initialize_file_filters();
		$this->scan_stats = array();
		$this->memory_usage = array();
	}

	/**
	 * Initialize the optimizer with dependencies
	 *
	 * @since    1.0.0
	 */
	public function init() {
		$this->performance_monitor = new WP_Breach_Performance_Monitor();
		$this->cache = new WP_Breach_Cache_Manager();
		
		// Register optimization hooks
		add_filter( 'wp_breach_scan_file_list', array( $this, 'optimize_file_list' ), 10, 2 );
		add_filter( 'wp_breach_scan_batch_size', array( $this, 'calculate_optimal_batch_size' ), 10, 2 );
		add_action( 'wp_breach_scan_started', array( $this, 'prepare_scan_optimization' ) );
		add_action( 'wp_breach_scan_completed', array( $this, 'finalize_scan_optimization' ) );
	}

	/**
	 * Optimize file filtering to reduce scan overhead
	 *
	 * @since    1.0.0
	 * @param    array    $file_list     Original file list.
	 * @param    array    $scan_options  Scan configuration options.
	 * @return   array                   Optimized file list.
	 */
	public function optimize_file_list( $file_list, $scan_options = array() ) {
		$profile_id = $this->performance_monitor->start_profiling( 'file_list_optimization' );
		
		// Apply intelligent file filtering
		$filtered_files = $this->apply_intelligent_filtering( $file_list, $scan_options );
		
		// Sort files for optimal processing order
		$optimized_files = $this->optimize_file_processing_order( $filtered_files );
		
		// Cache file metadata for faster subsequent scans
		$this->cache_file_metadata( $optimized_files );
		
		$this->performance_monitor->end_profiling( $profile_id );
		
		return $optimized_files;
	}

	/**
	 * Implement parallel processing for large scans
	 *
	 * @since    1.0.0
	 * @param    array    $file_batches    File batches to process.
	 * @param    array    $scan_options    Scan configuration.
	 * @return   array                     Scan results from all batches.
	 */
	public function implement_parallel_processing( $file_batches, $scan_options = array() ) {
		$profile_id = $this->performance_monitor->start_profiling( 'parallel_scan_processing' );
		
		$results = array();
		$max_parallel = $this->config['max_parallel_processes'];
		$active_processes = array();
		
		// Process batches in parallel
		foreach ( $file_batches as $batch_id => $batch_files ) {
			// Wait if we've reached the parallel limit
			if ( count( $active_processes ) >= $max_parallel ) {
				$completed_process = $this->wait_for_process_completion( $active_processes );
				$results[] = $this->get_process_results( $completed_process );
				unset( $active_processes[ $completed_process ] );
			}
			
			// Start new process for this batch
			$process_id = $this->start_batch_process( $batch_id, $batch_files, $scan_options );
			$active_processes[ $process_id ] = $batch_id;
		}
		
		// Wait for remaining processes to complete
		while ( ! empty( $active_processes ) ) {
			$completed_process = $this->wait_for_process_completion( $active_processes );
			$results[] = $this->get_process_results( $completed_process );
			unset( $active_processes[ $completed_process ] );
		}
		
		$this->performance_monitor->end_profiling( $profile_id );
		
		return $this->merge_batch_results( $results );
	}

	/**
	 * Calculate optimal batch size based on system resources
	 *
	 * @since    1.0.0
	 * @param    int      $default_size     Default batch size.
	 * @param    array    $scan_context     Current scan context.
	 * @return   int                        Optimized batch size.
	 */
	public function calculate_optimal_batch_size( $default_size, $scan_context = array() ) {
		$available_memory = $this->get_available_memory();
		$system_load = $this->get_system_load();
		$file_complexity = $this->estimate_file_complexity( $scan_context );
		
		// Base calculation on available resources
		$memory_factor = min( 1.5, $available_memory / ( 128 * 1024 * 1024 ) ); // 128MB base
		$load_factor = max( 0.5, 2.0 - $system_load );
		$complexity_factor = max( 0.5, 2.0 - $file_complexity );
		
		$optimized_size = intval( $default_size * $memory_factor * $load_factor * $complexity_factor );
		
		// Apply configuration limits
		$optimized_size = max( $this->config['min_batch_size'], $optimized_size );
		$optimized_size = min( $this->config['max_batch_size'], $optimized_size );
		
		return $optimized_size;
	}

	/**
	 * Optimize memory usage during scanning
	 *
	 * @since    1.0.0
	 * @param    string    $scan_stage    Current scan stage.
	 * @return   bool                     True if optimization successful.
	 */
	public function optimize_memory_usage( $scan_stage = 'scanning' ) {
		$current_memory = memory_get_usage( true );
		$memory_limit = $this->get_memory_limit();
		$usage_percentage = ( $current_memory / $memory_limit ) * 100;
		
		// Track memory usage
		$this->memory_usage[ $scan_stage ] = array(
			'current' => $current_memory,
			'peak' => memory_get_peak_usage( true ),
			'percentage' => $usage_percentage,
			'timestamp' => microtime( true )
		);
		
		// Apply memory optimization if usage is high
		if ( $usage_percentage > $this->config['memory_threshold'] ) {
			return $this->apply_memory_optimization( $scan_stage );
		}
		
		return true;
	}

	/**
	 * Implement smart caching for scan results
	 *
	 * @since    1.0.0
	 * @param    string    $file_path      File being scanned.
	 * @param    array     $scan_result    Scan result for the file.
	 * @param    string    $file_hash      File content hash.
	 * @return   bool                      True if cached successfully.
	 */
	public function implement_smart_caching( $file_path, $scan_result, $file_hash ) {
		// Generate cache key based on file path and hash
		$cache_key = $this->generate_scan_cache_key( $file_path, $file_hash );
		
		// Determine cache TTL based on file characteristics
		$cache_ttl = $this->determine_cache_ttl( $file_path, $scan_result );
		
		// Cache the scan result
		$cached = $this->cache->set_cached_data( $cache_key, $scan_result, $cache_ttl, 'scan_results' );
		
		// Update cache statistics
		$this->update_cache_statistics( $file_path, $cached );
		
		return $cached;
	}

	/**
	 * Check for cached scan results
	 *
	 * @since    1.0.0
	 * @param    string    $file_path    File path to check.
	 * @param    string    $file_hash    Current file hash.
	 * @return   mixed                   Cached result or false if not found.
	 */
	public function get_cached_scan_result( $file_path, $file_hash ) {
		$cache_key = $this->generate_scan_cache_key( $file_path, $file_hash );
		
		$cached_result = $this->cache->get_cached_data( $cache_key, 'scan_results' );
		
		if ( $cached_result !== false ) {
			$this->scan_stats['cache_hits'] = ( $this->scan_stats['cache_hits'] ?? 0 ) + 1;
			return $cached_result;
		}
		
		$this->scan_stats['cache_misses'] = ( $this->scan_stats['cache_misses'] ?? 0 ) + 1;
		return false;
	}

	/**
	 * Optimize scan resource allocation
	 *
	 * @since    1.0.0
	 * @param    array    $scan_options    Scan configuration options.
	 * @return   array                     Optimized resource allocation.
	 */
	public function optimize_resource_allocation( $scan_options = array() ) {
		$system_resources = $this->analyze_system_resources();
		
		$allocation = array(
			'cpu_allocation' => $this->calculate_cpu_allocation( $system_resources ),
			'memory_allocation' => $this->calculate_memory_allocation( $system_resources ),
			'io_allocation' => $this->calculate_io_allocation( $system_resources ),
			'parallel_processes' => $this->calculate_parallel_processes( $system_resources ),
			'batch_size' => $this->calculate_optimal_batch_size( 
				$scan_options['default_batch_size'] ?? 50, 
				$scan_options 
			)
		);
		
		return $allocation;
	}

	/**
	 * Get scan performance metrics
	 *
	 * @since    1.0.0
	 * @return   array    Performance metrics for scans.
	 */
	public function get_scan_performance_metrics() {
		return array(
			'scan_statistics' => $this->scan_stats,
			'memory_usage' => $this->memory_usage,
			'cache_performance' => $this->get_cache_performance(),
			'file_processing_rates' => $this->get_file_processing_rates(),
			'optimization_effectiveness' => $this->calculate_optimization_effectiveness(),
			'resource_utilization' => $this->get_resource_utilization()
		);
	}

	/**
	 * Prepare scan for optimization
	 *
	 * @since    1.0.0
	 * @param    array    $scan_data    Scan configuration data.
	 */
	public function prepare_scan_optimization( $scan_data ) {
		// Reset scan statistics
		$this->scan_stats = array(
			'files_processed' => 0,
			'files_skipped' => 0,
			'cache_hits' => 0,
			'cache_misses' => 0,
			'start_time' => microtime( true ),
			'optimization_enabled' => true
		);
		
		// Warm up caches for this scan
		$this->warm_up_scan_caches( $scan_data );
		
		// Optimize system settings for scanning
		$this->optimize_system_settings_for_scan();
	}

	/**
	 * Finalize scan optimization
	 *
	 * @since    1.0.0
	 * @param    array    $scan_results    Completed scan results.
	 */
	public function finalize_scan_optimization( $scan_results ) {
		$this->scan_stats['end_time'] = microtime( true );
		$this->scan_stats['total_duration'] = $this->scan_stats['end_time'] - $this->scan_stats['start_time'];
		
		// Calculate performance improvements
		$optimization_report = $this->generate_optimization_report();
		
		// Update optimization strategies based on results
		$this->update_optimization_strategies( $scan_results, $optimization_report );
		
		// Clean up temporary resources
		$this->cleanup_scan_resources();
		
		// Store performance data for analysis
		$this->store_scan_performance_data( $scan_results, $optimization_report );
	}

	/**
	 * Initialize optimization configuration
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function initialize_config() {
		$defaults = array(
			'enable_file_filtering' => true,
			'enable_parallel_processing' => true,
			'enable_smart_caching' => true,
			'max_parallel_processes' => 3,
			'min_batch_size' => 10,
			'max_batch_size' => 200,
			'memory_threshold' => 80,              // 80% memory usage
			'file_size_threshold' => 10 * 1024 * 1024, // 10MB
			'cache_ttl_short' => 300,              // 5 minutes
			'cache_ttl_medium' => 1800,            // 30 minutes
			'cache_ttl_long' => 3600               // 1 hour
		);
		
		$user_config = get_option( 'wp_breach_scan_optimizer_config', array() );
		$this->config = array_merge( $defaults, $user_config );
	}

	/**
	 * Initialize file filtering patterns
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function initialize_file_filters() {
		$this->file_filters = array(
			'exclude_extensions' => array(
				'jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp',
				'mp3', 'mp4', 'avi', 'mov', 'wmv', 'flv',
				'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
				'zip', 'rar', '7z', 'tar', 'gz'
			),
			'exclude_directories' => array(
				'node_modules',
				'.git',
				'.svn',
				'vendor/bin',
				'uploads/cache',
				'cache',
				'tmp',
				'temp'
			),
			'exclude_patterns' => array(
				'/\.min\.(js|css)$/',
				'/backup-/',
				'/cache-/',
				'/\.log$/',
				'/\.tmp$/'
			),
			'include_extensions' => array(
				'php', 'js', 'css', 'html', 'htm', 'xml', 'json',
				'txt', 'md', 'ini', 'conf', 'htaccess'
			)
		);
		
		// Allow customization via filter
		$this->file_filters = apply_filters( 'wp_breach_scan_file_filters', $this->file_filters );
	}

	/**
	 * Apply intelligent file filtering
	 *
	 * @since    1.0.0
	 * @param    array    $file_list       Original file list.
	 * @param    array    $scan_options    Scan options.
	 * @return   array                     Filtered file list.
	 * @access   private
	 */
	private function apply_intelligent_filtering( $file_list, $scan_options ) {
		$filtered_files = array();
		
		foreach ( $file_list as $file_path ) {
			// Skip if file doesn't exist
			if ( ! file_exists( $file_path ) ) {
				$this->scan_stats['files_skipped']++;
				continue;
			}
			
			// Apply extension filtering
			if ( ! $this->should_scan_file_extension( $file_path ) ) {
				$this->scan_stats['files_skipped']++;
				continue;
			}
			
			// Apply directory filtering
			if ( ! $this->should_scan_directory( $file_path ) ) {
				$this->scan_stats['files_skipped']++;
				continue;
			}
			
			// Apply pattern filtering
			if ( ! $this->should_scan_file_pattern( $file_path ) ) {
				$this->scan_stats['files_skipped']++;
				continue;
			}
			
			// Apply size filtering
			if ( ! $this->should_scan_file_size( $file_path ) ) {
				$this->scan_stats['files_skipped']++;
				continue;
			}
			
			$filtered_files[] = $file_path;
		}
		
		return $filtered_files;
	}

	/**
	 * Optimize file processing order
	 *
	 * @since    1.0.0
	 * @param    array    $files    File list to optimize.
	 * @return   array              Optimized file order.
	 * @access   private
	 */
	private function optimize_file_processing_order( $files ) {
		// Sort files by processing priority
		usort( $files, array( $this, 'compare_file_priority' ) );
		
		return $files;
	}

	/**
	 * Compare file priority for processing order
	 *
	 * @since    1.0.0
	 * @param    string    $file_a    First file path.
	 * @param    string    $file_b    Second file path.
	 * @return   int                  Comparison result.
	 * @access   private
	 */
	private function compare_file_priority( $file_a, $file_b ) {
		$priority_a = $this->get_file_priority( $file_a );
		$priority_b = $this->get_file_priority( $file_b );
		
		// Higher priority first
		return $priority_b - $priority_a;
	}

	/**
	 * Get file processing priority
	 *
	 * @since    1.0.0
	 * @param    string    $file_path    File path.
	 * @return   int                     Priority score.
	 * @access   private
	 */
	private function get_file_priority( $file_path ) {
		$priority = 0;
		
		// Higher priority for PHP files
		if ( pathinfo( $file_path, PATHINFO_EXTENSION ) === 'php' ) {
			$priority += 100;
		}
		
		// Higher priority for theme/plugin files
		if ( strpos( $file_path, '/themes/' ) !== false || strpos( $file_path, '/plugins/' ) !== false ) {
			$priority += 50;
		}
		
		// Higher priority for configuration files
		if ( basename( $file_path ) === 'wp-config.php' || strpos( $file_path, '.htaccess' ) !== false ) {
			$priority += 200;
		}
		
		// Lower priority for larger files (they take more time)
		$file_size = filesize( $file_path );
		$priority -= min( 50, $file_size / ( 1024 * 1024 ) ); // Reduce priority by 1 per MB
		
		return $priority;
	}

	/**
	 * Cache file metadata for optimization
	 *
	 * @since    1.0.0
	 * @param    array    $files    File list.
	 * @access   private
	 */
	private function cache_file_metadata( $files ) {
		$metadata = array();
		
		foreach ( $files as $file_path ) {
			$metadata[ $file_path ] = array(
				'size' => filesize( $file_path ),
				'modified' => filemtime( $file_path ),
				'hash' => md5_file( $file_path ),
				'extension' => pathinfo( $file_path, PATHINFO_EXTENSION ),
				'priority' => $this->get_file_priority( $file_path )
			);
		}
		
		$this->cache->set_cached_data( 'file_metadata_' . md5( serialize( $files ) ), $metadata, 1800, 'file_metadata' );
	}

	/**
	 * Start batch process for parallel scanning
	 *
	 * @since    1.0.0
	 * @param    string    $batch_id      Batch identifier.
	 * @param    array     $batch_files   Files in this batch.
	 * @param    array     $scan_options  Scan options.
	 * @return   string                   Process identifier.
	 * @access   private
	 */
	private function start_batch_process( $batch_id, $batch_files, $scan_options ) {
		// In a real implementation, this would start an actual separate process
		// For now, we'll simulate with a background task
		$process_id = uniqid( 'process_' );
		
		// Store batch data for processing
		$batch_data = array(
			'batch_id' => $batch_id,
			'files' => $batch_files,
			'options' => $scan_options,
			'started_at' => microtime( true ),
			'status' => 'running'
		);
		
		$this->cache->set_cached_data( "batch_process_{$process_id}", $batch_data, 3600, 'batch_processes' );
		
		return $process_id;
	}

	/**
	 * Wait for process completion
	 *
	 * @since    1.0.0
	 * @param    array    $active_processes    Active process list.
	 * @return   string                        Completed process ID.
	 * @access   private
	 */
	private function wait_for_process_completion( $active_processes ) {
		// Simulate process completion (in real implementation, would check actual processes)
		return array_keys( $active_processes )[0];
	}

	/**
	 * Get process results
	 *
	 * @since    1.0.0
	 * @param    string    $process_id    Process identifier.
	 * @return   array                    Process results.
	 * @access   private
	 */
	private function get_process_results( $process_id ) {
		$batch_data = $this->cache->get_cached_data( "batch_process_{$process_id}", 'batch_processes' );
		
		// Simulate processing results
		return array(
			'batch_id' => $batch_data['batch_id'],
			'files_processed' => count( $batch_data['files'] ),
			'vulnerabilities_found' => 0, // Would be actual scan results
			'processing_time' => microtime( true ) - $batch_data['started_at']
		);
	}

	/**
	 * Merge batch results
	 *
	 * @since    1.0.0
	 * @param    array    $batch_results    Results from all batches.
	 * @return   array                      Merged results.
	 * @access   private
	 */
	private function merge_batch_results( $batch_results ) {
		$merged = array(
			'total_files_processed' => 0,
			'total_vulnerabilities' => 0,
			'total_processing_time' => 0,
			'batch_count' => count( $batch_results ),
			'batch_details' => $batch_results
		);
		
		foreach ( $batch_results as $result ) {
			$merged['total_files_processed'] += $result['files_processed'];
			$merged['total_vulnerabilities'] += $result['vulnerabilities_found'];
			$merged['total_processing_time'] += $result['processing_time'];
		}
		
		return $merged;
	}

	/**
	 * Check if file extension should be scanned
	 *
	 * @since    1.0.0
	 * @param    string    $file_path    File path.
	 * @return   bool                    True if should scan, false otherwise.
	 * @access   private
	 */
	private function should_scan_file_extension( $file_path ) {
		$extension = strtolower( pathinfo( $file_path, PATHINFO_EXTENSION ) );
		
		// Check exclude list first
		if ( in_array( $extension, $this->file_filters['exclude_extensions'] ) ) {
			return false;
		}
		
		// Check include list
		return in_array( $extension, $this->file_filters['include_extensions'] );
	}

	/**
	 * Check if directory should be scanned
	 *
	 * @since    1.0.0
	 * @param    string    $file_path    File path.
	 * @return   bool                    True if should scan, false otherwise.
	 * @access   private
	 */
	private function should_scan_directory( $file_path ) {
		foreach ( $this->file_filters['exclude_directories'] as $exclude_dir ) {
			if ( strpos( $file_path, '/' . $exclude_dir . '/' ) !== false ) {
				return false;
			}
		}
		
		return true;
	}

	/**
	 * Check if file pattern should be scanned
	 *
	 * @since    1.0.0
	 * @param    string    $file_path    File path.
	 * @return   bool                    True if should scan, false otherwise.
	 * @access   private
	 */
	private function should_scan_file_pattern( $file_path ) {
		foreach ( $this->file_filters['exclude_patterns'] as $pattern ) {
			if ( preg_match( $pattern, $file_path ) ) {
				return false;
			}
		}
		
		return true;
	}

	/**
	 * Check if file size should be scanned
	 *
	 * @since    1.0.0
	 * @param    string    $file_path    File path.
	 * @return   bool                    True if should scan, false otherwise.
	 * @access   private
	 */
	private function should_scan_file_size( $file_path ) {
		$file_size = filesize( $file_path );
		return $file_size <= $this->config['file_size_threshold'];
	}

	/**
	 * Generate scan result cache key
	 *
	 * @since    1.0.0
	 * @param    string    $file_path    File path.
	 * @param    string    $file_hash    File hash.
	 * @return   string                  Cache key.
	 * @access   private
	 */
	private function generate_scan_cache_key( $file_path, $file_hash ) {
		return 'scan_result_' . md5( $file_path . $file_hash );
	}

	/**
	 * Determine cache TTL for scan results
	 *
	 * @since    1.0.0
	 * @param    string    $file_path     File path.
	 * @param    array     $scan_result   Scan result.
	 * @return   int                      Cache TTL in seconds.
	 * @access   private
	 */
	private function determine_cache_ttl( $file_path, $scan_result ) {
		// Longer cache for clean files
		if ( empty( $scan_result['vulnerabilities'] ) ) {
			return $this->config['cache_ttl_long'];
		}
		
		// Medium cache for files with minor issues
		if ( count( $scan_result['vulnerabilities'] ) <= 2 ) {
			return $this->config['cache_ttl_medium'];
		}
		
		// Short cache for files with many issues
		return $this->config['cache_ttl_short'];
	}

	/**
	 * Get available system memory
	 *
	 * @since    1.0.0
	 * @return   int    Available memory in bytes.
	 * @access   private
	 */
	private function get_available_memory() {
		$memory_limit = $this->get_memory_limit();
		$current_usage = memory_get_usage( true );
		
		return max( 0, $memory_limit - $current_usage );
	}

	/**
	 * Get PHP memory limit
	 *
	 * @since    1.0.0
	 * @return   int    Memory limit in bytes.
	 * @access   private
	 */
	private function get_memory_limit() {
		$memory_limit = ini_get( 'memory_limit' );
		
		if ( $memory_limit === '-1' ) {
			return PHP_INT_MAX;
		}
		
		return $this->parse_size( $memory_limit );
	}

	/**
	 * Parse size string to bytes
	 *
	 * @since    1.0.0
	 * @param    string    $size    Size string (e.g., "128M").
	 * @return   int                Size in bytes.
	 * @access   private
	 */
	private function parse_size( $size ) {
		$unit = strtoupper( substr( $size, -1 ) );
		$value = intval( $size );
		
		switch ( $unit ) {
			case 'G':
				return $value * 1024 * 1024 * 1024;
			case 'M':
				return $value * 1024 * 1024;
			case 'K':
				return $value * 1024;
			default:
				return $value;
		}
	}

	/**
	 * Get current system load
	 *
	 * @since    1.0.0
	 * @return   float    System load average.
	 * @access   private
	 */
	private function get_system_load() {
		if ( function_exists( 'sys_getloadavg' ) ) {
			$load = sys_getloadavg();
			return $load[0]; // 1-minute average
		}
		
		// Fallback estimation
		return 1.0;
	}

	/**
	 * Estimate file complexity for scanning
	 *
	 * @since    1.0.0
	 * @param    array    $scan_context    Scan context information.
	 * @return   float                     Complexity factor (1.0 = normal).
	 * @access   private
	 */
	private function estimate_file_complexity( $scan_context ) {
		$complexity = 1.0;
		
		// More complex for larger files
		$avg_file_size = $scan_context['average_file_size'] ?? 0;
		if ( $avg_file_size > 1024 * 1024 ) { // > 1MB
			$complexity += 0.5;
		}
		
		// More complex for certain file types
		$php_files_ratio = ( $scan_context['php_files'] ?? 0 ) / max( 1, $scan_context['total_files'] ?? 1 );
		$complexity += $php_files_ratio * 0.3;
		
		return min( 2.0, $complexity );
	}
}
