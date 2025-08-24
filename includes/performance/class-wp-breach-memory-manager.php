<?php
/**
 * The memory management system for WP-Breach.
 *
 * This class provides memory monitoring, optimization, and management
 * to prevent memory-related issues during scanning operations.
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/performance
 */

/**
 * The memory manager class.
 *
 * This class handles memory usage monitoring, optimization strategies,
 * and automatic memory management during resource-intensive operations.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/performance
 * @author     luozongbao <luo.zongbao@outlook.com>
 */
class WP_Breach_Memory_Manager {

	/**
	 * Memory usage tracking data
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      array    $memory_tracking    Memory usage tracking.
	 */
	private $memory_tracking;

	/**
	 * Memory optimization configuration
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      array    $config    Memory management configuration.
	 */
	private $config;

	/**
	 * Memory checkpoints for operations
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      array    $checkpoints    Memory checkpoints.
	 */
	private $checkpoints;

	/**
	 * Emergency cleanup handlers
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      array    $cleanup_handlers    Emergency cleanup functions.
	 */
	private $cleanup_handlers;

	/**
	 * Memory alerts and warnings
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      array    $alerts    Memory alerts.
	 */
	private $alerts;

	/**
	 * Cache manager instance
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      WP_Breach_Cache_Manager    $cache    Cache manager.
	 */
	private $cache;

	/**
	 * Initialize the memory manager
	 *
	 * @since    1.0.0
	 */
	public function __construct() {
		$this->memory_tracking = array();
		$this->checkpoints = array();
		$this->cleanup_handlers = array();
		$this->alerts = array();
		$this->initialize_config();
		$this->register_emergency_handlers();
	}

	/**
	 * Initialize memory manager with dependencies
	 *
	 * @since    1.0.0
	 */
	public function init() {
		$this->cache = new WP_Breach_Cache_Manager();
		
		// Start memory monitoring
		$this->start_memory_monitoring();
		
		// Register WordPress hooks
		add_action( 'wp_breach_scan_started', array( $this, 'prepare_memory_for_scan' ) );
		add_action( 'wp_breach_scan_completed', array( $this, 'cleanup_after_scan' ) );
		add_action( 'wp_breach_memory_warning', array( $this, 'handle_memory_warning' ) );
		add_action( 'shutdown', array( $this, 'final_memory_cleanup' ) );
	}

	/**
	 * Monitor memory usage throughout operations
	 *
	 * @since    1.0.0
	 * @param    string    $operation_id    Unique operation identifier.
	 * @param    string    $stage           Current operation stage.
	 * @return   array                      Current memory status.
	 */
	public function monitor_memory_usage( $operation_id, $stage = 'unknown' ) {
		$current_memory = memory_get_usage( true );
		$peak_memory = memory_get_peak_usage( true );
		$memory_limit = $this->get_memory_limit();
		
		$memory_status = array(
			'current_usage' => $current_memory,
			'peak_usage' => $peak_memory,
			'memory_limit' => $memory_limit,
			'usage_percentage' => ( $current_memory / $memory_limit ) * 100,
			'peak_percentage' => ( $peak_memory / $memory_limit ) * 100,
			'available_memory' => $memory_limit - $current_memory,
			'timestamp' => microtime( true ),
			'operation_id' => $operation_id,
			'stage' => $stage
		);
		
		// Store tracking data
		$this->memory_tracking[ $operation_id ][ $stage ] = $memory_status;
		
		// Check for memory warnings
		$this->check_memory_thresholds( $memory_status );
		
		return $memory_status;
	}

	/**
	 * Create memory checkpoint for restoration
	 *
	 * @since    1.0.0
	 * @param    string    $checkpoint_id    Checkpoint identifier.
	 * @return   bool                        True if checkpoint created successfully.
	 */
	public function create_memory_checkpoint( $checkpoint_id ) {
		$checkpoint_data = array(
			'memory_usage' => memory_get_usage( true ),
			'peak_memory' => memory_get_peak_usage( true ),
			'timestamp' => microtime( true ),
			'backtrace' => wp_debug_backtrace_summary(),
			'active_objects' => $this->count_active_objects()
		);
		
		$this->checkpoints[ $checkpoint_id ] = $checkpoint_data;
		
		return true;
	}

	/**
	 * Optimize memory usage with various strategies
	 *
	 * @since    1.0.0
	 * @param    string    $strategy    Optimization strategy to apply.
	 * @return   array                  Optimization results.
	 */
	public function optimize_memory_usage( $strategy = 'auto' ) {
		$before_optimization = memory_get_usage( true );
		
		switch ( $strategy ) {
			case 'aggressive':
				$results = $this->apply_aggressive_optimization();
				break;
			case 'conservative':
				$results = $this->apply_conservative_optimization();
				break;
			case 'emergency':
				$results = $this->apply_emergency_optimization();
				break;
			default:
				$results = $this->apply_auto_optimization();
				break;
		}
		
		$after_optimization = memory_get_usage( true );
		$memory_freed = $before_optimization - $after_optimization;
		
		$optimization_results = array(
			'strategy_used' => $strategy,
			'memory_before' => $before_optimization,
			'memory_after' => $after_optimization,
			'memory_freed' => $memory_freed,
			'memory_freed_mb' => round( $memory_freed / ( 1024 * 1024 ), 2 ),
			'optimization_details' => $results,
			'timestamp' => microtime( true )
		);
		
		// Log optimization results
		$this->log_optimization_results( $optimization_results );
		
		return $optimization_results;
	}

	/**
	 * Implement automatic garbage collection strategies
	 *
	 * @since    1.0.0
	 * @param    bool    $force    Force garbage collection even if not recommended.
	 * @return   array             Garbage collection results.
	 */
	public function implement_garbage_collection( $force = false ) {
		$gc_results = array();
		
		// Check if garbage collection is beneficial
		if ( ! $force && ! $this->should_run_garbage_collection() ) {
			return array(
				'executed' => false,
				'reason' => 'Garbage collection not beneficial at this time'
			);
		}
		
		// Get memory status before GC
		$memory_before = memory_get_usage( true );
		$cycles_before = gc_status();
		
		// Force garbage collection
		$collected_cycles = gc_collect_cycles();
		
		// Get memory status after GC
		$memory_after = memory_get_usage( true );
		$cycles_after = gc_status();
		
		$gc_results = array(
			'executed' => true,
			'memory_before' => $memory_before,
			'memory_after' => $memory_after,
			'memory_freed' => $memory_before - $memory_after,
			'cycles_collected' => $collected_cycles,
			'gc_runs_before' => $cycles_before['runs'] ?? 0,
			'gc_runs_after' => $cycles_after['runs'] ?? 0,
			'effectiveness' => $this->calculate_gc_effectiveness( $memory_before, $memory_after ),
			'timestamp' => microtime( true )
		);
		
		return $gc_results;
	}

	/**
	 * Clear specific memory allocations and caches
	 *
	 * @since    1.0.0
	 * @param    array    $clear_options    What to clear (caches, variables, etc.).
	 * @return   bool                       True if clearing successful.
	 */
	public function clear_memory_allocations( $clear_options = array() ) {
		$default_options = array(
			'clear_object_cache' => true,
			'clear_transients' => true,
			'clear_file_cache' => true,
			'clear_scan_cache' => true,
			'unset_large_variables' => true,
			'clear_temporary_data' => true
		);
		
		$options = array_merge( $default_options, $clear_options );
		$cleared_items = array();
		
		// Clear object cache
		if ( $options['clear_object_cache'] ) {
			wp_cache_flush();
			$cleared_items[] = 'object_cache';
		}
		
		// Clear transients
		if ( $options['clear_transients'] ) {
			$this->clear_expired_transients();
			$cleared_items[] = 'transients';
		}
		
		// Clear file cache
		if ( $options['clear_file_cache'] && $this->cache ) {
			$this->cache->clear_cache_group( 'file_metadata' );
			$cleared_items[] = 'file_cache';
		}
		
		// Clear scan cache
		if ( $options['clear_scan_cache'] && $this->cache ) {
			$this->cache->clear_cache_group( 'scan_results' );
			$cleared_items[] = 'scan_cache';
		}
		
		// Clear temporary data
		if ( $options['clear_temporary_data'] ) {
			$this->clear_temporary_variables();
			$cleared_items[] = 'temporary_data';
		}
		
		return ! empty( $cleared_items );
	}

	/**
	 * Get comprehensive memory statistics
	 *
	 * @since    1.0.0
	 * @return   array    Memory usage statistics.
	 */
	public function get_memory_statistics() {
		$memory_limit = $this->get_memory_limit();
		$current_usage = memory_get_usage( true );
		$peak_usage = memory_get_peak_usage( true );
		
		$statistics = array(
			'current_usage' => $current_usage,
			'current_usage_mb' => round( $current_usage / ( 1024 * 1024 ), 2 ),
			'peak_usage' => $peak_usage,
			'peak_usage_mb' => round( $peak_usage / ( 1024 * 1024 ), 2 ),
			'memory_limit' => $memory_limit,
			'memory_limit_mb' => round( $memory_limit / ( 1024 * 1024 ), 2 ),
			'usage_percentage' => round( ( $current_usage / $memory_limit ) * 100, 2 ),
			'peak_percentage' => round( ( $peak_usage / $memory_limit ) * 100, 2 ),
			'available_memory' => $memory_limit - $current_usage,
			'available_memory_mb' => round( ( $memory_limit - $current_usage ) / ( 1024 * 1024 ), 2 ),
			'gc_status' => gc_status(),
			'tracking_operations' => count( $this->memory_tracking ),
			'active_checkpoints' => count( $this->checkpoints ),
			'memory_alerts' => count( $this->alerts ),
			'timestamp' => microtime( true )
		);
		
		return $statistics;
	}

	/**
	 * Prepare memory optimization for scan operations
	 *
	 * @since    1.0.0
	 * @param    array    $scan_data    Scan configuration data.
	 */
	public function prepare_memory_for_scan( $scan_data ) {
		// Create checkpoint before scan
		$this->create_memory_checkpoint( 'pre_scan_' . time() );
		
		// Clear unnecessary memory allocations
		$this->clear_memory_allocations( array(
			'clear_scan_cache' => false, // Keep scan cache for performance
			'clear_temporary_data' => true
		) );
		
		// Optimize garbage collection settings for scan
		$this->optimize_gc_for_scan();
		
		// Set up memory monitoring for scan
		$scan_id = $scan_data['scan_id'] ?? uniqid( 'scan_' );
		$this->monitor_memory_usage( $scan_id, 'scan_prepared' );
		
		// Pre-allocate memory if beneficial
		$this->preallocate_scan_memory( $scan_data );
	}

	/**
	 * Clean up memory after scan completion
	 *
	 * @since    1.0.0
	 * @param    array    $scan_results    Completed scan results.
	 */
	public function cleanup_after_scan( $scan_results ) {
		$scan_id = $scan_results['scan_id'] ?? 'unknown';
		
		// Monitor memory usage after scan
		$this->monitor_memory_usage( $scan_id, 'scan_completed' );
		
		// Run garbage collection
		$this->implement_garbage_collection( true );
		
		// Clear scan-specific memory allocations
		$this->clear_scan_memory_allocations( $scan_id );
		
		// Generate memory usage report for scan
		$this->generate_scan_memory_report( $scan_id );
		
		// Clean up old checkpoints
		$this->cleanup_old_checkpoints();
	}

	/**
	 * Handle memory warning situations
	 *
	 * @since    1.0.0
	 * @param    array    $warning_data    Memory warning information.
	 */
	public function handle_memory_warning( $warning_data ) {
		$warning_level = $warning_data['level'] ?? 'medium';
		
		switch ( $warning_level ) {
			case 'critical':
				$this->handle_critical_memory_situation();
				break;
			case 'high':
				$this->handle_high_memory_usage();
				break;
			case 'medium':
				$this->handle_medium_memory_usage();
				break;
			default:
				$this->handle_low_memory_warning();
				break;
		}
		
		// Log the warning
		$this->log_memory_warning( $warning_data );
	}

	/**
	 * Final memory cleanup on shutdown
	 *
	 * @since    1.0.0
	 */
	public function final_memory_cleanup() {
		// Clear all tracking data
		$this->memory_tracking = array();
		$this->checkpoints = array();
		
		// Run final garbage collection
		if ( $this->config['final_gc_enabled'] ) {
			gc_collect_cycles();
		}
		
		// Clear temporary cache data
		if ( $this->cache ) {
			$this->cache->clear_cache_group( 'temporary' );
		}
	}

	/**
	 * Initialize memory management configuration
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function initialize_config() {
		$defaults = array(
			'warning_threshold' => 75,          // Warn at 75% memory usage
			'critical_threshold' => 90,         // Critical at 90% memory usage
			'gc_threshold' => 80,               // Run GC at 80% usage
			'monitoring_enabled' => true,
			'automatic_optimization' => true,
			'emergency_cleanup_enabled' => true,
			'final_gc_enabled' => true,
			'checkpoint_retention' => 3600,     // Keep checkpoints for 1 hour
			'max_tracking_operations' => 100    // Maximum operations to track
		);
		
		$user_config = get_option( 'wp_breach_memory_manager_config', array() );
		$this->config = array_merge( $defaults, $user_config );
	}

	/**
	 * Register emergency memory handlers
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function register_emergency_handlers() {
		// Register handlers for different types of cleanup
		$this->cleanup_handlers['cache_flush'] = function() {
			wp_cache_flush();
			return true;
		};
		
		$this->cleanup_handlers['transient_cleanup'] = function() {
			$this->clear_expired_transients();
			return true;
		};
		
		$this->cleanup_handlers['temporary_data'] = function() {
			$this->clear_temporary_variables();
			return true;
		};
		
		$this->cleanup_handlers['garbage_collection'] = function() {
			return gc_collect_cycles() > 0;
		};
	}

	/**
	 * Start memory monitoring system
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function start_memory_monitoring() {
		if ( ! $this->config['monitoring_enabled'] ) {
			return;
		}
		
		// Set up periodic memory checking
		add_action( 'wp_loaded', function() {
			$this->monitor_memory_usage( 'wp_loaded', 'initialization' );
		} );
		
		// Monitor at various WordPress hooks
		add_action( 'init', function() {
			$this->monitor_memory_usage( 'init', 'wordpress_init' );
		} );
		
		add_action( 'wp_footer', function() {
			$this->monitor_memory_usage( 'wp_footer', 'page_render' );
		} );
	}

	/**
	 * Check memory thresholds and trigger alerts
	 *
	 * @since    1.0.0
	 * @param    array    $memory_status    Current memory status.
	 * @access   private
	 */
	private function check_memory_thresholds( $memory_status ) {
		$usage_percentage = $memory_status['usage_percentage'];
		
		if ( $usage_percentage >= $this->config['critical_threshold'] ) {
			$this->trigger_memory_alert( 'critical', $memory_status );
		} elseif ( $usage_percentage >= $this->config['warning_threshold'] ) {
			$this->trigger_memory_alert( 'warning', $memory_status );
		}
		
		// Automatic optimization if enabled
		if ( $this->config['automatic_optimization'] && $usage_percentage >= $this->config['gc_threshold'] ) {
			$this->optimize_memory_usage( 'auto' );
		}
	}

	/**
	 * Trigger memory alert
	 *
	 * @since    1.0.0
	 * @param    string    $level           Alert level.
	 * @param    array     $memory_status   Memory status data.
	 * @access   private
	 */
	private function trigger_memory_alert( $level, $memory_status ) {
		$alert = array(
			'level' => $level,
			'memory_status' => $memory_status,
			'timestamp' => microtime( true ),
			'backtrace' => wp_debug_backtrace_summary()
		);
		
		$this->alerts[] = $alert;
		
		// Trigger WordPress action for alert handling
		do_action( 'wp_breach_memory_warning', array(
			'level' => $level,
			'memory_data' => $memory_status
		) );
		
		// Log critical alerts
		if ( $level === 'critical' ) {
			error_log( "WP-Breach Critical Memory Alert: {$memory_status['usage_percentage']}% usage" );
		}
	}

	/**
	 * Get system memory limit
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
	 * Count active objects for memory analysis
	 *
	 * @since    1.0.0
	 * @return   array    Object count by type.
	 * @access   private
	 */
	private function count_active_objects() {
		$object_count = array();
		
		// Get memory usage by different WordPress components
		$object_count['wp_object_cache'] = wp_cache_get_multi( array() ) ? 1 : 0;
		$object_count['active_plugins'] = count( get_option( 'active_plugins', array() ) );
		$object_count['loaded_themes'] = 1; // Current theme
		
		return $object_count;
	}

	/**
	 * Apply aggressive memory optimization
	 *
	 * @since    1.0.0
	 * @return   array    Optimization results.
	 * @access   private
	 */
	private function apply_aggressive_optimization() {
		$results = array();
		
		// Clear all caches
		$results['cache_cleared'] = $this->clear_memory_allocations( array(
			'clear_object_cache' => true,
			'clear_transients' => true,
			'clear_file_cache' => true,
			'clear_scan_cache' => true,
			'clear_temporary_data' => true
		) );
		
		// Force garbage collection multiple times
		$results['gc_cycles'] = 0;
		for ( $i = 0; $i < 3; $i++ ) {
			$results['gc_cycles'] += gc_collect_cycles();
		}
		
		// Clear tracking data
		$this->clear_old_tracking_data();
		$results['tracking_cleared'] = true;
		
		return $results;
	}

	/**
	 * Apply conservative memory optimization
	 *
	 * @since    1.0.0
	 * @return   array    Optimization results.
	 * @access   private
	 */
	private function apply_conservative_optimization() {
		$results = array();
		
		// Clear only temporary data
		$results['temp_cleared'] = $this->clear_memory_allocations( array(
			'clear_object_cache' => false,
			'clear_transients' => false,
			'clear_file_cache' => false,
			'clear_scan_cache' => false,
			'clear_temporary_data' => true
		) );
		
		// Single garbage collection
		$results['gc_cycles'] = gc_collect_cycles();
		
		return $results;
	}

	/**
	 * Apply emergency memory optimization
	 *
	 * @since    1.0.0
	 * @return   array    Optimization results.
	 * @access   private
	 */
	private function apply_emergency_optimization() {
		$results = array();
		
		// Execute all cleanup handlers
		foreach ( $this->cleanup_handlers as $handler_name => $handler ) {
			try {
				$results[ $handler_name ] = call_user_func( $handler );
			} catch ( Exception $e ) {
				$results[ $handler_name ] = false;
				error_log( "Emergency cleanup handler failed: {$handler_name} - " . $e->getMessage() );
			}
		}
		
		// Clear all internal data
		$this->memory_tracking = array();
		$this->checkpoints = array();
		$this->alerts = array();
		$results['internal_data_cleared'] = true;
		
		return $results;
	}

	/**
	 * Apply automatic memory optimization
	 *
	 * @since    1.0.0
	 * @return   array    Optimization results.
	 * @access   private
	 */
	private function apply_auto_optimization() {
		$current_usage = memory_get_usage( true );
		$memory_limit = $this->get_memory_limit();
		$usage_percentage = ( $current_usage / $memory_limit ) * 100;
		
		if ( $usage_percentage >= 90 ) {
			return $this->apply_aggressive_optimization();
		} elseif ( $usage_percentage >= 80 ) {
			return $this->apply_conservative_optimization();
		} else {
			// Light optimization
			return array( 'gc_cycles' => gc_collect_cycles() );
		}
	}

	/**
	 * Check if garbage collection should run
	 *
	 * @since    1.0.0
	 * @return   bool    True if GC should run.
	 * @access   private
	 */
	private function should_run_garbage_collection() {
		$current_usage = memory_get_usage( true );
		$memory_limit = $this->get_memory_limit();
		$usage_percentage = ( $current_usage / $memory_limit ) * 100;
		
		return $usage_percentage >= $this->config['gc_threshold'];
	}

	/**
	 * Calculate garbage collection effectiveness
	 *
	 * @since    1.0.0
	 * @param    int    $memory_before    Memory before GC.
	 * @param    int    $memory_after     Memory after GC.
	 * @return   float                    Effectiveness percentage.
	 * @access   private
	 */
	private function calculate_gc_effectiveness( $memory_before, $memory_after ) {
		if ( $memory_before <= 0 ) {
			return 0;
		}
		
		$memory_freed = $memory_before - $memory_after;
		return ( $memory_freed / $memory_before ) * 100;
	}

	/**
	 * Clear expired transients to free memory
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function clear_expired_transients() {
		global $wpdb;
		
		// Delete expired transients
		$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_%' AND option_value < UNIX_TIMESTAMP()" );
		$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_%' AND option_name NOT LIKE '_transient_timeout_%' AND option_name NOT IN (SELECT REPLACE(option_name, '_timeout', '') FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_%')" );
	}

	/**
	 * Clear temporary variables and data structures
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function clear_temporary_variables() {
		// Clear old memory tracking data
		$this->clear_old_tracking_data();
		
		// Clear old alerts
		$this->alerts = array_slice( $this->alerts, -10 ); // Keep only last 10 alerts
	}

	/**
	 * Clear old tracking data
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function clear_old_tracking_data() {
		$max_operations = $this->config['max_tracking_operations'];
		
		if ( count( $this->memory_tracking ) > $max_operations ) {
			$this->memory_tracking = array_slice( $this->memory_tracking, -$max_operations, null, true );
		}
	}

	/**
	 * Handle critical memory situation
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function handle_critical_memory_situation() {
		// Apply emergency optimization
		$this->optimize_memory_usage( 'emergency' );
		
		// Log critical situation
		error_log( 'WP-Breach: Critical memory situation detected, emergency cleanup applied' );
	}

	/**
	 * Log memory warning
	 *
	 * @since    1.0.0
	 * @param    array    $warning_data    Warning information.
	 * @access   private
	 */
	private function log_memory_warning( $warning_data ) {
		if ( defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG ) {
			$level = $warning_data['level'];
			$usage = round( $warning_data['memory_data']['usage_percentage'], 2 );
			error_log( "WP-Breach Memory Warning ({$level}): {$usage}% memory usage" );
		}
	}
}
