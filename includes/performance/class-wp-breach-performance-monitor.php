<?php
/**
 * The performance monitoring system for WP-Breach.
 *
 * This class provides comprehensive performance monitoring, profiling,
 * and alerting capabilities for the WP-Breach plugin.
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/performance
 */

/**
 * The performance monitor class.
 *
 * This class handles performance profiling, resource monitoring,
 * and performance alerting for all plugin operations.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/performance
 * @author     luozongbao <luo.zongbao@outlook.com>
 */
class WP_Breach_Performance_Monitor {

	/**
	 * Performance metrics storage
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      array    $metrics    Performance metrics data.
	 */
	private $metrics;

	/**
	 * Active profiling sessions
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      array    $active_profiles    Currently running profiles.
	 */
	private $active_profiles;

	/**
	 * Performance thresholds
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      array    $thresholds    Performance alert thresholds.
	 */
	private $thresholds;

	/**
	 * Database instance
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      WP_Breach_Database    $database    Database instance.
	 */
	private $database;

	/**
	 * Cache manager instance
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      WP_Breach_Cache_Manager    $cache    Cache manager instance.
	 */
	private $cache;

	/**
	 * Initialize the performance monitor
	 *
	 * @since    1.0.0
	 */
	public function __construct() {
		$this->metrics = array();
		$this->active_profiles = array();
		$this->initialize_thresholds();
		$this->setup_hooks();
	}

	/**
	 * Initialize WordPress hooks
	 *
	 * @since    1.0.0
	 */
	public function init() {
		$this->database = new WP_Breach_Database();
		$this->cache = new WP_Breach_Cache_Manager();
		
		// Monitor WordPress performance
		add_action( 'init', array( $this, 'start_wordpress_monitoring' ) );
		add_action( 'shutdown', array( $this, 'end_wordpress_monitoring' ) );
		
		// Monitor admin performance
		add_action( 'admin_init', array( $this, 'start_admin_monitoring' ) );
		
		// Monitor scan performance
		add_action( 'wp_breach_scan_start', array( $this, 'start_scan_monitoring' ) );
		add_action( 'wp_breach_scan_end', array( $this, 'end_scan_monitoring' ) );
	}

	/**
	 * Set up performance monitoring hooks
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function setup_hooks() {
		// Monitor database queries if in debug mode
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			add_filter( 'query', array( $this, 'monitor_database_query' ) );
		}
		
		// Monitor memory usage
		add_action( 'wp_loaded', array( $this, 'record_memory_usage' ), 1 );
		add_action( 'wp_footer', array( $this, 'record_memory_usage' ), 999 );
	}

	/**
	 * Initialize performance thresholds
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function initialize_thresholds() {
		$this->thresholds = array(
			'max_execution_time' => 300,        // 5 minutes
			'max_memory_usage' => 268435456,    // 256MB
			'max_db_queries' => 100,            // Per page load
			'max_scan_time' => 1800,            // 30 minutes
			'max_file_operations' => 1000,      // Per scan
			'cache_hit_rate_min' => 0.8,        // 80% minimum
			'page_load_time_max' => 0.05        // 50ms plugin overhead
		);
		
		// Allow customization via settings
		$custom_thresholds = get_option( 'wp_breach_performance_thresholds', array() );
		$this->thresholds = array_merge( $this->thresholds, $custom_thresholds );
	}

	/**
	 * Start profiling an operation
	 *
	 * @since    1.0.0
	 * @param    string    $operation_name    Name of the operation to profile.
	 * @param    array     $context          Additional context data.
	 * @return   string                      Profile ID for ending the profile.
	 */
	public function start_profiling( $operation_name, $context = array() ) {
		$profile_id = uniqid( 'profile_' );
		
		$this->active_profiles[ $profile_id ] = array(
			'operation' => $operation_name,
			'start_time' => microtime( true ),
			'start_memory' => memory_get_usage( true ),
			'start_peak_memory' => memory_get_peak_usage( true ),
			'start_db_queries' => $this->get_query_count(),
			'context' => $context,
			'pid' => getmypid()
		);
		
		return $profile_id;
	}

	/**
	 * End profiling an operation
	 *
	 * @since    1.0.0
	 * @param    string    $profile_id    Profile ID returned by start_profiling().
	 * @return   array|false              Performance metrics or false on error.
	 */
	public function end_profiling( $profile_id ) {
		if ( ! isset( $this->active_profiles[ $profile_id ] ) ) {
			return false;
		}

		$profile = $this->active_profiles[ $profile_id ];
		$end_time = microtime( true );
		$end_memory = memory_get_usage( true );
		$end_peak_memory = memory_get_peak_usage( true );
		$end_db_queries = $this->get_query_count();

		$metrics = array(
			'operation' => $profile['operation'],
			'execution_time' => $end_time - $profile['start_time'],
			'memory_used' => $end_memory - $profile['start_memory'],
			'peak_memory' => max( $end_peak_memory, $profile['start_peak_memory'] ),
			'memory_delta' => $end_memory - $profile['start_memory'],
			'db_queries' => $end_db_queries - $profile['start_db_queries'],
			'start_time' => $profile['start_time'],
			'end_time' => $end_time,
			'context' => $profile['context'],
			'pid' => $profile['pid']
		);

		// Store metrics
		$this->store_metrics( $profile_id, $metrics );
		
		// Check thresholds and alert if necessary
		$this->check_performance_thresholds( $metrics );
		
		// Clean up active profile
		unset( $this->active_profiles[ $profile_id ] );
		
		return $metrics;
	}

	/**
	 * Get current memory usage
	 *
	 * @since    1.0.0
	 * @param    bool    $real_usage    Whether to get real or emalloc usage.
	 * @return   array                  Memory usage information.
	 */
	public function get_memory_usage( $real_usage = true ) {
		return array(
			'current' => memory_get_usage( $real_usage ),
			'peak' => memory_get_peak_usage( $real_usage ),
			'limit' => $this->get_memory_limit(),
			'available' => $this->get_available_memory(),
			'percentage' => $this->get_memory_percentage_used()
		);
	}

	/**
	 * Get execution time for an operation
	 *
	 * @since    1.0.0
	 * @param    string    $operation    Operation name.
	 * @param    string    $timeframe   Timeframe (hour, day, week).
	 * @return   array                  Execution time statistics.
	 */
	public function get_execution_time( $operation, $timeframe = 'day' ) {
		$cache_key = "execution_time_{$operation}_{$timeframe}";
		$cached = $this->cache->get_cached_data( $cache_key, 'performance' );
		
		if ( $cached !== false ) {
			return $cached;
		}

		$metrics = $this->get_historical_metrics( $operation, $timeframe );
		
		if ( empty( $metrics ) ) {
			return array(
				'average' => 0,
				'min' => 0,
				'max' => 0,
				'count' => 0
			);
		}

		$times = array_column( $metrics, 'execution_time' );
		$stats = array(
			'average' => array_sum( $times ) / count( $times ),
			'min' => min( $times ),
			'max' => max( $times ),
			'count' => count( $times ),
			'median' => $this->calculate_median( $times ),
			'percentile_95' => $this->calculate_percentile( $times, 95 )
		);
		
		// Cache for 5 minutes
		$this->cache->set_cached_data( $cache_key, $stats, 300, 'performance' );
		
		return $stats;
	}

	/**
	 * Get database performance metrics
	 *
	 * @since    1.0.0
	 * @param    string    $timeframe    Timeframe for metrics.
	 * @return   array                   Database performance data.
	 */
	public function get_database_metrics( $timeframe = 'day' ) {
		global $wpdb;
		
		$cache_key = "db_metrics_{$timeframe}";
		$cached = $this->cache->get_cached_data( $cache_key, 'performance' );
		
		if ( $cached !== false ) {
			return $cached;
		}

		$metrics = array(
			'total_queries' => $this->get_query_count(),
			'slow_queries' => $this->get_slow_query_count(),
			'cache_hit_rate' => $this->calculate_cache_hit_rate(),
			'average_query_time' => $this->get_average_query_time(),
			'connection_count' => $this->get_database_connections(),
			'table_sizes' => $this->get_table_sizes()
		);
		
		// Cache for 2 minutes
		$this->cache->set_cached_data( $cache_key, $metrics, 120, 'performance' );
		
		return $metrics;
	}

	/**
	 * Generate comprehensive performance report
	 *
	 * @since    1.0.0
	 * @param    string    $timeframe    Report timeframe.
	 * @return   array                   Performance report data.
	 */
	public function generate_performance_report( $timeframe = 'week' ) {
		$report = array(
			'summary' => $this->get_performance_summary( $timeframe ),
			'scan_performance' => $this->get_scan_performance_stats( $timeframe ),
			'database_performance' => $this->get_database_metrics( $timeframe ),
			'memory_usage' => $this->get_memory_usage_stats( $timeframe ),
			'cache_performance' => $this->get_cache_performance_stats( $timeframe ),
			'alert_summary' => $this->get_alert_summary( $timeframe ),
			'recommendations' => $this->generate_performance_recommendations(),
			'generated_at' => current_time( 'mysql' ),
			'timeframe' => $timeframe
		);
		
		// Store report for historical reference
		$this->store_performance_report( $report );
		
		return $report;
	}

	/**
	 * Start WordPress monitoring
	 *
	 * @since    1.0.0
	 */
	public function start_wordpress_monitoring() {
		if ( ! is_admin() ) {
			$this->start_profiling( 'wordpress_frontend_load' );
		}
	}

	/**
	 * End WordPress monitoring
	 *
	 * @since    1.0.0
	 */
	public function end_wordpress_monitoring() {
		// Find and end any active WordPress profiles
		foreach ( $this->active_profiles as $profile_id => $profile ) {
			if ( strpos( $profile['operation'], 'wordpress_' ) === 0 ) {
				$this->end_profiling( $profile_id );
			}
		}
	}

	/**
	 * Start admin monitoring
	 *
	 * @since    1.0.0
	 */
	public function start_admin_monitoring() {
		$screen = get_current_screen();
		if ( $screen && strpos( $screen->id, 'wp-breach' ) !== false ) {
			$this->start_profiling( 'admin_page_load', array( 'screen' => $screen->id ) );
		}
	}

	/**
	 * Start scan monitoring
	 *
	 * @since    1.0.0
	 * @param    array    $scan_data    Scan information.
	 */
	public function start_scan_monitoring( $scan_data ) {
		$context = array(
			'scan_id' => $scan_data['scan_id'] ?? null,
			'scan_type' => $scan_data['scan_type'] ?? 'unknown'
		);
		
		$this->start_profiling( 'security_scan', $context );
	}

	/**
	 * End scan monitoring
	 *
	 * @since    1.0.0
	 * @param    array    $scan_data    Scan completion data.
	 */
	public function end_scan_monitoring( $scan_data ) {
		// Find and end the scan profile
		foreach ( $this->active_profiles as $profile_id => $profile ) {
			if ( $profile['operation'] === 'security_scan' ) {
				$metrics = $this->end_profiling( $profile_id );
				
				// Store scan-specific metrics
				if ( $metrics && isset( $scan_data['scan_id'] ) ) {
					$this->store_scan_metrics( $scan_data['scan_id'], $metrics );
				}
				break;
			}
		}
	}

	/**
	 * Monitor database queries
	 *
	 * @since    1.0.0
	 * @param    string    $query    SQL query.
	 * @return   string              The query (unchanged).
	 */
	public function monitor_database_query( $query ) {
		$start_time = microtime( true );
		
		// Store query info for analysis
		$this->metrics['db_queries'][] = array(
			'query' => $query,
			'start_time' => $start_time,
			'backtrace' => wp_debug_backtrace_summary()
		);
		
		return $query;
	}

	/**
	 * Record memory usage at checkpoints
	 *
	 * @since    1.0.0
	 */
	public function record_memory_usage() {
		$this->metrics['memory_checkpoints'][] = array(
			'timestamp' => microtime( true ),
			'usage' => memory_get_usage( true ),
			'peak' => memory_get_peak_usage( true ),
			'hook' => current_action()
		);
	}

	/**
	 * Check performance thresholds and alert if exceeded
	 *
	 * @since    1.0.0
	 * @param    array    $metrics    Performance metrics to check.
	 * @access   private
	 */
	private function check_performance_thresholds( $metrics ) {
		$alerts = array();
		
		// Check execution time
		if ( $metrics['execution_time'] > $this->thresholds['max_execution_time'] ) {
			$alerts[] = array(
				'type' => 'execution_time',
				'value' => $metrics['execution_time'],
				'threshold' => $this->thresholds['max_execution_time'],
				'severity' => 'high'
			);
		}
		
		// Check memory usage
		if ( $metrics['peak_memory'] > $this->thresholds['max_memory_usage'] ) {
			$alerts[] = array(
				'type' => 'memory_usage',
				'value' => $metrics['peak_memory'],
				'threshold' => $this->thresholds['max_memory_usage'],
				'severity' => 'high'
			);
		}
		
		// Check database queries
		if ( $metrics['db_queries'] > $this->thresholds['max_db_queries'] ) {
			$alerts[] = array(
				'type' => 'database_queries',
				'value' => $metrics['db_queries'],
				'threshold' => $this->thresholds['max_db_queries'],
				'severity' => 'medium'
			);
		}
		
		// Generate alerts if any thresholds exceeded
		foreach ( $alerts as $alert ) {
			$this->generate_performance_alert( $alert, $metrics );
		}
	}

	/**
	 * Generate performance alert
	 *
	 * @since    1.0.0
	 * @param    array    $alert     Alert information.
	 * @param    array    $metrics   Associated performance metrics.
	 * @access   private
	 */
	private function generate_performance_alert( $alert, $metrics ) {
		$alert_data = array(
			'type' => 'performance',
			'subtype' => $alert['type'],
			'severity' => $alert['severity'],
			'value' => $alert['value'],
			'threshold' => $alert['threshold'],
			'operation' => $metrics['operation'],
			'context' => $metrics['context'],
			'timestamp' => current_time( 'mysql' ),
			'resolved' => false
		);
		
		// Store alert in database
		$this->store_performance_alert( $alert_data );
		
		// Trigger WordPress action for external handling
		do_action( 'wp_breach_performance_alert', $alert_data );
		
		// Log critical alerts
		if ( $alert['severity'] === 'high' ) {
			error_log( "WP-Breach Performance Alert: {$alert['type']} exceeded threshold" );
		}
	}

	/**
	 * Store performance metrics
	 *
	 * @since    1.0.0
	 * @param    string    $profile_id    Profile identifier.
	 * @param    array     $metrics       Performance metrics.
	 * @access   private
	 */
	private function store_metrics( $profile_id, $metrics ) {
		global $wpdb;
		
		$table_name = $wpdb->prefix . 'wp_breach_performance_metrics';
		
		$data = array(
			'profile_id' => $profile_id,
			'operation' => $metrics['operation'],
			'execution_time' => $metrics['execution_time'],
			'memory_used' => $metrics['memory_used'],
			'peak_memory' => $metrics['peak_memory'],
			'db_queries' => $metrics['db_queries'],
			'context' => wp_json_encode( $metrics['context'] ),
			'created_at' => current_time( 'mysql' )
		);
		
		$wpdb->insert( $table_name, $data );
	}

	/**
	 * Get query count from WordPress
	 *
	 * @since    1.0.0
	 * @return   int    Number of database queries.
	 * @access   private
	 */
	private function get_query_count() {
		global $wpdb;
		return $wpdb->num_queries;
	}

	/**
	 * Get memory limit in bytes
	 *
	 * @since    1.0.0
	 * @return   int    Memory limit in bytes.
	 * @access   private
	 */
	private function get_memory_limit() {
		$limit = ini_get( 'memory_limit' );
		return $this->convert_to_bytes( $limit );
	}

	/**
	 * Get available memory
	 *
	 * @since    1.0.0
	 * @return   int    Available memory in bytes.
	 * @access   private
	 */
	private function get_available_memory() {
		return $this->get_memory_limit() - memory_get_usage( true );
	}

	/**
	 * Get memory usage percentage
	 *
	 * @since    1.0.0
	 * @return   float    Memory usage percentage.
	 * @access   private
	 */
	private function get_memory_percentage_used() {
		$limit = $this->get_memory_limit();
		$used = memory_get_usage( true );
		
		return $limit > 0 ? ( $used / $limit ) * 100 : 0;
	}

	/**
	 * Convert memory value to bytes
	 *
	 * @since    1.0.0
	 * @param    string    $value    Memory value (e.g., "256M", "1G").
	 * @return   int                 Value in bytes.
	 * @access   private
	 */
	private function convert_to_bytes( $value ) {
		$value = trim( $value );
		$last = strtolower( $value[ strlen( $value ) - 1 ] );
		$number = (int) $value;
		
		switch ( $last ) {
			case 'g':
				$number *= 1024;
			case 'm':
				$number *= 1024;
			case 'k':
				$number *= 1024;
		}
		
		return $number;
	}

	/**
	 * Calculate median value
	 *
	 * @since    1.0.0
	 * @param    array    $values    Array of numeric values.
	 * @return   float               Median value.
	 * @access   private
	 */
	private function calculate_median( $values ) {
		sort( $values );
		$count = count( $values );
		
		if ( $count === 0 ) {
			return 0;
		}
		
		$middle = floor( $count / 2 );
		
		if ( $count % 2 === 0 ) {
			return ( $values[ $middle - 1 ] + $values[ $middle ] ) / 2;
		}
		
		return $values[ $middle ];
	}

	/**
	 * Calculate percentile value
	 *
	 * @since    1.0.0
	 * @param    array    $values      Array of numeric values.
	 * @param    int      $percentile  Percentile to calculate (0-100).
	 * @return   float                 Percentile value.
	 * @access   private
	 */
	private function calculate_percentile( $values, $percentile ) {
		sort( $values );
		$count = count( $values );
		
		if ( $count === 0 ) {
			return 0;
		}
		
		$index = ( $percentile / 100 ) * ( $count - 1 );
		$lower = floor( $index );
		$upper = ceil( $index );
		
		if ( $lower === $upper ) {
			return $values[ $lower ];
		}
		
		$weight = $index - $lower;
		return $values[ $lower ] * ( 1 - $weight ) + $values[ $upper ] * $weight;
	}

	/**
	 * Store performance alert
	 *
	 * @since    1.0.0
	 * @param    array    $alert_data    Alert information.
	 * @access   private
	 */
	private function store_performance_alert( $alert_data ) {
		global $wpdb;
		
		$table_name = $wpdb->prefix . 'wp_breach_performance_alerts';
		$wpdb->insert( $table_name, $alert_data );
	}

	/**
	 * Store scan metrics
	 *
	 * @since    1.0.0
	 * @param    int      $scan_id    Scan ID.
	 * @param    array    $metrics    Performance metrics.
	 * @access   private
	 */
	private function store_scan_metrics( $scan_id, $metrics ) {
		global $wpdb;
		
		$table_name = $wpdb->prefix . 'wp_breach_scans';
		
		$wpdb->update(
			$table_name,
			array(
				'duration_seconds' => $metrics['execution_time'],
				'memory_peak' => $metrics['peak_memory'],
				'db_queries' => $metrics['db_queries']
			),
			array( 'id' => $scan_id ),
			array( '%f', '%d', '%d' ),
			array( '%d' )
		);
	}

	/**
	 * Get historical metrics for analysis
	 *
	 * @since    1.0.0
	 * @param    string    $operation    Operation name.
	 * @param    string    $timeframe   Timeframe for data.
	 * @return   array                  Historical metrics.
	 * @access   private
	 */
	private function get_historical_metrics( $operation, $timeframe ) {
		global $wpdb;
		
		$table_name = $wpdb->prefix . 'wp_breach_performance_metrics';
		$where_date = $this->get_timeframe_where_clause( $timeframe );
		
		$query = $wpdb->prepare(
			"SELECT * FROM {$table_name} 
			 WHERE operation = %s 
			 AND {$where_date}
			 ORDER BY created_at DESC",
			$operation
		);
		
		return $wpdb->get_results( $query, ARRAY_A );
	}

	/**
	 * Get timeframe WHERE clause
	 *
	 * @since    1.0.0
	 * @param    string    $timeframe    Timeframe (hour, day, week, month).
	 * @return   string                  SQL WHERE clause.
	 * @access   private
	 */
	private function get_timeframe_where_clause( $timeframe ) {
		switch ( $timeframe ) {
			case 'hour':
				return "created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)";
			case 'day':
				return "created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)";
			case 'week':
				return "created_at >= DATE_SUB(NOW(), INTERVAL 1 WEEK)";
			case 'month':
				return "created_at >= DATE_SUB(NOW(), INTERVAL 1 MONTH)";
			default:
				return "created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)";
		}
	}

	/**
	 * Cleanup old performance data
	 *
	 * @since    1.0.0
	 * @param    int    $days_to_keep    Number of days to retain data.
	 */
	public function cleanup_old_data( $days_to_keep = 30 ) {
		global $wpdb;
		
		$tables = array(
			$wpdb->prefix . 'wp_breach_performance_metrics',
			$wpdb->prefix . 'wp_breach_performance_alerts'
		);
		
		foreach ( $tables as $table ) {
			$wpdb->query( $wpdb->prepare(
				"DELETE FROM {$table} WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)",
				$days_to_keep
			) );
		}
	}

	/**
	 * Get performance summary
	 *
	 * @since    1.0.0
	 * @param    string    $timeframe    Summary timeframe.
	 * @return   array                   Performance summary.
	 * @access   private
	 */
	private function get_performance_summary( $timeframe ) {
		// Implementation for getting performance summary
		return array(
			'total_operations' => 0,
			'average_execution_time' => 0,
			'average_memory_usage' => 0,
			'total_alerts' => 0
		);
	}

	/**
	 * Generate performance recommendations
	 *
	 * @since    1.0.0
	 * @return   array    Performance improvement recommendations.
	 * @access   private
	 */
	private function generate_performance_recommendations() {
		$recommendations = array();
		
		// Analyze current performance and suggest improvements
		$memory_usage = $this->get_memory_usage();
		if ( $memory_usage['percentage'] > 80 ) {
			$recommendations[] = array(
				'type' => 'memory',
				'priority' => 'high',
				'message' => 'Memory usage is high. Consider increasing memory limit or optimizing code.',
				'action' => 'optimize_memory'
			);
		}
		
		return $recommendations;
	}
}
