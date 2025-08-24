<?php
/**
 * The database optimization system for WP-Breach.
 *
 * This class provides database query optimization, indexing management,
 * and performance monitoring for all database operations.
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/performance
 */

/**
 * The database optimizer class.
 *
 * This class handles database performance optimization including
 * query optimization, index management, and connection optimization.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/performance
 * @author     luozongbao <luo.zongbao@outlook.com>
 */
class WP_Breach_DB_Optimizer {

	/**
	 * Query cache storage
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      array    $query_cache    Cached query results.
	 */
	private $query_cache;

	/**
	 * Slow query log
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      array    $slow_queries    Log of slow queries.
	 */
	private $slow_queries;

	/**
	 * Database performance metrics
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      array    $metrics    Performance metrics.
	 */
	private $metrics;

	/**
	 * Optimization configuration
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      array    $config    Optimization settings.
	 */
	private $config;

	/**
	 * Cache manager instance
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      WP_Breach_Cache_Manager    $cache    Cache manager.
	 */
	private $cache;

	/**
	 * Initialize the database optimizer
	 *
	 * @since    1.0.0
	 */
	public function __construct() {
		$this->query_cache = array();
		$this->slow_queries = array();
		$this->metrics = array();
		$this->initialize_config();
		$this->setup_hooks();
	}

	/**
	 * Initialize WordPress hooks
	 *
	 * @since    1.0.0
	 */
	public function init() {
		$this->cache = new WP_Breach_Cache_Manager();
		
		// Query monitoring
		if ( $this->config['enable_query_monitoring'] ) {
			add_filter( 'query', array( $this, 'monitor_query_performance' ) );
		}
		
		// Database maintenance
		add_action( 'wp_breach_daily_maintenance', array( $this, 'run_daily_optimization' ) );
		add_action( 'wp_breach_weekly_maintenance', array( $this, 'run_weekly_optimization' ) );
	}

	/**
	 * Optimize scan queries for better performance
	 *
	 * @since    1.0.0
	 * @return   bool    True on success, false on failure.
	 */
	public function optimize_scan_queries() {
		global $wpdb;
		
		$optimization_results = array();
		
		// Optimize vulnerability queries
		$optimization_results['vulnerabilities'] = $this->optimize_vulnerability_queries();
		
		// Optimize scan results queries
		$optimization_results['scan_results'] = $this->optimize_scan_result_queries();
		
		// Optimize performance metrics queries
		$optimization_results['performance_metrics'] = $this->optimize_performance_queries();
		
		// Update query cache strategies
		$optimization_results['cache_optimization'] = $this->optimize_query_caching();
		
		// Log optimization results
		$this->log_optimization_results( $optimization_results );
		
		return array_reduce( $optimization_results, function( $carry, $result ) {
			return $carry && $result;
		}, true );
	}

	/**
	 * Cache frequently used queries
	 *
	 * @since    1.0.0
	 * @param    string    $query_key     Unique key for the query.
	 * @param    string    $sql           SQL query.
	 * @param    array     $params        Query parameters.
	 * @param    int       $cache_time    Cache duration in seconds.
	 * @return   mixed                    Query results.
	 */
	public function cache_frequent_queries( $query_key, $sql, $params = array(), $cache_time = 300 ) {
		global $wpdb;
		
		// Generate cache key based on query and parameters
		$cache_key = $this->generate_query_cache_key( $query_key, $sql, $params );
		
		// Try to get from cache
		$cached_result = $this->cache->get_cached_data( $cache_key, 'db_queries' );
		if ( $cached_result !== false ) {
			$this->record_query_cache_hit( $query_key );
			return $cached_result;
		}
		
		// Execute query with performance monitoring
		$start_time = microtime( true );
		
		if ( ! empty( $params ) ) {
			$result = $wpdb->get_results( $wpdb->prepare( $sql, $params ), ARRAY_A );
		} else {
			$result = $wpdb->get_results( $sql, ARRAY_A );
		}
		
		$execution_time = microtime( true ) - $start_time;
		
		// Record performance metrics
		$this->record_query_performance( $query_key, $execution_time, $sql );
		
		// Cache successful results
		if ( $result !== false && $wpdb->last_error === '' ) {
			$this->cache->set_cached_data( $cache_key, $result, $cache_time, 'db_queries' );
			$this->record_query_cache_miss( $query_key );
		}
		
		return $result;
	}

	/**
	 * Analyze and identify slow queries
	 *
	 * @since    1.0.0
	 * @param    string    $timeframe    Analysis timeframe.
	 * @return   array                   Slow query analysis results.
	 */
	public function analyze_slow_queries( $timeframe = 'day' ) {
		$slow_threshold = $this->config['slow_query_threshold'];
		$cache_key = "slow_query_analysis_{$timeframe}";
		
		// Try to get from cache
		$cached_analysis = $this->cache->get_cached_data( $cache_key, 'db_analysis' );
		if ( $cached_analysis !== false ) {
			return $cached_analysis;
		}
		
		// Analyze queries from performance metrics
		$slow_queries = $this->get_slow_queries_from_metrics( $timeframe, $slow_threshold );
		
		$analysis = array(
			'total_slow_queries' => count( $slow_queries ),
			'average_execution_time' => $this->calculate_average_execution_time( $slow_queries ),
			'most_frequent_slow_queries' => $this->get_most_frequent_slow_queries( $slow_queries ),
			'optimization_recommendations' => $this->generate_query_optimization_recommendations( $slow_queries ),
			'timeframe' => $timeframe,
			'analyzed_at' => current_time( 'mysql' )
		);
		
		// Cache analysis for 1 hour
		$this->cache->set_cached_data( $cache_key, $analysis, 3600, 'db_analysis' );
		
		return $analysis;
	}

	/**
	 * Implement query pagination for large result sets
	 *
	 * @since    1.0.0
	 * @param    string    $base_query    Base SQL query.
	 * @param    int       $page_size     Number of results per page.
	 * @param    int       $page_number   Page number (1-based).
	 * @param    array     $params        Query parameters.
	 * @return   array                    Paginated results with metadata.
	 */
	public function implement_query_pagination( $base_query, $page_size = 50, $page_number = 1, $params = array() ) {
		global $wpdb;
		
		// Validate inputs
		$page_size = max( 1, min( $page_size, $this->config['max_page_size'] ) );
		$page_number = max( 1, $page_number );
		$offset = ( $page_number - 1 ) * $page_size;
		
		// Get total count for pagination metadata
		$count_query = $this->convert_to_count_query( $base_query );
		$total_count = $this->cache_frequent_queries(
			"pagination_count_" . md5( $count_query ),
			$count_query,
			$params,
			600 // 10 minutes cache
		);
		
		$total_count = intval( $total_count[0]['count'] ?? 0 );
		
		// Add LIMIT and OFFSET to the query
		$paginated_query = $base_query . $wpdb->prepare( " LIMIT %d OFFSET %d", $page_size, $offset );
		
		// Execute paginated query
		$results = $this->cache_frequent_queries(
			"paginated_" . md5( $paginated_query ) . "_{$page_number}",
			$paginated_query,
			$params,
			300 // 5 minutes cache
		);
		
		// Calculate pagination metadata
		$total_pages = ceil( $total_count / $page_size );
		$has_previous = $page_number > 1;
		$has_next = $page_number < $total_pages;
		
		return array(
			'data' => $results,
			'pagination' => array(
				'current_page' => $page_number,
				'page_size' => $page_size,
				'total_count' => $total_count,
				'total_pages' => $total_pages,
				'has_previous' => $has_previous,
				'has_next' => $has_next,
				'previous_page' => $has_previous ? $page_number - 1 : null,
				'next_page' => $has_next ? $page_number + 1 : null
			)
		);
	}

	/**
	 * Optimize database indexes for better performance
	 *
	 * @since    1.0.0
	 * @return   array    Index optimization results.
	 */
	public function optimize_database_indexes() {
		global $wpdb;
		
		$optimization_results = array();
		
		// Get list of WP-Breach tables
		$tables = $this->get_plugin_tables();
		
		foreach ( $tables as $table ) {
			$optimization_results[ $table ] = $this->optimize_table_indexes( $table );
		}
		
		// Analyze index usage
		$index_analysis = $this->analyze_index_usage();
		$optimization_results['index_analysis'] = $index_analysis;
		
		// Create missing indexes based on query patterns
		$missing_indexes = $this->identify_missing_indexes();
		$optimization_results['missing_indexes'] = $missing_indexes;
		
		return $optimization_results;
	}

	/**
	 * Get database connection performance metrics
	 *
	 * @since    1.0.0
	 * @return   array    Connection performance data.
	 */
	public function get_connection_performance() {
		global $wpdb;
		
		$metrics = array(
			'connection_count' => $this->get_active_connection_count(),
			'connection_time' => $this->measure_connection_time(),
			'query_cache_hit_rate' => $this->get_query_cache_hit_rate(),
			'slow_query_count' => count( $this->slow_queries ),
			'average_query_time' => $this->get_average_query_time(),
			'total_queries' => $wpdb->num_queries,
			'database_size' => $this->get_database_size(),
			'table_status' => $this->get_table_status()
		);
		
		return $metrics;
	}

	/**
	 * Run daily database optimization tasks
	 *
	 * @since    1.0.0
	 */
	public function run_daily_optimization() {
		// Optimize frequently accessed tables
		$this->optimize_table_performance();
		
		// Update query statistics
		$this->update_query_statistics();
		
		// Clean up old performance data
		$this->cleanup_old_performance_data();
		
		// Refresh query cache
		$this->refresh_query_cache();
		
		// Log optimization completion
		error_log( 'WP-Breach: Daily database optimization completed' );
	}

	/**
	 * Run weekly database optimization tasks
	 *
	 * @since    1.0.0
	 */
	public function run_weekly_optimization() {
		// Analyze and optimize indexes
		$this->optimize_database_indexes();
		
		// Analyze slow queries
		$slow_query_analysis = $this->analyze_slow_queries( 'week' );
		
		// Defragment tables if needed
		$this->defragment_tables();
		
		// Update database statistics
		$this->update_database_statistics();
		
		// Generate optimization report
		$this->generate_optimization_report( $slow_query_analysis );
		
		error_log( 'WP-Breach: Weekly database optimization completed' );
	}

	/**
	 * Monitor query performance in real-time
	 *
	 * @since    1.0.0
	 * @param    string    $query    SQL query to monitor.
	 * @return   string              The query (unchanged).
	 */
	public function monitor_query_performance( $query ) {
		// Skip monitoring for non-plugin queries if configured
		if ( $this->config['monitor_plugin_queries_only'] && ! $this->is_plugin_query( $query ) ) {
			return $query;
		}
		
		$start_time = microtime( true );
		
		// Store query start information
		$query_id = uniqid( 'query_' );
		$this->metrics['active_queries'][ $query_id ] = array(
			'query' => $query,
			'start_time' => $start_time,
			'backtrace' => wp_debug_backtrace_summary()
		);
		
		// Monitor query after execution (using shutdown hook)
		add_action( 'shutdown', function() use ( $query_id, $query, $start_time ) {
			$execution_time = microtime( true ) - $start_time;
			
			// Record performance metrics
			$this->record_query_performance( $query_id, $execution_time, $query );
			
			// Check if query is slow
			if ( $execution_time > $this->config['slow_query_threshold'] ) {
				$this->log_slow_query( $query, $execution_time );
			}
			
			// Clean up active query tracking
			unset( $this->metrics['active_queries'][ $query_id ] );
		}, 999 );
		
		return $query;
	}

	/**
	 * Initialize optimization configuration
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function initialize_config() {
		$defaults = array(
			'enable_query_monitoring' => true,
			'monitor_plugin_queries_only' => false,
			'slow_query_threshold' => 1.0,        // 1 second
			'max_page_size' => 200,
			'query_cache_ttl' => 300,             // 5 minutes
			'enable_index_optimization' => true,
			'auto_create_indexes' => false,
			'maintenance_mode' => false
		);
		
		$user_config = get_option( 'wp_breach_db_optimizer_config', array() );
		$this->config = array_merge( $defaults, $user_config );
	}

	/**
	 * Setup database hooks
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function setup_hooks() {
		// Database maintenance hooks
		add_action( 'wp_breach_cleanup_database', array( $this, 'cleanup_old_performance_data' ) );
		
		// Query cache invalidation
		add_action( 'wp_breach_vulnerability_updated', array( $this, 'invalidate_vulnerability_cache' ) );
		add_action( 'wp_breach_scan_completed', array( $this, 'invalidate_scan_cache' ) );
	}

	/**
	 * Optimize vulnerability queries
	 *
	 * @since    1.0.0
	 * @return   bool    True on success, false on failure.
	 * @access   private
	 */
	private function optimize_vulnerability_queries() {
		global $wpdb;
		
		$table_name = $wpdb->prefix . 'wp_breach_vulnerabilities';
		
		// Check and create optimized indexes
		$indexes_to_create = array(
			'idx_status_severity' => "ALTER TABLE {$table_name} ADD INDEX idx_status_severity (status, severity)",
			'idx_component_type_name' => "ALTER TABLE {$table_name} ADD INDEX idx_component_type_name (component_type, component_name)",
			'idx_detected_at_severity' => "ALTER TABLE {$table_name} ADD INDEX idx_detected_at_severity (detected_at, severity)",
			'idx_scan_id_status' => "ALTER TABLE {$table_name} ADD INDEX idx_scan_id_status (scan_id, status)"
		);
		
		$success = true;
		foreach ( $indexes_to_create as $index_name => $sql ) {
			if ( ! $this->index_exists( $table_name, $index_name ) ) {
				$result = $wpdb->query( $sql );
				$success = $success && ( $result !== false );
			}
		}
		
		return $success;
	}

	/**
	 * Optimize scan result queries
	 *
	 * @since    1.0.0
	 * @return   bool    True on success, false on failure.
	 * @access   private
	 */
	private function optimize_scan_result_queries() {
		global $wpdb;
		
		$table_name = $wpdb->prefix . 'wp_breach_scans';
		
		// Optimize scan table indexes
		$indexes_to_create = array(
			'idx_status_started_at' => "ALTER TABLE {$table_name} ADD INDEX idx_status_started_at (status, started_at)",
			'idx_scan_type_status' => "ALTER TABLE {$table_name} ADD INDEX idx_scan_type_status (scan_type, status)",
			'idx_created_by_started_at' => "ALTER TABLE {$table_name} ADD INDEX idx_created_by_started_at (created_by, started_at)"
		);
		
		$success = true;
		foreach ( $indexes_to_create as $index_name => $sql ) {
			if ( ! $this->index_exists( $table_name, $index_name ) ) {
				$result = $wpdb->query( $sql );
				$success = $success && ( $result !== false );
			}
		}
		
		return $success;
	}

	/**
	 * Optimize performance metrics queries
	 *
	 * @since    1.0.0
	 * @return   bool    True on success, false on failure.
	 * @access   private
	 */
	private function optimize_performance_queries() {
		global $wpdb;
		
		$table_name = $wpdb->prefix . 'wp_breach_performance_metrics';
		
		// Create performance metrics table if it doesn't exist
		$this->create_performance_metrics_table();
		
		// Optimize performance metrics indexes
		$indexes_to_create = array(
			'idx_operation_created_at' => "ALTER TABLE {$table_name} ADD INDEX idx_operation_created_at (operation, created_at)",
			'idx_execution_time' => "ALTER TABLE {$table_name} ADD INDEX idx_execution_time (execution_time)",
			'idx_created_at' => "ALTER TABLE {$table_name} ADD INDEX idx_created_at (created_at)"
		);
		
		$success = true;
		foreach ( $indexes_to_create as $index_name => $sql ) {
			if ( ! $this->index_exists( $table_name, $index_name ) ) {
				$result = $wpdb->query( $sql );
				$success = $success && ( $result !== false );
			}
		}
		
		return $success;
	}

	/**
	 * Optimize query caching strategies
	 *
	 * @since    1.0.0
	 * @return   bool    True on success, false on failure.
	 * @access   private
	 */
	private function optimize_query_caching() {
		// Analyze query patterns to optimize caching
		$query_patterns = $this->analyze_query_patterns();
		
		// Update cache TTL based on query frequency
		$this->update_cache_strategies( $query_patterns );
		
		// Pre-warm frequently accessed queries
		$this->prewarm_frequent_queries();
		
		return true;
	}

	/**
	 * Generate cache key for query results
	 *
	 * @since    1.0.0
	 * @param    string    $query_key    Base query key.
	 * @param    string    $sql          SQL query.
	 * @param    array     $params       Query parameters.
	 * @return   string                  Generated cache key.
	 * @access   private
	 */
	private function generate_query_cache_key( $query_key, $sql, $params ) {
		$key_data = array(
			'query_key' => $query_key,
			'sql_hash' => md5( $sql ),
			'params_hash' => md5( serialize( $params ) )
		);
		
		return 'db_query_' . md5( serialize( $key_data ) );
	}

	/**
	 * Record query cache hit
	 *
	 * @since    1.0.0
	 * @param    string    $query_key    Query identifier.
	 * @access   private
	 */
	private function record_query_cache_hit( $query_key ) {
		$this->metrics['cache_hits'][ $query_key ] = ( $this->metrics['cache_hits'][ $query_key ] ?? 0 ) + 1;
	}

	/**
	 * Record query cache miss
	 *
	 * @since    1.0.0
	 * @param    string    $query_key    Query identifier.
	 * @access   private
	 */
	private function record_query_cache_miss( $query_key ) {
		$this->metrics['cache_misses'][ $query_key ] = ( $this->metrics['cache_misses'][ $query_key ] ?? 0 ) + 1;
	}

	/**
	 * Record query performance metrics
	 *
	 * @since    1.0.0
	 * @param    string    $query_id        Query identifier.
	 * @param    float     $execution_time  Execution time in seconds.
	 * @param    string    $sql             SQL query.
	 * @access   private
	 */
	private function record_query_performance( $query_id, $execution_time, $sql ) {
		$this->metrics['query_performance'][] = array(
			'query_id' => $query_id,
			'execution_time' => $execution_time,
			'sql' => $sql,
			'timestamp' => microtime( true )
		);
		
		// Store in database for historical analysis
		$this->store_query_performance_metric( $query_id, $execution_time, $sql );
	}

	/**
	 * Convert query to count query for pagination
	 *
	 * @since    1.0.0
	 * @param    string    $query    Original SQL query.
	 * @return   string              Count query.
	 * @access   private
	 */
	private function convert_to_count_query( $query ) {
		// Simple approach: wrap the query in a COUNT
		// More sophisticated parsing could be implemented
		$count_query = "SELECT COUNT(*) as count FROM ($query) as count_subquery";
		
		return $count_query;
	}

	/**
	 * Check if index exists on table
	 *
	 * @since    1.0.0
	 * @param    string    $table        Table name.
	 * @param    string    $index_name   Index name.
	 * @return   bool                    True if index exists, false otherwise.
	 * @access   private
	 */
	private function index_exists( $table, $index_name ) {
		global $wpdb;
		
		$result = $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS 
			 WHERE TABLE_SCHEMA = %s 
			 AND TABLE_NAME = %s 
			 AND INDEX_NAME = %s",
			DB_NAME,
			$table,
			$index_name
		) );
		
		return intval( $result ) > 0;
	}

	/**
	 * Create performance metrics table
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function create_performance_metrics_table() {
		global $wpdb;
		
		$table_name = $wpdb->prefix . 'wp_breach_performance_metrics';
		$charset_collate = $wpdb->get_charset_collate();
		
		$sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
			id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			profile_id varchar(50) NOT NULL,
			operation varchar(100) NOT NULL,
			execution_time decimal(10,6) NOT NULL,
			memory_used bigint(20) UNSIGNED NOT NULL,
			peak_memory bigint(20) UNSIGNED NOT NULL,
			db_queries int UNSIGNED NOT NULL,
			context longtext,
			created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY idx_operation (operation),
			KEY idx_execution_time (execution_time),
			KEY idx_created_at (created_at),
			KEY idx_operation_created_at (operation, created_at)
		) {$charset_collate};";
		
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	/**
	 * Get plugin tables for optimization
	 *
	 * @since    1.0.0
	 * @return   array    List of plugin table names.
	 * @access   private
	 */
	private function get_plugin_tables() {
		global $wpdb;
		
		return array(
			$wpdb->prefix . 'wp_breach_scans',
			$wpdb->prefix . 'wp_breach_vulnerabilities',
			$wpdb->prefix . 'wp_breach_fixes',
			$wpdb->prefix . 'wp_breach_performance_metrics',
			$wpdb->prefix . 'wp_breach_audit_logs',
			$wpdb->prefix . 'wp_breach_delegations',
			$wpdb->prefix . 'wp_breach_user_sessions'
		);
	}

	/**
	 * Store query performance metric in database
	 *
	 * @since    1.0.0
	 * @param    string    $query_id        Query identifier.
	 * @param    float     $execution_time  Execution time.
	 * @param    string    $sql             SQL query.
	 * @access   private
	 */
	private function store_query_performance_metric( $query_id, $execution_time, $sql ) {
		global $wpdb;
		
		$table_name = $wpdb->prefix . 'wp_breach_performance_metrics';
		
		$wpdb->insert(
			$table_name,
			array(
				'profile_id' => $query_id,
				'operation' => 'database_query',
				'execution_time' => $execution_time,
				'memory_used' => memory_get_usage( true ),
				'peak_memory' => memory_get_peak_usage( true ),
				'db_queries' => 1,
				'context' => wp_json_encode( array( 'sql' => substr( $sql, 0, 500 ) ) ),
				'created_at' => current_time( 'mysql' )
			),
			array( '%s', '%s', '%f', '%d', '%d', '%d', '%s', '%s' )
		);
	}

	/**
	 * Log slow query for analysis
	 *
	 * @since    1.0.0
	 * @param    string    $query           SQL query.
	 * @param    float     $execution_time  Execution time.
	 * @access   private
	 */
	private function log_slow_query( $query, $execution_time ) {
		$this->slow_queries[] = array(
			'query' => $query,
			'execution_time' => $execution_time,
			'timestamp' => time(),
			'backtrace' => wp_debug_backtrace_summary()
		);
		
		// Log to WordPress error log if enabled
		if ( defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG ) {
			error_log( "WP-Breach Slow Query ({$execution_time}s): " . substr( $query, 0, 200 ) );
		}
	}

	/**
	 * Check if query is related to plugin
	 *
	 * @since    1.0.0
	 * @param    string    $query    SQL query.
	 * @return   bool                True if plugin query, false otherwise.
	 * @access   private
	 */
	private function is_plugin_query( $query ) {
		$plugin_patterns = array(
			'wp_breach_',
			'WP_Breach',
			'wp-breach'
		);
		
		foreach ( $plugin_patterns as $pattern ) {
			if ( strpos( $query, $pattern ) !== false ) {
				return true;
			}
		}
		
		return false;
	}

	/**
	 * Get active database connection count
	 *
	 * @since    1.0.0
	 * @return   int    Number of active connections.
	 * @access   private
	 */
	private function get_active_connection_count() {
		global $wpdb;
		
		$result = $wpdb->get_var( "SHOW STATUS LIKE 'Threads_connected'" );
		return intval( $result );
	}

	/**
	 * Measure database connection time
	 *
	 * @since    1.0.0
	 * @return   float    Connection time in seconds.
	 * @access   private
	 */
	private function measure_connection_time() {
		$start_time = microtime( true );
		
		// Simple query to test connection
		global $wpdb;
		$wpdb->get_var( "SELECT 1" );
		
		return microtime( true ) - $start_time;
	}

	/**
	 * Get query cache hit rate
	 *
	 * @since    1.0.0
	 * @return   float    Cache hit rate percentage.
	 * @access   private
	 */
	private function get_query_cache_hit_rate() {
		$total_hits = array_sum( $this->metrics['cache_hits'] ?? array() );
		$total_misses = array_sum( $this->metrics['cache_misses'] ?? array() );
		$total_requests = $total_hits + $total_misses;
		
		return $total_requests > 0 ? ( $total_hits / $total_requests ) * 100 : 0;
	}

	/**
	 * Get average query execution time
	 *
	 * @since    1.0.0
	 * @return   float    Average execution time in seconds.
	 * @access   private
	 */
	private function get_average_query_time() {
		$performances = $this->metrics['query_performance'] ?? array();
		
		if ( empty( $performances ) ) {
			return 0;
		}
		
		$total_time = array_sum( array_column( $performances, 'execution_time' ) );
		return $total_time / count( $performances );
	}

	/**
	 * Get database size information
	 *
	 * @since    1.0.0
	 * @return   array    Database size information.
	 * @access   private
	 */
	private function get_database_size() {
		global $wpdb;
		
		$result = $wpdb->get_row( $wpdb->prepare(
			"SELECT 
				SUM(data_length + index_length) as total_size,
				SUM(data_length) as data_size,
				SUM(index_length) as index_size
			 FROM information_schema.TABLES 
			 WHERE table_schema = %s 
			 AND table_name LIKE %s",
			DB_NAME,
			$wpdb->prefix . 'wp_breach_%'
		), ARRAY_A );
		
		return array(
			'total_size' => intval( $result['total_size'] ?? 0 ),
			'data_size' => intval( $result['data_size'] ?? 0 ),
			'index_size' => intval( $result['index_size'] ?? 0 ),
			'total_size_human' => size_format( intval( $result['total_size'] ?? 0 ) )
		);
	}

	/**
	 * Cleanup old performance data
	 *
	 * @since    1.0.0
	 */
	public function cleanup_old_performance_data() {
		global $wpdb;
		
		$retention_days = 30; // Keep 30 days of performance data
		$table_name = $wpdb->prefix . 'wp_breach_performance_metrics';
		
		$wpdb->query( $wpdb->prepare(
			"DELETE FROM {$table_name} WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)",
			$retention_days
		) );
	}
}
