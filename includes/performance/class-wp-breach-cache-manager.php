<?php
/**
 * The cache management system for WP-Breach.
 *
 * This class provides multi-level caching capabilities to optimize
 * performance across all plugin operations.
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/performance
 */

/**
 * The cache manager class.
 *
 * This class implements a sophisticated multi-level caching system
 * with object cache, transients, and file-based caching.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/performance
 * @author     luozongbao <luo.zongbao@outlook.com>
 */
class WP_Breach_Cache_Manager {

	/**
	 * Cache statistics
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      array    $stats    Cache hit/miss statistics.
	 */
	private $stats;

	/**
	 * Cache configuration
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      array    $config    Cache configuration settings.
	 */
	private $config;

	/**
	 * File cache directory
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      string    $cache_dir    Directory for file-based cache.
	 */
	private $cache_dir;

	/**
	 * Initialize the cache manager
	 *
	 * @since    1.0.0
	 */
	public function __construct() {
		$this->initialize_stats();
		$this->initialize_config();
		$this->setup_cache_directory();
		$this->setup_hooks();
	}

	/**
	 * Initialize WordPress hooks
	 *
	 * @since    1.0.0
	 */
	public function init() {
		// Cache warming on plugin activation
		add_action( 'wp_breach_plugin_activated', array( $this, 'warm_cache' ) );
		
		// Cache cleanup
		add_action( 'wp_breach_daily_cleanup', array( $this, 'cleanup_expired_cache' ) );
		
		// Performance monitoring
		add_action( 'wp_breach_cache_hit', array( $this, 'record_cache_hit' ) );
		add_action( 'wp_breach_cache_miss', array( $this, 'record_cache_miss' ) );
	}

	/**
	 * Get cached data with multi-level fallback
	 *
	 * @since    1.0.0
	 * @param    string    $key      Cache key.
	 * @param    string    $group    Cache group.
	 * @return   mixed               Cached data or false if not found.
	 */
	public function get_cached_data( $key, $group = 'wp_breach' ) {
		$full_key = $this->generate_cache_key( $key, $group );
		
		// Level 1: Object Cache (fastest)
		$data = wp_cache_get( $full_key, $group );
		if ( $data !== false ) {
			$this->record_cache_hit( 'object', $full_key );
			return $data;
		}
		
		// Level 2: Transient Cache
		$data = get_transient( $full_key );
		if ( $data !== false ) {
			// Store in object cache for faster subsequent access
			wp_cache_set( $full_key, $data, $group, 300 ); // 5 minutes
			$this->record_cache_hit( 'transient', $full_key );
			return $data;
		}
		
		// Level 3: File Cache (for large data)
		if ( $this->config['enable_file_cache'] ) {
			$data = $this->get_file_cache( $full_key );
			if ( $data !== false ) {
				// Store in upper levels for faster access
				set_transient( $full_key, $data, 3600 ); // 1 hour
				wp_cache_set( $full_key, $data, $group, 300 ); // 5 minutes
				$this->record_cache_hit( 'file', $full_key );
				return $data;
			}
		}
		
		$this->record_cache_miss( $full_key );
		return false;
	}

	/**
	 * Set cached data across multiple levels
	 *
	 * @since    1.0.0
	 * @param    string    $key       Cache key.
	 * @param    mixed     $data      Data to cache.
	 * @param    int       $expiry    Expiration time in seconds.
	 * @param    string    $group     Cache group.
	 * @return   bool                 True on success, false on failure.
	 */
	public function set_cached_data( $key, $data, $expiry = 3600, $group = 'wp_breach' ) {
		$full_key = $this->generate_cache_key( $key, $group );
		$success = true;
		
		// Determine caching strategy based on data size
		$data_size = strlen( serialize( $data ) );
		$use_file_cache = $data_size > $this->config['file_cache_threshold'];
		
		// Level 1: Object Cache (always, but limited time for large data)
		$object_expiry = $use_file_cache ? min( 300, $expiry ) : min( 300, $expiry );
		$success = wp_cache_set( $full_key, $data, $group, $object_expiry ) && $success;
		
		// Level 2: Transient Cache
		$success = set_transient( $full_key, $data, $expiry ) && $success;
		
		// Level 3: File Cache (for large data or long-term storage)
		if ( $use_file_cache && $this->config['enable_file_cache'] ) {
			$success = $this->set_file_cache( $full_key, $data, $expiry ) && $success;
		}
		
		return $success;
	}

	/**
	 * Delete cached data from all levels
	 *
	 * @since    1.0.0
	 * @param    string    $key      Cache key.
	 * @param    string    $group    Cache group.
	 * @return   bool                True on success, false on failure.
	 */
	public function delete_cached_data( $key, $group = 'wp_breach' ) {
		$full_key = $this->generate_cache_key( $key, $group );
		
		// Remove from all cache levels
		wp_cache_delete( $full_key, $group );
		delete_transient( $full_key );
		
		if ( $this->config['enable_file_cache'] ) {
			$this->delete_file_cache( $full_key );
		}
		
		return true;
	}

	/**
	 * Flush all cached data for the plugin
	 *
	 * @since    1.0.0
	 * @param    string    $group    Specific group to flush, or null for all.
	 * @return   bool                True on success, false on failure.
	 */
	public function flush_cache( $group = null ) {
		if ( $group ) {
			return $this->flush_group_cache( $group );
		}
		
		// Flush object cache for WP-Breach
		wp_cache_flush_group( 'wp_breach' );
		
		// Flush transients
		$this->flush_transients();
		
		// Flush file cache
		if ( $this->config['enable_file_cache'] ) {
			$this->flush_file_cache();
		}
		
		// Reset statistics
		$this->initialize_stats();
		
		return true;
	}

	/**
	 * Get cache statistics
	 *
	 * @since    1.0.0
	 * @return   array    Cache performance statistics.
	 */
	public function get_cache_stats() {
		$total_requests = $this->stats['hits'] + $this->stats['misses'];
		
		$stats = array(
			'hits' => $this->stats['hits'],
			'misses' => $this->stats['misses'],
			'total_requests' => $total_requests,
			'hit_rate' => $total_requests > 0 ? ( $this->stats['hits'] / $total_requests ) * 100 : 0,
			'hit_rate_by_level' => $this->stats['hits_by_level'],
			'cache_size' => $this->get_cache_size(),
			'memory_usage' => $this->get_cache_memory_usage()
		);
		
		return $stats;
	}

	/**
	 * Cache scan results with intelligent invalidation
	 *
	 * @since    1.0.0
	 * @param    int      $scan_id      Scan ID.
	 * @param    array    $results      Scan results.
	 * @param    string   $scan_type    Type of scan.
	 * @return   bool                   True on success, false on failure.
	 */
	public function cache_scan_results( $scan_id, $results, $scan_type = 'full' ) {
		$cache_key = "scan_results_{$scan_id}";
		$expiry = $this->get_scan_cache_expiry( $scan_type );
		
		// Add metadata for intelligent invalidation
		$cached_data = array(
			'results' => $results,
			'scan_type' => $scan_type,
			'cached_at' => time(),
			'file_hashes' => $this->get_current_file_hashes(),
			'plugin_versions' => $this->get_plugin_versions()
		);
		
		return $this->set_cached_data( $cache_key, $cached_data, $expiry, 'scan_results' );
	}

	/**
	 * Get cached scan results with validation
	 *
	 * @since    1.0.0
	 * @param    int      $scan_id    Scan ID.
	 * @return   array|false          Cached scan results or false if invalid.
	 */
	public function get_cached_scan_results( $scan_id ) {
		$cache_key = "scan_results_{$scan_id}";
		$cached_data = $this->get_cached_data( $cache_key, 'scan_results' );
		
		if ( $cached_data === false ) {
			return false;
		}
		
		// Validate cache freshness
		if ( ! $this->is_scan_cache_valid( $cached_data ) ) {
			$this->delete_cached_data( $cache_key, 'scan_results' );
			return false;
		}
		
		return $cached_data['results'];
	}

	/**
	 * Cache vulnerability database
	 *
	 * @since    1.0.0
	 * @param    array    $vulnerability_db    Vulnerability database.
	 * @return   bool                          True on success, false on failure.
	 */
	public function cache_vulnerability_database( $vulnerability_db ) {
		$cache_key = 'vulnerability_database';
		$expiry = $this->config['vulnerability_db_cache_expiry'];
		
		return $this->set_cached_data( $cache_key, $vulnerability_db, $expiry, 'vulnerability_data' );
	}

	/**
	 * Get cached vulnerability database
	 *
	 * @since    1.0.0
	 * @return   array|false    Cached vulnerability database or false if not found.
	 */
	public function get_cached_vulnerability_database() {
		return $this->get_cached_data( 'vulnerability_database', 'vulnerability_data' );
	}

	/**
	 * Cache file hash for integrity monitoring
	 *
	 * @since    1.0.0
	 * @param    string    $file_path    File path.
	 * @param    string    $hash         File hash.
	 * @return   bool                    True on success, false on failure.
	 */
	public function cache_file_hash( $file_path, $hash ) {
		$cache_key = 'file_hash_' . md5( $file_path );
		$expiry = $this->config['file_hash_cache_expiry'];
		
		$data = array(
			'hash' => $hash,
			'file_path' => $file_path,
			'cached_at' => time()
		);
		
		return $this->set_cached_data( $cache_key, $data, $expiry, 'file_hashes' );
	}

	/**
	 * Get cached file hash
	 *
	 * @since    1.0.0
	 * @param    string    $file_path    File path.
	 * @return   string|false            Cached file hash or false if not found.
	 */
	public function get_cached_file_hash( $file_path ) {
		$cache_key = 'file_hash_' . md5( $file_path );
		$data = $this->get_cached_data( $cache_key, 'file_hashes' );
		
		return $data !== false ? $data['hash'] : false;
	}

	/**
	 * Warm up cache with frequently accessed data
	 *
	 * @since    1.0.0
	 */
	public function warm_cache() {
		if ( ! $this->config['enable_cache_warming'] ) {
			return;
		}
		
		// Warm up configuration cache
		$this->warm_configuration_cache();
		
		// Warm up vulnerability database cache
		$this->warm_vulnerability_database_cache();
		
		// Warm up frequently accessed scan results
		$this->warm_scan_results_cache();
	}

	/**
	 * Initialize cache statistics
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function initialize_stats() {
		$this->stats = array(
			'hits' => 0,
			'misses' => 0,
			'hits_by_level' => array(
				'object' => 0,
				'transient' => 0,
				'file' => 0
			)
		);
	}

	/**
	 * Initialize cache configuration
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function initialize_config() {
		$defaults = array(
			'enable_file_cache' => true,
			'file_cache_threshold' => 1048576, // 1MB
			'enable_cache_warming' => true,
			'scan_cache_expiry' => 3600,        // 1 hour
			'vulnerability_db_cache_expiry' => 86400, // 24 hours
			'file_hash_cache_expiry' => 7200,   // 2 hours
			'max_file_cache_size' => 104857600  // 100MB
		);
		
		$user_config = get_option( 'wp_breach_cache_config', array() );
		$this->config = array_merge( $defaults, $user_config );
	}

	/**
	 * Setup cache directory
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function setup_cache_directory() {
		$upload_dir = wp_upload_dir();
		$this->cache_dir = $upload_dir['basedir'] . '/wp-breach-cache/';
		
		// Create cache directory if it doesn't exist
		if ( ! file_exists( $this->cache_dir ) ) {
			wp_mkdir_p( $this->cache_dir );
			
			// Add .htaccess for security
			$htaccess_content = "Deny from all\n";
			file_put_contents( $this->cache_dir . '.htaccess', $htaccess_content );
		}
	}

	/**
	 * Setup cache hooks
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function setup_hooks() {
		// Clean up cache on plugin deactivation
		register_deactivation_hook( WP_BREACH_PLUGIN_FILE, array( $this, 'flush_cache' ) );
		
		// Cache invalidation triggers
		add_action( 'wp_breach_vulnerability_fixed', array( $this, 'invalidate_scan_cache' ) );
		add_action( 'wp_breach_settings_updated', array( $this, 'invalidate_config_cache' ) );
	}

	/**
	 * Generate cache key
	 *
	 * @since    1.0.0
	 * @param    string    $key      Base cache key.
	 * @param    string    $group    Cache group.
	 * @return   string              Full cache key.
	 * @access   private
	 */
	private function generate_cache_key( $key, $group ) {
		return "wp_breach_{$group}_{$key}";
	}

	/**
	 * Get file cache
	 *
	 * @since    1.0.0
	 * @param    string    $key    Cache key.
	 * @return   mixed             Cached data or false if not found.
	 * @access   private
	 */
	private function get_file_cache( $key ) {
		$cache_file = $this->get_cache_file_path( $key );
		
		if ( ! file_exists( $cache_file ) ) {
			return false;
		}
		
		// Check if cache has expired
		$file_time = filemtime( $cache_file );
		$expiry_time = $this->get_file_cache_expiry( $key );
		
		if ( time() - $file_time > $expiry_time ) {
			unlink( $cache_file );
			return false;
		}
		
		$data = file_get_contents( $cache_file );
		return $data ? unserialize( $data ) : false;
	}

	/**
	 * Set file cache
	 *
	 * @since    1.0.0
	 * @param    string    $key      Cache key.
	 * @param    mixed     $data     Data to cache.
	 * @param    int       $expiry   Expiration time.
	 * @return   bool                True on success, false on failure.
	 * @access   private
	 */
	private function set_file_cache( $key, $data, $expiry ) {
		$cache_file = $this->get_cache_file_path( $key );
		$serialized_data = serialize( $data );
		
		// Check cache size limits
		if ( strlen( $serialized_data ) > $this->config['max_file_cache_size'] ) {
			return false;
		}
		
		return file_put_contents( $cache_file, $serialized_data ) !== false;
	}

	/**
	 * Delete file cache
	 *
	 * @since    1.0.0
	 * @param    string    $key    Cache key.
	 * @return   bool              True on success, false on failure.
	 * @access   private
	 */
	private function delete_file_cache( $key ) {
		$cache_file = $this->get_cache_file_path( $key );
		
		if ( file_exists( $cache_file ) ) {
			return unlink( $cache_file );
		}
		
		return true;
	}

	/**
	 * Get cache file path
	 *
	 * @since    1.0.0
	 * @param    string    $key    Cache key.
	 * @return   string            File path for cache key.
	 * @access   private
	 */
	private function get_cache_file_path( $key ) {
		return $this->cache_dir . md5( $key ) . '.cache';
	}

	/**
	 * Record cache hit
	 *
	 * @since    1.0.0
	 * @param    string    $level    Cache level (object, transient, file).
	 * @param    string    $key      Cache key.
	 * @access   private
	 */
	private function record_cache_hit( $level, $key ) {
		$this->stats['hits']++;
		$this->stats['hits_by_level'][ $level ]++;
		
		do_action( 'wp_breach_cache_hit', $level, $key );
	}

	/**
	 * Record cache miss
	 *
	 * @since    1.0.0
	 * @param    string    $key    Cache key.
	 * @access   private
	 */
	private function record_cache_miss( $key ) {
		$this->stats['misses']++;
		
		do_action( 'wp_breach_cache_miss', $key );
	}

	/**
	 * Check if scan cache is valid
	 *
	 * @since    1.0.0
	 * @param    array    $cached_data    Cached scan data.
	 * @return   bool                     True if valid, false otherwise.
	 * @access   private
	 */
	private function is_scan_cache_valid( $cached_data ) {
		// Check if files have changed
		$current_hashes = $this->get_current_file_hashes();
		if ( $current_hashes !== $cached_data['file_hashes'] ) {
			return false;
		}
		
		// Check if plugins have been updated
		$current_versions = $this->get_plugin_versions();
		if ( $current_versions !== $cached_data['plugin_versions'] ) {
			return false;
		}
		
		return true;
	}

	/**
	 * Get current file hashes for validation
	 *
	 * @since    1.0.0
	 * @return   array    File hashes for key files.
	 * @access   private
	 */
	private function get_current_file_hashes() {
		// This would be implemented to hash key WordPress files
		// for cache invalidation purposes
		return array();
	}

	/**
	 * Get current plugin versions
	 *
	 * @since    1.0.0
	 * @return   array    Plugin versions.
	 * @access   private
	 */
	private function get_plugin_versions() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		
		$plugins = get_plugins();
		$versions = array();
		
		foreach ( $plugins as $plugin_file => $plugin_data ) {
			$versions[ $plugin_file ] = $plugin_data['Version'];
		}
		
		return $versions;
	}

	/**
	 * Get scan cache expiry based on scan type
	 *
	 * @since    1.0.0
	 * @param    string    $scan_type    Type of scan.
	 * @return   int                     Expiry time in seconds.
	 * @access   private
	 */
	private function get_scan_cache_expiry( $scan_type ) {
		switch ( $scan_type ) {
			case 'quick':
				return 1800; // 30 minutes
			case 'full':
				return 3600; // 1 hour
			case 'custom':
				return 2400; // 40 minutes
			default:
				return $this->config['scan_cache_expiry'];
		}
	}

	/**
	 * Cleanup expired cache files
	 *
	 * @since    1.0.0
	 */
	public function cleanup_expired_cache() {
		if ( ! $this->config['enable_file_cache'] ) {
			return;
		}
		
		$cache_files = glob( $this->cache_dir . '*.cache' );
		
		foreach ( $cache_files as $cache_file ) {
			$file_time = filemtime( $cache_file );
			if ( time() - $file_time > 86400 ) { // 24 hours
				unlink( $cache_file );
			}
		}
	}

	/**
	 * Get cache size information
	 *
	 * @since    1.0.0
	 * @return   array    Cache size information.
	 * @access   private
	 */
	private function get_cache_size() {
		$size = 0;
		$file_count = 0;
		
		if ( $this->config['enable_file_cache'] && is_dir( $this->cache_dir ) ) {
			$cache_files = glob( $this->cache_dir . '*.cache' );
			$file_count = count( $cache_files );
			
			foreach ( $cache_files as $cache_file ) {
				$size += filesize( $cache_file );
			}
		}
		
		return array(
			'total_size' => $size,
			'file_count' => $file_count,
			'human_readable' => size_format( $size )
		);
	}

	/**
	 * Get cache memory usage
	 *
	 * @since    1.0.0
	 * @return   int    Memory usage in bytes.
	 * @access   private
	 */
	private function get_cache_memory_usage() {
		// This would require integration with object cache statistics
		// Implementation depends on the object cache backend
		return 0;
	}

	/**
	 * Invalidate scan cache
	 *
	 * @since    1.0.0
	 */
	public function invalidate_scan_cache() {
		$this->flush_group_cache( 'scan_results' );
	}

	/**
	 * Invalidate configuration cache
	 *
	 * @since    1.0.0
	 */
	public function invalidate_config_cache() {
		$this->delete_cached_data( 'plugin_settings', 'configuration' );
	}

	/**
	 * Flush group cache
	 *
	 * @since    1.0.0
	 * @param    string    $group    Cache group to flush.
	 * @return   bool                True on success, false on failure.
	 * @access   private
	 */
	private function flush_group_cache( $group ) {
		// Flush object cache group
		wp_cache_flush_group( $group );
		
		// Flush related transients
		$this->flush_group_transients( $group );
		
		// Flush file cache for group
		if ( $this->config['enable_file_cache'] ) {
			$this->flush_group_file_cache( $group );
		}
		
		return true;
	}

	/**
	 * Flush transients for a group
	 *
	 * @since    1.0.0
	 * @param    string    $group    Cache group.
	 * @access   private
	 */
	private function flush_group_transients( $group ) {
		global $wpdb;
		
		$pattern = "wp_breach_{$group}_%";
		$wpdb->query( $wpdb->prepare(
			"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
			$pattern
		) );
	}

	/**
	 * Flush file cache for a group
	 *
	 * @since    1.0.0
	 * @param    string    $group    Cache group.
	 * @access   private
	 */
	private function flush_group_file_cache( $group ) {
		$cache_files = glob( $this->cache_dir . '*.cache' );
		
		foreach ( $cache_files as $cache_file ) {
			$filename = basename( $cache_file );
			// This is a simplified approach; in practice, you'd need
			// a more sophisticated way to identify group membership
			if ( strpos( $filename, md5( $group ) ) !== false ) {
				unlink( $cache_file );
			}
		}
	}

	/**
	 * Warm configuration cache
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function warm_configuration_cache() {
		// Pre-load frequently accessed settings
		$settings = get_option( 'wp_breach_settings' );
		if ( $settings ) {
			$this->set_cached_data( 'plugin_settings', $settings, 3600, 'configuration' );
		}
	}

	/**
	 * Warm vulnerability database cache
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function warm_vulnerability_database_cache() {
		// This would be implemented to pre-load vulnerability database
		// if it's not already cached
	}

	/**
	 * Warm scan results cache
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function warm_scan_results_cache() {
		// Pre-load recent scan results that are likely to be accessed
		global $wpdb;
		
		$recent_scans = $wpdb->get_results(
			"SELECT id FROM {$wpdb->prefix}wp_breach_scans 
			 WHERE status = 'completed' 
			 ORDER BY completed_at DESC 
			 LIMIT 5",
			ARRAY_A
		);
		
		foreach ( $recent_scans as $scan ) {
			// This would trigger loading of scan results into cache
			// Implementation depends on scan results structure
		}
	}
}
