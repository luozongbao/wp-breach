<?php

/**
 * The vulnerability database integration class.
 *
 * This class handles integration with external vulnerability databases
 * and provides caching and lookup functionality.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/detection
 */

/**
 * The vulnerability database class.
 *
 * This class provides integration with external vulnerability databases
 * like WPScan API, NVD, and CVE databases.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/detection
 * @author     WP Breach Team
 */
class WP_Breach_Vuln_Database {

    /**
     * API integrations.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $apis    Array of API integration instances.
     */
    protected $apis;

    /**
     * Cache instance.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $cache    Cache for API responses.
     */
    protected $cache;

    /**
     * Configuration options.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $config    Configuration options.
     */
    protected $config;

    /**
     * Rate limiting data.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $rate_limits    Rate limiting information.
     */
    protected $rate_limits;

    /**
     * Initialize the vulnerability database.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->apis = array();
        $this->cache = array();
        $this->rate_limits = array();
        $this->load_config();
        $this->init_apis();
        $this->load_cache();
    }

    /**
     * Load configuration options.
     *
     * @since    1.0.0
     */
    private function load_config() {
        $defaults = array(
            'enable_wpscan' => true,
            'enable_nvd' => true,
            'enable_cve' => true,
            'cache_duration' => 86400, // 24 hours
            'rate_limit_requests' => 100,
            'rate_limit_period' => 3600, // 1 hour
            'timeout' => 30,
            'max_retries' => 3,
            'enable_background_updates' => true,
            'wpscan_api_key' => '',
            'nvd_api_key' => ''
        );

        $stored_config = get_option('wp_breach_vuln_db_config', array());
        $this->config = wp_parse_args($stored_config, $defaults);
    }

    /**
     * Initialize API integrations.
     *
     * @since    1.0.0
     */
    private function init_apis() {
        // Initialize WPScan API
        if ($this->config['enable_wpscan']) {
            require_once plugin_dir_path(dirname(__FILE__)) . 'detection/apis/class-wp-breach-wpscan-api.php';
            $this->apis['wpscan'] = new WP_Breach_WPScan_API($this->config['wpscan_api_key']);
        }

        // Initialize NVD API
        if ($this->config['enable_nvd']) {
            require_once plugin_dir_path(dirname(__FILE__)) . 'detection/apis/class-wp-breach-nvd-api.php';
            $this->apis['nvd'] = new WP_Breach_NVD_API($this->config['nvd_api_key']);
        }
    }

    /**
     * Load cached data.
     *
     * @since    1.0.0
     */
    private function load_cache() {
        $cached_data = get_option('wp_breach_vuln_cache', array());
        if (is_array($cached_data)) {
            $this->cache = $cached_data;
        }
    }

    /**
     * Save cache data.
     *
     * @since    1.0.0
     */
    private function save_cache() {
        update_option('wp_breach_vuln_cache', $this->cache);
    }

    /**
     * Check external vulnerabilities for file.
     *
     * @since    1.0.0
     * @param    array     $file_info       File information.
     * @return   array                      Array of external vulnerabilities.
     */
    public function check_external_vulnerabilities($file_info) {
        $vulnerabilities = array();

        // Extract plugin/theme information if applicable
        if ($file_info['is_plugin']) {
            $plugin_info = $this->extract_plugin_info($file_info['path']);
            if ($plugin_info) {
                $plugin_vulns = $this->check_plugin_vulnerabilities($plugin_info);
                $vulnerabilities = array_merge($vulnerabilities, $plugin_vulns);
            }
        }

        if ($file_info['is_theme']) {
            $theme_info = $this->extract_theme_info($file_info['path']);
            if ($theme_info) {
                $theme_vulns = $this->check_theme_vulnerabilities($theme_info);
                $vulnerabilities = array_merge($vulnerabilities, $theme_vulns);
            }
        }

        // Check for WordPress core vulnerabilities
        if ($file_info['is_wordpress_core']) {
            $core_vulns = $this->check_core_vulnerabilities();
            $vulnerabilities = array_merge($vulnerabilities, $core_vulns);
        }

        return $vulnerabilities;
    }

    /**
     * Check plugin vulnerabilities.
     *
     * @since    1.0.0
     * @param    array     $plugin_info     Plugin information.
     * @return   array                      Array of plugin vulnerabilities.
     */
    public function check_plugin_vulnerabilities($plugin_info) {
        $cache_key = 'plugin_' . $plugin_info['slug'] . '_' . $plugin_info['version'];
        
        // Check cache first
        if ($this->is_cached($cache_key)) {
            return $this->get_cached($cache_key);
        }

        $vulnerabilities = array();

        // Check WPScan database
        if (isset($this->apis['wpscan'])) {
            $wpscan_vulns = $this->apis['wpscan']->get_plugin_vulnerabilities($plugin_info['slug'], $plugin_info['version']);
            if (!empty($wpscan_vulns)) {
                $vulnerabilities = array_merge($vulnerabilities, $this->normalize_wpscan_vulns($wpscan_vulns));
            }
        }

        // Check NVD database
        if (isset($this->apis['nvd'])) {
            $nvd_vulns = $this->apis['nvd']->search_vulnerabilities($plugin_info['name'], $plugin_info['version']);
            if (!empty($nvd_vulns)) {
                $vulnerabilities = array_merge($vulnerabilities, $this->normalize_nvd_vulns($nvd_vulns));
            }
        }

        // Cache results
        $this->cache_result($cache_key, $vulnerabilities);

        return $vulnerabilities;
    }

    /**
     * Check theme vulnerabilities.
     *
     * @since    1.0.0
     * @param    array     $theme_info      Theme information.
     * @return   array                      Array of theme vulnerabilities.
     */
    public function check_theme_vulnerabilities($theme_info) {
        $cache_key = 'theme_' . $theme_info['slug'] . '_' . $theme_info['version'];
        
        // Check cache first
        if ($this->is_cached($cache_key)) {
            return $this->get_cached($cache_key);
        }

        $vulnerabilities = array();

        // Check WPScan database for themes
        if (isset($this->apis['wpscan'])) {
            $wpscan_vulns = $this->apis['wpscan']->get_theme_vulnerabilities($theme_info['slug'], $theme_info['version']);
            if (!empty($wpscan_vulns)) {
                $vulnerabilities = array_merge($vulnerabilities, $this->normalize_wpscan_vulns($wpscan_vulns));
            }
        }

        // Cache results
        $this->cache_result($cache_key, $vulnerabilities);

        return $vulnerabilities;
    }

    /**
     * Check WordPress core vulnerabilities.
     *
     * @since    1.0.0
     * @return   array                      Array of core vulnerabilities.
     */
    public function check_core_vulnerabilities() {
        global $wp_version;
        $cache_key = 'wp_core_' . $wp_version;
        
        // Check cache first
        if ($this->is_cached($cache_key)) {
            return $this->get_cached($cache_key);
        }

        $vulnerabilities = array();

        // Check WPScan database for WordPress core
        if (isset($this->apis['wpscan'])) {
            $wpscan_vulns = $this->apis['wpscan']->get_wordpress_vulnerabilities($wp_version);
            if (!empty($wpscan_vulns)) {
                $vulnerabilities = array_merge($vulnerabilities, $this->normalize_wpscan_vulns($wpscan_vulns));
            }
        }

        // Cache results
        $this->cache_result($cache_key, $vulnerabilities);

        return $vulnerabilities;
    }

    /**
     * Extract plugin information from file path.
     *
     * @since    1.0.0
     * @param    string    $file_path       File path.
     * @return   array|false               Plugin information or false.
     */
    private function extract_plugin_info($file_path) {
        // Extract plugin slug from path
        $plugin_dir = str_replace(WP_PLUGIN_DIR . '/', '', $file_path);
        $plugin_slug = explode('/', $plugin_dir)[0];

        if (empty($plugin_slug)) {
            return false;
        }

        // Get plugin data
        $plugin_file = $plugin_slug . '/' . $plugin_slug . '.php';
        $plugin_path = WP_PLUGIN_DIR . '/' . $plugin_file;

        if (!file_exists($plugin_path)) {
            // Try to find main plugin file
            $plugin_files = glob(WP_PLUGIN_DIR . '/' . $plugin_slug . '/*.php');
            foreach ($plugin_files as $file) {
                $content = file_get_contents($file);
                if (strpos($content, 'Plugin Name:') !== false) {
                    $plugin_path = $file;
                    break;
                }
            }
        }

        if (!file_exists($plugin_path)) {
            return false;
        }

        $plugin_data = get_plugin_data($plugin_path);

        return array(
            'slug' => $plugin_slug,
            'name' => $plugin_data['Name'],
            'version' => $plugin_data['Version'],
            'author' => $plugin_data['Author'],
            'description' => $plugin_data['Description']
        );
    }

    /**
     * Extract theme information from file path.
     *
     * @since    1.0.0
     * @param    string    $file_path       File path.
     * @return   array|false               Theme information or false.
     */
    private function extract_theme_info($file_path) {
        $theme_root = get_theme_root();
        $theme_dir = str_replace($theme_root . '/', '', $file_path);
        $theme_slug = explode('/', $theme_dir)[0];

        if (empty($theme_slug)) {
            return false;
        }

        $theme = wp_get_theme($theme_slug);
        if (!$theme->exists()) {
            return false;
        }

        return array(
            'slug' => $theme_slug,
            'name' => $theme->get('Name'),
            'version' => $theme->get('Version'),
            'author' => $theme->get('Author'),
            'description' => $theme->get('Description')
        );
    }

    /**
     * Normalize WPScan vulnerability data.
     *
     * @since    1.0.0
     * @param    array     $vulns           WPScan vulnerabilities.
     * @return   array                      Normalized vulnerabilities.
     */
    private function normalize_wpscan_vulns($vulns) {
        $normalized = array();

        foreach ($vulns as $vuln) {
            $normalized[] = array(
                'type' => 'external',
                'subtype' => isset($vuln['type']) ? $vuln['type'] : 'unknown',
                'severity' => $this->map_wpscan_severity(isset($vuln['severity']) ? $vuln['severity'] : 'medium'),
                'confidence' => 0.9, // High confidence for external databases
                'description' => isset($vuln['title']) ? $vuln['title'] : 'External vulnerability',
                'source' => 'WPScan',
                'external_id' => isset($vuln['id']) ? $vuln['id'] : '',
                'cve_id' => isset($vuln['cve']) ? $vuln['cve'] : null,
                'published_date' => isset($vuln['published_date']) ? $vuln['published_date'] : '',
                'updated_date' => isset($vuln['updated_date']) ? $vuln['updated_date'] : '',
                'references' => isset($vuln['references']) ? $vuln['references'] : array(),
                'affected_versions' => isset($vuln['affected_versions']) ? $vuln['affected_versions'] : array(),
                'fixed_in' => isset($vuln['fixed_in']) ? $vuln['fixed_in'] : '',
                'proof_of_concept' => isset($vuln['poc']) ? $vuln['poc'] : ''
            );
        }

        return $normalized;
    }

    /**
     * Normalize NVD vulnerability data.
     *
     * @since    1.0.0
     * @param    array     $vulns           NVD vulnerabilities.
     * @return   array                      Normalized vulnerabilities.
     */
    private function normalize_nvd_vulns($vulns) {
        $normalized = array();

        foreach ($vulns as $vuln) {
            $normalized[] = array(
                'type' => 'external',
                'subtype' => 'cve',
                'severity' => $this->map_nvd_severity(isset($vuln['cvss_score']) ? $vuln['cvss_score'] : 5.0),
                'confidence' => 0.95, // Very high confidence for NVD
                'description' => isset($vuln['description']) ? $vuln['description'] : 'CVE vulnerability',
                'source' => 'NVD',
                'external_id' => isset($vuln['cve_id']) ? $vuln['cve_id'] : '',
                'cve_id' => isset($vuln['cve_id']) ? $vuln['cve_id'] : null,
                'cvss_score' => isset($vuln['cvss_score']) ? $vuln['cvss_score'] : null,
                'cvss_vector' => isset($vuln['cvss_vector']) ? $vuln['cvss_vector'] : '',
                'published_date' => isset($vuln['published_date']) ? $vuln['published_date'] : '',
                'updated_date' => isset($vuln['last_modified']) ? $vuln['last_modified'] : '',
                'references' => isset($vuln['references']) ? $vuln['references'] : array(),
                'cpe_matches' => isset($vuln['cpe_matches']) ? $vuln['cpe_matches'] : array()
            );
        }

        return $normalized;
    }

    /**
     * Map WPScan severity to standard levels.
     *
     * @since    1.0.0
     * @param    string    $wpscan_severity WPScan severity.
     * @return   string                     Standard severity.
     */
    private function map_wpscan_severity($wpscan_severity) {
        $mapping = array(
            'critical' => 'critical',
            'high' => 'high',
            'medium' => 'medium',
            'low' => 'low',
            'informational' => 'info'
        );

        return isset($mapping[strtolower($wpscan_severity)]) ? 
               $mapping[strtolower($wpscan_severity)] : 'medium';
    }

    /**
     * Map NVD CVSS score to severity levels.
     *
     * @since    1.0.0
     * @param    float     $cvss_score      CVSS score.
     * @return   string                     Severity level.
     */
    private function map_nvd_severity($cvss_score) {
        if ($cvss_score >= 9.0) {
            return 'critical';
        } elseif ($cvss_score >= 7.0) {
            return 'high';
        } elseif ($cvss_score >= 4.0) {
            return 'medium';
        } elseif ($cvss_score > 0.0) {
            return 'low';
        } else {
            return 'info';
        }
    }

    /**
     * Check if result is cached and valid.
     *
     * @since    1.0.0
     * @param    string    $cache_key       Cache key.
     * @return   bool                       True if cached and valid.
     */
    private function is_cached($cache_key) {
        if (!isset($this->cache[$cache_key])) {
            return false;
        }

        $cached_data = $this->cache[$cache_key];
        $expiry_time = $cached_data['timestamp'] + $this->config['cache_duration'];

        return time() < $expiry_time;
    }

    /**
     * Get cached result.
     *
     * @since    1.0.0
     * @param    string    $cache_key       Cache key.
     * @return   array                      Cached data.
     */
    private function get_cached($cache_key) {
        return isset($this->cache[$cache_key]['data']) ? $this->cache[$cache_key]['data'] : array();
    }

    /**
     * Cache result.
     *
     * @since    1.0.0
     * @param    string    $cache_key       Cache key.
     * @param    array     $data            Data to cache.
     */
    private function cache_result($cache_key, $data) {
        $this->cache[$cache_key] = array(
            'data' => $data,
            'timestamp' => time()
        );

        // Clean old cache entries
        $this->clean_cache();

        // Save to database
        $this->save_cache();
    }

    /**
     * Clean expired cache entries.
     *
     * @since    1.0.0
     */
    private function clean_cache() {
        $current_time = time();
        
        foreach ($this->cache as $key => $data) {
            $expiry_time = $data['timestamp'] + $this->config['cache_duration'];
            if ($current_time >= $expiry_time) {
                unset($this->cache[$key]);
            }
        }
    }

    /**
     * Check rate limits for API calls.
     *
     * @since    1.0.0
     * @param    string    $api_name        API name.
     * @return   bool                       True if within limits.
     */
    public function check_rate_limit($api_name) {
        $current_time = time();
        $period_start = $current_time - $this->config['rate_limit_period'];

        if (!isset($this->rate_limits[$api_name])) {
            $this->rate_limits[$api_name] = array();
        }

        // Remove old requests
        $this->rate_limits[$api_name] = array_filter(
            $this->rate_limits[$api_name],
            function($timestamp) use ($period_start) {
                return $timestamp > $period_start;
            }
        );

        // Check if within limits
        if (count($this->rate_limits[$api_name]) >= $this->config['rate_limit_requests']) {
            return false;
        }

        // Add current request
        $this->rate_limits[$api_name][] = $current_time;

        return true;
    }

    /**
     * Get vulnerability statistics.
     *
     * @since    1.0.0
     * @return   array                      Statistics.
     */
    public function get_statistics() {
        $stats = array(
            'cache_entries' => count($this->cache),
            'apis_enabled' => count($this->apis),
            'rate_limits' => array()
        );

        foreach ($this->rate_limits as $api => $requests) {
            $stats['rate_limits'][$api] = count($requests);
        }

        return $stats;
    }

    /**
     * Clear all cached data.
     *
     * @since    1.0.0
     */
    public function clear_cache() {
        $this->cache = array();
        delete_option('wp_breach_vuln_cache');
    }

    /**
     * Update database configuration.
     *
     * @since    1.0.0
     * @param    array     $config          New configuration.
     */
    public function update_config($config) {
        $this->config = wp_parse_args($config, $this->config);
        update_option('wp_breach_vuln_db_config', $this->config);
        
        // Reinitialize APIs if needed
        $this->init_apis();
    }

    /**
     * Get configuration.
     *
     * @since    1.0.0
     * @return   array                      Current configuration.
     */
    public function get_config() {
        return $this->config;
    }

    /**
     * Force refresh of vulnerabilities for a component.
     *
     * @since    1.0.0
     * @param    string    $type            Component type (plugin/theme/core).
     * @param    string    $slug            Component slug.
     * @param    string    $version         Component version.
     * @return   array                      Updated vulnerabilities.
     */
    public function force_refresh($type, $slug, $version) {
        $cache_key = $type . '_' . $slug . '_' . $version;
        
        // Remove from cache
        unset($this->cache[$cache_key]);
        
        // Fetch fresh data
        switch ($type) {
            case 'plugin':
                return $this->check_plugin_vulnerabilities(array(
                    'slug' => $slug,
                    'version' => $version,
                    'name' => $slug
                ));
            case 'theme':
                return $this->check_theme_vulnerabilities(array(
                    'slug' => $slug,
                    'version' => $version,
                    'name' => $slug
                ));
            case 'core':
                return $this->check_core_vulnerabilities();
            default:
                return array();
        }
    }
}
