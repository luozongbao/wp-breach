<?php

/**
 * WPScan API integration for vulnerability data.
 *
 * This class handles communication with the WPScan Vulnerability Database API
 * to fetch vulnerability data for WordPress plugins, themes, and core.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/detection/api
 */

/**
 * WPScan API integration class.
 *
 * Provides methods to interact with WPScan Vulnerability Database API.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/detection/api
 * @author     WP Breach Team
 */
class WP_Breach_WPScan_API {

    /**
     * WPScan API base URL.
     *
     * @since    1.0.0
     * @access   private
     * @var      string    $api_base_url    WPScan API base URL.
     */
    private $api_base_url = 'https://wpscan.com/api/v3/';

    /**
     * API token for authentication.
     *
     * @since    1.0.0
     * @access   private
     * @var      string    $api_token    WPScan API token.
     */
    private $api_token;

    /**
     * Cache expiration time in seconds.
     *
     * @since    1.0.0
     * @access   private
     * @var      int    $cache_expiry    Cache expiration time.
     */
    private $cache_expiry = 3600; // 1 hour

    /**
     * Rate limiting settings.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $rate_limit    Rate limiting configuration.
     */
    private $rate_limit = array(
        'requests_per_minute' => 25,
        'requests_per_day' => 500
    );

    /**
     * Initialize the WPScan API integration.
     *
     * @since    1.0.0
     * @param    string    $api_token    WPScan API token.
     */
    public function __construct($api_token = '') {
        $this->api_token = $api_token ?: get_option('wp_breach_wpscan_api_token', '');
    }

    /**
     * Get vulnerabilities for a WordPress plugin.
     *
     * @since    1.0.0
     * @param    string    $plugin_slug    Plugin slug.
     * @param    string    $version        Plugin version.
     * @return   array|WP_Error           Vulnerability data or error.
     */
    public function get_plugin_vulnerabilities($plugin_slug, $version = '') {
        $cache_key = "wpscan_plugin_{$plugin_slug}_{$version}";
        
        // Check cache first
        $cached_data = $this->get_cached_data($cache_key);
        if ($cached_data !== false) {
            return $cached_data;
        }

        // Check rate limiting
        if (!$this->check_rate_limit()) {
            return new WP_Error('rate_limit', 'API rate limit exceeded');
        }

        $endpoint = "plugins/{$plugin_slug}";
        $response = $this->make_api_request($endpoint);

        if (is_wp_error($response)) {
            return $response;
        }

        $vulnerabilities = $this->parse_plugin_response($response, $version);
        
        // Cache the response
        $this->cache_data($cache_key, $vulnerabilities);

        return $vulnerabilities;
    }

    /**
     * Get vulnerabilities for a WordPress theme.
     *
     * @since    1.0.0
     * @param    string    $theme_slug     Theme slug.
     * @param    string    $version        Theme version.
     * @return   array|WP_Error           Vulnerability data or error.
     */
    public function get_theme_vulnerabilities($theme_slug, $version = '') {
        $cache_key = "wpscan_theme_{$theme_slug}_{$version}";
        
        // Check cache first
        $cached_data = $this->get_cached_data($cache_key);
        if ($cached_data !== false) {
            return $cached_data;
        }

        // Check rate limiting
        if (!$this->check_rate_limit()) {
            return new WP_Error('rate_limit', 'API rate limit exceeded');
        }

        $endpoint = "themes/{$theme_slug}";
        $response = $this->make_api_request($endpoint);

        if (is_wp_error($response)) {
            return $response;
        }

        $vulnerabilities = $this->parse_theme_response($response, $version);
        
        // Cache the response
        $this->cache_data($cache_key, $vulnerabilities);

        return $vulnerabilities;
    }

    /**
     * Get vulnerabilities for WordPress core.
     *
     * @since    1.0.0
     * @param    string    $version        WordPress version.
     * @return   array|WP_Error           Vulnerability data or error.
     */
    public function get_core_vulnerabilities($version = '') {
        if (empty($version)) {
            $version = get_bloginfo('version');
        }

        $cache_key = "wpscan_core_{$version}";
        
        // Check cache first
        $cached_data = $this->get_cached_data($cache_key);
        if ($cached_data !== false) {
            return $cached_data;
        }

        // Check rate limiting
        if (!$this->check_rate_limit()) {
            return new WP_Error('rate_limit', 'API rate limit exceeded');
        }

        $endpoint = "wordpresses/{$version}";
        $response = $this->make_api_request($endpoint);

        if (is_wp_error($response)) {
            return $response;
        }

        $vulnerabilities = $this->parse_core_response($response);
        
        // Cache the response
        $this->cache_data($cache_key, $vulnerabilities);

        return $vulnerabilities;
    }

    /**
     * Search for vulnerabilities by keyword.
     *
     * @since    1.0.0
     * @param    string    $keyword        Search keyword.
     * @param    int       $per_page       Results per page.
     * @param    int       $page           Page number.
     * @return   array|WP_Error           Search results or error.
     */
    public function search_vulnerabilities($keyword, $per_page = 25, $page = 1) {
        $cache_key = "wpscan_search_{$keyword}_{$per_page}_{$page}";
        
        // Check cache first
        $cached_data = $this->get_cached_data($cache_key);
        if ($cached_data !== false) {
            return $cached_data;
        }

        // Check rate limiting
        if (!$this->check_rate_limit()) {
            return new WP_Error('rate_limit', 'API rate limit exceeded');
        }

        $endpoint = 'vulnerabilities';
        $params = array(
            'search' => $keyword,
            'per_page' => min($per_page, 100), // API limit
            'page' => $page
        );

        $response = $this->make_api_request($endpoint, $params);

        if (is_wp_error($response)) {
            return $response;
        }

        $results = $this->parse_search_response($response);
        
        // Cache the response for shorter time (search results change more frequently)
        $this->cache_data($cache_key, $results, 1800); // 30 minutes

        return $results;
    }

    /**
     * Get vulnerability details by ID.
     *
     * @since    1.0.0
     * @param    string    $vulnerability_id    Vulnerability ID.
     * @return   array|WP_Error                Vulnerability details or error.
     */
    public function get_vulnerability_details($vulnerability_id) {
        $cache_key = "wpscan_vuln_{$vulnerability_id}";
        
        // Check cache first
        $cached_data = $this->get_cached_data($cache_key);
        if ($cached_data !== false) {
            return $cached_data;
        }

        // Check rate limiting
        if (!$this->check_rate_limit()) {
            return new WP_Error('rate_limit', 'API rate limit exceeded');
        }

        $endpoint = "vulnerabilities/{$vulnerability_id}";
        $response = $this->make_api_request($endpoint);

        if (is_wp_error($response)) {
            return $response;
        }

        $vulnerability = $this->parse_vulnerability_response($response);
        
        // Cache the response
        $this->cache_data($cache_key, $vulnerability);

        return $vulnerability;
    }

    /**
     * Make API request to WPScan.
     *
     * @since    1.0.0
     * @param    string    $endpoint       API endpoint.
     * @param    array     $params         Request parameters.
     * @return   array|WP_Error           Response data or error.
     */
    private function make_api_request($endpoint, $params = array()) {
        if (empty($this->api_token)) {
            return new WP_Error('no_token', 'WPScan API token not configured');
        }

        $url = $this->api_base_url . $endpoint;
        
        if (!empty($params)) {
            $url .= '?' . http_build_query($params);
        }

        $args = array(
            'headers' => array(
                'Authorization' => 'Token token=' . $this->api_token,
                'User-Agent' => 'WP-Breach-Plugin/1.0.0'
            ),
            'timeout' => 30,
            'sslverify' => true
        );

        $response = wp_remote_get($url, $args);

        if (is_wp_error($response)) {
            return $response;
        }

        $status_code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);

        if ($status_code !== 200) {
            return $this->handle_api_error($status_code, $body);
        }

        $data = json_decode($body, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            return new WP_Error('json_error', 'Invalid JSON response');
        }

        // Update rate limit tracking
        $this->update_rate_limit_tracking();

        return $data;
    }

    /**
     * Parse plugin vulnerability response.
     *
     * @since    1.0.0
     * @param    array     $response       API response.
     * @param    string    $version        Plugin version.
     * @return   array                     Parsed vulnerabilities.
     */
    private function parse_plugin_response($response, $version) {
        $vulnerabilities = array();

        if (!isset($response[$version]['vulnerabilities'])) {
            return $vulnerabilities;
        }

        foreach ($response[$version]['vulnerabilities'] as $vuln) {
            $vulnerabilities[] = array(
                'id' => $vuln['id'] ?? '',
                'title' => $vuln['title'] ?? '',
                'description' => $vuln['description'] ?? '',
                'cvss_score' => $vuln['cvss']['score'] ?? null,
                'cvss_vector' => $vuln['cvss']['vector'] ?? '',
                'severity' => $this->map_cvss_to_severity($vuln['cvss']['score'] ?? 0),
                'published_date' => $vuln['published_date'] ?? '',
                'updated_date' => $vuln['updated_date'] ?? '',
                'poc' => $vuln['poc'] ?? '',
                'references' => $vuln['references'] ?? array(),
                'fixed_in' => $vuln['fixed_in'] ?? '',
                'introduced_in' => $vuln['introduced_in'] ?? '',
                'source' => 'wpscan',
                'type' => $this->determine_vulnerability_type($vuln),
                'affected_versions' => $this->parse_affected_versions($vuln)
            );
        }

        return $vulnerabilities;
    }

    /**
     * Parse theme vulnerability response.
     *
     * @since    1.0.0
     * @param    array     $response       API response.
     * @param    string    $version        Theme version.
     * @return   array                     Parsed vulnerabilities.
     */
    private function parse_theme_response($response, $version) {
        // Similar to plugin parsing, but for themes
        return $this->parse_plugin_response($response, $version);
    }

    /**
     * Parse core vulnerability response.
     *
     * @since    1.0.0
     * @param    array     $response       API response.
     * @return   array                     Parsed vulnerabilities.
     */
    private function parse_core_response($response) {
        $vulnerabilities = array();

        if (!isset($response['vulnerabilities'])) {
            return $vulnerabilities;
        }

        foreach ($response['vulnerabilities'] as $vuln) {
            $vulnerabilities[] = array(
                'id' => $vuln['id'] ?? '',
                'title' => $vuln['title'] ?? '',
                'description' => $vuln['description'] ?? '',
                'cvss_score' => $vuln['cvss']['score'] ?? null,
                'cvss_vector' => $vuln['cvss']['vector'] ?? '',
                'severity' => $this->map_cvss_to_severity($vuln['cvss']['score'] ?? 0),
                'published_date' => $vuln['published_date'] ?? '',
                'updated_date' => $vuln['updated_date'] ?? '',
                'references' => $vuln['references'] ?? array(),
                'fixed_in' => $vuln['fixed_in'] ?? '',
                'source' => 'wpscan',
                'type' => $this->determine_vulnerability_type($vuln),
                'component' => 'wordpress-core'
            );
        }

        return $vulnerabilities;
    }

    /**
     * Parse search response.
     *
     * @since    1.0.0
     * @param    array     $response       API response.
     * @return   array                     Parsed search results.
     */
    private function parse_search_response($response) {
        $results = array();

        if (!isset($response['vulnerabilities'])) {
            return $results;
        }

        foreach ($response['vulnerabilities'] as $vuln) {
            $results[] = array(
                'id' => $vuln['id'] ?? '',
                'title' => $vuln['title'] ?? '',
                'description' => $vuln['description'] ?? '',
                'severity' => $this->map_cvss_to_severity($vuln['cvss']['score'] ?? 0),
                'published_date' => $vuln['published_date'] ?? '',
                'component_type' => $vuln['component_type'] ?? '',
                'component_name' => $vuln['component_name'] ?? '',
                'source' => 'wpscan'
            );
        }

        return $results;
    }

    /**
     * Parse individual vulnerability response.
     *
     * @since    1.0.0
     * @param    array     $response       API response.
     * @return   array                     Parsed vulnerability.
     */
    private function parse_vulnerability_response($response) {
        $vuln = $response['vulnerability'] ?? $response;

        return array(
            'id' => $vuln['id'] ?? '',
            'title' => $vuln['title'] ?? '',
            'description' => $vuln['description'] ?? '',
            'cvss_score' => $vuln['cvss']['score'] ?? null,
            'cvss_vector' => $vuln['cvss']['vector'] ?? '',
            'severity' => $this->map_cvss_to_severity($vuln['cvss']['score'] ?? 0),
            'published_date' => $vuln['published_date'] ?? '',
            'updated_date' => $vuln['updated_date'] ?? '',
            'poc' => $vuln['poc'] ?? '',
            'references' => $vuln['references'] ?? array(),
            'fixed_in' => $vuln['fixed_in'] ?? '',
            'introduced_in' => $vuln['introduced_in'] ?? '',
            'component_type' => $vuln['component_type'] ?? '',
            'component_name' => $vuln['component_name'] ?? '',
            'source' => 'wpscan',
            'type' => $this->determine_vulnerability_type($vuln),
            'affected_versions' => $this->parse_affected_versions($vuln)
        );
    }

    /**
     * Map CVSS score to severity level.
     *
     * @since    1.0.0
     * @param    float     $score          CVSS score.
     * @return   string                    Severity level.
     */
    private function map_cvss_to_severity($score) {
        if ($score >= 9.0) {
            return 'critical';
        } elseif ($score >= 7.0) {
            return 'high';
        } elseif ($score >= 4.0) {
            return 'medium';
        } elseif ($score > 0) {
            return 'low';
        } else {
            return 'info';
        }
    }

    /**
     * Determine vulnerability type from response data.
     *
     * @since    1.0.0
     * @param    array     $vuln           Vulnerability data.
     * @return   string                    Vulnerability type.
     */
    private function determine_vulnerability_type($vuln) {
        $title = strtolower($vuln['title'] ?? '');
        $description = strtolower($vuln['description'] ?? '');
        $text = $title . ' ' . $description;

        if (strpos($text, 'sql injection') !== false || strpos($text, 'sqli') !== false) {
            return 'sql-injection';
        } elseif (strpos($text, 'cross-site scripting') !== false || strpos($text, 'xss') !== false) {
            return 'xss';
        } elseif (strpos($text, 'csrf') !== false || strpos($text, 'cross-site request forgery') !== false) {
            return 'csrf';
        } elseif (strpos($text, 'file inclusion') !== false || strpos($text, 'lfi') !== false || strpos($text, 'rfi') !== false) {
            return 'file-inclusion';
        } elseif (strpos($text, 'authentication') !== false || strpos($text, 'privilege') !== false) {
            return 'auth-bypass';
        } elseif (strpos($text, 'code injection') !== false || strpos($text, 'code execution') !== false) {
            return 'code-injection';
        } else {
            return 'other';
        }
    }

    /**
     * Parse affected versions from vulnerability data.
     *
     * @since    1.0.0
     * @param    array     $vuln           Vulnerability data.
     * @return   array                     Affected version ranges.
     */
    private function parse_affected_versions($vuln) {
        $versions = array();

        if (isset($vuln['introduced_in']) && isset($vuln['fixed_in'])) {
            $versions[] = array(
                'from' => $vuln['introduced_in'],
                'to' => $vuln['fixed_in'],
                'inclusive' => false
            );
        }

        return $versions;
    }

    /**
     * Handle API error responses.
     *
     * @since    1.0.0
     * @param    int       $status_code    HTTP status code.
     * @param    string    $body           Response body.
     * @return   WP_Error                  Error object.
     */
    private function handle_api_error($status_code, $body) {
        $error_data = json_decode($body, true);
        $message = $error_data['error'] ?? 'Unknown API error';

        switch ($status_code) {
            case 401:
                return new WP_Error('unauthorized', 'Invalid WPScan API token');
            case 403:
                return new WP_Error('forbidden', 'Access denied to WPScan API');
            case 404:
                return new WP_Error('not_found', 'Resource not found');
            case 429:
                return new WP_Error('rate_limited', 'API rate limit exceeded');
            case 500:
                return new WP_Error('server_error', 'WPScan API server error');
            default:
                return new WP_Error('api_error', $message, array('status' => $status_code));
        }
    }

    /**
     * Check rate limiting.
     *
     * @since    1.0.0
     * @return   bool                      True if request allowed.
     */
    private function check_rate_limit() {
        $minute_key = 'wpscan_requests_' . floor(time() / 60);
        $day_key = 'wpscan_requests_' . date('Y-m-d');

        $minute_requests = get_transient($minute_key) ?: 0;
        $day_requests = get_transient($day_key) ?: 0;

        if ($minute_requests >= $this->rate_limit['requests_per_minute']) {
            return false;
        }

        if ($day_requests >= $this->rate_limit['requests_per_day']) {
            return false;
        }

        return true;
    }

    /**
     * Update rate limit tracking.
     *
     * @since    1.0.0
     */
    private function update_rate_limit_tracking() {
        $minute_key = 'wpscan_requests_' . floor(time() / 60);
        $day_key = 'wpscan_requests_' . date('Y-m-d');

        $minute_requests = get_transient($minute_key) ?: 0;
        $day_requests = get_transient($day_key) ?: 0;

        set_transient($minute_key, $minute_requests + 1, 60);
        set_transient($day_key, $day_requests + 1, DAY_IN_SECONDS);
    }

    /**
     * Get cached data.
     *
     * @since    1.0.0
     * @param    string    $key            Cache key.
     * @return   mixed                     Cached data or false.
     */
    private function get_cached_data($key) {
        return get_transient('wp_breach_' . $key);
    }

    /**
     * Cache data.
     *
     * @since    1.0.0
     * @param    string    $key            Cache key.
     * @param    mixed     $data           Data to cache.
     * @param    int       $expiry         Cache expiry time.
     */
    private function cache_data($key, $data, $expiry = null) {
        if ($expiry === null) {
            $expiry = $this->cache_expiry;
        }
        
        set_transient('wp_breach_' . $key, $data, $expiry);
    }

    /**
     * Clear all cached data.
     *
     * @since    1.0.0
     */
    public function clear_cache() {
        global $wpdb;
        
        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
                '_transient_wp_breach_wpscan_%'
            )
        );
    }

    /**
     * Set API token.
     *
     * @since    1.0.0
     * @param    string    $token          API token.
     */
    public function set_api_token($token) {
        $this->api_token = $token;
        update_option('wp_breach_wpscan_api_token', $token);
    }

    /**
     * Get API status.
     *
     * @since    1.0.0
     * @return   array                     API status information.
     */
    public function get_api_status() {
        $response = $this->make_api_request('status');
        
        if (is_wp_error($response)) {
            return array(
                'status' => 'error',
                'message' => $response->get_error_message()
            );
        }

        return array(
            'status' => 'ok',
            'data' => $response
        );
    }
}
