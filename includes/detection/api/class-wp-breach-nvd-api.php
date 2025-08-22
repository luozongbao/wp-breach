<?php

/**
 * National Vulnerability Database (NVD) API integration.
 *
 * This class handles communication with the NIST NVD API
 * to fetch CVE data and vulnerability information.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/detection/api
 */

/**
 * NVD API integration class.
 *
 * Provides methods to interact with NIST National Vulnerability Database API.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/detection/api
 * @author     WP Breach Team
 */
class WP_Breach_NVD_API {

    /**
     * NVD API base URL.
     *
     * @since    1.0.0
     * @access   private
     * @var      string    $api_base_url    NVD API base URL.
     */
    private $api_base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0/';

    /**
     * API key for enhanced rate limits.
     *
     * @since    1.0.0
     * @access   private
     * @var      string    $api_key    NVD API key.
     */
    private $api_key;

    /**
     * Cache expiration time in seconds.
     *
     * @since    1.0.0
     * @access   private
     * @var      int    $cache_expiry    Cache expiration time.
     */
    private $cache_expiry = 7200; // 2 hours

    /**
     * Rate limiting settings.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $rate_limit    Rate limiting configuration.
     */
    private $rate_limit = array(
        'without_key' => array(
            'requests_per_30_seconds' => 5,
            'requests_per_30_minutes' => 10
        ),
        'with_key' => array(
            'requests_per_30_seconds' => 50,
            'requests_per_30_minutes' => 10000
        )
    );

    /**
     * Initialize the NVD API integration.
     *
     * @since    1.0.0
     * @param    string    $api_key    NVD API key (optional).
     */
    public function __construct($api_key = '') {
        $this->api_key = $api_key ?: get_option('wp_breach_nvd_api_key', '');
    }

    /**
     * Search CVEs by keyword.
     *
     * @since    1.0.0
     * @param    string    $keyword        Search keyword.
     * @param    int       $results_per_page Results per page (max 2000).
     * @param    int       $start_index    Starting index.
     * @return   array|WP_Error           CVE data or error.
     */
    public function search_cves($keyword, $results_per_page = 20, $start_index = 0) {
        $cache_key = "nvd_search_{$keyword}_{$results_per_page}_{$start_index}";
        
        // Check cache first
        $cached_data = $this->get_cached_data($cache_key);
        if ($cached_data !== false) {
            return $cached_data;
        }

        // Check rate limiting
        if (!$this->check_rate_limit()) {
            return new WP_Error('rate_limit', 'NVD API rate limit exceeded');
        }

        $params = array(
            'keywordSearch' => $keyword,
            'resultsPerPage' => min($results_per_page, 2000),
            'startIndex' => $start_index
        );

        $response = $this->make_api_request('', $params);

        if (is_wp_error($response)) {
            return $response;
        }

        $cves = $this->parse_cve_response($response);
        
        // Cache the response
        $this->cache_data($cache_key, $cves);

        return $cves;
    }

    /**
     * Get specific CVE by ID.
     *
     * @since    1.0.0
     * @param    string    $cve_id         CVE identifier (e.g., CVE-2021-34527).
     * @return   array|WP_Error           CVE data or error.
     */
    public function get_cve($cve_id) {
        $cache_key = "nvd_cve_{$cve_id}";
        
        // Check cache first
        $cached_data = $this->get_cached_data($cache_key);
        if ($cached_data !== false) {
            return $cached_data;
        }

        // Check rate limiting
        if (!$this->check_rate_limit()) {
            return new WP_Error('rate_limit', 'NVD API rate limit exceeded');
        }

        $params = array('cveId' => $cve_id);
        $response = $this->make_api_request('', $params);

        if (is_wp_error($response)) {
            return $response;
        }

        $cves = $this->parse_cve_response($response);
        $cve = !empty($cves) ? $cves[0] : null;
        
        // Cache the response for longer (CVEs don't change often)
        $this->cache_data($cache_key, $cve, 86400); // 24 hours

        return $cve;
    }

    /**
     * Search CVEs by date range.
     *
     * @since    1.0.0
     * @param    string    $pub_start_date Publication start date (YYYY-MM-DDTHH:mm:ss:sss Z).
     * @param    string    $pub_end_date   Publication end date (YYYY-MM-DDTHH:mm:ss:sss Z).
     * @param    int       $results_per_page Results per page.
     * @param    int       $start_index    Starting index.
     * @return   array|WP_Error           CVE data or error.
     */
    public function get_cves_by_date($pub_start_date, $pub_end_date, $results_per_page = 20, $start_index = 0) {
        $cache_key = "nvd_date_{$pub_start_date}_{$pub_end_date}_{$results_per_page}_{$start_index}";
        
        // Check cache first
        $cached_data = $this->get_cached_data($cache_key);
        if ($cached_data !== false) {
            return $cached_data;
        }

        // Check rate limiting
        if (!$this->check_rate_limit()) {
            return new WP_Error('rate_limit', 'NVD API rate limit exceeded');
        }

        $params = array(
            'pubStartDate' => $pub_start_date,
            'pubEndDate' => $pub_end_date,
            'resultsPerPage' => min($results_per_page, 2000),
            'startIndex' => $start_index
        );

        $response = $this->make_api_request('', $params);

        if (is_wp_error($response)) {
            return $response;
        }

        $cves = $this->parse_cve_response($response);
        
        // Cache the response
        $this->cache_data($cache_key, $cves);

        return $cves;
    }

    /**
     * Search CVEs by CVSS score range.
     *
     * @since    1.0.0
     * @param    float     $cvss_v3_min    Minimum CVSS v3 score.
     * @param    float     $cvss_v3_max    Maximum CVSS v3 score.
     * @param    string    $severity       Severity level (LOW, MEDIUM, HIGH, CRITICAL).
     * @param    int       $results_per_page Results per page.
     * @param    int       $start_index    Starting index.
     * @return   array|WP_Error           CVE data or error.
     */
    public function get_cves_by_cvss($cvss_v3_min = null, $cvss_v3_max = null, $severity = '', $results_per_page = 20, $start_index = 0) {
        $cache_key = "nvd_cvss_{$cvss_v3_min}_{$cvss_v3_max}_{$severity}_{$results_per_page}_{$start_index}";
        
        // Check cache first
        $cached_data = $this->get_cached_data($cache_key);
        if ($cached_data !== false) {
            return $cached_data;
        }

        // Check rate limiting
        if (!$this->check_rate_limit()) {
            return new WP_Error('rate_limit', 'NVD API rate limit exceeded');
        }

        $params = array(
            'resultsPerPage' => min($results_per_page, 2000),
            'startIndex' => $start_index
        );

        if ($cvss_v3_min !== null) {
            $params['cvssV3Severity'] = strtoupper($severity);
        }

        $response = $this->make_api_request('', $params);

        if (is_wp_error($response)) {
            return $response;
        }

        $cves = $this->parse_cve_response($response);
        
        // Filter by CVSS score if specified
        if ($cvss_v3_min !== null || $cvss_v3_max !== null) {
            $cves = $this->filter_by_cvss_score($cves, $cvss_v3_min, $cvss_v3_max);
        }
        
        // Cache the response
        $this->cache_data($cache_key, $cves);

        return $cves;
    }

    /**
     * Search WordPress-related CVEs.
     *
     * @since    1.0.0
     * @param    int       $results_per_page Results per page.
     * @param    int       $start_index    Starting index.
     * @return   array|WP_Error           CVE data or error.
     */
    public function get_wordpress_cves($results_per_page = 20, $start_index = 0) {
        return $this->search_cves('wordpress', $results_per_page, $start_index);
    }

    /**
     * Get recent high-severity CVEs.
     *
     * @since    1.0.0
     * @param    int       $days           Number of days back to search.
     * @param    int       $results_per_page Results per page.
     * @return   array|WP_Error           CVE data or error.
     */
    public function get_recent_high_severity_cves($days = 7, $results_per_page = 20) {
        $end_date = new DateTime();
        $start_date = new DateTime();
        $start_date->sub(new DateInterval("P{$days}D"));

        $pub_start_date = $start_date->format('Y-m-d\TH:i:s.v\Z');
        $pub_end_date = $end_date->format('Y-m-d\TH:i:s.v\Z');

        $cves = $this->get_cves_by_date($pub_start_date, $pub_end_date, $results_per_page);

        if (is_wp_error($cves)) {
            return $cves;
        }

        // Filter for high and critical severity
        $high_severity_cves = array_filter($cves, function($cve) {
            return in_array($cve['severity'], array('high', 'critical'));
        });

        return array_values($high_severity_cves);
    }

    /**
     * Make API request to NVD.
     *
     * @since    1.0.0
     * @param    string    $endpoint       API endpoint (usually empty for CVE API).
     * @param    array     $params         Request parameters.
     * @return   array|WP_Error           Response data or error.
     */
    private function make_api_request($endpoint = '', $params = array()) {
        $url = $this->api_base_url . $endpoint;
        
        if (!empty($params)) {
            $url .= '?' . http_build_query($params);
        }

        $headers = array(
            'User-Agent' => 'WP-Breach-Plugin/1.0.0',
            'Accept' => 'application/json'
        );

        // Add API key if available
        if (!empty($this->api_key)) {
            $headers['apiKey'] = $this->api_key;
        }

        $args = array(
            'headers' => $headers,
            'timeout' => 60, // NVD can be slow
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
            return new WP_Error('json_error', 'Invalid JSON response from NVD API');
        }

        // Update rate limit tracking
        $this->update_rate_limit_tracking();

        return $data;
    }

    /**
     * Parse CVE response from NVD API.
     *
     * @since    1.0.0
     * @param    array     $response       API response.
     * @return   array                     Parsed CVE data.
     */
    private function parse_cve_response($response) {
        $cves = array();

        if (!isset($response['vulnerabilities'])) {
            return $cves;
        }

        foreach ($response['vulnerabilities'] as $vulnerability) {
            $cve_data = $vulnerability['cve'];
            
            $parsed_cve = array(
                'id' => $cve_data['id'],
                'source_identifier' => $cve_data['sourceIdentifier'] ?? '',
                'published' => $cve_data['published'] ?? '',
                'last_modified' => $cve_data['lastModified'] ?? '',
                'vuln_status' => $cve_data['vulnStatus'] ?? '',
                'descriptions' => $this->parse_descriptions($cve_data['descriptions'] ?? array()),
                'cvss_metrics' => $this->parse_cvss_metrics($cve_data['metrics'] ?? array()),
                'weakness' => $this->parse_weaknesses($cve_data['weaknesses'] ?? array()),
                'configurations' => $this->parse_configurations($cve_data['configurations'] ?? array()),
                'references' => $this->parse_references($cve_data['references'] ?? array()),
                'vendor_comments' => $this->parse_vendor_comments($cve_data['vendorComments'] ?? array()),
                'severity' => '',
                'score' => 0.0,
                'source' => 'nvd'
            );

            // Extract primary CVSS score and severity
            $cvss_info = $this->extract_primary_cvss($parsed_cve['cvss_metrics']);
            $parsed_cve['score'] = $cvss_info['score'];
            $parsed_cve['severity'] = $cvss_info['severity'];
            $parsed_cve['vector'] = $cvss_info['vector'];

            $cves[] = $parsed_cve;
        }

        return $cves;
    }

    /**
     * Parse description array.
     *
     * @since    1.0.0
     * @param    array     $descriptions   Description array.
     * @return   array                     Parsed descriptions.
     */
    private function parse_descriptions($descriptions) {
        $parsed = array();
        
        foreach ($descriptions as $desc) {
            $parsed[] = array(
                'lang' => $desc['lang'] ?? 'en',
                'value' => $desc['value'] ?? ''
            );
        }

        return $parsed;
    }

    /**
     * Parse CVSS metrics.
     *
     * @since    1.0.0
     * @param    array     $metrics        CVSS metrics array.
     * @return   array                     Parsed CVSS metrics.
     */
    private function parse_cvss_metrics($metrics) {
        $parsed = array();

        foreach (array('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2') as $version) {
            if (isset($metrics[$version])) {
                foreach ($metrics[$version] as $metric) {
                    $cvss_data = $metric['cvssData'] ?? array();
                    
                    $parsed[] = array(
                        'source' => $metric['source'] ?? '',
                        'type' => $metric['type'] ?? '',
                        'version' => $cvss_data['version'] ?? '',
                        'vector_string' => $cvss_data['vectorString'] ?? '',
                        'base_score' => $cvss_data['baseScore'] ?? 0.0,
                        'base_severity' => $cvss_data['baseSeverity'] ?? '',
                        'impact_score' => $metric['impactScore'] ?? 0.0,
                        'exploitability_score' => $metric['exploitabilityScore'] ?? 0.0
                    );
                }
            }
        }

        return $parsed;
    }

    /**
     * Parse weaknesses (CWE data).
     *
     * @since    1.0.0
     * @param    array     $weaknesses     Weaknesses array.
     * @return   array                     Parsed weaknesses.
     */
    private function parse_weaknesses($weaknesses) {
        $parsed = array();
        
        foreach ($weaknesses as $weakness) {
            if (isset($weakness['description'])) {
                foreach ($weakness['description'] as $desc) {
                    $parsed[] = array(
                        'source' => $weakness['source'] ?? '',
                        'type' => $weakness['type'] ?? '',
                        'lang' => $desc['lang'] ?? 'en',
                        'value' => $desc['value'] ?? ''
                    );
                }
            }
        }

        return $parsed;
    }

    /**
     * Parse configurations (affected products).
     *
     * @since    1.0.0
     * @param    array     $configurations Configuration array.
     * @return   array                     Parsed configurations.
     */
    private function parse_configurations($configurations) {
        $parsed = array();
        
        foreach ($configurations as $config) {
            if (isset($config['nodes'])) {
                $parsed[] = array(
                    'operator' => $config['operator'] ?? '',
                    'negate' => $config['negate'] ?? false,
                    'nodes' => $this->parse_config_nodes($config['nodes'])
                );
            }
        }

        return $parsed;
    }

    /**
     * Parse configuration nodes.
     *
     * @since    1.0.0
     * @param    array     $nodes          Nodes array.
     * @return   array                     Parsed nodes.
     */
    private function parse_config_nodes($nodes) {
        $parsed = array();
        
        foreach ($nodes as $node) {
            $parsed_node = array(
                'operator' => $node['operator'] ?? '',
                'negate' => $node['negate'] ?? false,
                'cpe_match' => array()
            );

            if (isset($node['cpeMatch'])) {
                foreach ($node['cpeMatch'] as $cpe) {
                    $parsed_node['cpe_match'][] = array(
                        'vulnerable' => $cpe['vulnerable'] ?? false,
                        'criteria' => $cpe['criteria'] ?? '',
                        'version_start_including' => $cpe['versionStartIncluding'] ?? '',
                        'version_start_excluding' => $cpe['versionStartExcluding'] ?? '',
                        'version_end_including' => $cpe['versionEndIncluding'] ?? '',
                        'version_end_excluding' => $cpe['versionEndExcluding'] ?? ''
                    );
                }
            }

            $parsed[] = $parsed_node;
        }

        return $parsed;
    }

    /**
     * Parse references.
     *
     * @since    1.0.0
     * @param    array     $references     References array.
     * @return   array                     Parsed references.
     */
    private function parse_references($references) {
        $parsed = array();
        
        foreach ($references as $ref) {
            $parsed[] = array(
                'url' => $ref['url'] ?? '',
                'source' => $ref['source'] ?? '',
                'tags' => $ref['tags'] ?? array()
            );
        }

        return $parsed;
    }

    /**
     * Parse vendor comments.
     *
     * @since    1.0.0
     * @param    array     $comments       Vendor comments array.
     * @return   array                     Parsed comments.
     */
    private function parse_vendor_comments($comments) {
        $parsed = array();
        
        foreach ($comments as $comment) {
            $parsed[] = array(
                'organization' => $comment['organization'] ?? '',
                'comment' => $comment['comment'] ?? '',
                'last_modified' => $comment['lastModified'] ?? ''
            );
        }

        return $parsed;
    }

    /**
     * Extract primary CVSS score and severity.
     *
     * @since    1.0.0
     * @param    array     $cvss_metrics   CVSS metrics array.
     * @return   array                     Primary CVSS info.
     */
    private function extract_primary_cvss($cvss_metrics) {
        $primary = array(
            'score' => 0.0,
            'severity' => 'info',
            'vector' => ''
        );

        // Prefer CVSSv3.1, then v3.0, then v2
        foreach ($cvss_metrics as $metric) {
            if ($metric['type'] === 'Primary' || empty($primary['vector'])) {
                $primary['score'] = $metric['base_score'];
                $primary['severity'] = $this->map_nvd_severity($metric['base_severity']);
                $primary['vector'] = $metric['vector_string'];
                
                if ($metric['type'] === 'Primary') {
                    break; // Prefer primary metrics
                }
            }
        }

        return $primary;
    }

    /**
     * Map NVD severity to our severity levels.
     *
     * @since    1.0.0
     * @param    string    $nvd_severity   NVD severity level.
     * @return   string                    Mapped severity.
     */
    private function map_nvd_severity($nvd_severity) {
        $severity_map = array(
            'CRITICAL' => 'critical',
            'HIGH' => 'high',
            'MEDIUM' => 'medium',
            'LOW' => 'low'
        );

        return $severity_map[strtoupper($nvd_severity)] ?? 'info';
    }

    /**
     * Filter CVEs by CVSS score range.
     *
     * @since    1.0.0
     * @param    array     $cves           CVE array.
     * @param    float     $min_score      Minimum score.
     * @param    float     $max_score      Maximum score.
     * @return   array                     Filtered CVEs.
     */
    private function filter_by_cvss_score($cves, $min_score = null, $max_score = null) {
        return array_filter($cves, function($cve) use ($min_score, $max_score) {
            $score = $cve['score'];
            
            if ($min_score !== null && $score < $min_score) {
                return false;
            }
            
            if ($max_score !== null && $score > $max_score) {
                return false;
            }
            
            return true;
        });
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
        switch ($status_code) {
            case 403:
                return new WP_Error('forbidden', 'Access denied to NVD API - check API key');
            case 404:
                return new WP_Error('not_found', 'NVD API endpoint not found');
            case 429:
                return new WP_Error('rate_limited', 'NVD API rate limit exceeded');
            case 500:
                return new WP_Error('server_error', 'NVD API server error');
            case 503:
                return new WP_Error('service_unavailable', 'NVD API service temporarily unavailable');
            default:
                return new WP_Error('api_error', 'NVD API error: ' . $status_code, array('status' => $status_code));
        }
    }

    /**
     * Check rate limiting.
     *
     * @since    1.0.0
     * @return   bool                      True if request allowed.
     */
    private function check_rate_limit() {
        $limits = !empty($this->api_key) ? $this->rate_limit['with_key'] : $this->rate_limit['without_key'];
        
        $thirty_second_key = 'nvd_requests_30s_' . floor(time() / 30);
        $thirty_minute_key = 'nvd_requests_30m_' . floor(time() / 1800);

        $thirty_second_requests = get_transient($thirty_second_key) ?: 0;
        $thirty_minute_requests = get_transient($thirty_minute_key) ?: 0;

        if ($thirty_second_requests >= $limits['requests_per_30_seconds']) {
            return false;
        }

        if ($thirty_minute_requests >= $limits['requests_per_30_minutes']) {
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
        $thirty_second_key = 'nvd_requests_30s_' . floor(time() / 30);
        $thirty_minute_key = 'nvd_requests_30m_' . floor(time() / 1800);

        $thirty_second_requests = get_transient($thirty_second_key) ?: 0;
        $thirty_minute_requests = get_transient($thirty_minute_key) ?: 0;

        set_transient($thirty_second_key, $thirty_second_requests + 1, 30);
        set_transient($thirty_minute_key, $thirty_minute_requests + 1, 1800);
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
                '_transient_wp_breach_nvd_%'
            )
        );
    }

    /**
     * Set API key.
     *
     * @since    1.0.0
     * @param    string    $key            API key.
     */
    public function set_api_key($key) {
        $this->api_key = $key;
        update_option('wp_breach_nvd_api_key', $key);
    }

    /**
     * Test API connectivity.
     *
     * @since    1.0.0
     * @return   array                     API status information.
     */
    public function test_api() {
        $response = $this->search_cves('test', 1);
        
        if (is_wp_error($response)) {
            return array(
                'status' => 'error',
                'message' => $response->get_error_message()
            );
        }

        return array(
            'status' => 'ok',
            'message' => 'NVD API connection successful',
            'has_api_key' => !empty($this->api_key)
        );
    }
}
