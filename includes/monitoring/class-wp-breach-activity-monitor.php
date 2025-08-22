<?php

/**
 * Activity Monitor for WP-Breach.
 *
 * This class handles real-time monitoring of user activities, login attempts,
 * administrative actions, and suspicious behavior patterns.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/monitoring
 */

/**
 * The activity monitoring class.
 *
 * Monitors user activities, authentication events, and administrative
 * actions to detect suspicious behavior and potential security threats.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/monitoring
 * @author     WP Breach Team
 */
class WP_Breach_Activity_Monitor {

    /**
     * Activity monitoring configuration.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $config    Activity monitoring configuration.
     */
    private $config;

    /**
     * Database connection.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Breach_Database    $database    Database instance.
     */
    private $database;

    /**
     * Threat intelligence instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Breach_Threat_Intelligence    $threat_intel    Threat intelligence.
     */
    private $threat_intel;

    /**
     * Session tracking data.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $session_data    Current session tracking data.
     */
    private $session_data;

    /**
     * Activity patterns cache.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $activity_patterns    Cached activity patterns.
     */
    private $activity_patterns;

    /**
     * Initialize the activity monitor.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->setup_config();
        $this->database = new WP_Breach_Database();
        $this->threat_intel = new WP_Breach_Threat_Intelligence();
        $this->session_data = array();
        $this->activity_patterns = array();
        
        // Register hooks
        $this->register_hooks();
        
        // Initialize session tracking
        $this->initialize_session_tracking();
    }

    /**
     * Setup activity monitoring configuration.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_config() {
        $this->config = array(
            'monitoring_enabled' => true,
            'login_monitoring' => true,
            'admin_monitoring' => true,
            'request_monitoring' => true,
            'behavior_analysis' => true,
            'ip_tracking' => true,
            'geolocation_tracking' => false,
            'session_timeout' => 30 * MINUTE_IN_SECONDS,
            'failed_login_threshold' => 5,
            'failed_login_window' => 15 * MINUTE_IN_SECONDS,
            'lockout_duration' => 60 * MINUTE_IN_SECONDS,
            'suspicious_activity_threshold' => 10,
            'request_rate_limit' => 100, // requests per minute
            'admin_action_monitoring' => array(
                'user_creation',
                'user_deletion',
                'role_changes',
                'plugin_activation',
                'plugin_deactivation',
                'theme_changes',
                'option_updates',
                'file_modifications'
            ),
            'monitored_capabilities' => array(
                'manage_options',
                'edit_plugins',
                'edit_themes',
                'install_plugins',
                'delete_plugins',
                'create_users',
                'delete_users'
            ),
            'suspicious_patterns' => array(
                'rapid_requests',
                'unusual_user_agents',
                'suspicious_referrers',
                'automated_behavior',
                'privilege_escalation_attempts'
            )
        );
    }

    /**
     * Register WordPress hooks for activity monitoring.
     *
     * @since    1.0.0
     * @access   private
     */
    private function register_hooks() {
        // Authentication monitoring
        add_action('wp_login', array($this, 'track_successful_login'), 10, 2);
        add_action('wp_login_failed', array($this, 'track_failed_login'));
        add_action('wp_logout', array($this, 'track_logout'));
        add_action('authenticate', array($this, 'pre_authentication_check'), 5, 3);
        
        // Administrative action monitoring
        add_action('user_register', array($this, 'track_user_creation'));
        add_action('delete_user', array($this, 'track_user_deletion'));
        add_action('set_user_role', array($this, 'track_role_change'), 10, 3);
        add_action('activated_plugin', array($this, 'track_plugin_activation'));
        add_action('deactivated_plugin', array($this, 'track_plugin_deactivation'));
        add_action('switch_theme', array($this, 'track_theme_change'));
        add_action('updated_option', array($this, 'track_option_update'), 10, 3);
        
        // Request monitoring
        add_action('init', array($this, 'track_request'), 1);
        add_action('wp_loaded', array($this, 'analyze_request_patterns'));
        
        // File monitoring integration
        add_action('wp_handle_upload', array($this, 'track_file_upload'));
        
        // Session monitoring
        add_action('wp', array($this, 'track_user_session'));
        add_action('wp_ajax_heartbeat', array($this, 'update_session_activity'));
        
        // Scheduled activities
        add_action('wp_breach_analyze_activity_patterns', array($this, 'analyze_activity_patterns'));
        add_action('wp_breach_cleanup_activity_logs', array($this, 'cleanup_old_logs'));
        
        // Schedule periodic analysis
        if (!wp_next_scheduled('wp_breach_analyze_activity_patterns')) {
            wp_schedule_event(time(), 'hourly', 'wp_breach_analyze_activity_patterns');
        }
        
        if (!wp_next_scheduled('wp_breach_cleanup_activity_logs')) {
            wp_schedule_event(time(), 'daily', 'wp_breach_cleanup_activity_logs');
        }
    }

    /**
     * Initialize session tracking.
     *
     * @since    1.0.0
     * @access   private
     */
    private function initialize_session_tracking() {
        if (!session_id()) {
            session_start();
        }
        
        $this->session_data = array(
            'session_id' => session_id(),
            'user_ip' => $this->get_client_ip(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'start_time' => time(),
            'last_activity' => time(),
            'request_count' => 0,
            'page_views' => array(),
            'actions_performed' => array()
        );
    }

    /**
     * Track successful login attempt.
     *
     * @since    1.0.0
     * @param    string   $user_login    Username.
     * @param    WP_User  $user         User object.
     */
    public function track_successful_login($user_login, $user) {
        $login_data = array(
            'user_id' => $user->ID,
            'username' => $user_login,
            'user_ip' => $this->get_client_ip(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'login_time' => current_time('mysql'),
            'status' => 'success',
            'session_id' => session_id(),
            'login_location' => $this->get_geolocation(),
            'is_admin' => user_can($user, 'manage_options'),
            'capabilities' => array_keys($user->allcaps ?? array())
        );
        
        // Check for suspicious login patterns
        $risk_assessment = $this->assess_login_risk($login_data);
        $login_data['risk_score'] = $risk_assessment['score'];
        $login_data['risk_factors'] = $risk_assessment['factors'];
        
        // Save login event
        $this->save_activity_event('login_success', $login_data);
        
        // Clear failed login attempts for this user
        $this->clear_failed_login_attempts($user_login);
        
        // Check for anomalous login
        if ($risk_assessment['score'] > 70) {
            $this->create_suspicious_login_alert($login_data, $risk_assessment);
        }
        
        // Update user session tracking
        $this->update_user_session($user->ID, 'login');
    }

    /**
     * Track failed login attempt.
     *
     * @since    1.0.0
     * @param    string   $username    Failed username.
     */
    public function track_failed_login($username) {
        $client_ip = $this->get_client_ip();
        
        $failed_login_data = array(
            'username' => $username,
            'user_ip' => $client_ip,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'attempt_time' => current_time('mysql'),
            'status' => 'failed',
            'failure_reason' => $this->determine_failure_reason($username)
        );
        
        // Save failed login event
        $this->save_activity_event('login_failed', $failed_login_data);
        
        // Check for brute force attack
        $recent_failures = $this->get_recent_failed_logins($client_ip, $username);
        
        if (count($recent_failures) >= $this->config['failed_login_threshold']) {
            $this->handle_brute_force_attempt($client_ip, $username, $recent_failures);
        }
        
        // Check IP reputation
        $this->check_ip_reputation($client_ip);
    }

    /**
     * Pre-authentication security check.
     *
     * @since    1.0.0
     * @param    WP_User|WP_Error|null  $user      User object or error.
     * @param    string                 $username  Username.
     * @param    string                 $password  Password.
     * @return   WP_User|WP_Error|null            Modified user object or error.
     */
    public function pre_authentication_check($user, $username, $password) {
        $client_ip = $this->get_client_ip();
        
        // Check if IP is currently locked out
        if ($this->is_ip_locked_out($client_ip)) {
            return new WP_Error('ip_locked_out', 'Too many failed login attempts. Please try again later.');
        }
        
        // Check if username is being brute forced
        if ($this->is_username_under_attack($username)) {
            return new WP_Error('username_locked', 'This account is temporarily locked due to suspicious activity.');
        }
        
        // Check IP reputation
        $ip_reputation = $this->threat_intel->check_ip_reputation($client_ip);
        if ($ip_reputation['is_malicious']) {
            $this->save_activity_event('malicious_ip_attempt', array(
                'user_ip' => $client_ip,
                'username' => $username,
                'reputation_data' => $ip_reputation,
                'blocked' => true
            ));
            
            return new WP_Error('malicious_ip', 'Login attempt blocked due to security concerns.');
        }
        
        return $user;
    }

    /**
     * Track administrative actions.
     *
     * @since    1.0.0
     * @param    string   $action       Action type.
     * @param    array    $action_data  Action data.
     */
    public function track_admin_action($action, $action_data = array()) {
        if (!$this->config['admin_monitoring']) {
            return;
        }
        
        $current_user = wp_get_current_user();
        
        $admin_action_data = array(
            'user_id' => $current_user->ID,
            'username' => $current_user->user_login,
            'action_type' => $action,
            'action_data' => $action_data,
            'user_ip' => $this->get_client_ip(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
            'timestamp' => current_time('mysql'),
            'user_capabilities' => array_keys($current_user->allcaps ?? array())
        );
        
        // Assess action risk
        $risk_assessment = $this->assess_admin_action_risk($admin_action_data);
        $admin_action_data['risk_score'] = $risk_assessment['score'];
        $admin_action_data['risk_factors'] = $risk_assessment['factors'];
        
        // Save admin action event
        $this->save_activity_event('admin_action', $admin_action_data);
        
        // Check for privilege escalation attempts
        if ($this->is_privilege_escalation_attempt($admin_action_data)) {
            $this->create_privilege_escalation_alert($admin_action_data);
        }
        
        // Check for unusual admin activity
        if ($risk_assessment['score'] > 80) {
            $this->create_suspicious_admin_alert($admin_action_data, $risk_assessment);
        }
    }

    /**
     * Track HTTP requests for pattern analysis.
     *
     * @since    1.0.0
     */
    public function track_request() {
        if (!$this->config['request_monitoring']) {
            return;
        }
        
        $request_data = array(
            'user_ip' => $this->get_client_ip(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'request_method' => $_SERVER['REQUEST_METHOD'] ?? '',
            'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
            'http_referer' => $_SERVER['HTTP_REFERER'] ?? '',
            'query_string' => $_SERVER['QUERY_STRING'] ?? '',
            'request_time' => microtime(true),
            'timestamp' => current_time('mysql')
        );
        
        // Add user context if available
        if (is_user_logged_in()) {
            $current_user = wp_get_current_user();
            $request_data['user_id'] = $current_user->ID;
            $request_data['username'] = $current_user->user_login;
        }
        
        // Update session data
        $this->session_data['request_count']++;
        $this->session_data['last_activity'] = time();
        $this->session_data['page_views'][] = $request_data['request_uri'];
        
        // Check for suspicious request patterns
        $this->analyze_request_suspicious_patterns($request_data);
        
        // Rate limiting check
        if ($this->is_rate_limit_exceeded($request_data['user_ip'])) {
            $this->handle_rate_limit_violation($request_data);
        }
        
        // Save significant requests
        if ($this->is_significant_request($request_data)) {
            $this->save_activity_event('http_request', $request_data);
        }
    }

    /**
     * Analyze request patterns for suspicious activity.
     *
     * @since    1.0.0
     */
    public function analyze_request_patterns() {
        // Analyze patterns from recent requests
        $recent_requests = $this->get_recent_requests();
        
        // Check for automated behavior
        $this->detect_automated_behavior($recent_requests);
        
        // Check for scan attempts
        $this->detect_scan_attempts($recent_requests);
        
        // Check for injection attempts
        $this->detect_injection_attempts($recent_requests);
    }

    /**
     * Analyze suspicious request patterns.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $request_data    Request data.
     */
    private function analyze_request_suspicious_patterns($request_data) {
        $suspicious_factors = array();
        
        // Check for suspicious user agents
        if ($this->is_suspicious_user_agent($request_data['user_agent'])) {
            $suspicious_factors[] = 'suspicious_user_agent';
        }
        
        // Check for suspicious referrers
        if ($this->is_suspicious_referrer($request_data['http_referer'])) {
            $suspicious_factors[] = 'suspicious_referrer';
        }
        
        // Check for injection patterns in query string
        if ($this->contains_injection_patterns($request_data['query_string'])) {
            $suspicious_factors[] = 'injection_attempt';
        }
        
        // Check for directory traversal attempts
        if ($this->contains_directory_traversal($request_data['request_uri'])) {
            $suspicious_factors[] = 'directory_traversal';
        }
        
        // Check for file inclusion attempts
        if ($this->contains_file_inclusion_patterns($request_data['request_uri'])) {
            $suspicious_factors[] = 'file_inclusion_attempt';
        }
        
        if (!empty($suspicious_factors)) {
            $request_data['suspicious_factors'] = $suspicious_factors;
            $request_data['risk_score'] = count($suspicious_factors) * 20;
            
            $this->save_activity_event('suspicious_request', $request_data);
            
            if (count($suspicious_factors) >= 2) {
                $this->create_suspicious_request_alert($request_data);
            }
        }
    }

    /**
     * Assess login risk based on various factors.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $login_data    Login data.
     * @return   array                   Risk assessment.
     */
    private function assess_login_risk($login_data) {
        $risk_score = 0;
        $risk_factors = array();
        
        // Check for unusual login time
        $login_hour = (int) date('H', strtotime($login_data['login_time']));
        if ($login_hour < 6 || $login_hour > 22) {
            $risk_score += 10;
            $risk_factors[] = 'unusual_time';
        }
        
        // Check for new location (if geolocation is enabled)
        if ($this->config['geolocation_tracking'] && !empty($login_data['login_location'])) {
            if ($this->is_new_location($login_data['user_id'], $login_data['login_location'])) {
                $risk_score += 30;
                $risk_factors[] = 'new_location';
            }
        }
        
        // Check for multiple rapid logins
        $recent_logins = $this->get_recent_successful_logins($login_data['user_id']);
        if (count($recent_logins) > 5) {
            $risk_score += 20;
            $risk_factors[] = 'rapid_logins';
        }
        
        // Check for admin privileges
        if ($login_data['is_admin']) {
            $risk_score += 10;
            $risk_factors[] = 'admin_account';
        }
        
        // Check user agent consistency
        if ($this->is_inconsistent_user_agent($login_data['user_id'], $login_data['user_agent'])) {
            $risk_score += 15;
            $risk_factors[] = 'inconsistent_user_agent';
        }
        
        return array(
            'score' => min($risk_score, 100),
            'factors' => $risk_factors
        );
    }

    /**
     * Get client IP address.
     *
     * @since    1.0.0
     * @access   private
     * @return   string    Client IP address.
     */
    private function get_client_ip() {
        $ip_headers = array(
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        );
        
        foreach ($ip_headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = $_SERVER[$header];
                
                // Handle comma-separated IPs
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                
                // Validate IP
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    /**
     * Get geolocation data for IP address.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $ip_address    IP address.
     * @return   array|null             Geolocation data.
     */
    private function get_geolocation($ip_address = null) {
        if (!$this->config['geolocation_tracking']) {
            return null;
        }
        
        if (!$ip_address) {
            $ip_address = $this->get_client_ip();
        }
        
        // Use threat intelligence service for geolocation
        return $this->threat_intel->get_ip_geolocation($ip_address);
    }

    /**
     * Save activity event to database.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $event_type    Event type.
     * @param    array    $event_data    Event data.
     */
    private function save_activity_event($event_type, $event_data) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_monitoring';
        
        $wpdb->insert(
            $table_name,
            array(
                'monitor_type' => 'activity',
                'event_type' => $event_type,
                'user_ip' => $event_data['user_ip'] ?? null,
                'user_id' => $event_data['user_id'] ?? null,
                'event_data' => json_encode($event_data),
                'risk_score' => $event_data['risk_score'] ?? 0,
                'detected_at' => $event_data['timestamp'] ?? current_time('mysql'),
                'created_at' => current_time('mysql')
            ),
            array('%s', '%s', '%s', '%d', '%s', '%d', '%s', '%s')
        );
    }

    /**
     * Get recent failed login attempts.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $ip_address    IP address.
     * @param    string   $username      Username.
     * @return   array                   Recent failed attempts.
     */
    private function get_recent_failed_logins($ip_address, $username = null) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_monitoring';
        $since = date('Y-m-d H:i:s', time() - $this->config['failed_login_window']);
        
        $where_conditions = array(
            "monitor_type = 'activity'",
            "event_type = 'login_failed'",
            "user_ip = %s",
            "detected_at > %s"
        );
        
        $params = array($ip_address, $since);
        
        if ($username) {
            $where_conditions[] = "JSON_EXTRACT(event_data, '$.username') = %s";
            $params[] = $username;
        }
        
        $sql = "SELECT * FROM {$table_name} WHERE " . implode(' AND ', $where_conditions) . " ORDER BY detected_at DESC";
        
        return $wpdb->get_results($wpdb->prepare($sql, $params), ARRAY_A);
    }

    /**
     * Handle brute force attack attempt.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $ip_address       IP address.
     * @param    string   $username         Username.
     * @param    array    $failed_attempts  Failed attempts.
     */
    private function handle_brute_force_attempt($ip_address, $username, $failed_attempts) {
        // Lock out IP address
        $this->lockout_ip_address($ip_address);
        
        // Create brute force alert
        $alert_data = array(
            'type' => 'brute_force_attack',
            'severity' => 'high',
            'title' => 'Brute Force Attack Detected',
            'message' => sprintf(
                'Brute force attack detected from IP %s against username %s. %d failed attempts in %d minutes.',
                $ip_address,
                $username,
                count($failed_attempts),
                $this->config['failed_login_window'] / 60
            ),
            'details' => array(
                'ip_address' => $ip_address,
                'username' => $username,
                'failed_attempts' => count($failed_attempts),
                'time_window' => $this->config['failed_login_window']
            ),
            'source' => 'activity_monitor'
        );
        
        $alert_manager = new WP_Breach_Alert_Manager();
        $alert_manager->create_alert($alert_data);
        
        // Log brute force event
        $this->save_activity_event('brute_force_detected', array(
            'user_ip' => $ip_address,
            'username' => $username,
            'attempt_count' => count($failed_attempts),
            'lockout_applied' => true,
            'timestamp' => current_time('mysql')
        ));
    }

    /**
     * Check if IP address is currently locked out.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $ip_address    IP address.
     * @return   bool                    True if IP is locked out.
     */
    private function is_ip_locked_out($ip_address) {
        $lockout_key = 'wp_breach_lockout_' . md5($ip_address);
        return get_transient($lockout_key) !== false;
    }

    /**
     * Lock out IP address for specified duration.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $ip_address    IP address to lock out.
     */
    private function lockout_ip_address($ip_address) {
        $lockout_key = 'wp_breach_lockout_' . md5($ip_address);
        set_transient($lockout_key, time(), $this->config['lockout_duration']);
    }

    // Additional helper methods for the activity monitor...
    
    private function determine_failure_reason($username) {
        // Determine why login failed (user doesn't exist, wrong password, etc.)
        if (!username_exists($username) && !email_exists($username)) {
            return 'invalid_username';
        }
        return 'invalid_password';
    }
    
    private function clear_failed_login_attempts($username) {
        // Implementation to clear failed attempts after successful login
    }
    
    private function is_username_under_attack($username) {
        // Check if username is being brute forced from multiple IPs
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_monitoring';
        $since = date('Y-m-d H:i:s', time() - $this->config['failed_login_window']);
        
        $count = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(DISTINCT user_ip) FROM {$table_name} 
             WHERE monitor_type = 'activity' 
             AND event_type = 'login_failed' 
             AND JSON_EXTRACT(event_data, '$.username') = %s 
             AND detected_at > %s",
            $username,
            $since
        ));
        
        return $count >= 3; // Multiple IPs attacking same username
    }
    
    private function check_ip_reputation($ip_address) {
        // Check IP against threat intelligence
        $reputation = $this->threat_intel->check_ip_reputation($ip_address);
        
        if ($reputation['is_malicious']) {
            $this->save_activity_event('malicious_ip_detected', array(
                'user_ip' => $ip_address,
                'reputation_data' => $reputation,
                'timestamp' => current_time('mysql')
            ));
        }
    }
    
    private function update_user_session($user_id, $action) {
        // Update user session tracking
        $this->session_data['actions_performed'][] = array(
            'action' => $action,
            'timestamp' => time()
        );
    }

    // Track specific admin actions
    public function track_user_creation($user_id) {
        $this->track_admin_action('user_creation', array('created_user_id' => $user_id));
    }

    public function track_user_deletion($user_id) {
        $this->track_admin_action('user_deletion', array('deleted_user_id' => $user_id));
    }

    public function track_role_change($user_id, $role, $old_roles) {
        $this->track_admin_action('role_change', array(
            'target_user_id' => $user_id,
            'new_role' => $role,
            'old_roles' => $old_roles
        ));
    }

    public function track_plugin_activation($plugin) {
        $this->track_admin_action('plugin_activation', array('plugin' => $plugin));
    }

    public function track_plugin_deactivation($plugin) {
        $this->track_admin_action('plugin_deactivation', array('plugin' => $plugin));
    }

    public function track_theme_change($new_name, $new_theme) {
        $this->track_admin_action('theme_change', array(
            'new_theme' => $new_name,
            'theme_object' => $new_theme
        ));
    }

    public function track_option_update($option_name, $old_value, $value) {
        // Only track sensitive options
        $sensitive_options = array(
            'admin_email',
            'users_can_register',
            'default_role',
            'active_plugins',
            'template',
            'stylesheet'
        );
        
        if (in_array($option_name, $sensitive_options)) {
            $this->track_admin_action('option_update', array(
                'option_name' => $option_name,
                'old_value' => $old_value,
                'new_value' => $value
            ));
        }
    }

    public function track_logout($user_id) {
        $logout_data = array(
            'user_id' => $user_id,
            'user_ip' => $this->get_client_ip(),
            'session_duration' => time() - ($this->session_data['start_time'] ?? time()),
            'logout_time' => current_time('mysql')
        );
        
        $this->save_activity_event('logout', $logout_data);
    }

    public function track_user_session() {
        if (is_user_logged_in()) {
            $current_user = wp_get_current_user();
            
            // Update session tracking
            $this->session_data['user_id'] = $current_user->ID;
            $this->session_data['last_activity'] = time();
        }
    }

    public function update_session_activity() {
        // Update last activity timestamp
        $this->session_data['last_activity'] = time();
    }

    public function track_file_upload($upload) {
        $upload_data = array(
            'user_id' => get_current_user_id(),
            'user_ip' => $this->get_client_ip(),
            'file_name' => $upload['file'],
            'file_type' => $upload['type'],
            'file_size' => filesize($upload['file']),
            'upload_time' => current_time('mysql')
        );
        
        $this->save_activity_event('file_upload', $upload_data);
    }

    // Pattern analysis methods
    public function analyze_activity_patterns() {
        // Analyze activity patterns for behavioral anomalies
        $this->detect_unusual_activity_patterns();
        $this->detect_privilege_escalation_patterns();
        $this->detect_automated_behavior_patterns();
    }

    public function cleanup_old_logs() {
        // Clean up old activity logs based on retention policy
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_monitoring';
        $cutoff_date = date('Y-m-d H:i:s', time() - (90 * DAY_IN_SECONDS));
        
        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$table_name} WHERE monitor_type = 'activity' AND created_at < %s",
            $cutoff_date
        ));
    }

    // Additional helper methods would continue here...
    private function is_significant_request($request_data) {
        // Determine if request should be logged
        return strpos($request_data['request_uri'], '/wp-admin/') === 0 ||
               strpos($request_data['request_uri'], '/wp-login.php') === 0 ||
               !empty($request_data['user_id']);
    }

    private function is_rate_limit_exceeded($ip_address) {
        // Check request rate limiting
        $rate_key = 'wp_breach_rate_' . md5($ip_address);
        $current_count = get_transient($rate_key) ?: 0;
        
        if ($current_count >= $this->config['request_rate_limit']) {
            return true;
        }
        
        set_transient($rate_key, $current_count + 1, MINUTE_IN_SECONDS);
        return false;
    }

    private function handle_rate_limit_violation($request_data) {
        $this->save_activity_event('rate_limit_exceeded', $request_data);
        
        // Create alert for excessive requests
        $alert_manager = new WP_Breach_Alert_Manager();
        $alert_manager->create_alert(array(
            'type' => 'rate_limit_violation',
            'severity' => 'medium',
            'title' => 'Rate Limit Exceeded',
            'message' => 'IP address ' . $request_data['user_ip'] . ' has exceeded the request rate limit.',
            'details' => $request_data,
            'source' => 'activity_monitor'
        ));
    }

    // Additional suspicious pattern detection methods would be implemented here...
}
