<?php

/**
 * Alert Manager for WP-Breach.
 *
 * This class handles centralized creation, management, and delivery of security alerts.
 * It coordinates with various monitoring components and manages alert channels.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/monitoring
 */

/**
 * The alert management class.
 *
 * Manages security alerts including creation, prioritization, delivery,
 * escalation, and resolution tracking.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/monitoring
 * @author     WP Breach Team
 */
class WP_Breach_Alert_Manager {

    /**
     * Alert configuration.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $config    Alert configuration.
     */
    private $config;

    /**
     * Alert channels.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $channels    Available alert channels.
     */
    private $channels;

    /**
     * Alert queue.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $alert_queue    Pending alerts queue.
     */
    private $alert_queue;

    /**
     * Escalation rules.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $escalation_rules    Alert escalation rules.
     */
    private $escalation_rules;

    /**
     * Rate limiting tracker.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $rate_limiter    Rate limiting data.
     */
    private $rate_limiter;

    /**
     * Initialize the alert manager.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->setup_config();
        $this->setup_channels();
        $this->setup_escalation_rules();
        $this->alert_queue = array();
        $this->rate_limiter = array();
        
        // Register hooks
        $this->register_hooks();
        
        // Schedule alert processing
        $this->schedule_alert_processing();
    }

    /**
     * Setup alert configuration.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_config() {
        $this->config = array(
            'enabled' => true,
            'batch_processing' => true,
            'batch_size' => 10,
            'processing_interval' => 60, // seconds
            'rate_limiting' => true,
            'max_alerts_per_hour' => 50,
            'max_alerts_per_day' => 200,
            'duplicate_suppression' => true,
            'duplicate_window' => 300, // 5 minutes
            'escalation_enabled' => true,
            'auto_resolution' => true,
            'retention_period' => 90 * DAY_IN_SECONDS,
            'priority_levels' => array('low', 'medium', 'high', 'critical'),
            'alert_types' => array(
                'malware_detected',
                'file_integrity_violation',
                'suspicious_activity',
                'brute_force_attack',
                'unauthorized_access',
                'configuration_change',
                'vulnerability_detected',
                'system_compromise',
                'data_breach',
                'anomaly_detected'
            ),
            'severity_mapping' => array(
                'low' => 1,
                'medium' => 2,
                'high' => 3,
                'critical' => 4
            )
        );
    }

    /**
     * Setup alert delivery channels.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_channels() {
        $this->channels = array(
            'email' => array(
                'enabled' => true,
                'class' => 'WP_Breach_Email_Alert_Channel',
                'priority' => 1,
                'supports' => array('immediate', 'batch', 'digest'),
                'rate_limit' => 10 // per hour
            ),
            'dashboard' => array(
                'enabled' => true,
                'class' => 'WP_Breach_Dashboard_Alert_Channel',
                'priority' => 2,
                'supports' => array('immediate', 'persistent'),
                'rate_limit' => 100 // per hour
            ),
            'webhook' => array(
                'enabled' => false,
                'class' => 'WP_Breach_Webhook_Alert_Channel',
                'priority' => 3,
                'supports' => array('immediate'),
                'rate_limit' => 50 // per hour
            ),
            'sms' => array(
                'enabled' => false,
                'class' => 'WP_Breach_SMS_Alert_Channel',
                'priority' => 4,
                'supports' => array('immediate'),
                'rate_limit' => 5 // per hour
            ),
            'slack' => array(
                'enabled' => false,
                'class' => 'WP_Breach_Slack_Alert_Channel',
                'priority' => 5,
                'supports' => array('immediate', 'batch'),
                'rate_limit' => 20 // per hour
            )
        );
    }

    /**
     * Setup escalation rules.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_escalation_rules() {
        $this->escalation_rules = array(
            'critical' => array(
                'immediate_notify' => true,
                'escalation_delay' => 300, // 5 minutes
                'max_escalations' => 3,
                'escalation_channels' => array('email', 'sms', 'webhook'),
                'auto_response' => true
            ),
            'high' => array(
                'immediate_notify' => true,
                'escalation_delay' => 900, // 15 minutes
                'max_escalations' => 2,
                'escalation_channels' => array('email', 'dashboard'),
                'auto_response' => false
            ),
            'medium' => array(
                'immediate_notify' => false,
                'escalation_delay' => 1800, // 30 minutes
                'max_escalations' => 1,
                'escalation_channels' => array('email'),
                'auto_response' => false
            ),
            'low' => array(
                'immediate_notify' => false,
                'escalation_delay' => 3600, // 1 hour
                'max_escalations' => 0,
                'escalation_channels' => array('dashboard'),
                'auto_response' => false
            )
        );
    }

    /**
     * Register WordPress hooks.
     *
     * @since    1.0.0
     * @access   private
     */
    private function register_hooks() {
        // Alert processing
        add_action('wp_breach_process_alerts', array($this, 'process_alert_queue'));
        add_action('wp_breach_escalate_alerts', array($this, 'process_escalations'));
        add_action('wp_breach_cleanup_alerts', array($this, 'cleanup_old_alerts'));
        
        // Alert status updates
        add_action('wp_breach_alert_acknowledged', array($this, 'handle_alert_acknowledgment'));
        add_action('wp_breach_alert_resolved', array($this, 'handle_alert_resolution'));
        
        // Emergency response
        add_action('wp_breach_emergency_alert', array($this, 'handle_emergency_alert'));
        
        // Rate limit reset
        add_action('wp_breach_reset_rate_limits', array($this, 'reset_rate_limits'));
    }

    /**
     * Schedule alert processing tasks.
     *
     * @since    1.0.0
     * @access   private
     */
    private function schedule_alert_processing() {
        // Regular alert processing
        if (!wp_next_scheduled('wp_breach_process_alerts')) {
            wp_schedule_event(time(), 'wp_breach_minute', 'wp_breach_process_alerts');
        }
        
        // Escalation processing
        if (!wp_next_scheduled('wp_breach_escalate_alerts')) {
            wp_schedule_event(time(), 'wp_breach_five_minutes', 'wp_breach_escalate_alerts');
        }
        
        // Daily cleanup
        if (!wp_next_scheduled('wp_breach_cleanup_alerts')) {
            wp_schedule_event(time(), 'daily', 'wp_breach_cleanup_alerts');
        }
        
        // Hourly rate limit reset
        if (!wp_next_scheduled('wp_breach_reset_rate_limits')) {
            wp_schedule_event(time(), 'hourly', 'wp_breach_reset_rate_limits');
        }
    }

    /**
     * Create a new security alert.
     *
     * @since    1.0.0
     * @param    array    $alert_data    Alert data.
     * @return   array                   Alert creation result.
     */
    public function create_alert($alert_data) {
        try {
            // Validate alert data
            $validation_result = $this->validate_alert_data($alert_data);
            if (!$validation_result['valid']) {
                return array(
                    'success' => false,
                    'error' => $validation_result['error']
                );
            }
            
            // Check for duplicates
            if ($this->config['duplicate_suppression']) {
                $duplicate_check = $this->check_duplicate_alert($alert_data);
                if ($duplicate_check['is_duplicate']) {
                    return array(
                        'success' => true,
                        'duplicate' => true,
                        'existing_alert_id' => $duplicate_check['alert_id']
                    );
                }
            }
            
            // Check rate limits
            if ($this->config['rate_limiting']) {
                $rate_limit_check = $this->check_rate_limits($alert_data);
                if (!$rate_limit_check['allowed']) {
                    return array(
                        'success' => false,
                        'error' => 'Rate limit exceeded',
                        'retry_after' => $rate_limit_check['retry_after']
                    );
                }
            }
            
            // Prepare alert
            $alert = $this->prepare_alert($alert_data);
            
            // Store alert in database
            $alert_id = $this->store_alert($alert);
            if (!$alert_id) {
                return array(
                    'success' => false,
                    'error' => 'Failed to store alert'
                );
            }
            
            $alert['id'] = $alert_id;
            
            // Add to processing queue
            $this->add_to_queue($alert);
            
            // Handle immediate alerts
            if ($this->requires_immediate_processing($alert)) {
                $this->process_immediate_alert($alert);
            }
            
            // Update rate limiting
            $this->update_rate_limits($alert_data);
            
            // Log alert creation
            $this->log_alert_activity($alert_id, 'created', $alert);
            
            return array(
                'success' => true,
                'alert_id' => $alert_id,
                'alert' => $alert
            );

        } catch (Exception $e) {
            error_log("WP-Breach Alert Creation Error: " . $e->getMessage());
            return array(
                'success' => false,
                'error' => $e->getMessage()
            );
        }
    }

    /**
     * Validate alert data.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $alert_data    Alert data.
     * @return   array                   Validation result.
     */
    private function validate_alert_data($alert_data) {
        // Required fields
        $required_fields = array('type', 'severity', 'title', 'message');
        
        foreach ($required_fields as $field) {
            if (empty($alert_data[$field])) {
                return array(
                    'valid' => false,
                    'error' => "Missing required field: {$field}"
                );
            }
        }
        
        // Validate alert type
        if (!in_array($alert_data['type'], $this->config['alert_types'])) {
            return array(
                'valid' => false,
                'error' => 'Invalid alert type'
            );
        }
        
        // Validate severity
        if (!in_array($alert_data['severity'], $this->config['priority_levels'])) {
            return array(
                'valid' => false,
                'error' => 'Invalid severity level'
            );
        }
        
        return array('valid' => true);
    }

    /**
     * Check for duplicate alerts.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $alert_data    Alert data.
     * @return   array                   Duplicate check result.
     */
    private function check_duplicate_alert($alert_data) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_alerts';
        $duplicate_window = $this->config['duplicate_window'];
        
        // Create alert signature for duplicate detection
        $signature_data = array(
            'type' => $alert_data['type'],
            'source' => $alert_data['source'] ?? '',
            'details_hash' => md5(json_encode($alert_data['details'] ?? array()))
        );
        $alert_signature = md5(json_encode($signature_data));
        
        $existing_alert = $wpdb->get_row($wpdb->prepare(
            "SELECT id FROM {$table_name} 
             WHERE alert_signature = %s 
             AND status IN ('new', 'acknowledged')
             AND created_at > %s
             ORDER BY created_at DESC LIMIT 1",
            $alert_signature,
            date('Y-m-d H:i:s', time() - $duplicate_window)
        ));
        
        if ($existing_alert) {
            // Update duplicate count
            $wpdb->query($wpdb->prepare(
                "UPDATE {$table_name} 
                 SET duplicate_count = duplicate_count + 1,
                     last_occurrence = %s
                 WHERE id = %d",
                current_time('mysql'),
                $existing_alert->id
            ));
            
            return array(
                'is_duplicate' => true,
                'alert_id' => $existing_alert->id
            );
        }
        
        return array('is_duplicate' => false);
    }

    /**
     * Check rate limits.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $alert_data    Alert data.
     * @return   array                   Rate limit check result.
     */
    private function check_rate_limits($alert_data) {
        $current_hour = date('Y-m-d H');
        $current_day = date('Y-m-d');
        
        // Check hourly limit
        $hourly_key = "alerts_hour_{$current_hour}";
        $hourly_count = $this->rate_limiter[$hourly_key] ?? 0;
        
        if ($hourly_count >= $this->config['max_alerts_per_hour']) {
            return array(
                'allowed' => false,
                'reason' => 'hourly_limit_exceeded',
                'retry_after' => 3600 - (time() % 3600)
            );
        }
        
        // Check daily limit
        $daily_key = "alerts_day_{$current_day}";
        $daily_count = $this->rate_limiter[$daily_key] ?? 0;
        
        if ($daily_count >= $this->config['max_alerts_per_day']) {
            return array(
                'allowed' => false,
                'reason' => 'daily_limit_exceeded',
                'retry_after' => 86400 - (time() % 86400)
            );
        }
        
        return array('allowed' => true);
    }

    /**
     * Prepare alert for storage and processing.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $alert_data    Raw alert data.
     * @return   array                   Prepared alert.
     */
    private function prepare_alert($alert_data) {
        // Generate alert signature for duplicate detection
        $signature_data = array(
            'type' => $alert_data['type'],
            'source' => $alert_data['source'] ?? '',
            'details_hash' => md5(json_encode($alert_data['details'] ?? array()))
        );
        
        $alert = array(
            'type' => $alert_data['type'],
            'severity' => $alert_data['severity'],
            'priority' => $this->config['severity_mapping'][$alert_data['severity']],
            'title' => $alert_data['title'],
            'message' => $alert_data['message'],
            'details' => $alert_data['details'] ?? array(),
            'source' => $alert_data['source'] ?? 'unknown',
            'status' => 'new',
            'created_at' => current_time('mysql'),
            'alert_signature' => md5(json_encode($signature_data)),
            'duplicate_count' => 1,
            'last_occurrence' => current_time('mysql'),
            'escalation_level' => 0,
            'acknowledged_at' => null,
            'acknowledged_by' => null,
            'resolved_at' => null,
            'resolved_by' => null,
            'metadata' => array(
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                'ip_address' => $this->get_client_ip(),
                'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
                'created_timestamp' => time()
            )
        );
        
        return $alert;
    }

    /**
     * Store alert in database.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $alert    Prepared alert data.
     * @return   int|false          Alert ID or false on failure.
     */
    private function store_alert($alert) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_alerts';
        
        $result = $wpdb->insert(
            $table_name,
            array(
                'type' => $alert['type'],
                'severity' => $alert['severity'],
                'priority' => $alert['priority'],
                'title' => $alert['title'],
                'message' => $alert['message'],
                'details' => json_encode($alert['details']),
                'source' => $alert['source'],
                'status' => $alert['status'],
                'alert_signature' => $alert['alert_signature'],
                'duplicate_count' => $alert['duplicate_count'],
                'escalation_level' => $alert['escalation_level'],
                'metadata' => json_encode($alert['metadata']),
                'created_at' => $alert['created_at'],
                'last_occurrence' => $alert['last_occurrence']
            ),
            array(
                '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%d', '%s', '%s', '%s'
            )
        );
        
        return $result ? $wpdb->insert_id : false;
    }

    /**
     * Add alert to processing queue.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $alert    Alert data.
     */
    private function add_to_queue($alert) {
        $this->alert_queue[] = $alert;
        
        // Persist queue for reliability
        update_option('wp_breach_alert_queue', $this->alert_queue);
    }

    /**
     * Check if alert requires immediate processing.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $alert    Alert data.
     * @return   bool              Whether immediate processing is required.
     */
    private function requires_immediate_processing($alert) {
        $escalation_rules = $this->escalation_rules[$alert['severity']] ?? array();
        
        return $escalation_rules['immediate_notify'] ?? false;
    }

    /**
     * Process alert immediately.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $alert    Alert data.
     */
    private function process_immediate_alert($alert) {
        $escalation_rules = $this->escalation_rules[$alert['severity']] ?? array();
        $channels = $escalation_rules['escalation_channels'] ?? array('email', 'dashboard');
        
        foreach ($channels as $channel_name) {
            if ($this->is_channel_available($channel_name)) {
                $this->send_alert_to_channel($alert, $channel_name, 'immediate');
            }
        }
        
        // Auto-response for critical alerts
        if ($alert['severity'] === 'critical' && ($escalation_rules['auto_response'] ?? false)) {
            $this->trigger_auto_response($alert);
        }
    }

    /**
     * Process alert queue.
     *
     * @since    1.0.0
     */
    public function process_alert_queue() {
        if (!$this->config['enabled'] || empty($this->alert_queue)) {
            return;
        }
        
        $batch_size = $this->config['batch_size'];
        $processed = 0;
        
        while (!empty($this->alert_queue) && $processed < $batch_size) {
            $alert = array_shift($this->alert_queue);
            
            try {
                $this->process_single_alert($alert);
                $processed++;
                
            } catch (Exception $e) {
                error_log("WP-Breach Alert Processing Error: " . $e->getMessage());
                
                // Re-queue failed alert with retry limit
                $alert['retry_count'] = ($alert['retry_count'] ?? 0) + 1;
                if ($alert['retry_count'] < 3) {
                    $this->alert_queue[] = $alert;
                }
            }
        }
        
        // Update persistent queue
        update_option('wp_breach_alert_queue', $this->alert_queue);
    }

    /**
     * Process single alert.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $alert    Alert data.
     */
    private function process_single_alert($alert) {
        // Skip if already processed immediately
        if ($this->requires_immediate_processing($alert)) {
            return;
        }
        
        // Determine delivery channels based on severity
        $channels = $this->get_alert_channels($alert);
        
        foreach ($channels as $channel_name) {
            if ($this->is_channel_available($channel_name)) {
                $this->send_alert_to_channel($alert, $channel_name, 'batch');
            }
        }
        
        // Update alert status
        $this->update_alert_status($alert['id'], 'processed');
        
        // Schedule escalation if needed
        $this->schedule_escalation($alert);
    }

    /**
     * Get appropriate channels for alert.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $alert    Alert data.
     * @return   array             Channel names.
     */
    private function get_alert_channels($alert) {
        $escalation_rules = $this->escalation_rules[$alert['severity']] ?? array();
        $default_channels = array('email', 'dashboard');
        
        return $escalation_rules['escalation_channels'] ?? $default_channels;
    }

    /**
     * Check if channel is available.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $channel_name    Channel name.
     * @return   bool                      Whether channel is available.
     */
    private function is_channel_available($channel_name) {
        $channel = $this->channels[$channel_name] ?? null;
        
        if (!$channel || !$channel['enabled']) {
            return false;
        }
        
        // Check rate limits for channel
        $current_hour = date('Y-m-d H');
        $rate_key = "channel_{$channel_name}_{$current_hour}";
        $current_rate = $this->rate_limiter[$rate_key] ?? 0;
        
        return $current_rate < $channel['rate_limit'];
    }

    /**
     * Send alert to specific channel.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $alert           Alert data.
     * @param    string   $channel_name    Channel name.
     * @param    string   $delivery_mode   Delivery mode.
     */
    private function send_alert_to_channel($alert, $channel_name, $delivery_mode) {
        $channel = $this->channels[$channel_name] ?? null;
        
        if (!$channel || !class_exists($channel['class'])) {
            return;
        }
        
        try {
            $channel_instance = new $channel['class']();
            
            if (in_array($delivery_mode, $channel['supports'])) {
                $result = $channel_instance->send_alert($alert, $delivery_mode);
                
                if ($result['success']) {
                    // Update channel rate limits
                    $current_hour = date('Y-m-d H');
                    $rate_key = "channel_{$channel_name}_{$current_hour}";
                    $this->rate_limiter[$rate_key] = ($this->rate_limiter[$rate_key] ?? 0) + 1;
                    
                    // Log successful delivery
                    $this->log_alert_activity($alert['id'], 'delivered', array(
                        'channel' => $channel_name,
                        'delivery_mode' => $delivery_mode
                    ));
                }
            }

        } catch (Exception $e) {
            error_log("WP-Breach Alert Channel Error ({$channel_name}): " . $e->getMessage());
        }
    }

    /**
     * Trigger automated response for critical alerts.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $alert    Alert data.
     */
    private function trigger_auto_response($alert) {
        // Implement automated response based on alert type
        switch ($alert['type']) {
            case 'malware_detected':
                $this->auto_response_malware($alert);
                break;
                
            case 'brute_force_attack':
                $this->auto_response_brute_force($alert);
                break;
                
            case 'file_integrity_violation':
                $this->auto_response_file_integrity($alert);
                break;
                
            case 'system_compromise':
                $this->auto_response_system_compromise($alert);
                break;
        }
    }

    /**
     * Process alert escalations.
     *
     * @since    1.0.0
     */
    public function process_escalations() {
        if (!$this->config['escalation_enabled']) {
            return;
        }
        
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_alerts';
        
        // Get unresolved alerts that need escalation
        $alerts = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$table_name} 
             WHERE status IN ('new', 'acknowledged', 'escalated')
             AND severity IN ('medium', 'high', 'critical')
             AND created_at < %s
             ORDER BY priority DESC, created_at ASC",
            date('Y-m-d H:i:s', time() - 300) // 5 minutes ago
        ));
        
        foreach ($alerts as $alert) {
            $this->check_and_escalate_alert($alert);
        }
    }

    /**
     * Check and escalate alert if needed.
     *
     * @since    1.0.0
     * @access   private
     * @param    object   $alert    Alert record.
     */
    private function check_and_escalate_alert($alert) {
        $escalation_rules = $this->escalation_rules[$alert->severity] ?? array();
        $escalation_delay = $escalation_rules['escalation_delay'] ?? 900;
        $max_escalations = $escalation_rules['max_escalations'] ?? 1;
        
        // Check if enough time has passed since last escalation
        $last_escalation = strtotime($alert->last_escalation ?? $alert->created_at);
        $time_since_escalation = time() - $last_escalation;
        
        if ($time_since_escalation >= $escalation_delay && $alert->escalation_level < $max_escalations) {
            $this->escalate_alert($alert);
        }
    }

    /**
     * Escalate alert to next level.
     *
     * @since    1.0.0
     * @access   private
     * @param    object   $alert    Alert record.
     */
    private function escalate_alert($alert) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_alerts';
        
        // Update escalation level
        $new_escalation_level = $alert->escalation_level + 1;
        
        $wpdb->update(
            $table_name,
            array(
                'escalation_level' => $new_escalation_level,
                'status' => 'escalated',
                'last_escalation' => current_time('mysql')
            ),
            array('id' => $alert->id),
            array('%d', '%s', '%s'),
            array('%d')
        );
        
        // Send escalation notifications
        $escalation_rules = $this->escalation_rules[$alert->severity] ?? array();
        $channels = $escalation_rules['escalation_channels'] ?? array('email');
        
        foreach ($channels as $channel_name) {
            if ($this->is_channel_available($channel_name)) {
                $escalated_alert = (array) $alert;
                $escalated_alert['escalation_level'] = $new_escalation_level;
                $escalated_alert['escalated'] = true;
                
                $this->send_alert_to_channel($escalated_alert, $channel_name, 'immediate');
            }
        }
        
        // Log escalation
        $this->log_alert_activity($alert->id, 'escalated', array(
            'escalation_level' => $new_escalation_level
        ));
    }

    /**
     * Update alert status.
     *
     * @since    1.0.0
     * @param    int      $alert_id    Alert ID.
     * @param    string   $status      New status.
     * @param    array    $metadata    Additional metadata.
     */
    public function update_alert_status($alert_id, $status, $metadata = array()) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_alerts';
        
        $update_data = array('status' => $status);
        $update_format = array('%s');
        
        // Add status-specific fields
        switch ($status) {
            case 'acknowledged':
                $update_data['acknowledged_at'] = current_time('mysql');
                $update_data['acknowledged_by'] = get_current_user_id();
                $update_format[] = '%s';
                $update_format[] = '%d';
                break;
                
            case 'resolved':
                $update_data['resolved_at'] = current_time('mysql');
                $update_data['resolved_by'] = get_current_user_id();
                $update_format[] = '%s';
                $update_format[] = '%d';
                break;
        }
        
        $wpdb->update(
            $table_name,
            $update_data,
            array('id' => $alert_id),
            $update_format,
            array('%d')
        );
        
        // Log status change
        $this->log_alert_activity($alert_id, 'status_changed', array_merge(
            array('new_status' => $status),
            $metadata
        ));
    }

    /**
     * Handle alert acknowledgment.
     *
     * @since    1.0.0
     * @param    int      $alert_id    Alert ID.
     * @param    int      $user_id     User ID.
     */
    public function handle_alert_acknowledgment($alert_id, $user_id = null) {
        $user_id = $user_id ?? get_current_user_id();
        
        $this->update_alert_status($alert_id, 'acknowledged', array(
            'acknowledged_by' => $user_id,
            'acknowledged_at' => current_time('mysql')
        ));
        
        // Trigger acknowledgment actions
        do_action('wp_breach_alert_acknowledged', $alert_id, $user_id);
    }

    /**
     * Handle alert resolution.
     *
     * @since    1.0.0
     * @param    int      $alert_id      Alert ID.
     * @param    string   $resolution    Resolution details.
     * @param    int      $user_id       User ID.
     */
    public function handle_alert_resolution($alert_id, $resolution = '', $user_id = null) {
        $user_id = $user_id ?? get_current_user_id();
        
        $this->update_alert_status($alert_id, 'resolved', array(
            'resolved_by' => $user_id,
            'resolved_at' => current_time('mysql'),
            'resolution' => $resolution
        ));
        
        // Trigger resolution actions
        do_action('wp_breach_alert_resolved', $alert_id, $user_id, $resolution);
    }

    /**
     * Get alerts with filters.
     *
     * @since    1.0.0
     * @param    array    $filters    Filter criteria.
     * @return   array               Filtered alerts.
     */
    public function get_alerts($filters = array()) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_alerts';
        
        $where_conditions = array('1=1');
        $where_values = array();
        
        // Status filter
        if (!empty($filters['status'])) {
            $where_conditions[] = 'status = %s';
            $where_values[] = $filters['status'];
        }
        
        // Severity filter
        if (!empty($filters['severity'])) {
            $where_conditions[] = 'severity = %s';
            $where_values[] = $filters['severity'];
        }
        
        // Type filter
        if (!empty($filters['type'])) {
            $where_conditions[] = 'type = %s';
            $where_values[] = $filters['type'];
        }
        
        // Date range filter
        if (!empty($filters['date_from'])) {
            $where_conditions[] = 'created_at >= %s';
            $where_values[] = $filters['date_from'];
        }
        
        if (!empty($filters['date_to'])) {
            $where_conditions[] = 'created_at <= %s';
            $where_values[] = $filters['date_to'];
        }
        
        // Build query
        $where_clause = implode(' AND ', $where_conditions);
        $order_by = $filters['order_by'] ?? 'created_at DESC';
        $limit = $filters['limit'] ?? 50;
        $offset = $filters['offset'] ?? 0;
        
        $query = "SELECT * FROM {$table_name} WHERE {$where_clause} ORDER BY {$order_by} LIMIT %d OFFSET %d";
        $where_values[] = $limit;
        $where_values[] = $offset;
        
        if (!empty($where_values)) {
            $query = $wpdb->prepare($query, $where_values);
        }
        
        return $wpdb->get_results($query);
    }

    /**
     * Get alert statistics.
     *
     * @since    1.0.0
     * @param    string   $period    Period (day, week, month).
     * @return   array              Alert statistics.
     */
    public function get_alert_statistics($period = 'week') {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_alerts';
        
        // Calculate date range
        $date_intervals = array(
            'day' => '-1 day',
            'week' => '-1 week',
            'month' => '-1 month'
        );
        
        $date_from = date('Y-m-d H:i:s', strtotime($date_intervals[$period] ?? '-1 week'));
        
        // Get overall statistics
        $stats = array(
            'total_alerts' => 0,
            'by_severity' => array(),
            'by_type' => array(),
            'by_status' => array(),
            'escalated_alerts' => 0,
            'average_resolution_time' => 0,
            'alerts_per_day' => array()
        );
        
        // Total alerts
        $stats['total_alerts'] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table_name} WHERE created_at >= %s",
            $date_from
        ));
        
        // By severity
        $severity_stats = $wpdb->get_results($wpdb->prepare(
            "SELECT severity, COUNT(*) as count FROM {$table_name} 
             WHERE created_at >= %s GROUP BY severity",
            $date_from
        ));
        
        foreach ($severity_stats as $stat) {
            $stats['by_severity'][$stat->severity] = $stat->count;
        }
        
        // By type
        $type_stats = $wpdb->get_results($wpdb->prepare(
            "SELECT type, COUNT(*) as count FROM {$table_name} 
             WHERE created_at >= %s GROUP BY type",
            $date_from
        ));
        
        foreach ($type_stats as $stat) {
            $stats['by_type'][$stat->type] = $stat->count;
        }
        
        // By status
        $status_stats = $wpdb->get_results($wpdb->prepare(
            "SELECT status, COUNT(*) as count FROM {$table_name} 
             WHERE created_at >= %s GROUP BY status",
            $date_from
        ));
        
        foreach ($status_stats as $stat) {
            $stats['by_status'][$stat->status] = $stat->count;
        }
        
        // Escalated alerts
        $stats['escalated_alerts'] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table_name} 
             WHERE created_at >= %s AND escalation_level > 0",
            $date_from
        ));
        
        return $stats;
    }

    // Helper methods...
    
    private function update_rate_limits($alert_data) {
        $current_hour = date('Y-m-d H');
        $current_day = date('Y-m-d');
        
        $hourly_key = "alerts_hour_{$current_hour}";
        $daily_key = "alerts_day_{$current_day}";
        
        $this->rate_limiter[$hourly_key] = ($this->rate_limiter[$hourly_key] ?? 0) + 1;
        $this->rate_limiter[$daily_key] = ($this->rate_limiter[$daily_key] ?? 0) + 1;
    }
    
    private function schedule_escalation($alert) {
        $escalation_rules = $this->escalation_rules[$alert['severity']] ?? array();
        $escalation_delay = $escalation_rules['escalation_delay'] ?? 900;
        
        if ($escalation_delay > 0) {
            wp_schedule_single_event(
                time() + $escalation_delay,
                'wp_breach_check_escalation',
                array($alert['id'])
            );
        }
    }
    
    private function log_alert_activity($alert_id, $action, $data = array()) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_alert_log';
        
        $wpdb->insert(
            $table_name,
            array(
                'alert_id' => $alert_id,
                'action' => $action,
                'data' => json_encode($data),
                'user_id' => get_current_user_id(),
                'created_at' => current_time('mysql')
            ),
            array('%d', '%s', '%s', '%d', '%s')
        );
    }
    
    private function get_client_ip() {
        $ip_keys = array('HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR');
        
        foreach ($ip_keys as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = trim($_SERVER[$key]);
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }

    public function reset_rate_limits() {
        // Clean up old rate limit data
        $current_time = time();
        $cutoff_time = $current_time - 86400; // 24 hours ago
        
        foreach ($this->rate_limiter as $key => $value) {
            if (strpos($key, 'hour_') !== false) {
                $hour_timestamp = strtotime(str_replace('alerts_hour_', '', $key));
                if ($hour_timestamp < $cutoff_time) {
                    unset($this->rate_limiter[$key]);
                }
            }
        }
    }

    public function cleanup_old_alerts() {
        if (!$this->config['auto_resolution']) {
            return;
        }
        
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_alerts';
        $retention_cutoff = date('Y-m-d H:i:s', time() - $this->config['retention_period']);
        
        // Archive old resolved alerts
        $wpdb->query($wpdb->prepare(
            "UPDATE {$table_name} SET status = 'archived' 
             WHERE status = 'resolved' AND resolved_at < %s",
            $retention_cutoff
        ));
        
        // Auto-resolve very old low-priority alerts
        $auto_resolve_cutoff = date('Y-m-d H:i:s', time() - (7 * DAY_IN_SECONDS));
        $wpdb->query($wpdb->prepare(
            "UPDATE {$table_name} SET status = 'auto_resolved', resolved_at = %s 
             WHERE status IN ('new', 'acknowledged') AND severity = 'low' AND created_at < %s",
            current_time('mysql'),
            $auto_resolve_cutoff
        ));
    }

    // Auto-response methods
    private function auto_response_malware($alert) {
        // Quarantine malicious files
        if (!empty($alert['details']['file_path'])) {
            do_action('wp_breach_auto_quarantine', $alert['details']['file_path']);
        }
    }

    private function auto_response_brute_force($alert) {
        // Block IP addresses
        if (!empty($alert['details']['ip_address'])) {
            do_action('wp_breach_auto_block_ip', $alert['details']['ip_address']);
        }
    }

    private function auto_response_file_integrity($alert) {
        // Create backup of affected files
        if (!empty($alert['details']['file_path'])) {
            do_action('wp_breach_auto_backup', $alert['details']['file_path']);
        }
    }

    private function auto_response_system_compromise($alert) {
        // Enable emergency mode
        do_action('wp_breach_emergency_mode', $alert);
    }

    public function handle_emergency_alert($alert_data) {
        // Force immediate processing for emergency alerts
        $alert_data['severity'] = 'critical';
        $result = $this->create_alert($alert_data);
        
        if ($result['success']) {
            // Override rate limits for emergency
            $this->process_immediate_alert($result['alert']);
            
            // Notify all available channels
            foreach ($this->channels as $channel_name => $channel) {
                if ($channel['enabled']) {
                    $this->send_alert_to_channel($result['alert'], $channel_name, 'immediate');
                }
            }
        }
        
        return $result;
    }
}
