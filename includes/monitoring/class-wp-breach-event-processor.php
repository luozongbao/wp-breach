<?php

/**
 * Event Processor for WP-Breach.
 *
 * This class coordinates the real-time monitoring system by processing events,
 * managing monitoring workflows, and orchestrating responses between components.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/monitoring
 */

/**
 * The event processing class.
 *
 * Serves as the central coordinator for all monitoring activities,
 * processing events from various sources and triggering appropriate responses.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/monitoring
 * @author     WP Breach Team
 */
class WP_Breach_Event_Processor {

    /**
     * Event processor configuration.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $config    Event processor configuration.
     */
    private $config;

    /**
     * Event queue.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $event_queue    Pending events queue.
     */
    private $event_queue;

    /**
     * Monitoring components.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $monitors    Active monitoring components.
     */
    private $monitors;

    /**
     * Event processors map.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $processors    Event type to processor mapping.
     */
    private $processors;

    /**
     * Alert manager instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Breach_Alert_Manager    $alert_manager    Alert manager.
     */
    private $alert_manager;

    /**
     * Risk assessment engine.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $risk_engine    Risk assessment data.
     */
    private $risk_engine;

    /**
     * Performance metrics.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $metrics    Performance tracking metrics.
     */
    private $metrics;

    /**
     * Initialize the event processor.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->setup_config();
        $this->initialize_components();
        $this->setup_event_processors();
        $this->setup_risk_engine();
        $this->event_queue = array();
        $this->metrics = array();
        
        // Register hooks
        $this->register_hooks();
        
        // Schedule event processing
        $this->schedule_event_processing();
        
        // Initialize real-time monitoring
        $this->initialize_real_time_monitoring();
    }

    /**
     * Setup event processor configuration.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_config() {
        $this->config = array(
            'enabled' => true,
            'real_time_processing' => true,
            'batch_processing' => true,
            'batch_size' => 50,
            'processing_interval' => 30, // seconds
            'max_queue_size' => 1000,
            'event_retention' => 7 * DAY_IN_SECONDS,
            'performance_monitoring' => true,
            'correlation_enabled' => true,
            'correlation_window' => 300, // 5 minutes
            'threat_scoring' => true,
            'auto_response' => true,
            'priority_queue' => true,
            'parallel_processing' => false,
            'max_processing_time' => 30, // seconds
            'memory_limit' => '128M',
            'event_types' => array(
                'file_change',
                'file_creation',
                'file_deletion',
                'login_attempt',
                'login_success',
                'login_failure',
                'admin_action',
                'malware_detected',
                'suspicious_activity',
                'vulnerability_detected',
                'configuration_change',
                'user_registration',
                'plugin_activation',
                'theme_change',
                'database_query',
                'network_request',
                'error_occurrence'
            )
        );
    }

    /**
     * Initialize monitoring components.
     *
     * @since    1.0.0
     * @access   private
     */
    private function initialize_components() {
        $this->monitors = array(
            'file_monitor' => new WP_Breach_File_Monitor(),
            'activity_monitor' => new WP_Breach_Activity_Monitor(),
            'malware_scanner' => new WP_Breach_Malware_Scanner()
        );
        
        $this->alert_manager = new WP_Breach_Alert_Manager();
    }

    /**
     * Setup event processors for different event types.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_event_processors() {
        $this->processors = array(
            'file_change' => array($this, 'process_file_change_event'),
            'file_creation' => array($this, 'process_file_creation_event'),
            'file_deletion' => array($this, 'process_file_deletion_event'),
            'login_attempt' => array($this, 'process_login_attempt_event'),
            'login_success' => array($this, 'process_login_success_event'),
            'login_failure' => array($this, 'process_login_failure_event'),
            'admin_action' => array($this, 'process_admin_action_event'),
            'malware_detected' => array($this, 'process_malware_detection_event'),
            'suspicious_activity' => array($this, 'process_suspicious_activity_event'),
            'vulnerability_detected' => array($this, 'process_vulnerability_event'),
            'configuration_change' => array($this, 'process_configuration_change_event'),
            'user_registration' => array($this, 'process_user_registration_event'),
            'plugin_activation' => array($this, 'process_plugin_activation_event'),
            'theme_change' => array($this, 'process_theme_change_event'),
            'database_query' => array($this, 'process_database_query_event'),
            'network_request' => array($this, 'process_network_request_event'),
            'error_occurrence' => array($this, 'process_error_event')
        );
    }

    /**
     * Setup risk assessment engine.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_risk_engine() {
        $this->risk_engine = array(
            'baseline_risk' => 0,
            'current_risk' => 0,
            'threat_indicators' => array(),
            'risk_factors' => array(
                'file_integrity' => 0,
                'user_behavior' => 0,
                'malware_presence' => 0,
                'vulnerability_exposure' => 0,
                'configuration_security' => 0,
                'network_activity' => 0
            ),
            'correlation_rules' => array(
                'multiple_login_failures' => array(
                    'events' => array('login_failure'),
                    'threshold' => 5,
                    'window' => 300,
                    'risk_score' => 30
                ),
                'mass_file_changes' => array(
                    'events' => array('file_change', 'file_creation'),
                    'threshold' => 10,
                    'window' => 60,
                    'risk_score' => 40
                ),
                'suspicious_admin_activity' => array(
                    'events' => array('admin_action', 'plugin_activation'),
                    'threshold' => 3,
                    'window' => 180,
                    'risk_score' => 25
                ),
                'coordinated_attack' => array(
                    'events' => array('login_failure', 'malware_detected', 'file_change'),
                    'threshold' => 3,
                    'window' => 600,
                    'risk_score' => 60
                )
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
        // Event processing
        add_action('wp_breach_process_events', array($this, 'process_event_queue'));
        add_action('wp_breach_process_event', array($this, 'process_single_event'), 10, 2);
        
        // Real-time event hooks
        add_action('wp_breach_file_changed', array($this, 'handle_file_change'), 10, 2);
        add_action('wp_breach_file_created', array($this, 'handle_file_creation'), 10, 2);
        add_action('wp_breach_file_deleted', array($this, 'handle_file_deletion'), 10, 2);
        add_action('wp_breach_login_attempt', array($this, 'handle_login_attempt'), 10, 2);
        add_action('wp_breach_malware_detected', array($this, 'handle_malware_detection'), 10, 2);
        add_action('wp_breach_suspicious_activity', array($this, 'handle_suspicious_activity'), 10, 2);
        
        // WordPress core hooks
        add_action('wp_login', array($this, 'handle_wp_login'), 10, 2);
        add_action('wp_login_failed', array($this, 'handle_wp_login_failed'));
        add_action('user_register', array($this, 'handle_user_register'));
        add_action('activated_plugin', array($this, 'handle_plugin_activation'));
        add_action('switch_theme', array($this, 'handle_theme_change'));
        
        // Admin hooks
        add_action('admin_init', array($this, 'monitor_admin_actions'));
        add_action('wp_ajax_*', array($this, 'monitor_ajax_requests'));
        
        // Database monitoring
        add_filter('query', array($this, 'monitor_database_queries'));
        
        // Error monitoring
        add_action('wp_error_added', array($this, 'handle_wp_error'));
        
        // Cleanup
        add_action('wp_breach_cleanup_events', array($this, 'cleanup_old_events'));
        
        // Performance monitoring
        add_action('shutdown', array($this, 'record_performance_metrics'));
    }

    /**
     * Schedule event processing tasks.
     *
     * @since    1.0.0
     * @access   private
     */
    private function schedule_event_processing() {
        // Regular event processing
        if (!wp_next_scheduled('wp_breach_process_events')) {
            wp_schedule_event(time(), 'wp_breach_thirty_seconds', 'wp_breach_process_events');
        }
        
        // Daily cleanup
        if (!wp_next_scheduled('wp_breach_cleanup_events')) {
            wp_schedule_event(time(), 'daily', 'wp_breach_cleanup_events');
        }
    }

    /**
     * Initialize real-time monitoring.
     *
     * @since    1.0.0
     * @access   private
     */
    private function initialize_real_time_monitoring() {
        if (!$this->config['real_time_processing']) {
            return;
        }
        
        // Start monitoring components
        foreach ($this->monitors as $monitor) {
            if (method_exists($monitor, 'start_real_time_monitoring')) {
                $monitor->start_real_time_monitoring();
            }
        }
        
        // Initialize performance tracking
        $this->metrics['start_time'] = microtime(true);
        $this->metrics['memory_start'] = memory_get_usage();
    }

    /**
     * Queue event for processing.
     *
     * @since    1.0.0
     * @param    string   $event_type    Event type.
     * @param    array    $event_data    Event data.
     * @param    string   $priority      Event priority (low, medium, high, critical).
     * @return   bool                    Success status.
     */
    public function queue_event($event_type, $event_data, $priority = 'medium') {
        try {
            // Validate event type
            if (!in_array($event_type, $this->config['event_types'])) {
                return false;
            }
            
            // Check queue size limits
            if (count($this->event_queue) >= $this->config['max_queue_size']) {
                // Remove oldest low-priority events
                $this->cleanup_queue();
            }
            
            // Prepare event
            $event = array(
                'id' => $this->generate_event_id(),
                'type' => $event_type,
                'data' => $event_data,
                'priority' => $priority,
                'timestamp' => time(),
                'created_at' => current_time('mysql'),
                'processed' => false,
                'attempts' => 0,
                'correlation_id' => $this->generate_correlation_id($event_type, $event_data)
            );
            
            // Add to queue with priority
            if ($this->config['priority_queue']) {
                $this->add_to_priority_queue($event);
            } else {
                $this->event_queue[] = $event;
            }
            
            // Process immediately for critical events
            if ($priority === 'critical' && $this->config['real_time_processing']) {
                $this->process_single_event($event, true);
            }
            
            // Persist queue
            $this->persist_event_queue();
            
            return true;

        } catch (Exception $e) {
            error_log("WP-Breach Event Queue Error: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Process event queue.
     *
     * @since    1.0.0
     */
    public function process_event_queue() {
        if (!$this->config['enabled'] || empty($this->event_queue)) {
            return;
        }
        
        $start_time = microtime(true);
        $processed = 0;
        $batch_size = $this->config['batch_size'];
        
        // Load persistent queue
        $this->load_event_queue();
        
        while (!empty($this->event_queue) && $processed < $batch_size) {
            $event = array_shift($this->event_queue);
            
            try {
                $this->process_single_event($event);
                $processed++;
                
            } catch (Exception $e) {
                error_log("WP-Breach Event Processing Error: " . $e->getMessage());
                
                // Re-queue failed event with retry limit
                $event['attempts'] = ($event['attempts'] ?? 0) + 1;
                if ($event['attempts'] < 3) {
                    $this->event_queue[] = $event;
                }
            }
            
            // Check processing time limit
            if ((microtime(true) - $start_time) > $this->config['max_processing_time']) {
                break;
            }
        }
        
        // Update persistent queue
        $this->persist_event_queue();
        
        // Update metrics
        $this->metrics['events_processed'] = ($this->metrics['events_processed'] ?? 0) + $processed;
        $this->metrics['last_processing_time'] = microtime(true) - $start_time;
    }

    /**
     * Process single event.
     *
     * @since    1.0.0
     * @param    array    $event       Event data.
     * @param    bool     $immediate   Immediate processing flag.
     * @return   array                Processing result.
     */
    public function process_single_event($event, $immediate = false) {
        $processing_start = microtime(true);
        
        try {
            // Validate event
            if (!isset($this->processors[$event['type']])) {
                return array(
                    'success' => false,
                    'error' => 'No processor for event type: ' . $event['type']
                );
            }
            
            // Pre-processing correlation
            if ($this->config['correlation_enabled']) {
                $correlation_result = $this->correlate_event($event);
                $event['correlation_result'] = $correlation_result;
            }
            
            // Risk assessment
            if ($this->config['threat_scoring']) {
                $risk_score = $this->assess_event_risk($event);
                $event['risk_score'] = $risk_score;
            }
            
            // Process event
            $processor = $this->processors[$event['type']];
            $result = call_user_func($processor, $event, $immediate);
            
            // Post-processing
            $this->handle_post_processing($event, $result);
            
            // Store event in database
            $this->store_event($event, $result);
            
            // Update risk engine
            $this->update_risk_engine($event, $result);
            
            // Performance tracking
            $processing_time = microtime(true) - $processing_start;
            $this->metrics['average_processing_time'] = $this->calculate_average_processing_time($processing_time);
            
            return array(
                'success' => true,
                'event_id' => $event['id'],
                'processing_time' => $processing_time,
                'result' => $result
            );

        } catch (Exception $e) {
            error_log("WP-Breach Event Processing Error for {$event['type']}: " . $e->getMessage());
            
            return array(
                'success' => false,
                'error' => $e->getMessage(),
                'event_id' => $event['id']
            );
        }
    }

    /**
     * Correlate event with existing events.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $event    Event data.
     * @return   array             Correlation result.
     */
    private function correlate_event($event) {
        $correlation_window = $this->config['correlation_window'];
        $current_time = time();
        $correlation_result = array(
            'correlated_events' => array(),
            'patterns_detected' => array(),
            'risk_amplification' => 0
        );
        
        // Check correlation rules
        foreach ($this->risk_engine['correlation_rules'] as $rule_name => $rule) {
            if (in_array($event['type'], $rule['events'])) {
                $related_events = $this->get_related_events(
                    $rule['events'],
                    $current_time - $rule['window'],
                    $current_time
                );
                
                if (count($related_events) >= ($rule['threshold'] - 1)) { // -1 because current event counts
                    $correlation_result['patterns_detected'][] = $rule_name;
                    $correlation_result['risk_amplification'] += $rule['risk_score'];
                    $correlation_result['correlated_events'] = array_merge(
                        $correlation_result['correlated_events'],
                        $related_events
                    );
                }
            }
        }
        
        return $correlation_result;
    }

    /**
     * Assess event risk score.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $event    Event data.
     * @return   int               Risk score.
     */
    private function assess_event_risk($event) {
        $base_risk_scores = array(
            'malware_detected' => 80,
            'file_change' => 20,
            'file_creation' => 15,
            'file_deletion' => 25,
            'login_failure' => 10,
            'login_success' => 5,
            'admin_action' => 15,
            'suspicious_activity' => 40,
            'vulnerability_detected' => 60,
            'configuration_change' => 30
        );
        
        $base_score = $base_risk_scores[$event['type']] ?? 10;
        
        // Apply correlation amplification
        if (!empty($event['correlation_result']['risk_amplification'])) {
            $base_score += $event['correlation_result']['risk_amplification'];
        }
        
        // Apply context-specific factors
        $context_multiplier = $this->calculate_context_multiplier($event);
        $final_score = min(100, $base_score * $context_multiplier);
        
        return round($final_score);
    }

    /**
     * Calculate context multiplier for risk assessment.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $event    Event data.
     * @return   float             Context multiplier.
     */
    private function calculate_context_multiplier($event) {
        $multiplier = 1.0;
        
        // Time-based factors
        $hour = date('H');
        if ($hour < 6 || $hour > 22) {
            $multiplier += 0.3; // After hours activity
        }
        
        // User context
        if (!empty($event['data']['user_id'])) {
            $user = get_user_by('ID', $event['data']['user_id']);
            if ($user && !in_array('administrator', $user->roles)) {
                $multiplier += 0.2; // Non-admin activity
            }
        }
        
        // IP reputation
        if (!empty($event['data']['ip_address'])) {
            $ip_reputation = $this->check_ip_reputation($event['data']['ip_address']);
            if ($ip_reputation['malicious']) {
                $multiplier += 0.5;
            }
        }
        
        // File sensitivity
        if (!empty($event['data']['file_path'])) {
            $file_sensitivity = $this->assess_file_sensitivity($event['data']['file_path']);
            $multiplier += $file_sensitivity;
        }
        
        return $multiplier;
    }

    // Event processors for different event types
    
    /**
     * Process file change event.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $event       Event data.
     * @param    bool     $immediate   Immediate processing flag.
     * @return   array                Processing result.
     */
    private function process_file_change_event($event, $immediate = false) {
        $file_path = $event['data']['file_path'] ?? '';
        
        // Trigger malware scan
        if (!empty($file_path)) {
            $scan_result = $this->monitors['malware_scanner']->scan_file($file_path);
            
            if ($scan_result['success'] && $scan_result['is_malicious']) {
                // Create critical alert
                $this->alert_manager->create_alert(array(
                    'type' => 'malware_detected',
                    'severity' => 'critical',
                    'title' => 'Malware Detected in Modified File',
                    'message' => "Malicious code detected in modified file: {$file_path}",
                    'details' => array_merge($event['data'], $scan_result),
                    'source' => 'event_processor'
                ));
            }
        }
        
        // Check file integrity
        $integrity_result = $this->monitors['file_monitor']->check_file_integrity($file_path);
        
        return array(
            'file_scanned' => !empty($file_path),
            'malware_detected' => $scan_result['is_malicious'] ?? false,
            'integrity_check' => $integrity_result
        );
    }

    /**
     * Process file creation event.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $event       Event data.
     * @param    bool     $immediate   Immediate processing flag.
     * @return   array                Processing result.
     */
    private function process_file_creation_event($event, $immediate = false) {
        $file_path = $event['data']['file_path'] ?? '';
        
        // Scan new files immediately
        if (!empty($file_path)) {
            $scan_result = $this->monitors['malware_scanner']->scan_file($file_path);
            
            if ($scan_result['success'] && $scan_result['is_malicious']) {
                // Critical alert for malicious new files
                $this->alert_manager->create_alert(array(
                    'type' => 'malware_detected',
                    'severity' => 'critical',
                    'title' => 'Malicious File Created',
                    'message' => "Malicious file created: {$file_path}",
                    'details' => array_merge($event['data'], $scan_result),
                    'source' => 'event_processor'
                ));
                
                return array(
                    'action_taken' => 'malware_alert_created',
                    'malware_detected' => true,
                    'scan_result' => $scan_result
                );
            }
        }
        
        // Check if file creation is in sensitive location
        if ($this->is_sensitive_location($file_path)) {
            $this->alert_manager->create_alert(array(
                'type' => 'suspicious_activity',
                'severity' => 'medium',
                'title' => 'File Created in Sensitive Location',
                'message' => "New file created in sensitive directory: {$file_path}",
                'details' => $event['data'],
                'source' => 'event_processor'
            ));
        }
        
        return array(
            'file_scanned' => true,
            'malware_detected' => false,
            'sensitive_location' => $this->is_sensitive_location($file_path)
        );
    }

    /**
     * Process malware detection event.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $event       Event data.
     * @param    bool     $immediate   Immediate processing flag.
     * @return   array                Processing result.
     */
    private function process_malware_detection_event($event, $immediate = false) {
        $file_path = $event['data']['file_path'] ?? '';
        $threat_score = $event['data']['threat_score'] ?? 0;
        
        // Determine response based on threat score
        $response_actions = array();
        
        if ($threat_score >= 90) {
            // Critical threat - immediate isolation
            $response_actions[] = 'emergency_quarantine';
            do_action('wp_breach_emergency_response', $file_path, $event['data']);
            
        } elseif ($threat_score >= 70) {
            // High threat - quarantine
            $response_actions[] = 'quarantine';
            do_action('wp_breach_quarantine_file', $file_path);
            
        } elseif ($threat_score >= 40) {
            // Medium threat - monitoring
            $response_actions[] = 'enhanced_monitoring';
            do_action('wp_breach_monitor_file', $file_path);
        }
        
        // Create detailed alert
        $severity = $threat_score >= 90 ? 'critical' : ($threat_score >= 70 ? 'high' : 'medium');
        
        $this->alert_manager->create_alert(array(
            'type' => 'malware_detected',
            'severity' => $severity,
            'title' => 'Malware Detection Confirmed',
            'message' => "Malware detected with threat score {$threat_score}: {$file_path}",
            'details' => $event['data'],
            'source' => 'event_processor'
        ));
        
        return array(
            'threat_score' => $threat_score,
            'response_actions' => $response_actions,
            'alert_created' => true
        );
    }

    /**
     * Process login attempt event.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $event       Event data.
     * @param    bool     $immediate   Immediate processing flag.
     * @return   array                Processing result.
     */
    private function process_login_attempt_event($event, $immediate = false) {
        $ip_address = $event['data']['ip_address'] ?? '';
        $username = $event['data']['username'] ?? '';
        $success = $event['data']['success'] ?? false;
        
        // Track attempt patterns
        $pattern_analysis = $this->monitors['activity_monitor']->analyze_login_patterns($ip_address, $username);
        
        if (!$success && $pattern_analysis['suspicious']) {
            // Brute force detection
            if ($pattern_analysis['brute_force_detected']) {
                $this->alert_manager->create_alert(array(
                    'type' => 'brute_force_attack',
                    'severity' => 'high',
                    'title' => 'Brute Force Attack Detected',
                    'message' => "Brute force attack detected from IP: {$ip_address}",
                    'details' => array_merge($event['data'], $pattern_analysis),
                    'source' => 'event_processor'
                ));
                
                // Auto-block if enabled
                if ($this->config['auto_response']) {
                    do_action('wp_breach_block_ip', $ip_address, 'brute_force');
                }
            }
        }
        
        return array(
            'pattern_analysis' => $pattern_analysis,
            'brute_force_detected' => $pattern_analysis['brute_force_detected'] ?? false
        );
    }

    /**
     * Process suspicious activity event.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $event       Event data.
     * @param    bool     $immediate   Immediate processing flag.
     * @return   array                Processing result.
     */
    private function process_suspicious_activity_event($event, $immediate = false) {
        $activity_type = $event['data']['activity_type'] ?? '';
        $risk_score = $event['data']['risk_score'] ?? 0;
        
        // Escalate based on risk score
        $severity = 'low';
        if ($risk_score >= 70) {
            $severity = 'high';
        } elseif ($risk_score >= 40) {
            $severity = 'medium';
        }
        
        $this->alert_manager->create_alert(array(
            'type' => 'suspicious_activity',
            'severity' => $severity,
            'title' => 'Suspicious Activity Detected',
            'message' => "Suspicious activity detected: {$activity_type}",
            'details' => $event['data'],
            'source' => 'event_processor'
        ));
        
        return array(
            'alert_severity' => $severity,
            'risk_score' => $risk_score
        );
    }

    // WordPress hook handlers
    
    public function handle_file_change($file_path, $change_data) {
        $this->queue_event('file_change', array(
            'file_path' => $file_path,
            'change_data' => $change_data,
            'timestamp' => time()
        ), 'medium');
    }

    public function handle_file_creation($file_path, $creation_data) {
        $this->queue_event('file_creation', array(
            'file_path' => $file_path,
            'creation_data' => $creation_data,
            'timestamp' => time()
        ), 'high');
    }

    public function handle_malware_detection($file_path, $scan_results) {
        $this->queue_event('malware_detected', array(
            'file_path' => $file_path,
            'scan_results' => $scan_results,
            'threat_score' => $scan_results['threat_score'] ?? 0,
            'timestamp' => time()
        ), 'critical');
    }

    public function handle_wp_login($user_login, $user) {
        $this->queue_event('login_success', array(
            'username' => $user_login,
            'user_id' => $user->ID,
            'ip_address' => $this->get_client_ip(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'timestamp' => time()
        ), 'low');
    }

    public function handle_wp_login_failed($username) {
        $this->queue_event('login_failure', array(
            'username' => $username,
            'ip_address' => $this->get_client_ip(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'timestamp' => time()
        ), 'medium');
    }

    // Helper methods
    
    private function generate_event_id() {
        return uniqid('event_', true);
    }

    private function generate_correlation_id($event_type, $event_data) {
        $correlation_data = array(
            'type' => $event_type,
            'ip' => $event_data['ip_address'] ?? '',
            'user' => $event_data['user_id'] ?? '',
            'hour' => date('Y-m-d-H')
        );
        
        return md5(json_encode($correlation_data));
    }

    private function add_to_priority_queue($event) {
        $priority_order = array('critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3);
        $event_priority = $priority_order[$event['priority']] ?? 2;
        
        // Find insertion point
        $insert_index = 0;
        foreach ($this->event_queue as $index => $queued_event) {
            $queued_priority = $priority_order[$queued_event['priority']] ?? 2;
            if ($event_priority <= $queued_priority) {
                $insert_index = $index;
                break;
            }
            $insert_index = $index + 1;
        }
        
        array_splice($this->event_queue, $insert_index, 0, array($event));
    }

    private function cleanup_queue() {
        // Remove oldest low-priority events
        $this->event_queue = array_filter($this->event_queue, function($event) {
            return $event['priority'] !== 'low' || (time() - $event['timestamp']) < 300;
        });
        
        // If still too many, remove older medium priority
        if (count($this->event_queue) >= $this->config['max_queue_size']) {
            $this->event_queue = array_filter($this->event_queue, function($event) {
                return $event['priority'] === 'critical' || $event['priority'] === 'high' || 
                       (time() - $event['timestamp']) < 600;
            });
        }
    }

    private function persist_event_queue() {
        update_option('wp_breach_event_queue', $this->event_queue);
    }

    private function load_event_queue() {
        $saved_queue = get_option('wp_breach_event_queue', array());
        if (!empty($saved_queue)) {
            $this->event_queue = array_merge($this->event_queue, $saved_queue);
        }
    }

    private function store_event($event, $result) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_events';
        
        $wpdb->insert(
            $table_name,
            array(
                'event_id' => $event['id'],
                'event_type' => $event['type'],
                'event_data' => json_encode($event['data']),
                'risk_score' => $event['risk_score'] ?? 0,
                'correlation_id' => $event['correlation_id'],
                'processing_result' => json_encode($result),
                'created_at' => $event['created_at'],
                'processed_at' => current_time('mysql')
            ),
            array('%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s')
        );
    }

    private function get_related_events($event_types, $start_time, $end_time) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_events';
        $placeholders = implode(',', array_fill(0, count($event_types), '%s'));
        
        $query = $wpdb->prepare(
            "SELECT * FROM {$table_name} 
             WHERE event_type IN ({$placeholders})
             AND UNIX_TIMESTAMP(created_at) BETWEEN %d AND %d
             ORDER BY created_at DESC",
            array_merge($event_types, array($start_time, $end_time))
        );
        
        return $wpdb->get_results($query);
    }

    private function is_sensitive_location($file_path) {
        $sensitive_paths = array(
            ABSPATH . 'wp-config.php',
            ABSPATH . '.htaccess',
            WP_CONTENT_DIR . '/uploads/',
            WPMU_PLUGIN_DIR,
            WP_PLUGIN_DIR,
            get_theme_root()
        );
        
        foreach ($sensitive_paths as $sensitive_path) {
            if (strpos($file_path, $sensitive_path) === 0) {
                return true;
            }
        }
        
        return false;
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

    private function check_ip_reputation($ip_address) {
        // Placeholder for IP reputation check
        return array('malicious' => false, 'score' => 0);
    }

    private function assess_file_sensitivity($file_path) {
        // Return sensitivity multiplier (0.0 to 1.0)
        if (strpos($file_path, 'wp-config.php') !== false) return 1.0;
        if (strpos($file_path, '.htaccess') !== false) return 0.8;
        if (strpos($file_path, '/plugins/') !== false) return 0.6;
        if (strpos($file_path, '/themes/') !== false) return 0.4;
        if (strpos($file_path, '/uploads/') !== false) return 0.3;
        
        return 0.1;
    }

    private function update_risk_engine($event, $result) {
        // Update current risk level based on event
        $risk_increase = $event['risk_score'] ?? 0;
        $this->risk_engine['current_risk'] = min(100, $this->risk_engine['current_risk'] + ($risk_increase * 0.1));
        
        // Decay risk over time
        $time_factor = max(0.9, 1 - ((time() - ($this->risk_engine['last_update'] ?? time())) / 3600));
        $this->risk_engine['current_risk'] *= $time_factor;
        $this->risk_engine['last_update'] = time();
    }

    private function calculate_average_processing_time($new_time) {
        $current_avg = $this->metrics['average_processing_time'] ?? 0;
        $count = $this->metrics['events_processed'] ?? 1;
        
        return (($current_avg * ($count - 1)) + $new_time) / $count;
    }

    public function record_performance_metrics() {
        if (!$this->config['performance_monitoring']) {
            return;
        }
        
        $this->metrics['end_time'] = microtime(true);
        $this->metrics['memory_end'] = memory_get_usage();
        $this->metrics['memory_peak'] = memory_get_peak_usage();
        
        // Store metrics
        update_option('wp_breach_processor_metrics', $this->metrics);
    }

    public function cleanup_old_events() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_events';
        $retention_cutoff = date('Y-m-d H:i:s', time() - $this->config['event_retention']);
        
        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$table_name} WHERE created_at < %s",
            $retention_cutoff
        ));
    }

    // Additional event processors would be implemented here...
    private function process_file_deletion_event($event, $immediate = false) { return array(); }
    private function process_login_success_event($event, $immediate = false) { return array(); }
    private function process_admin_action_event($event, $immediate = false) { return array(); }
    private function process_vulnerability_event($event, $immediate = false) { return array(); }
    private function process_configuration_change_event($event, $immediate = false) { return array(); }
    private function process_user_registration_event($event, $immediate = false) { return array(); }
    private function process_plugin_activation_event($event, $immediate = false) { return array(); }
    private function process_theme_change_event($event, $immediate = false) { return array(); }
    private function process_database_query_event($event, $immediate = false) { return array(); }
    private function process_network_request_event($event, $immediate = false) { return array(); }
    private function process_error_event($event, $immediate = false) { return array(); }
}
