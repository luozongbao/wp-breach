<?php

/**
 * Report scheduler for automated security report generation.
 *
 * This class handles the scheduling and automated generation of security reports
 * with support for multiple frequencies, recipient management, and delivery options.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/reports
 */

/**
 * The report scheduler class.
 *
 * Manages automated report generation and delivery using WordPress Cron
 * with support for multiple schedules and delivery methods.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/reports
 * @author     WP Breach Team
 */
class WP_Breach_Report_Scheduler {

    /**
     * Scheduler configuration.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $config    Scheduler configuration.
     */
    private $config;

    /**
     * Active schedules.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $schedules    Active report schedules.
     */
    private $schedules;

    /**
     * Report generator instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Breach_Report_Generator    $report_generator    Report generator.
     */
    private $report_generator;

    /**
     * Email delivery instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Breach_Email_Delivery    $email_delivery    Email delivery.
     */
    private $email_delivery;

    /**
     * Initialize the report scheduler.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->setup_config();
        $this->load_schedules();
        
        // Initialize dependencies
        $this->report_generator = new WP_Breach_Report_Generator();
        $this->email_delivery = new WP_Breach_Email_Delivery();
        
        // Register hooks
        $this->register_hooks();
        
        // Add custom cron schedules
        add_filter('cron_schedules', array($this, 'add_custom_cron_schedules'));
    }

    /**
     * Setup scheduler configuration.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_config() {
        $this->config = array(
            'max_concurrent_jobs' => 3,
            'job_timeout' => 300, // 5 minutes
            'retry_failed_jobs' => true,
            'max_retries' => 3,
            'retry_delay' => 1800, // 30 minutes
            'cleanup_old_logs' => true,
            'log_retention_days' => 30,
            'supported_frequencies' => array(
                'hourly' => 'Every Hour',
                'daily' => 'Daily',
                'weekly' => 'Weekly',
                'monthly' => 'Monthly',
                'custom' => 'Custom Interval'
            ),
            'default_report_types' => array(
                'executive-summary',
                'technical-vulnerability',
                'compliance'
            ),
            'timezone_support' => true
        );
    }

    /**
     * Load active schedules from database.
     *
     * @since    1.0.0
     * @access   private
     */
    private function load_schedules() {
        $this->schedules = get_option('wp_breach_report_schedules', array());
        
        // Validate and clean up schedules
        $this->schedules = array_filter($this->schedules, array($this, 'validate_schedule'));
    }

    /**
     * Register WordPress hooks.
     *
     * @since    1.0.0
     * @access   private
     */
    private function register_hooks() {
        // Register scheduled report hooks
        add_action('wp_breach_generate_scheduled_report', array($this, 'execute_scheduled_report'));
        add_action('wp_breach_cleanup_scheduler_logs', array($this, 'cleanup_old_logs'));
        add_action('wp_breach_retry_failed_reports', array($this, 'retry_failed_reports'));
        
        // Admin hooks
        add_action('wp_breach_schedule_created', array($this, 'schedule_report_cron'));
        add_action('wp_breach_schedule_updated', array($this, 'update_report_cron'));
        add_action('wp_breach_schedule_deleted', array($this, 'unschedule_report_cron'));
        
        // Cleanup hook
        if (!wp_next_scheduled('wp_breach_cleanup_scheduler_logs')) {
            wp_schedule_event(time(), 'daily', 'wp_breach_cleanup_scheduler_logs');
        }
        
        // Retry failed reports hook
        if (!wp_next_scheduled('wp_breach_retry_failed_reports')) {
            wp_schedule_event(time(), 'hourly', 'wp_breach_retry_failed_reports');
        }
    }

    /**
     * Create a new report schedule.
     *
     * @since    1.0.0
     * @param    array    $schedule_data    Schedule configuration.
     * @return   array                      Creation result.
     */
    public function create_schedule($schedule_data) {
        try {
            // Validate schedule data
            $this->validate_schedule_data($schedule_data);
            
            // Generate unique schedule ID
            $schedule_id = $this->generate_schedule_id();
            
            // Prepare schedule configuration
            $schedule = array(
                'id' => $schedule_id,
                'name' => sanitize_text_field($schedule_data['name']),
                'description' => sanitize_textarea_field($schedule_data['description'] ?? ''),
                'frequency' => $schedule_data['frequency'],
                'custom_interval' => $schedule_data['custom_interval'] ?? null,
                'report_types' => $schedule_data['report_types'],
                'recipients' => $schedule_data['recipients'],
                'delivery_options' => $schedule_data['delivery_options'] ?? array(),
                'report_options' => $schedule_data['report_options'] ?? array(),
                'timezone' => $schedule_data['timezone'] ?? wp_timezone_string(),
                'next_run' => $this->calculate_next_run($schedule_data),
                'active' => true,
                'created_at' => current_time('mysql'),
                'created_by' => get_current_user_id(),
                'execution_log' => array()
            );
            
            // Add to schedules array
            $this->schedules[$schedule_id] = $schedule;
            
            // Save to database
            $this->save_schedules();
            
            // Schedule the cron job
            $this->schedule_report_cron($schedule);
            
            // Log creation
            $this->log_scheduler_event('schedule_created', $schedule_id, array(
                'schedule_name' => $schedule['name'],
                'frequency' => $schedule['frequency']
            ));

            return array(
                'success' => true,
                'schedule_id' => $schedule_id,
                'next_run' => $schedule['next_run']
            );

        } catch (Exception $e) {
            error_log("WP-Breach Schedule Creation Error: " . $e->getMessage());
            return array(
                'success' => false,
                'error' => $e->getMessage()
            );
        }
    }

    /**
     * Execute a scheduled report.
     *
     * @since    1.0.0
     * @param    string   $schedule_id     Schedule ID.
     */
    public function execute_scheduled_report($schedule_id) {
        try {
            // Get schedule
            if (!isset($this->schedules[$schedule_id])) {
                throw new Exception("Schedule not found: {$schedule_id}");
            }

            $schedule = $this->schedules[$schedule_id];
            
            // Check if schedule is active
            if (!$schedule['active']) {
                return;
            }

            // Log execution start
            $execution_id = $this->log_execution_start($schedule_id);
            
            // Generate reports for each type
            $reports = array();
            foreach ($schedule['report_types'] as $report_type) {
                $report_options = array_merge($schedule['report_options'], array(
                    'type' => $report_type,
                    'scheduled' => true,
                    'schedule_id' => $schedule_id
                ));
                
                $report = $this->report_generator->generate_report($report_options);
                
                if ($report['success']) {
                    $reports[] = $report;
                } else {
                    throw new Exception("Failed to generate {$report_type} report: " . $report['error']);
                }
            }

            // Send reports via email if configured
            if (!empty($schedule['recipients'])) {
                $this->deliver_scheduled_reports($reports, $schedule);
            }

            // Update schedule for next run
            $this->update_schedule_next_run($schedule_id);
            
            // Log successful execution
            $this->log_execution_complete($schedule_id, $execution_id, true, array(
                'reports_generated' => count($reports),
                'recipients_notified' => count($schedule['recipients'])
            ));

        } catch (Exception $e) {
            error_log("WP-Breach Scheduled Report Error: " . $e->getMessage());
            
            // Log failed execution
            $this->log_execution_complete($schedule_id, $execution_id ?? null, false, array(
                'error' => $e->getMessage()
            ));
            
            // Schedule retry if configured
            if ($this->config['retry_failed_jobs']) {
                $this->schedule_retry($schedule_id);
            }
        }
    }

    /**
     * Deliver scheduled reports via email.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $reports         Generated reports.
     * @param    array    $schedule        Schedule configuration.
     */
    private function deliver_scheduled_reports($reports, $schedule) {
        foreach ($reports as $report) {
            $delivery_options = array_merge($schedule['delivery_options'], array(
                'template' => 'scheduled_report',
                'report_period' => $this->get_report_period_text($schedule['frequency']),
                'attach_formats' => $schedule['delivery_options']['attach_formats'] ?? array('pdf')
            ));

            $delivery_result = $this->email_delivery->send_report(
                $report,
                $schedule['recipients'],
                $delivery_options
            );

            if (!$delivery_result['success']) {
                throw new Exception("Failed to deliver report: " . $delivery_result['error']);
            }
        }
    }

    /**
     * Update schedule for next run.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $schedule_id     Schedule ID.
     */
    private function update_schedule_next_run($schedule_id) {
        if (isset($this->schedules[$schedule_id])) {
            $schedule = $this->schedules[$schedule_id];
            
            // Calculate next run time
            $this->schedules[$schedule_id]['next_run'] = $this->calculate_next_run($schedule);
            $this->schedules[$schedule_id]['last_run'] = current_time('mysql');
            
            // Save updates
            $this->save_schedules();
            
            // Reschedule cron job
            $this->schedule_report_cron($this->schedules[$schedule_id]);
        }
    }

    /**
     * Calculate next run time for schedule.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $schedule        Schedule configuration.
     * @return   string                    Next run timestamp.
     */
    private function calculate_next_run($schedule) {
        $timezone = new DateTimeZone($schedule['timezone'] ?? wp_timezone_string());
        $now = new DateTime('now', $timezone);
        
        switch ($schedule['frequency']) {
            case 'hourly':
                $now->add(new DateInterval('PT1H'));
                break;
            case 'daily':
                $now->add(new DateInterval('P1D'));
                // Set to specific time if configured
                if (!empty($schedule['daily_time'])) {
                    $time_parts = explode(':', $schedule['daily_time']);
                    $now->setTime((int)$time_parts[0], (int)$time_parts[1], 0);
                }
                break;
            case 'weekly':
                $now->add(new DateInterval('P7D'));
                // Set to specific day/time if configured
                if (!empty($schedule['weekly_day'])) {
                    $now->modify('next ' . $schedule['weekly_day']);
                }
                break;
            case 'monthly':
                $now->add(new DateInterval('P1M'));
                // Set to specific day if configured
                if (!empty($schedule['monthly_day'])) {
                    $now->setDate($now->format('Y'), $now->format('n'), min($schedule['monthly_day'], $now->format('t')));
                }
                break;
            case 'custom':
                if (!empty($schedule['custom_interval'])) {
                    $now->add(new DateInterval($schedule['custom_interval']));
                }
                break;
        }
        
        return $now->format('Y-m-d H:i:s');
    }

    /**
     * Schedule WordPress cron job for report.
     *
     * @since    1.0.0
     * @param    array    $schedule        Schedule configuration.
     */
    public function schedule_report_cron($schedule) {
        $hook = 'wp_breach_generate_scheduled_report';
        $args = array($schedule['id']);
        
        // Clear existing schedule
        wp_clear_scheduled_hook($hook, $args);
        
        // Calculate next run timestamp
        $next_run_timestamp = strtotime($schedule['next_run']);
        
        // Schedule new event
        wp_schedule_single_event($next_run_timestamp, $hook, $args);
    }

    /**
     * Add custom cron schedules.
     *
     * @since    1.0.0
     * @param    array    $schedules       Existing schedules.
     * @return   array                     Modified schedules.
     */
    public function add_custom_cron_schedules($schedules) {
        $schedules['wp_breach_fifteen_minutes'] = array(
            'interval' => 15 * MINUTE_IN_SECONDS,
            'display' => __('Every 15 Minutes', 'wp-breach')
        );
        
        $schedules['wp_breach_six_hours'] = array(
            'interval' => 6 * HOUR_IN_SECONDS,
            'display' => __('Every 6 Hours', 'wp-breach')
        );
        
        return $schedules;
    }

    /**
     * Get all active schedules.
     *
     * @since    1.0.0
     * @return   array                     Active schedules.
     */
    public function get_schedules() {
        return array_filter($this->schedules, function($schedule) {
            return $schedule['active'];
        });
    }

    /**
     * Get schedule by ID.
     *
     * @since    1.0.0
     * @param    string   $schedule_id     Schedule ID.
     * @return   array|null               Schedule data or null.
     */
    public function get_schedule($schedule_id) {
        return $this->schedules[$schedule_id] ?? null;
    }

    /**
     * Update existing schedule.
     *
     * @since    1.0.0
     * @param    string   $schedule_id     Schedule ID.
     * @param    array    $schedule_data   Updated schedule data.
     * @return   array                     Update result.
     */
    public function update_schedule($schedule_id, $schedule_data) {
        try {
            if (!isset($this->schedules[$schedule_id])) {
                throw new Exception("Schedule not found: {$schedule_id}");
            }

            // Validate updated data
            $this->validate_schedule_data($schedule_data);
            
            // Update schedule
            $schedule = $this->schedules[$schedule_id];
            $schedule['name'] = sanitize_text_field($schedule_data['name']);
            $schedule['description'] = sanitize_textarea_field($schedule_data['description'] ?? '');
            $schedule['frequency'] = $schedule_data['frequency'];
            $schedule['custom_interval'] = $schedule_data['custom_interval'] ?? null;
            $schedule['report_types'] = $schedule_data['report_types'];
            $schedule['recipients'] = $schedule_data['recipients'];
            $schedule['delivery_options'] = $schedule_data['delivery_options'] ?? array();
            $schedule['report_options'] = $schedule_data['report_options'] ?? array();
            $schedule['timezone'] = $schedule_data['timezone'] ?? wp_timezone_string();
            $schedule['next_run'] = $this->calculate_next_run($schedule);
            $schedule['updated_at'] = current_time('mysql');
            $schedule['updated_by'] = get_current_user_id();
            
            $this->schedules[$schedule_id] = $schedule;
            
            // Save to database
            $this->save_schedules();
            
            // Update cron job
            $this->schedule_report_cron($schedule);

            return array(
                'success' => true,
                'next_run' => $schedule['next_run']
            );

        } catch (Exception $e) {
            return array(
                'success' => false,
                'error' => $e->getMessage()
            );
        }
    }

    /**
     * Delete schedule.
     *
     * @since    1.0.0
     * @param    string   $schedule_id     Schedule ID.
     * @return   array                     Deletion result.
     */
    public function delete_schedule($schedule_id) {
        try {
            if (!isset($this->schedules[$schedule_id])) {
                throw new Exception("Schedule not found: {$schedule_id}");
            }

            // Clear cron job
            $this->unschedule_report_cron($this->schedules[$schedule_id]);
            
            // Remove from schedules
            unset($this->schedules[$schedule_id]);
            
            // Save to database
            $this->save_schedules();

            return array('success' => true);

        } catch (Exception $e) {
            return array(
                'success' => false,
                'error' => $e->getMessage()
            );
        }
    }

    /**
     * Activate or deactivate schedule.
     *
     * @since    1.0.0
     * @param    string   $schedule_id     Schedule ID.
     * @param    bool     $active          Active status.
     * @return   array                     Result.
     */
    public function set_schedule_active($schedule_id, $active) {
        if (!isset($this->schedules[$schedule_id])) {
            return array('success' => false, 'error' => 'Schedule not found');
        }

        $this->schedules[$schedule_id]['active'] = (bool) $active;
        
        if ($active) {
            // Reschedule
            $this->schedule_report_cron($this->schedules[$schedule_id]);
        } else {
            // Unschedule
            $this->unschedule_report_cron($this->schedules[$schedule_id]);
        }
        
        $this->save_schedules();
        
        return array('success' => true);
    }

    /**
     * Get execution history for schedule.
     *
     * @since    1.0.0
     * @param    string   $schedule_id     Schedule ID.
     * @param    int      $limit          Result limit.
     * @return   array                     Execution history.
     */
    public function get_execution_history($schedule_id, $limit = 50) {
        if (!isset($this->schedules[$schedule_id])) {
            return array();
        }

        $log = $this->schedules[$schedule_id]['execution_log'] ?? array();
        
        // Sort by timestamp descending
        usort($log, function($a, $b) {
            return strtotime($b['timestamp']) - strtotime($a['timestamp']);
        });
        
        return array_slice($log, 0, $limit);
    }

    // Private helper methods...
    
    private function validate_schedule_data($data) {
        if (empty($data['name'])) {
            throw new Exception('Schedule name is required');
        }
        
        if (empty($data['frequency']) || !array_key_exists($data['frequency'], $this->config['supported_frequencies'])) {
            throw new Exception('Valid frequency is required');
        }
        
        if (empty($data['report_types']) || !is_array($data['report_types'])) {
            throw new Exception('At least one report type is required');
        }
        
        if (empty($data['recipients']) || !is_array($data['recipients'])) {
            throw new Exception('At least one recipient is required');
        }
        
        foreach ($data['recipients'] as $recipient) {
            if (empty($recipient['email']) || !is_email($recipient['email'])) {
                throw new Exception('Valid email address required for all recipients');
            }
        }
    }

    private function validate_schedule($schedule) {
        return !empty($schedule['id']) && !empty($schedule['name']) && isset($schedule['active']);
    }

    private function generate_schedule_id() {
        return 'schedule_' . wp_generate_uuid4();
    }

    private function save_schedules() {
        update_option('wp_breach_report_schedules', $this->schedules);
    }

    private function log_execution_start($schedule_id) {
        $execution_id = uniqid('exec_');
        
        if (!isset($this->schedules[$schedule_id]['execution_log'])) {
            $this->schedules[$schedule_id]['execution_log'] = array();
        }
        
        $this->schedules[$schedule_id]['execution_log'][] = array(
            'execution_id' => $execution_id,
            'status' => 'running',
            'started_at' => current_time('mysql'),
            'timestamp' => current_time('mysql')
        );
        
        $this->save_schedules();
        
        return $execution_id;
    }

    private function log_execution_complete($schedule_id, $execution_id, $success, $details = array()) {
        if (!isset($this->schedules[$schedule_id]['execution_log'])) {
            return;
        }
        
        foreach ($this->schedules[$schedule_id]['execution_log'] as &$log_entry) {
            if ($log_entry['execution_id'] === $execution_id) {
                $log_entry['status'] = $success ? 'completed' : 'failed';
                $log_entry['completed_at'] = current_time('mysql');
                $log_entry['details'] = $details;
                break;
            }
        }
        
        $this->save_schedules();
    }

    private function log_scheduler_event($event_type, $schedule_id, $details = array()) {
        $log_entry = array(
            'event_type' => $event_type,
            'schedule_id' => $schedule_id,
            'timestamp' => current_time('mysql'),
            'details' => $details
        );
        
        $scheduler_log = get_option('wp_breach_scheduler_log', array());
        $scheduler_log[] = $log_entry;
        
        // Keep only last 1000 entries
        if (count($scheduler_log) > 1000) {
            $scheduler_log = array_slice($scheduler_log, -1000);
        }
        
        update_option('wp_breach_scheduler_log', $scheduler_log);
    }

    private function unschedule_report_cron($schedule) {
        $hook = 'wp_breach_generate_scheduled_report';
        $args = array($schedule['id']);
        wp_clear_scheduled_hook($hook, $args);
    }

    private function get_report_period_text($frequency) {
        $periods = array(
            'hourly' => 'Last Hour',
            'daily' => 'Last 24 Hours', 
            'weekly' => 'Last Week',
            'monthly' => 'Last Month'
        );
        
        return $periods[$frequency] ?? 'Recent Period';
    }

    private function schedule_retry($schedule_id) {
        $retry_time = time() + $this->config['retry_delay'];
        wp_schedule_single_event($retry_time, 'wp_breach_generate_scheduled_report', array($schedule_id));
    }

    public function cleanup_old_logs() {
        if (!$this->config['cleanup_old_logs']) {
            return;
        }
        
        // Clean up execution logs older than retention period
        $cutoff_date = date('Y-m-d H:i:s', strtotime('-' . $this->config['log_retention_days'] . ' days'));
        
        foreach ($this->schedules as &$schedule) {
            if (isset($schedule['execution_log'])) {
                $schedule['execution_log'] = array_filter($schedule['execution_log'], function($log) use ($cutoff_date) {
                    return $log['timestamp'] > $cutoff_date;
                });
            }
        }
        
        $this->save_schedules();
    }

    public function retry_failed_reports() {
        // Implementation for retrying failed scheduled reports
        // This would check for failed executions and retry them if within retry limits
    }
}
