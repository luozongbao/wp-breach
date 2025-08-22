<?php

/**
 * Admin interface for the automated fix system.
 *
 * This class handles the integration of the automated fix system
 * with the WordPress admin interface.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/admin/fixes
 */

/**
 * The admin interface class for automated fixes.
 *
 * Provides WordPress admin interface integration for:
 * - Fix management dashboard
 * - Manual fix guidance display
 * - Fix history and logs
 * - System configuration
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/admin/fixes
 * @author     WP Breach Team
 */
class WP_Breach_Fix_Admin {

    /**
     * The fix engine instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Breach_Fix_Engine    $fix_engine    Fix engine instance.
     */
    private $fix_engine;

    /**
     * The manual fix guidance instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Breach_Manual_Fix_Guidance    $manual_guidance    Manual guidance instance.
     */
    private $manual_guidance;

    /**
     * Initialize the admin interface.
     *
     * @since    1.0.0
     * @param    WP_Breach_Fix_Engine    $fix_engine    Fix engine instance.
     */
    public function __construct($fix_engine) {
        $this->fix_engine = $fix_engine;
        $this->manual_guidance = new WP_Breach_Manual_Fix_Guidance();
        
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
        add_action('wp_ajax_wp_breach_apply_fix', array($this, 'ajax_apply_fix'));
        add_action('wp_ajax_wp_breach_rollback_fix', array($this, 'ajax_rollback_fix'));
        add_action('wp_ajax_wp_breach_get_manual_guidance', array($this, 'ajax_get_manual_guidance'));
        add_action('wp_ajax_wp_breach_update_fix_settings', array($this, 'ajax_update_fix_settings'));
    }

    /**
     * Add admin menu pages.
     *
     * @since    1.0.0
     */
    public function add_admin_menu() {
        // Add main fixes page
        add_submenu_page(
            'wp-breach-dashboard',
            __('Automated Fixes', 'wp-breach'),
            __('Fixes', 'wp-breach'),
            'manage_options',
            'wp-breach-fixes',
            array($this, 'display_fixes_page')
        );

        // Add fix history page
        add_submenu_page(
            'wp-breach-dashboard',
            __('Fix History', 'wp-breach'),
            __('Fix History', 'wp-breach'),
            'manage_options',
            'wp-breach-fix-history',
            array($this, 'display_fix_history_page')
        );

        // Add manual guidance page
        add_submenu_page(
            'wp-breach-dashboard',
            __('Manual Fix Guidance', 'wp-breach'),
            __('Manual Guidance', 'wp-breach'),
            'manage_options',
            'wp-breach-manual-guidance',
            array($this, 'display_manual_guidance_page')
        );
    }

    /**
     * Enqueue admin scripts and styles.
     *
     * @since    1.0.0
     * @param    string    $hook    Current admin page hook.
     */
    public function enqueue_admin_scripts($hook) {
        if (!in_array($hook, array('wp-breach_page_wp-breach-fixes', 'wp-breach_page_wp-breach-fix-history', 'wp-breach_page_wp-breach-manual-guidance'))) {
            return;
        }

        wp_enqueue_script(
            'wp-breach-fix-admin',
            plugin_dir_url(__FILE__) . 'js/wp-breach-fix-admin.js',
            array('jquery'),
            '1.0.0',
            true
        );

        wp_enqueue_style(
            'wp-breach-fix-admin',
            plugin_dir_url(__FILE__) . 'css/wp-breach-fix-admin.css',
            array(),
            '1.0.0'
        );

        wp_localize_script(
            'wp-breach-fix-admin',
            'wpBreachFixAdmin',
            array(
                'ajaxUrl' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('wp_breach_fix_admin'),
                'strings' => array(
                    'confirmApplyFix' => __('Are you sure you want to apply this fix? A backup will be created automatically.', 'wp-breach'),
                    'confirmRollback' => __('Are you sure you want to rollback this fix? This will restore the previous state.', 'wp-breach'),
                    'fixInProgress' => __('Fix in progress...', 'wp-breach'),
                    'fixCompleted' => __('Fix completed successfully!', 'wp-breach'),
                    'fixFailed' => __('Fix failed. Please check the error details.', 'wp-breach'),
                )
            )
        );
    }

    /**
     * Display the main fixes page.
     *
     * @since    1.0.0
     */
    public function display_fixes_page() {
        $vulnerabilities = $this->get_fixable_vulnerabilities();
        $fix_settings = $this->get_fix_settings();
        
        include plugin_dir_path(__FILE__) . 'partials/wp-breach-fixes-display.php';
    }

    /**
     * Display the fix history page.
     *
     * @since    1.0.0
     */
    public function display_fix_history_page() {
        $fix_history = $this->get_fix_history();
        
        include plugin_dir_path(__FILE__) . 'partials/wp-breach-fix-history-display.php';
    }

    /**
     * Display the manual guidance page.
     *
     * @since    1.0.0
     */
    public function display_manual_guidance_page() {
        $vulnerability_id = isset($_GET['vulnerability_id']) ? intval($_GET['vulnerability_id']) : 0;
        $manual_instructions = null;
        
        if ($vulnerability_id) {
            $manual_instructions = $this->manual_guidance->get_manual_fix_instructions($vulnerability_id);
        }
        
        include plugin_dir_path(__FILE__) . 'partials/wp-breach-manual-guidance-display.php';
    }

    /**
     * Handle AJAX fix application.
     *
     * @since    1.0.0
     */
    public function ajax_apply_fix() {
        check_ajax_referer('wp_breach_fix_admin', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die(__('Insufficient permissions.', 'wp-breach'));
        }

        $vulnerability_id = intval($_POST['vulnerability_id']);
        if (!$vulnerability_id) {
            wp_send_json_error(array('message' => __('Invalid vulnerability ID.', 'wp-breach')));
        }

        try {
            // Get vulnerability details
            $vulnerability = $this->get_vulnerability_details($vulnerability_id);
            if (!$vulnerability) {
                throw new Exception(__('Vulnerability not found.', 'wp-breach'));
            }

            // Apply the fix
            $fix_result = $this->fix_engine->process_single_vulnerability($vulnerability);
            
            if ($fix_result['success']) {
                wp_send_json_success(array(
                    'message' => __('Fix applied successfully!', 'wp-breach'),
                    'fix_id' => $fix_result['fix_id'],
                    'actions_taken' => $fix_result['actions_taken'],
                    'changes_made' => $fix_result['changes_made']
                ));
            } else {
                wp_send_json_error(array(
                    'message' => $fix_result['error_message'] ?: __('Fix application failed.', 'wp-breach'),
                    'details' => $fix_result
                ));
            }

        } catch (Exception $e) {
            wp_send_json_error(array(
                'message' => $e->getMessage()
            ));
        }
    }

    /**
     * Handle AJAX fix rollback.
     *
     * @since    1.0.0
     */
    public function ajax_rollback_fix() {
        check_ajax_referer('wp_breach_fix_admin', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die(__('Insufficient permissions.', 'wp-breach'));
        }

        $fix_id = sanitize_text_field($_POST['fix_id']);
        if (!$fix_id) {
            wp_send_json_error(array('message' => __('Invalid fix ID.', 'wp-breach')));
        }

        try {
            $rollback_result = $this->fix_engine->rollback_fix($fix_id);
            
            if ($rollback_result['success']) {
                wp_send_json_success(array(
                    'message' => __('Fix rolled back successfully!', 'wp-breach'),
                    'actions_taken' => $rollback_result['actions_taken']
                ));
            } else {
                wp_send_json_error(array(
                    'message' => $rollback_result['error_message'] ?: __('Rollback failed.', 'wp-breach'),
                    'details' => $rollback_result
                ));
            }

        } catch (Exception $e) {
            wp_send_json_error(array(
                'message' => $e->getMessage()
            ));
        }
    }

    /**
     * Handle AJAX manual guidance request.
     *
     * @since    1.0.0
     */
    public function ajax_get_manual_guidance() {
        check_ajax_referer('wp_breach_fix_admin', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die(__('Insufficient permissions.', 'wp-breach'));
        }

        $vulnerability_id = intval($_POST['vulnerability_id']);
        if (!$vulnerability_id) {
            wp_send_json_error(array('message' => __('Invalid vulnerability ID.', 'wp-breach')));
        }

        try {
            $manual_instructions = $this->manual_guidance->get_manual_fix_instructions($vulnerability_id);
            
            if ($manual_instructions) {
                wp_send_json_success(array(
                    'instructions' => $manual_instructions
                ));
            } else {
                wp_send_json_error(array(
                    'message' => __('Manual instructions not available for this vulnerability.', 'wp-breach')
                ));
            }

        } catch (Exception $e) {
            wp_send_json_error(array(
                'message' => $e->getMessage()
            ));
        }
    }

    /**
     * Handle AJAX fix settings update.
     *
     * @since    1.0.0
     */
    public function ajax_update_fix_settings() {
        check_ajax_referer('wp_breach_fix_admin', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die(__('Insufficient permissions.', 'wp-breach'));
        }

        $settings = $_POST['settings'];
        if (!is_array($settings)) {
            wp_send_json_error(array('message' => __('Invalid settings data.', 'wp-breach')));
        }

        try {
            $this->update_fix_settings($settings);
            
            wp_send_json_success(array(
                'message' => __('Settings updated successfully!', 'wp-breach')
            ));

        } catch (Exception $e) {
            wp_send_json_error(array(
                'message' => $e->getMessage()
            ));
        }
    }

    /**
     * Get fixable vulnerabilities.
     *
     * @since    1.0.0
     * @return   array    Vulnerabilities that can be fixed.
     */
    private function get_fixable_vulnerabilities() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_vulnerabilities';
        $vulnerabilities = $wpdb->get_results(
            "SELECT * FROM {$table_name} 
             WHERE status = 'active' 
             AND fix_available = 1 
             ORDER BY severity DESC, created_at DESC",
            ARRAY_A
        );

        // Add fix capability information
        foreach ($vulnerabilities as &$vulnerability) {
            $vulnerability['can_auto_fix'] = $this->fix_engine->can_auto_fix_vulnerability($vulnerability);
            $vulnerability['safety_assessment'] = $this->fix_engine->assess_fix_safety($vulnerability);
        }

        return $vulnerabilities;
    }

    /**
     * Get vulnerability details.
     *
     * @since    1.0.0
     * @param    int      $vulnerability_id    Vulnerability ID.
     * @return   array                         Vulnerability details.
     */
    private function get_vulnerability_details($vulnerability_id) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_vulnerabilities';
        $vulnerability = $wpdb->get_row(
            $wpdb->prepare("SELECT * FROM {$table_name} WHERE id = %d", $vulnerability_id),
            ARRAY_A
        );

        if ($vulnerability) {
            // Decode JSON fields
            $json_fields = array('detection_data', 'affected_files', 'fix_data');
            foreach ($json_fields as $field) {
                if (isset($vulnerability[$field])) {
                    $vulnerability[$field] = json_decode($vulnerability[$field], true);
                }
            }
        }

        return $vulnerability;
    }

    /**
     * Get fix history.
     *
     * @since    1.0.0
     * @return   array    Fix history.
     */
    private function get_fix_history() {
        global $wpdb;
        
        $fixes_table = $wpdb->prefix . 'breach_fixes';
        $vulnerabilities_table = $wpdb->prefix . 'breach_vulnerabilities';
        
        $history = $wpdb->get_results("
            SELECT 
                f.*,
                v.title as vulnerability_title,
                v.type as vulnerability_type,
                v.severity
            FROM {$fixes_table} f
            LEFT JOIN {$vulnerabilities_table} v ON f.vulnerability_id = v.id
            ORDER BY f.created_at DESC
            LIMIT 100
        ", ARRAY_A);

        // Decode JSON fields
        foreach ($history as &$fix) {
            $json_fields = array('actions_taken', 'changes_made', 'rollback_data', 'safety_assessment');
            foreach ($json_fields as $field) {
                if (isset($fix[$field])) {
                    $fix[$field] = json_decode($fix[$field], true);
                }
            }
        }

        return $history;
    }

    /**
     * Get fix settings.
     *
     * @since    1.0.0
     * @return   array    Fix settings.
     */
    private function get_fix_settings() {
        $default_settings = array(
            'auto_fix_enabled' => false,
            'auto_fix_severity_threshold' => 'medium',
            'backup_retention_days' => 30,
            'safety_threshold' => 0.7,
            'notification_email' => get_option('admin_email'),
            'max_fixes_per_batch' => 5,
            'fix_scheduling_enabled' => false,
            'fix_schedule_time' => '02:00'
        );

        $settings = get_option('wp_breach_fix_settings', $default_settings);
        return array_merge($default_settings, $settings);
    }

    /**
     * Update fix settings.
     *
     * @since    1.0.0
     * @param    array    $settings    New settings.
     */
    private function update_fix_settings($settings) {
        $current_settings = $this->get_fix_settings();
        
        // Validate and sanitize settings
        $valid_settings = array();
        
        $valid_settings['auto_fix_enabled'] = isset($settings['auto_fix_enabled']) ? 
                                             (bool) $settings['auto_fix_enabled'] : 
                                             $current_settings['auto_fix_enabled'];

        $valid_settings['auto_fix_severity_threshold'] = isset($settings['auto_fix_severity_threshold']) && 
                                                        in_array($settings['auto_fix_severity_threshold'], array('low', 'medium', 'high', 'critical')) ?
                                                        $settings['auto_fix_severity_threshold'] :
                                                        $current_settings['auto_fix_severity_threshold'];

        $valid_settings['backup_retention_days'] = isset($settings['backup_retention_days']) && 
                                                  is_numeric($settings['backup_retention_days']) && 
                                                  $settings['backup_retention_days'] > 0 ?
                                                  intval($settings['backup_retention_days']) :
                                                  $current_settings['backup_retention_days'];

        $valid_settings['safety_threshold'] = isset($settings['safety_threshold']) && 
                                             is_numeric($settings['safety_threshold']) && 
                                             $settings['safety_threshold'] >= 0 && 
                                             $settings['safety_threshold'] <= 1 ?
                                             floatval($settings['safety_threshold']) :
                                             $current_settings['safety_threshold'];

        $valid_settings['notification_email'] = isset($settings['notification_email']) && 
                                               is_email($settings['notification_email']) ?
                                               sanitize_email($settings['notification_email']) :
                                               $current_settings['notification_email'];

        $valid_settings['max_fixes_per_batch'] = isset($settings['max_fixes_per_batch']) && 
                                               is_numeric($settings['max_fixes_per_batch']) && 
                                               $settings['max_fixes_per_batch'] > 0 && 
                                               $settings['max_fixes_per_batch'] <= 20 ?
                                               intval($settings['max_fixes_per_batch']) :
                                               $current_settings['max_fixes_per_batch'];

        $valid_settings['fix_scheduling_enabled'] = isset($settings['fix_scheduling_enabled']) ? 
                                                   (bool) $settings['fix_scheduling_enabled'] : 
                                                   $current_settings['fix_scheduling_enabled'];

        $valid_settings['fix_schedule_time'] = isset($settings['fix_schedule_time']) && 
                                             preg_match('/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/', $settings['fix_schedule_time']) ?
                                             sanitize_text_field($settings['fix_schedule_time']) :
                                             $current_settings['fix_schedule_time'];

        update_option('wp_breach_fix_settings', $valid_settings);
    }

    /**
     * Get fix status badge HTML.
     *
     * @since    1.0.0
     * @param    string   $status   Fix status.
     * @return   string             HTML badge.
     */
    public function get_fix_status_badge($status) {
        $badges = array(
            'pending' => '<span class="wp-breach-badge wp-breach-badge-warning">' . __('Pending', 'wp-breach') . '</span>',
            'in_progress' => '<span class="wp-breach-badge wp-breach-badge-info">' . __('In Progress', 'wp-breach') . '</span>',
            'completed' => '<span class="wp-breach-badge wp-breach-badge-success">' . __('Completed', 'wp-breach') . '</span>',
            'failed' => '<span class="wp-breach-badge wp-breach-badge-error">' . __('Failed', 'wp-breach') . '</span>',
            'rolled_back' => '<span class="wp-breach-badge wp-breach-badge-secondary">' . __('Rolled Back', 'wp-breach') . '</span>'
        );

        return isset($badges[$status]) ? $badges[$status] : '<span class="wp-breach-badge wp-breach-badge-default">' . esc_html($status) . '</span>';
    }

    /**
     * Get severity badge HTML.
     *
     * @since    1.0.0
     * @param    string   $severity   Severity level.
     * @return   string               HTML badge.
     */
    public function get_severity_badge($severity) {
        $badges = array(
            'low' => '<span class="wp-breach-badge wp-breach-badge-low">' . __('Low', 'wp-breach') . '</span>',
            'medium' => '<span class="wp-breach-badge wp-breach-badge-medium">' . __('Medium', 'wp-breach') . '</span>',
            'high' => '<span class="wp-breach-badge wp-breach-badge-high">' . __('High', 'wp-breach') . '</span>',
            'critical' => '<span class="wp-breach-badge wp-breach-badge-critical">' . __('Critical', 'wp-breach') . '</span>'
        );

        return isset($badges[$severity]) ? $badges[$severity] : '<span class="wp-breach-badge wp-breach-badge-default">' . esc_html($severity) . '</span>';
    }

    /**
     * Get safety score badge HTML.
     *
     * @since    1.0.0
     * @param    float    $score   Safety score (0-1).
     * @return   string            HTML badge.
     */
    public function get_safety_score_badge($score) {
        if ($score >= 0.8) {
            $class = 'wp-breach-badge-success';
            $text = __('Very Safe', 'wp-breach');
        } elseif ($score >= 0.6) {
            $class = 'wp-breach-badge-warning';
            $text = __('Moderately Safe', 'wp-breach');
        } else {
            $class = 'wp-breach-badge-error';
            $text = __('High Risk', 'wp-breach');
        }

        return '<span class="wp-breach-badge ' . $class . '">' . $text . ' (' . round($score * 100) . '%)</span>';
    }

    /**
     * Format time difference for display.
     *
     * @since    1.0.0
     * @param    string   $datetime   Datetime string.
     * @return   string               Formatted time difference.
     */
    public function time_ago($datetime) {
        if (empty($datetime)) {
            return __('Never', 'wp-breach');
        }

        $time = time() - strtotime($datetime);

        if ($time < 60) {
            return __('Just now', 'wp-breach');
        }

        $tokens = array(
            31536000 => __('year', 'wp-breach'),
            2592000 => __('month', 'wp-breach'),
            604800 => __('week', 'wp-breach'),
            86400 => __('day', 'wp-breach'),
            3600 => __('hour', 'wp-breach'),
            60 => __('minute', 'wp-breach')
        );

        foreach ($tokens as $unit => $text) {
            if ($time >= $unit) {
                $numberOfUnits = floor($time / $unit);
                return sprintf(
                    _n('%d %s ago', '%d %s ago', $numberOfUnits, 'wp-breach'),
                    $numberOfUnits,
                    $text
                );
            }
        }

        return __('Just now', 'wp-breach');
    }

    /**
     * Display fix actions for vulnerability.
     *
     * @since    1.0.0
     * @param    array    $vulnerability   Vulnerability data.
     * @return   string                    HTML for fix actions.
     */
    public function get_fix_actions_html($vulnerability) {
        $html = '<div class="wp-breach-fix-actions">';

        if ($vulnerability['can_auto_fix']) {
            $safety_score = $vulnerability['safety_assessment']['safety_score'];
            $disabled = $safety_score < 0.5 ? 'disabled' : '';
            
            $html .= sprintf(
                '<button class="button button-primary wp-breach-apply-fix" data-vulnerability-id="%d" %s>%s</button>',
                $vulnerability['id'],
                $disabled,
                __('Apply Auto Fix', 'wp-breach')
            );

            if ($disabled) {
                $html .= '<p class="description">' . __('Automatic fix disabled due to low safety score.', 'wp-breach') . '</p>';
            }
        }

        $html .= sprintf(
            '<button class="button wp-breach-get-manual-guidance" data-vulnerability-id="%d">%s</button>',
            $vulnerability['id'],
            __('Manual Guidance', 'wp-breach')
        );

        $html .= '</div>';

        return $html;
    }

    /**
     * Display fix history actions.
     *
     * @since    1.0.0
     * @param    array    $fix   Fix data.
     * @return   string           HTML for history actions.
     */
    public function get_fix_history_actions_html($fix) {
        $html = '<div class="wp-breach-fix-history-actions">';

        if ($fix['status'] === 'completed' && !empty($fix['rollback_data'])) {
            $html .= sprintf(
                '<button class="button wp-breach-rollback-fix" data-fix-id="%s">%s</button>',
                esc_attr($fix['fix_id']),
                __('Rollback', 'wp-breach')
            );
        }

        if (!empty($fix['backup_id'])) {
            $html .= sprintf(
                '<a href="%s" class="button">%s</a>',
                admin_url('admin.php?page=wp-breach-backups&backup_id=' . urlencode($fix['backup_id'])),
                __('View Backup', 'wp-breach')
            );
        }

        $html .= '</div>';

        return $html;
    }

    /**
     * Display fix statistics dashboard widget.
     *
     * @since    1.0.0
     * @return   string    HTML for statistics widget.
     */
    public function get_fix_statistics_widget() {
        global $wpdb;
        
        $fixes_table = $wpdb->prefix . 'breach_fixes';
        
        $stats = array(
            'total_fixes' => $wpdb->get_var("SELECT COUNT(*) FROM {$fixes_table}"),
            'successful_fixes' => $wpdb->get_var("SELECT COUNT(*) FROM {$fixes_table} WHERE status = 'completed'"),
            'failed_fixes' => $wpdb->get_var("SELECT COUNT(*) FROM {$fixes_table} WHERE status = 'failed'"),
            'pending_fixes' => $wpdb->get_var("SELECT COUNT(*) FROM {$fixes_table} WHERE status = 'pending'"),
            'recent_fixes' => $wpdb->get_var("SELECT COUNT(*) FROM {$fixes_table} WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)")
        );

        $success_rate = $stats['total_fixes'] > 0 ? 
                       round(($stats['successful_fixes'] / $stats['total_fixes']) * 100, 1) : 
                       0;

        ob_start();
        ?>
        <div class="wp-breach-fix-stats-widget">
            <h3><?php _e('Fix Statistics', 'wp-breach'); ?></h3>
            <div class="wp-breach-stats-grid">
                <div class="wp-breach-stat">
                    <span class="wp-breach-stat-number"><?php echo esc_html($stats['total_fixes']); ?></span>
                    <span class="wp-breach-stat-label"><?php _e('Total Fixes', 'wp-breach'); ?></span>
                </div>
                <div class="wp-breach-stat">
                    <span class="wp-breach-stat-number"><?php echo esc_html($stats['successful_fixes']); ?></span>
                    <span class="wp-breach-stat-label"><?php _e('Successful', 'wp-breach'); ?></span>
                </div>
                <div class="wp-breach-stat">
                    <span class="wp-breach-stat-number"><?php echo esc_html($stats['failed_fixes']); ?></span>
                    <span class="wp-breach-stat-label"><?php _e('Failed', 'wp-breach'); ?></span>
                </div>
                <div class="wp-breach-stat">
                    <span class="wp-breach-stat-number"><?php echo esc_html($success_rate); ?>%</span>
                    <span class="wp-breach-stat-label"><?php _e('Success Rate', 'wp-breach'); ?></span>
                </div>
            </div>
            <p class="wp-breach-stats-summary">
                <?php 
                printf(
                    __('%d fixes applied in the last 7 days', 'wp-breach'),
                    $stats['recent_fixes']
                ); 
                ?>
            </p>
        </div>
        <?php
        return ob_get_clean();
    }
}
