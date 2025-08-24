<?php

/**
 * Dashboard Alert Channel for WP-Breach.
 *
 * This class handles displaying security alerts in the WordPress admin dashboard
 * with real-time updates, persistent notifications, and interactive features.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/monitoring/channels
 */

/**
 * The dashboard alert channel class.
 *
 * Manages dashboard alert display including admin notices, dashboard widgets,
 * notification badges, and real-time alert updates.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/monitoring/channels
 * @author     WP Breach Team
 */
class WP_Breach_Dashboard_Alert_Channel {

    /**
     * Dashboard configuration.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $config    Dashboard configuration.
     */
    private $config;

    /**
     * Alert templates.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $templates    Alert display templates.
     */
    private $templates;

    /**
     * Active alerts cache.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $active_alerts    Currently active alerts.
     */
    private $active_alerts;

    /**
     * Dashboard widgets.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $widgets    Dashboard widget configuration.
     */
    private $widgets;

    /**
     * Initialize the dashboard alert channel.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->setup_config();
        $this->setup_templates();
        $this->setup_widgets();
        $this->active_alerts = array();
        
        // Register hooks
        $this->register_hooks();
    }

    /**
     * Setup dashboard configuration.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_config() {
        $this->config = array(
            'enabled' => true,
            'admin_notices' => true,
            'dashboard_widget' => true,
            'notification_badge' => true,
            'real_time_updates' => true,
            'auto_refresh_interval' => 30, // seconds
            'max_notices' => 3,
            'notice_persistence' => 24 * HOUR_IN_SECONDS,
            'dismissible_notices' => true,
            'severity_colors' => array(
                'critical' => '#d73527',
                'high' => '#ff6b35',
                'medium' => '#f7931e',
                'low' => '#2e8b57'
            ),
            'icon_mapping' => array(
                'malware_detected' => '🦠',
                'brute_force_attack' => '🔨',
                'file_integrity_violation' => '📁',
                'suspicious_activity' => '👁️',
                'vulnerability_detected' => '🛡️',
                'configuration_change' => '⚙️',
                'unauthorized_access' => '🚫',
                'system_compromise' => '💥',
                'data_breach' => '💾',
                'anomaly_detected' => '📊'
            ),
            'sound_alerts' => false,
            'desktop_notifications' => false,
            'alert_grouping' => true,
            'quick_actions' => true,
            'alert_details_modal' => true,
            'bulk_actions' => true
        );
    }

    /**
     * Setup alert templates.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_templates() {
        $this->templates = array(
            'admin_notice' => $this->get_admin_notice_template(),
            'dashboard_widget' => $this->get_dashboard_widget_template(),
            'notification_badge' => $this->get_notification_badge_template(),
            'alert_modal' => $this->get_alert_modal_template(),
            'alert_row' => $this->get_alert_row_template()
        );
    }

    /**
     * Setup dashboard widgets.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_widgets() {
        $this->widgets = array(
            'security_alerts' => array(
                'title' => 'Security Alerts',
                'callback' => array($this, 'render_security_alerts_widget'),
                'position' => 'normal',
                'priority' => 'high'
            ),
            'security_summary' => array(
                'title' => 'Security Summary',
                'callback' => array($this, 'render_security_summary_widget'),
                'position' => 'side',
                'priority' => 'high'
            ),
            'recent_activity' => array(
                'title' => 'Recent Security Activity',
                'callback' => array($this, 'render_recent_activity_widget'),
                'position' => 'normal',
                'priority' => 'low'
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
        // Admin notices
        add_action('admin_notices', array($this, 'display_admin_notices'));
        add_action('network_admin_notices', array($this, 'display_admin_notices'));
        
        // Dashboard widgets
        add_action('wp_dashboard_setup', array($this, 'setup_dashboard_widgets'));
        
        // AJAX handlers
        add_action('wp_ajax_wp_breach_dismiss_alert', array($this, 'handle_dismiss_alert'));
        add_action('wp_ajax_wp_breach_acknowledge_alert', array($this, 'handle_acknowledge_alert'));
        add_action('wp_ajax_wp_breach_get_alerts', array($this, 'handle_get_alerts'));
        add_action('wp_ajax_wp_breach_resolve_alert', array($this, 'handle_resolve_alert'));
        add_action('wp_ajax_wp_breach_bulk_action', array($this, 'handle_bulk_action'));
        
        // Enqueue scripts and styles
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_assets'));
        
        // Admin menu badge
        add_action('admin_menu', array($this, 'add_notification_badges'), 999);
        
        // Real-time updates
        if ($this->config['real_time_updates']) {
            add_action('wp_ajax_wp_breach_check_new_alerts', array($this, 'handle_check_new_alerts'));
        }
        
        // Cleanup
        add_action('wp_breach_cleanup_dashboard_alerts', array($this, 'cleanup_old_notices'));
    }

    /**
     * Send alert to dashboard.
     *
     * @since    1.0.0
     * @param    array    $alert          Alert data.
     * @param    string   $delivery_mode  Delivery mode (immediate, persistent).
     * @return   array                    Send result.
     */
    public function send_alert($alert, $delivery_mode = 'immediate') {
        try {
            if (!$this->config['enabled']) {
                return array(
                    'success' => false,
                    'error' => 'Dashboard channel disabled'
                );
            }
            
            switch ($delivery_mode) {
                case 'immediate':
                    return $this->add_immediate_alert($alert);
                    
                case 'persistent':
                    return $this->add_persistent_alert($alert);
                    
                default:
                    return array(
                        'success' => false,
                        'error' => 'Invalid delivery mode'
                    );
            }

        } catch (Exception $e) {
            error_log("WP-Breach Dashboard Alert Error: " . $e->getMessage());
            return array(
                'success' => false,
                'error' => $e->getMessage()
            );
        }
    }

    /**
     * Add immediate alert to dashboard.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $alert    Alert data.
     * @return   array             Result.
     */
    private function add_immediate_alert($alert) {
        // Store alert for admin notices
        $dashboard_alerts = get_option('wp_breach_dashboard_alerts', array());
        
        // Check if alert already exists
        $alert_key = $this->generate_alert_key($alert);
        if (isset($dashboard_alerts[$alert_key])) {
            // Update existing alert
            $dashboard_alerts[$alert_key]['count']++;
            $dashboard_alerts[$alert_key]['last_occurrence'] = current_time('mysql');
        } else {
            // Add new alert
            $dashboard_alerts[$alert_key] = array(
                'id' => $alert['id'],
                'type' => $alert['type'],
                'severity' => $alert['severity'],
                'title' => $alert['title'],
                'message' => $alert['message'],
                'details' => $alert['details'] ?? array(),
                'created_at' => $alert['created_at'],
                'last_occurrence' => current_time('mysql'),
                'count' => 1,
                'dismissed' => false,
                'acknowledged' => false,
                'expires_at' => date('Y-m-d H:i:s', time() + $this->config['notice_persistence'])
            );
        }
        
        update_option('wp_breach_dashboard_alerts', $dashboard_alerts);
        
        // Update notification badge count
        $this->update_notification_badge();
        
        // Trigger real-time update
        if ($this->config['real_time_updates']) {
            $this->trigger_real_time_update($alert);
        }
        
        return array(
            'success' => true,
            'alert_key' => $alert_key,
            'message' => 'Alert added to dashboard'
        );
    }

    /**
     * Add persistent alert to dashboard.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $alert    Alert data.
     * @return   array             Result.
     */
    private function add_persistent_alert($alert) {
        // Same as immediate but with longer persistence
        $result = $this->add_immediate_alert($alert);
        
        if ($result['success']) {
            $dashboard_alerts = get_option('wp_breach_dashboard_alerts', array());
            $alert_key = $result['alert_key'];
            
            // Extend expiration for persistent alerts
            $dashboard_alerts[$alert_key]['expires_at'] = date('Y-m-d H:i:s', time() + (7 * DAY_IN_SECONDS));
            $dashboard_alerts[$alert_key]['persistent'] = true;
            
            update_option('wp_breach_dashboard_alerts', $dashboard_alerts);
        }
        
        return $result;
    }

    /**
     * Display admin notices.
     *
     * @since    1.0.0
     */
    public function display_admin_notices() {
        if (!$this->config['admin_notices'] || !current_user_can('manage_options')) {
            return;
        }
        
        $dashboard_alerts = get_option('wp_breach_dashboard_alerts', array());
        $displayed_count = 0;
        
        foreach ($dashboard_alerts as $alert_key => $alert) {
            // Skip dismissed alerts
            if ($alert['dismissed']) {
                continue;
            }
            
            // Skip expired alerts
            if (strtotime($alert['expires_at']) < time()) {
                continue;
            }
            
            // Limit number of notices
            if ($displayed_count >= $this->config['max_notices']) {
                break;
            }
            
            $this->render_admin_notice($alert, $alert_key);
            $displayed_count++;
        }
    }

    /**
     * Render admin notice.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $alert       Alert data.
     * @param    string   $alert_key   Alert key.
     */
    private function render_admin_notice($alert, $alert_key) {
        $severity_class = 'notice-' . ($alert['severity'] === 'critical' ? 'error' : 'warning');
        $dismissible_class = $this->config['dismissible_notices'] ? 'is-dismissible' : '';
        $icon = $this->config['icon_mapping'][$alert['type']] ?? '⚠️';
        
        echo '<div class="notice ' . $severity_class . ' ' . $dismissible_class . ' wp-breach-alert-notice" data-alert-key="' . esc_attr($alert_key) . '">';
        echo '<div class="wp-breach-notice-content">';
        
        // Alert header
        echo '<div class="wp-breach-notice-header">';
        echo '<span class="wp-breach-alert-icon">' . $icon . '</span>';
        echo '<strong>' . esc_html($alert['title']) . '</strong>';
        
        if ($alert['count'] > 1) {
            echo ' <span class="wp-breach-alert-count">(' . $alert['count'] . ' occurrences)</span>';
        }
        
        echo '<span class="wp-breach-alert-severity wp-breach-severity-' . $alert['severity'] . '">' . strtoupper($alert['severity']) . '</span>';
        echo '</div>';
        
        // Alert message
        echo '<div class="wp-breach-notice-message">';
        echo '<p>' . esc_html($alert['message']) . '</p>';
        echo '</div>';
        
        // Alert actions
        if ($this->config['quick_actions']) {
            echo '<div class="wp-breach-notice-actions">';
            echo '<a href="#" class="button button-small wp-breach-acknowledge-alert" data-alert-id="' . $alert['id'] . '">Acknowledge</a>';
            echo '<a href="#" class="button button-small wp-breach-view-details" data-alert-id="' . $alert['id'] . '">View Details</a>';
            echo '<a href="' . admin_url('admin.php?page=wp-breach-alerts&alert=' . $alert['id']) . '" class="button button-primary button-small">Manage</a>';
            echo '</div>';
        }
        
        echo '</div>';
        echo '</div>';
    }

    /**
     * Setup dashboard widgets.
     *
     * @since    1.0.0
     */
    public function setup_dashboard_widgets() {
        if (!$this->config['dashboard_widget'] || !current_user_can('manage_options')) {
            return;
        }
        
        foreach ($this->widgets as $widget_id => $widget) {
            wp_add_dashboard_widget(
                'wp_breach_' . $widget_id,
                $widget['title'],
                $widget['callback']
            );
        }
    }

    /**
     * Render security alerts widget.
     *
     * @since    1.0.0
     */
    public function render_security_alerts_widget() {
        $recent_alerts = $this->get_recent_alerts(5);
        
        echo '<div class="wp-breach-dashboard-widget">';
        
        if (empty($recent_alerts)) {
            echo '<div class="wp-breach-no-alerts">';
            echo '<span class="dashicons dashicons-shield-alt" style="color: #46b450; font-size: 24px;"></span>';
            echo '<p><strong>No recent security alerts</strong></p>';
            echo '<p>Your site security is currently stable.</p>';
            echo '</div>';
        } else {
            echo '<div class="wp-breach-alerts-list">';
            
            foreach ($recent_alerts as $alert) {
                $this->render_widget_alert_item($alert);
            }
            
            echo '</div>';
            
            // View all link
            echo '<div class="wp-breach-widget-footer">';
            echo '<a href="' . admin_url('admin.php?page=wp-breach-alerts') . '" class="button">View All Alerts</a>';
            echo '</div>';
        }
        
        echo '</div>';
    }

    /**
     * Render security summary widget.
     *
     * @since    1.0.0
     */
    public function render_security_summary_widget() {
        $summary = $this->get_security_summary();
        
        echo '<div class="wp-breach-summary-widget">';
        
        // Security status indicator
        $status_class = $summary['critical_alerts'] > 0 ? 'critical' : 
                       ($summary['high_alerts'] > 0 ? 'warning' : 'ok');
        
        echo '<div class="wp-breach-status-indicator ' . $status_class . '">';
        echo '<div class="status-icon">';
        if ($status_class === 'critical') {
            echo '🚨';
        } elseif ($status_class === 'warning') {
            echo '⚠️';
        } else {
            echo '✅';
        }
        echo '</div>';
        echo '<div class="status-text">';
        echo '<strong>' . $this->get_status_text($status_class) . '</strong>';
        echo '</div>';
        echo '</div>';
        
        // Summary stats
        echo '<div class="wp-breach-summary-stats">';
        echo '<div class="stat-item">';
        echo '<span class="stat-number">' . $summary['total_alerts_24h'] . '</span>';
        echo '<span class="stat-label">Alerts (24h)</span>';
        echo '</div>';
        
        echo '<div class="stat-item">';
        echo '<span class="stat-number">' . $summary['active_threats'] . '</span>';
        echo '<span class="stat-label">Active Threats</span>';
        echo '</div>';
        
        echo '<div class="stat-item">';
        echo '<span class="stat-number">' . $summary['files_monitored'] . '</span>';
        echo '<span class="stat-label">Files Monitored</span>';
        echo '</div>';
        echo '</div>';
        
        // Quick actions
        echo '<div class="wp-breach-quick-actions">';
        echo '<a href="' . admin_url('admin.php?page=wp-breach-scan') . '" class="button button-secondary">Run Scan</a>';
        echo '<a href="' . admin_url('admin.php?page=wp-breach-dashboard') . '" class="button button-primary">Dashboard</a>';
        echo '</div>';
        
        echo '</div>';
    }

    /**
     * Render recent activity widget.
     *
     * @since    1.0.0
     */
    public function render_recent_activity_widget() {
        $recent_activity = $this->get_recent_activity(10);
        
        echo '<div class="wp-breach-activity-widget">';
        
        if (empty($recent_activity)) {
            echo '<p>No recent security activity.</p>';
        } else {
            echo '<ul class="wp-breach-activity-list">';
            
            foreach ($recent_activity as $activity) {
                echo '<li class="activity-item">';
                echo '<span class="activity-icon">' . $this->get_activity_icon($activity['type']) . '</span>';
                echo '<span class="activity-text">' . esc_html($activity['description']) . '</span>';
                echo '<span class="activity-time">' . human_time_diff(strtotime($activity['timestamp'])) . ' ago</span>';
                echo '</li>';
            }
            
            echo '</ul>';
        }
        
        echo '</div>';
    }

    /**
     * Enqueue admin assets.
     *
     * @since    1.0.0
     * @param    string   $hook    Current admin page hook.
     */
    public function enqueue_admin_assets($hook) {
        // Enqueue on all admin pages for notices
        wp_enqueue_style(
            'wp-breach-dashboard-alerts',
            plugins_url('assets/css/dashboard-alerts.css', dirname(dirname(__FILE__))),
            array(),
            WP_BREACH_VERSION
        );
        
        wp_enqueue_script(
            'wp-breach-dashboard-alerts',
            plugins_url('assets/js/dashboard-alerts.js', dirname(dirname(__FILE__))),
            array('jquery'),
            WP_BREACH_VERSION,
            true
        );
        
        // Localize script
        wp_localize_script('wp-breach-dashboard-alerts', 'wpBreachDashboard', array(
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('wp_breach_dashboard'),
            'autoRefresh' => $this->config['real_time_updates'],
            'refreshInterval' => $this->config['auto_refresh_interval'] * 1000,
            'soundAlerts' => $this->config['sound_alerts'],
            'desktopNotifications' => $this->config['desktop_notifications']
        ));
    }

    /**
     * Add notification badges to admin menu.
     *
     * @since    1.0.0
     */
    public function add_notification_badges() {
        if (!$this->config['notification_badge'] || !current_user_can('manage_options')) {
            return;
        }
        
        global $menu, $submenu;
        
        $alert_count = $this->get_unacknowledged_alert_count();
        
        if ($alert_count > 0) {
            // Find WP-Breach menu item and add badge
            foreach ($menu as $key => $menu_item) {
                if (isset($menu_item[2]) && strpos($menu_item[2], 'wp-breach') !== false) {
                    $menu[$key][0] .= ' <span class="awaiting-mod">' . $alert_count . '</span>';
                    break;
                }
            }
        }
    }

    /**
     * Handle dismiss alert AJAX request.
     *
     * @since    1.0.0
     */
    public function handle_dismiss_alert() {
        check_ajax_referer('wp_breach_dashboard', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die(-1);
        }
        
        $alert_key = sanitize_text_field($_POST['alert_key'] ?? '');
        
        if (empty($alert_key)) {
            wp_send_json_error('Invalid alert key');
        }
        
        $dashboard_alerts = get_option('wp_breach_dashboard_alerts', array());
        
        if (isset($dashboard_alerts[$alert_key])) {
            $dashboard_alerts[$alert_key]['dismissed'] = true;
            $dashboard_alerts[$alert_key]['dismissed_at'] = current_time('mysql');
            $dashboard_alerts[$alert_key]['dismissed_by'] = get_current_user_id();
            
            update_option('wp_breach_dashboard_alerts', $dashboard_alerts);
            
            // Update notification badge
            $this->update_notification_badge();
            
            wp_send_json_success('Alert dismissed');
        } else {
            wp_send_json_error('Alert not found');
        }
    }

    /**
     * Handle acknowledge alert AJAX request.
     *
     * @since    1.0.0
     */
    public function handle_acknowledge_alert() {
        check_ajax_referer('wp_breach_dashboard', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die(-1);
        }
        
        $alert_id = intval($_POST['alert_id'] ?? 0);
        
        if (!$alert_id) {
            wp_send_json_error('Invalid alert ID');
        }
        
        // Update alert in database
        $alert_manager = new WP_Breach_Alert_Manager();
        $alert_manager->handle_alert_acknowledgment($alert_id);
        
        // Update dashboard alerts
        $dashboard_alerts = get_option('wp_breach_dashboard_alerts', array());
        foreach ($dashboard_alerts as $key => &$alert) {
            if ($alert['id'] == $alert_id) {
                $alert['acknowledged'] = true;
                $alert['acknowledged_at'] = current_time('mysql');
                $alert['acknowledged_by'] = get_current_user_id();
                break;
            }
        }
        
        update_option('wp_breach_dashboard_alerts', $dashboard_alerts);
        
        wp_send_json_success('Alert acknowledged');
    }

    /**
     * Handle get alerts AJAX request.
     *
     * @since    1.0.0
     */
    public function handle_get_alerts() {
        check_ajax_referer('wp_breach_dashboard', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die(-1);
        }
        
        $alerts = $this->get_recent_alerts(20);
        $alert_count = $this->get_unacknowledged_alert_count();
        
        wp_send_json_success(array(
            'alerts' => $alerts,
            'count' => $alert_count,
            'timestamp' => current_time('mysql')
        ));
    }

    /**
     * Handle check new alerts AJAX request.
     *
     * @since    1.0.0
     */
    public function handle_check_new_alerts() {
        check_ajax_referer('wp_breach_dashboard', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die(-1);
        }
        
        $last_check = sanitize_text_field($_POST['last_check'] ?? '');
        $new_alerts = $this->get_alerts_since($last_check);
        
        wp_send_json_success(array(
            'new_alerts' => $new_alerts,
            'count' => count($new_alerts),
            'timestamp' => current_time('mysql')
        ));
    }

    // Template methods
    
    private function get_admin_notice_template() {
        return '<div class="notice {severity_class} {dismissible_class} wp-breach-alert-notice" data-alert-key="{alert_key}">
                    <div class="wp-breach-notice-content">
                        <div class="wp-breach-notice-header">
                            <span class="wp-breach-alert-icon">{icon}</span>
                            <strong>{title}</strong>
                            {count_badge}
                            <span class="wp-breach-alert-severity wp-breach-severity-{severity}">{severity_upper}</span>
                        </div>
                        <div class="wp-breach-notice-message">
                            <p>{message}</p>
                        </div>
                        {actions}
                    </div>
                </div>';
    }

    private function get_dashboard_widget_template() {
        return '<div class="wp-breach-dashboard-widget">{content}</div>';
    }

    private function get_notification_badge_template() {
        return '<span class="awaiting-mod">{count}</span>';
    }

    private function get_alert_modal_template() {
        return '<div id="wp-breach-alert-modal" class="wp-breach-modal">
                    <div class="wp-breach-modal-content">
                        <div class="wp-breach-modal-header">
                            <h3>{title}</h3>
                            <span class="wp-breach-modal-close">&times;</span>
                        </div>
                        <div class="wp-breach-modal-body">
                            {content}
                        </div>
                        <div class="wp-breach-modal-footer">
                            {actions}
                        </div>
                    </div>
                </div>';
    }

    private function get_alert_row_template() {
        return '<div class="wp-breach-alert-row wp-breach-severity-{severity}">
                    <div class="alert-icon">{icon}</div>
                    <div class="alert-content">
                        <div class="alert-title">{title}</div>
                        <div class="alert-message">{message}</div>
                        <div class="alert-meta">
                            <span class="alert-time">{time}</span>
                            <span class="alert-type">{type}</span>
                        </div>
                    </div>
                    <div class="alert-actions">{actions}</div>
                </div>';
    }

    // Helper methods
    
    private function generate_alert_key($alert) {
        return md5($alert['type'] . '_' . $alert['title'] . '_' . date('Y-m-d'));
    }

    private function update_notification_badge() {
        $count = $this->get_unacknowledged_alert_count();
        update_option('wp_breach_notification_count', $count);
    }

    private function get_unacknowledged_alert_count() {
        $dashboard_alerts = get_option('wp_breach_dashboard_alerts', array());
        $count = 0;
        
        foreach ($dashboard_alerts as $alert) {
            if (!$alert['dismissed'] && !$alert['acknowledged'] && strtotime($alert['expires_at']) > time()) {
                $count++;
            }
        }
        
        return $count;
    }

    private function get_recent_alerts($limit = 10) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_alerts';
        
        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$table_name} 
             WHERE created_at >= %s 
             ORDER BY created_at DESC 
             LIMIT %d",
            date('Y-m-d H:i:s', strtotime('-24 hours')),
            $limit
        ));
    }

    private function get_security_summary() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_alerts';
        
        // Get alert counts by severity for last 24 hours
        $alert_counts = $wpdb->get_results($wpdb->prepare(
            "SELECT severity, COUNT(*) as count 
             FROM {$table_name} 
             WHERE created_at >= %s 
             GROUP BY severity",
            date('Y-m-d H:i:s', strtotime('-24 hours'))
        ));
        
        $summary = array(
            'total_alerts_24h' => 0,
            'critical_alerts' => 0,
            'high_alerts' => 0,
            'medium_alerts' => 0,
            'low_alerts' => 0,
            'active_threats' => 0,
            'files_monitored' => 0
        );
        
        foreach ($alert_counts as $count) {
            $summary['total_alerts_24h'] += $count->count;
            $summary[$count->severity . '_alerts'] = $count->count;
        }
        
        // Get active threats (unresolved critical/high alerts)
        $summary['active_threats'] = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table_name} 
             WHERE status IN ('new', 'acknowledged') 
             AND severity IN ('critical', 'high')"
        ));
        
        // Get monitored files count (placeholder)
        $summary['files_monitored'] = get_option('wp_breach_monitored_files_count', 0);
        
        return $summary;
    }

    private function get_recent_activity($limit = 10) {
        // Placeholder for recent activity
        return array();
    }

    private function get_alerts_since($timestamp) {
        if (empty($timestamp)) {
            return array();
        }
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'breach_alerts';
        
        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$table_name} 
             WHERE created_at > %s 
             ORDER BY created_at DESC",
            $timestamp
        ));
    }

    private function render_widget_alert_item($alert) {
        $icon = $this->config['icon_mapping'][$alert->type] ?? '⚠️';
        $severity_color = $this->config['severity_colors'][$alert->severity] ?? '#666';
        
        echo '<div class="wp-breach-widget-alert-item" style="border-left: 3px solid ' . $severity_color . ';">';
        echo '<div class="alert-header">';
        echo '<span class="alert-icon">' . $icon . '</span>';
        echo '<strong>' . esc_html($alert->title) . '</strong>';
        echo '<span class="alert-time">' . human_time_diff(strtotime($alert->created_at)) . ' ago</span>';
        echo '</div>';
        echo '<div class="alert-message">' . esc_html($alert->message) . '</div>';
        echo '</div>';
    }

    private function get_status_text($status) {
        $status_texts = array(
            'critical' => 'Security Issues Detected',
            'warning' => 'Monitoring Active',
            'ok' => 'All Systems Normal'
        );
        
        return $status_texts[$status] ?? 'Unknown Status';
    }

    private function get_activity_icon($type) {
        $icons = array(
            'scan_completed' => '🔍',
            'threat_blocked' => '🛡️',
            'file_quarantined' => '🗂️',
            'user_blocked' => '🚫',
            'update_applied' => '🔄'
        );
        
        return $icons[$type] ?? '📋';
    }

    private function trigger_real_time_update($alert) {
        // Store update flag for real-time checking
        update_option('wp_breach_new_alert_timestamp', current_time('mysql'));
        
        // Could integrate with WebSocket or Server-Sent Events here
        do_action('wp_breach_real_time_alert', $alert);
    }

    public function cleanup_old_notices() {
        $dashboard_alerts = get_option('wp_breach_dashboard_alerts', array());
        $updated = false;
        
        foreach ($dashboard_alerts as $key => $alert) {
            // Remove expired alerts
            if (strtotime($alert['expires_at']) < time()) {
                unset($dashboard_alerts[$key]);
                $updated = true;
            }
        }
        
        if ($updated) {
            update_option('wp_breach_dashboard_alerts', $dashboard_alerts);
            $this->update_notification_badge();
        }
    }

    // Additional AJAX handlers...
    
    public function handle_resolve_alert() {
        check_ajax_referer('wp_breach_dashboard', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die(-1);
        }
        
        $alert_id = intval($_POST['alert_id'] ?? 0);
        $resolution = sanitize_textarea_field($_POST['resolution'] ?? '');
        
        if (!$alert_id) {
            wp_send_json_error('Invalid alert ID');
        }
        
        $alert_manager = new WP_Breach_Alert_Manager();
        $alert_manager->handle_alert_resolution($alert_id, $resolution);
        
        wp_send_json_success('Alert resolved');
    }

    public function handle_bulk_action() {
        check_ajax_referer('wp_breach_dashboard', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die(-1);
        }
        
        $action = sanitize_text_field($_POST['action'] ?? '');
        $alert_ids = array_map('intval', $_POST['alert_ids'] ?? array());
        
        if (empty($action) || empty($alert_ids)) {
            wp_send_json_error('Invalid bulk action parameters');
        }
        
        $alert_manager = new WP_Breach_Alert_Manager();
        $processed = 0;
        
        foreach ($alert_ids as $alert_id) {
            switch ($action) {
                case 'acknowledge':
                    $alert_manager->handle_alert_acknowledgment($alert_id);
                    $processed++;
                    break;
                    
                case 'resolve':
                    $alert_manager->handle_alert_resolution($alert_id, 'Bulk resolved');
                    $processed++;
                    break;
            }
        }
        
        wp_send_json_success("Processed {$processed} alerts");
    }
}
