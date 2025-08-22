<?php
/**
 * Admin Dashboard Display Template
 *
 * This file displays the main dashboard interface with security overview,
 * vulnerability widgets, charts, and quick actions.
 *
 * @package WP_Breach
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Initialize dashboard data
$dashboard = new WP_Breach_Admin_Dashboard($this->plugin_name, $this->version);
$dashboard_data = $dashboard->get_dashboard_data();
$widgets = $dashboard->get_dashboard_widgets();
?>

<div class="wrap wp-breach-dashboard">
    <h1 class="wp-heading-inline">
        <?php echo esc_html(get_admin_page_title()); ?>
        <span class="wp-breach-version">v<?php echo esc_html($this->version); ?></span>
    </h1>
    
    <!-- Dashboard Actions -->
    <div class="wp-breach-dashboard-actions">
        <button type="button" class="button button-primary" id="wp-breach-quick-scan">
            <span class="dashicons dashicons-search"></span>
            <?php esc_html_e('Quick Scan', 'wp-breach'); ?>
        </button>
        <button type="button" class="button" id="wp-breach-full-scan">
            <span class="dashicons dashicons-admin-tools"></span>
            <?php esc_html_e('Full Scan', 'wp-breach'); ?>
        </button>
        <button type="button" class="button" id="wp-breach-refresh-data">
            <span class="dashicons dashicons-update"></span>
            <?php esc_html_e('Refresh', 'wp-breach'); ?>
        </button>
    </div>
    
    <hr class="wp-header-end">
    
    <!-- Security Status Overview -->
    <div class="wp-breach-security-overview">
        <div class="wp-breach-status-cards">
            <div class="wp-breach-card wp-breach-card-critical">
                <div class="wp-breach-card-header">
                    <h3><?php esc_html_e('Critical Issues', 'wp-breach'); ?></h3>
                    <span class="wp-breach-card-icon dashicons dashicons-warning"></span>
                </div>
                <div class="wp-breach-card-content">
                    <div class="wp-breach-card-number"><?php echo esc_html($dashboard_data['security_status']['critical']); ?></div>
                    <div class="wp-breach-card-label"><?php esc_html_e('Critical vulnerabilities requiring immediate attention', 'wp-breach'); ?></div>
                </div>
            </div>
            
            <div class="wp-breach-card wp-breach-card-high">
                <div class="wp-breach-card-header">
                    <h3><?php esc_html_e('High Risk', 'wp-breach'); ?></h3>
                    <span class="wp-breach-card-icon dashicons dashicons-flag"></span>
                </div>
                <div class="wp-breach-card-content">
                    <div class="wp-breach-card-number"><?php echo esc_html($dashboard_data['security_status']['high']); ?></div>
                    <div class="wp-breach-card-label"><?php esc_html_e('High priority security issues', 'wp-breach'); ?></div>
                </div>
            </div>
            
            <div class="wp-breach-card wp-breach-card-medium">
                <div class="wp-breach-card-header">
                    <h3><?php esc_html_e('Medium Risk', 'wp-breach'); ?></h3>
                    <span class="dashicons dashicons-info"></span>
                </div>
                <div class="wp-breach-card-content">
                    <div class="wp-breach-card-number"><?php echo esc_html($dashboard_data['security_status']['medium']); ?></div>
                    <div class="wp-breach-card-label"><?php esc_html_e('Medium priority issues to address', 'wp-breach'); ?></div>
                </div>
            </div>
            
            <div class="wp-breach-card wp-breach-card-low">
                <div class="wp-breach-card-header">
                    <h3><?php esc_html_e('Low Risk', 'wp-breach'); ?></h3>
                    <span class="dashicons dashicons-yes-alt"></span>
                </div>
                <div class="wp-breach-card-content">
                    <div class="wp-breach-card-number"><?php echo esc_html($dashboard_data['security_status']['low']); ?></div>
                    <div class="wp-breach-card-label"><?php esc_html_e('Low priority recommendations', 'wp-breach'); ?></div>
                </div>
            </div>
        </div>
        
        <!-- Security Score Widget -->
        <div class="wp-breach-security-score-widget">
            <div class="wp-breach-score-container">
                <div class="wp-breach-score-circle">
                    <div class="wp-breach-score-text">
                        <span class="wp-breach-score-number"><?php echo esc_html($dashboard_data['security_score']); ?></span>
                        <span class="wp-breach-score-label"><?php esc_html_e('Security Score', 'wp-breach'); ?></span>
                    </div>
                </div>
                <div class="wp-breach-score-description">
                    <?php
                    $score = $dashboard_data['security_score'];
                    if ($score >= 80) {
                        echo '<span class="wp-breach-score-good">' . esc_html__('Good security posture', 'wp-breach') . '</span>';
                    } elseif ($score >= 60) {
                        echo '<span class="wp-breach-score-fair">' . esc_html__('Fair security posture', 'wp-breach') . '</span>';
                    } else {
                        echo '<span class="wp-breach-score-poor">' . esc_html__('Poor security posture', 'wp-breach') . '</span>';
                    }
                    ?>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Dashboard Grid -->
    <div class="wp-breach-dashboard-grid">
        <!-- Latest Scan Results -->
        <div class="wp-breach-widget wp-breach-latest-scan">
            <div class="wp-breach-widget-header">
                <h3><?php esc_html_e('Latest Scan Results', 'wp-breach'); ?></h3>
                <span class="wp-breach-widget-actions">
                    <a href="<?php echo esc_url(admin_url('admin.php?page=wp-breach-scan-config')); ?>" class="button button-small">
                        <?php esc_html_e('Configure Scans', 'wp-breach'); ?>
                    </a>
                </span>
            </div>
            <div class="wp-breach-widget-content">
                <?php if (!empty($dashboard_data['last_scan'])): ?>
                    <div class="wp-breach-scan-summary">
                        <div class="wp-breach-scan-info">
                            <strong><?php esc_html_e('Status:', 'wp-breach'); ?></strong>
                            <span class="wp-breach-status wp-breach-status-<?php echo esc_attr($dashboard_data['last_scan']['status']); ?>">
                                <?php echo esc_html(ucfirst($dashboard_data['last_scan']['status'])); ?>
                            </span>
                        </div>
                        <div class="wp-breach-scan-info">
                            <strong><?php esc_html_e('Completed:', 'wp-breach'); ?></strong>
                            <span><?php echo esc_html($dashboard_data['last_scan']['time_ago']); ?> <?php esc_html_e('ago', 'wp-breach'); ?></span>
                        </div>
                        <div class="wp-breach-scan-info">
                            <strong><?php esc_html_e('Duration:', 'wp-breach'); ?></strong>
                            <span><?php echo esc_html($dashboard_data['last_scan']['duration'] ?? __('N/A', 'wp-breach')); ?></span>
                        </div>
                        <div class="wp-breach-scan-info">
                            <strong><?php esc_html_e('Items Scanned:', 'wp-breach'); ?></strong>
                            <span><?php echo esc_html($dashboard_data['last_scan']['items_scanned'] ?? 0); ?></span>
                        </div>
                    </div>
                <?php else: ?>
                    <div class="wp-breach-no-scan">
                        <p><?php esc_html_e('No scans have been run yet.', 'wp-breach'); ?></p>
                        <button type="button" class="button button-primary" id="wp-breach-first-scan">
                            <?php esc_html_e('Run Your First Scan', 'wp-breach'); ?>
                        </button>
                    </div>
                <?php endif; ?>
            </div>
        </div>
        
        <!-- Recent Vulnerabilities -->
        <div class="wp-breach-widget wp-breach-recent-vulnerabilities">
            <div class="wp-breach-widget-header">
                <h3><?php esc_html_e('Recent Vulnerabilities', 'wp-breach'); ?></h3>
                <span class="wp-breach-widget-actions">
                    <a href="<?php echo esc_url(admin_url('admin.php?page=wp-breach-vulnerabilities')); ?>" class="button button-small">
                        <?php esc_html_e('View All', 'wp-breach'); ?>
                    </a>
                </span>
            </div>
            <div class="wp-breach-widget-content">
                <?php if (!empty($dashboard_data['recent_vulnerabilities'])): ?>
                    <div class="wp-breach-vulnerability-list">
                        <?php foreach ($dashboard_data['recent_vulnerabilities'] as $vulnerability): ?>
                            <div class="wp-breach-vulnerability-item" data-vulnerability-id="<?php echo esc_attr($vulnerability['id']); ?>">
                                <div class="wp-breach-vulnerability-severity wp-breach-severity-<?php echo esc_attr($vulnerability['severity']); ?>">
                                    <?php echo esc_html(ucfirst($vulnerability['severity'])); ?>
                                </div>
                                <div class="wp-breach-vulnerability-details">
                                    <div class="wp-breach-vulnerability-title">
                                        <strong><?php echo esc_html($vulnerability['title']); ?></strong>
                                    </div>
                                    <div class="wp-breach-vulnerability-meta">
                                        <span class="wp-breach-vulnerability-type"><?php echo esc_html($vulnerability['type']); ?></span>
                                        <span class="wp-breach-vulnerability-time"><?php echo esc_html($vulnerability['time_ago']); ?> <?php esc_html_e('ago', 'wp-breach'); ?></span>
                                    </div>
                                </div>
                                <div class="wp-breach-vulnerability-actions">
                                    <button type="button" class="button button-small wp-breach-view-vulnerability" data-vulnerability-id="<?php echo esc_attr($vulnerability['id']); ?>">
                                        <?php esc_html_e('View', 'wp-breach'); ?>
                                    </button>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <div class="wp-breach-no-vulnerabilities">
                        <p><?php esc_html_e('No vulnerabilities found. Your site appears secure!', 'wp-breach'); ?></p>
                    </div>
                <?php endif; ?>
            </div>
        </div>
        
        <!-- Scan Trend Chart -->
        <div class="wp-breach-widget wp-breach-scan-trends">
            <div class="wp-breach-widget-header">
                <h3><?php esc_html_e('Scan Activity (30 Days)', 'wp-breach'); ?></h3>
            </div>
            <div class="wp-breach-widget-content">
                <canvas id="wp-breach-scan-chart" width="400" height="200"></canvas>
                <div class="wp-breach-chart-legend">
                    <div class="wp-breach-legend-item">
                        <span class="wp-breach-legend-color wp-breach-legend-scans"></span>
                        <?php esc_html_e('Scans Performed', 'wp-breach'); ?>
                    </div>
                    <div class="wp-breach-legend-item">
                        <span class="wp-breach-legend-color wp-breach-legend-issues"></span>
                        <?php esc_html_e('Issues Found', 'wp-breach'); ?>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Vulnerability Distribution -->
        <div class="wp-breach-widget wp-breach-vulnerability-distribution">
            <div class="wp-breach-widget-header">
                <h3><?php esc_html_e('Vulnerability Types', 'wp-breach'); ?></h3>
            </div>
            <div class="wp-breach-widget-content">
                <?php if (!empty($dashboard_data['vulnerability_distribution'])): ?>
                    <div class="wp-breach-distribution-chart">
                        <canvas id="wp-breach-distribution-chart" width="300" height="300"></canvas>
                    </div>
                    <div class="wp-breach-distribution-list">
                        <?php foreach ($dashboard_data['vulnerability_distribution'] as $index => $dist): ?>
                            <div class="wp-breach-distribution-item">
                                <span class="wp-breach-distribution-label"><?php echo esc_html($dist['type']); ?></span>
                                <span class="wp-breach-distribution-count"><?php echo esc_html($dist['count']); ?></span>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <div class="wp-breach-no-distribution">
                        <p><?php esc_html_e('No vulnerability data available.', 'wp-breach'); ?></p>
                    </div>
                <?php endif; ?>
            </div>
        </div>
        
        <!-- System Information -->
        <div class="wp-breach-widget wp-breach-system-info">
            <div class="wp-breach-widget-header">
                <h3><?php esc_html_e('System Information', 'wp-breach'); ?></h3>
            </div>
            <div class="wp-breach-widget-content">
                <div class="wp-breach-system-stats">
                    <div class="wp-breach-system-stat">
                        <span class="wp-breach-stat-label"><?php esc_html_e('WordPress Version:', 'wp-breach'); ?></span>
                        <span class="wp-breach-stat-value"><?php echo esc_html($dashboard_data['system_status']['wordpress_version']); ?></span>
                    </div>
                    <div class="wp-breach-system-stat">
                        <span class="wp-breach-stat-label"><?php esc_html_e('PHP Version:', 'wp-breach'); ?></span>
                        <span class="wp-breach-stat-value"><?php echo esc_html($dashboard_data['system_status']['php_version']); ?></span>
                    </div>
                    <div class="wp-breach-system-stat">
                        <span class="wp-breach-stat-label"><?php esc_html_e('Memory Usage:', 'wp-breach'); ?></span>
                        <span class="wp-breach-stat-value"><?php echo esc_html($dashboard_data['system_status']['memory_usage']); ?></span>
                    </div>
                    <div class="wp-breach-system-stat">
                        <span class="wp-breach-stat-label"><?php esc_html_e('Active Plugins:', 'wp-breach'); ?></span>
                        <span class="wp-breach-stat-value"><?php echo esc_html($dashboard_data['system_status']['active_plugins']); ?></span>
                    </div>
                    <div class="wp-breach-system-stat">
                        <span class="wp-breach-stat-label"><?php esc_html_e('SSL Enabled:', 'wp-breach'); ?></span>
                        <span class="wp-breach-stat-value">
                            <?php echo $dashboard_data['system_status']['ssl_enabled'] ? esc_html__('Yes', 'wp-breach') : esc_html__('No', 'wp-breach'); ?>
                        </span>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Quick Actions -->
        <div class="wp-breach-widget wp-breach-quick-actions">
            <div class="wp-breach-widget-header">
                <h3><?php esc_html_e('Quick Actions', 'wp-breach'); ?></h3>
            </div>
            <div class="wp-breach-widget-content">
                <div class="wp-breach-action-buttons">
                    <button type="button" class="button button-primary wp-breach-action-button" id="wp-breach-action-scan">
                        <span class="dashicons dashicons-search"></span>
                        <?php esc_html_e('Run Security Scan', 'wp-breach'); ?>
                    </button>
                    <button type="button" class="button wp-breach-action-button" id="wp-breach-action-vulnerabilities">
                        <span class="dashicons dashicons-list-view"></span>
                        <?php esc_html_e('View Vulnerabilities', 'wp-breach'); ?>
                    </button>
                    <button type="button" class="button wp-breach-action-button" id="wp-breach-action-reports">
                        <span class="dashicons dashicons-chart-bar"></span>
                        <?php esc_html_e('Generate Report', 'wp-breach'); ?>
                    </button>
                    <button type="button" class="button wp-breach-action-button" id="wp-breach-action-settings">
                        <span class="dashicons dashicons-admin-settings"></span>
                        <?php esc_html_e('Settings', 'wp-breach'); ?>
                    </button>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Scan Progress Modal -->
<div id="wp-breach-scan-modal" class="wp-breach-modal" style="display: none;">
    <div class="wp-breach-modal-content">
        <div class="wp-breach-modal-header">
            <h3><?php esc_html_e('Security Scan in Progress', 'wp-breach'); ?></h3>
            <button type="button" class="wp-breach-modal-close">
                <span class="dashicons dashicons-no"></span>
            </button>
        </div>
        <div class="wp-breach-modal-body">
            <div class="wp-breach-scan-progress">
                <div class="wp-breach-progress-bar">
                    <div class="wp-breach-progress-fill" style="width: 0%;"></div>
                </div>
                <div class="wp-breach-progress-text">
                    <span class="wp-breach-progress-percentage">0%</span>
                    <span class="wp-breach-progress-status"><?php esc_html_e('Initializing scan...', 'wp-breach'); ?></span>
                </div>
            </div>
            <div class="wp-breach-scan-details">
                <div class="wp-breach-scan-detail">
                    <span class="wp-breach-detail-label"><?php esc_html_e('Current Phase:', 'wp-breach'); ?></span>
                    <span class="wp-breach-detail-value" id="wp-breach-scan-phase"><?php esc_html_e('Starting...', 'wp-breach'); ?></span>
                </div>
                <div class="wp-breach-scan-detail">
                    <span class="wp-breach-detail-label"><?php esc_html_e('Items Scanned:', 'wp-breach'); ?></span>
                    <span class="wp-breach-detail-value" id="wp-breach-scan-items">0</span>
                </div>
                <div class="wp-breach-scan-detail">
                    <span class="wp-breach-detail-label"><?php esc_html_e('Issues Found:', 'wp-breach'); ?></span>
                    <span class="wp-breach-detail-value" id="wp-breach-scan-issues">0</span>
                </div>
            </div>
        </div>
        <div class="wp-breach-modal-footer">
            <button type="button" class="button" id="wp-breach-pause-scan">
                <?php esc_html_e('Pause', 'wp-breach'); ?>
            </button>
            <button type="button" class="button" id="wp-breach-cancel-scan">
                <?php esc_html_e('Cancel', 'wp-breach'); ?>
            </button>
        </div>
    </div>
</div>

<!-- Include chart data for JavaScript -->
<script type="text/javascript">
    var wpBreachDashboardData = {
        scanHistory: <?php echo json_encode($dashboard_data['scan_history']); ?>,
        vulnerabilityDistribution: <?php echo json_encode($dashboard_data['vulnerability_distribution']); ?>,
        securityScore: <?php echo json_encode($dashboard_data['security_score']); ?>,
        ajaxUrl: '<?php echo esc_url(admin_url('admin-ajax.php')); ?>',
        nonce: '<?php echo wp_create_nonce('wp_breach_dashboard_nonce'); ?>'
    };
</script>
