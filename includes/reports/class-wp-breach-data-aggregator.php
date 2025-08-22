<?php

/**
 * Data aggregation engine for security reports.
 *
 * This class handles the aggregation, analysis, and processing of security data
 * from various sources to provide meaningful insights for report generation.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/reports
 */

/**
 * The data aggregator class.
 *
 * Aggregates vulnerability data, scan results, and security metrics to provide
 * comprehensive data sets for different types of security reports.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/reports
 * @author     WP Breach Team
 */
class WP_Breach_Data_Aggregator {

    /**
     * Database model instances.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $models    Database model instances.
     */
    private $models;

    /**
     * Calculation cache.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $cache    Cached calculation results.
     */
    private $cache;

    /**
     * Initialize the data aggregator.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->setup_models();
        $this->cache = array();
    }

    /**
     * Setup database model instances.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_models() {
        global $wp_breach_database;
        
        $this->models = array(
            'scans' => $wp_breach_database->get_scan_model(),
            'vulnerabilities' => $wp_breach_database->get_vulnerability_model(),
            'fixes' => $wp_breach_database->get_fix_model(),
            'alerts' => $wp_breach_database->get_alert_model(),
            'monitoring' => $wp_breach_database->get_monitoring_model()
        );
    }

    /**
     * Aggregate data based on filters and date range.
     *
     * @since    1.0.0
     * @param    array    $filters      Data filters.
     * @param    array    $date_range   Date range for data selection.
     * @return   array                 Aggregated data.
     */
    public function aggregate_data($filters = array(), $date_range = array()) {
        $cache_key = 'aggregate_' . md5(serialize(array($filters, $date_range)));
        
        if (isset($this->cache[$cache_key])) {
            return $this->cache[$cache_key];
        }

        $data = array(
            'scans' => $this->get_scan_data($filters, $date_range),
            'vulnerabilities' => $this->get_vulnerability_data($filters, $date_range),
            'fixes' => $this->get_fix_data($filters, $date_range),
            'alerts' => $this->get_alert_data($filters, $date_range),
            'monitoring' => $this->get_monitoring_data($filters, $date_range),
            'summary' => array()
        );

        // Generate summary data
        $data['summary'] = $this->generate_summary($data);

        $this->cache[$cache_key] = $data;
        return $data;
    }

    /**
     * Calculate overall security score.
     *
     * @since    1.0.0
     * @param    array    $data    Aggregated data.
     * @return   array            Security score and breakdown.
     */
    public function calculate_security_score($data) {
        $vulnerabilities = $data['vulnerabilities'];
        $total_vulns = count($vulnerabilities);
        
        if ($total_vulns === 0) {
            return array(
                'score' => 100,
                'grade' => 'A',
                'status' => 'excellent',
                'breakdown' => array(
                    'vulnerability_impact' => 100,
                    'fix_coverage' => 100,
                    'response_time' => 100
                )
            );
        }

        // Calculate component scores
        $vulnerability_score = $this->calculate_vulnerability_impact_score($vulnerabilities);
        $fix_coverage_score = $this->calculate_fix_coverage_score($data);
        $response_time_score = $this->calculate_response_time_score($data);

        // Weighted average
        $overall_score = round(
            ($vulnerability_score * 0.5) + 
            ($fix_coverage_score * 0.3) + 
            ($response_time_score * 0.2)
        );

        return array(
            'score' => $overall_score,
            'grade' => $this->score_to_grade($overall_score),
            'status' => $this->score_to_status($overall_score),
            'breakdown' => array(
                'vulnerability_impact' => $vulnerability_score,
                'fix_coverage' => $fix_coverage_score,
                'response_time' => $response_time_score
            ),
            'total_vulnerabilities' => $total_vulns
        );
    }

    /**
     * Summarize risk levels and distribution.
     *
     * @since    1.0.0
     * @param    array    $data    Aggregated data.
     * @return   array            Risk summary.
     */
    public function summarize_risks($data) {
        $vulnerabilities = $data['vulnerabilities'];
        $risk_counts = array(
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0
        );

        foreach ($vulnerabilities as $vuln) {
            $severity = strtolower($vuln['severity']);
            if (isset($risk_counts[$severity])) {
                $risk_counts[$severity]++;
            }
        }

        $total = array_sum($risk_counts);
        $percentages = array();
        
        foreach ($risk_counts as $level => $count) {
            $percentages[$level] = $total > 0 ? round(($count / $total) * 100, 1) : 0;
        }

        return array(
            'counts' => $risk_counts,
            'percentages' => $percentages,
            'total' => $total,
            'highest_risk' => $this->determine_highest_risk($risk_counts),
            'risk_trend' => $this->calculate_risk_trend($data)
        );
    }

    /**
     * Extract key security metrics.
     *
     * @since    1.0.0
     * @param    array    $data    Aggregated data.
     * @return   array            Key metrics.
     */
    public function extract_key_metrics($data) {
        $vulnerabilities = $data['vulnerabilities'];
        $fixes = $data['fixes'];
        $scans = $data['scans'];

        return array(
            'total_scans' => count($scans),
            'total_vulnerabilities' => count($vulnerabilities),
            'vulnerabilities_fixed' => $this->count_fixed_vulnerabilities($vulnerabilities),
            'average_fix_time' => $this->calculate_average_fix_time($fixes),
            'scan_frequency' => $this->calculate_scan_frequency($scans),
            'detection_rate' => $this->calculate_detection_rate($data),
            'false_positive_rate' => $this->calculate_false_positive_rate($vulnerabilities),
            'most_common_vulnerability' => $this->find_most_common_vulnerability($vulnerabilities),
            'most_affected_component' => $this->find_most_affected_component($vulnerabilities)
        );
    }

    /**
     * Get top security recommendations.
     *
     * @since    1.0.0
     * @param    array    $data      Aggregated data.
     * @param    int      $limit     Number of recommendations to return.
     * @return   array              Top recommendations.
     */
    public function get_top_recommendations($data, $limit = 5) {
        $recommendations = array();
        $vulnerabilities = $data['vulnerabilities'];

        // Analyze vulnerabilities to generate recommendations
        $critical_vulns = array_filter($vulnerabilities, function($v) {
            return strtolower($v['severity']) === 'critical';
        });

        $high_vulns = array_filter($vulnerabilities, function($v) {
            return strtolower($v['severity']) === 'high';
        });

        // Priority recommendations based on data
        if (count($critical_vulns) > 0) {
            $recommendations[] = array(
                'priority' => 'critical',
                'title' => 'Address Critical Vulnerabilities Immediately',
                'description' => sprintf('You have %d critical vulnerabilities requiring immediate attention.', count($critical_vulns)),
                'action' => 'Review and fix all critical vulnerabilities within 24 hours',
                'impact' => 'high',
                'effort' => 'medium'
            );
        }

        if (count($high_vulns) > 0) {
            $recommendations[] = array(
                'priority' => 'high',
                'title' => 'Schedule High-Priority Vulnerability Fixes',
                'description' => sprintf('You have %d high-severity vulnerabilities that should be addressed within a week.', count($high_vulns)),
                'action' => 'Create a remediation plan for high-priority vulnerabilities',
                'impact' => 'medium',
                'effort' => 'medium'
            );
        }

        // Add component-specific recommendations
        $component_analysis = $this->analyze_affected_components($data);
        foreach ($component_analysis['top_affected'] as $component) {
            if ($component['vulnerability_count'] > 3) {
                $recommendations[] = array(
                    'priority' => 'medium',
                    'title' => sprintf('Review %s Security', ucfirst($component['type'])),
                    'description' => sprintf('The %s "%s" has %d vulnerabilities detected.', $component['type'], $component['name'], $component['vulnerability_count']),
                    'action' => sprintf('Audit and update %s security configuration', $component['name']),
                    'impact' => 'medium',
                    'effort' => 'low'
                );
            }
        }

        // Add scan frequency recommendation
        $scan_frequency = $this->calculate_scan_frequency($data['scans']);
        if ($scan_frequency < 7) { // Less than weekly
            $recommendations[] = array(
                'priority' => 'medium',
                'title' => 'Increase Scan Frequency',
                'description' => sprintf('Current scan frequency is every %d days. More frequent scanning improves security posture.', $scan_frequency),
                'action' => 'Configure automated weekly security scans',
                'impact' => 'medium',
                'effort' => 'low'
            );
        }

        // Sort by priority and limit results
        usort($recommendations, function($a, $b) {
            $priority_order = array('critical' => 1, 'high' => 2, 'medium' => 3, 'low' => 4);
            return $priority_order[$a['priority']] - $priority_order[$b['priority']];
        });

        return array_slice($recommendations, 0, $limit);
    }

    /**
     * Assess compliance with security frameworks.
     *
     * @since    1.0.0
     * @param    array    $data    Aggregated data.
     * @return   array            Compliance assessment.
     */
    public function assess_compliance($data) {
        $frameworks = array(
            'owasp' => $this->assess_owasp_compliance($data),
            'nist' => $this->assess_nist_compliance($data),
            'pci_dss' => $this->assess_pci_compliance($data)
        );

        $overall_score = 0;
        foreach ($frameworks as $framework) {
            $overall_score += $framework['score'];
        }
        $overall_score = round($overall_score / count($frameworks));

        return array(
            'overall_score' => $overall_score,
            'overall_status' => $this->score_to_status($overall_score),
            'frameworks' => $frameworks,
            'recommendations' => $this->get_compliance_recommendations($data, array_keys($frameworks))
        );
    }

    /**
     * Get trend indicators for security metrics.
     *
     * @since    1.0.0
     * @param    array    $data    Aggregated data.
     * @return   array            Trend indicators.
     */
    public function get_trend_indicators($data) {
        return array(
            'vulnerability_trend' => $this->calculate_vulnerability_trend($data),
            'fix_rate_trend' => $this->calculate_fix_rate_trend($data),
            'security_score_trend' => $this->calculate_security_score_trend($data),
            'scan_coverage_trend' => $this->calculate_scan_coverage_trend($data)
        );
    }

    /**
     * Get detailed vulnerability information.
     *
     * @since    1.0.0
     * @param    array    $data    Aggregated data.
     * @return   array            Detailed vulnerability data.
     */
    public function get_detailed_vulnerabilities($data) {
        $vulnerabilities = $data['vulnerabilities'];
        
        foreach ($vulnerabilities as &$vuln) {
            $vuln['detailed_analysis'] = $this->analyze_vulnerability_details($vuln);
            $vuln['fix_recommendations'] = $this->get_vulnerability_fix_recommendations($vuln);
            $vuln['related_vulnerabilities'] = $this->find_related_vulnerabilities($vuln, $vulnerabilities);
        }

        return $vulnerabilities;
    }

    /**
     * Analyze affected components.
     *
     * @since    1.0.0
     * @param    array    $data    Aggregated data.
     * @return   array            Component analysis.
     */
    public function analyze_affected_components($data) {
        $vulnerabilities = $data['vulnerabilities'];
        $components = array();

        foreach ($vulnerabilities as $vuln) {
            $component_key = $vuln['component_type'] . ':' . $vuln['component_name'];
            
            if (!isset($components[$component_key])) {
                $components[$component_key] = array(
                    'type' => $vuln['component_type'],
                    'name' => $vuln['component_name'],
                    'vulnerability_count' => 0,
                    'severity_breakdown' => array('critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0),
                    'vulnerabilities' => array()
                );
            }

            $components[$component_key]['vulnerability_count']++;
            $severity = strtolower($vuln['severity']);
            if (isset($components[$component_key]['severity_breakdown'][$severity])) {
                $components[$component_key]['severity_breakdown'][$severity]++;
            }
            $components[$component_key]['vulnerabilities'][] = $vuln;
        }

        // Sort by vulnerability count
        uasort($components, function($a, $b) {
            return $b['vulnerability_count'] - $a['vulnerability_count'];
        });

        return array(
            'total_components' => count($components),
            'components' => $components,
            'top_affected' => array_slice($components, 0, 10),
            'component_types' => $this->analyze_component_types($components)
        );
    }

    /**
     * Generate fix procedures for vulnerabilities.
     *
     * @since    1.0.0
     * @param    array    $data    Aggregated data.
     * @return   array            Fix procedures.
     */
    public function generate_fix_procedures($data) {
        $vulnerabilities = $data['vulnerabilities'];
        $procedures = array();

        foreach ($vulnerabilities as $vuln) {
            if ($vuln['status'] !== 'fixed') {
                $procedures[] = array(
                    'vulnerability_id' => $vuln['id'],
                    'title' => $vuln['title'],
                    'severity' => $vuln['severity'],
                    'procedure' => $this->generate_specific_fix_procedure($vuln),
                    'estimated_time' => $this->estimate_fix_time($vuln),
                    'complexity' => $vuln['fix_complexity'] ?? 'medium',
                    'prerequisites' => $this->get_fix_prerequisites($vuln),
                    'validation_steps' => $this->get_validation_steps($vuln)
                );
            }
        }

        return $procedures;
    }

    /**
     * Calculate technical metrics.
     *
     * @since    1.0.0
     * @param    array    $data    Aggregated data.
     * @return   array            Technical metrics.
     */
    public function calculate_technical_metrics($data) {
        return array(
            'code_coverage' => $this->calculate_code_coverage($data),
            'attack_surface' => $this->calculate_attack_surface($data),
            'security_debt' => $this->calculate_security_debt($data),
            'remediation_velocity' => $this->calculate_remediation_velocity($data),
            'vulnerability_density' => $this->calculate_vulnerability_density($data),
            'mean_time_to_detection' => $this->calculate_mean_time_to_detection($data),
            'mean_time_to_resolution' => $this->calculate_mean_time_to_resolution($data)
        );
    }

    /**
     * Analyze current system security state.
     *
     * @since    1.0.0
     * @param    array    $data    Aggregated data.
     * @return   array            System analysis.
     */
    public function analyze_system_state($data) {
        return array(
            'wordpress_version' => $this->get_wordpress_version_info(),
            'plugin_analysis' => $this->analyze_plugins($data),
            'theme_analysis' => $this->analyze_themes($data),
            'server_configuration' => $this->analyze_server_config($data),
            'security_headers' => $this->analyze_security_headers($data),
            'file_permissions' => $this->analyze_file_permissions($data),
            'database_security' => $this->analyze_database_security($data)
        );
    }

    /**
     * Create comprehensive remediation plan.
     *
     * @since    1.0.0
     * @param    array    $data    Aggregated data.
     * @return   array            Remediation plan.
     */
    public function create_remediation_plan($data) {
        $vulnerabilities = $data['vulnerabilities'];
        $open_vulns = array_filter($vulnerabilities, function($v) {
            return $v['status'] === 'open';
        });

        // Group by priority
        $critical = array_filter($open_vulns, function($v) { return strtolower($v['severity']) === 'critical'; });
        $high = array_filter($open_vulns, function($v) { return strtolower($v['severity']) === 'high'; });
        $medium = array_filter($open_vulns, function($v) { return strtolower($v['severity']) === 'medium'; });
        $low = array_filter($open_vulns, function($v) { return strtolower($v['severity']) === 'low'; });

        return array(
            'immediate_actions' => $this->plan_immediate_actions($critical),
            'short_term_plan' => $this->plan_short_term_actions($high),
            'medium_term_plan' => $this->plan_medium_term_actions($medium),
            'long_term_plan' => $this->plan_long_term_actions($low),
            'resource_requirements' => $this->estimate_resource_requirements($open_vulns),
            'timeline' => $this->create_remediation_timeline($open_vulns),
            'success_metrics' => $this->define_success_metrics($data)
        );
    }

    /**
     * Get scan data based on filters and date range.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $filters      Data filters.
     * @param    array    $date_range   Date range.
     * @return   array                 Scan data.
     */
    private function get_scan_data($filters, $date_range) {
        $conditions = array();
        
        if (!empty($date_range)) {
            if (isset($date_range['start'])) {
                $conditions[] = array('field' => 'started_at', 'operator' => '>=', 'value' => $date_range['start']);
            }
            if (isset($date_range['end'])) {
                $conditions[] = array('field' => 'started_at', 'operator' => '<=', 'value' => $date_range['end']);
            }
        }

        if (isset($filters['scan_type'])) {
            $conditions[] = array('field' => 'scan_type', 'value' => $filters['scan_type']);
        }

        return $this->models['scans']->get_by_fields($conditions);
    }

    /**
     * Get vulnerability data based on filters and date range.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $filters      Data filters.
     * @param    array    $date_range   Date range.
     * @return   array                 Vulnerability data.
     */
    private function get_vulnerability_data($filters, $date_range) {
        $conditions = array();
        
        if (!empty($date_range)) {
            if (isset($date_range['start'])) {
                $conditions[] = array('field' => 'detected_at', 'operator' => '>=', 'value' => $date_range['start']);
            }
            if (isset($date_range['end'])) {
                $conditions[] = array('field' => 'detected_at', 'operator' => '<=', 'value' => $date_range['end']);
            }
        }

        if (isset($filters['severity'])) {
            $conditions[] = array('field' => 'severity', 'value' => $filters['severity']);
        }

        if (isset($filters['status'])) {
            $conditions[] = array('field' => 'status', 'value' => $filters['status']);
        }

        if (isset($filters['component_type'])) {
            $conditions[] = array('field' => 'component_type', 'value' => $filters['component_type']);
        }

        return $this->models['vulnerabilities']->get_by_fields($conditions);
    }

    /**
     * Get fix data based on filters and date range.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $filters      Data filters.
     * @param    array    $date_range   Date range.
     * @return   array                 Fix data.
     */
    private function get_fix_data($filters, $date_range) {
        $conditions = array();
        
        if (!empty($date_range)) {
            if (isset($date_range['start'])) {
                $conditions[] = array('field' => 'applied_at', 'operator' => '>=', 'value' => $date_range['start']);
            }
            if (isset($date_range['end'])) {
                $conditions[] = array('field' => 'applied_at', 'operator' => '<=', 'value' => $date_range['end']);
            }
        }

        if (isset($filters['fix_type'])) {
            $conditions[] = array('field' => 'fix_type', 'value' => $filters['fix_type']);
        }

        return $this->models['fixes']->get_by_fields($conditions);
    }

    /**
     * Get alert data based on filters and date range.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $filters      Data filters.
     * @param    array    $date_range   Date range.
     * @return   array                 Alert data.
     */
    private function get_alert_data($filters, $date_range) {
        $conditions = array();
        
        if (!empty($date_range)) {
            if (isset($date_range['start'])) {
                $conditions[] = array('field' => 'created_at', 'operator' => '>=', 'value' => $date_range['start']);
            }
            if (isset($date_range['end'])) {
                $conditions[] = array('field' => 'created_at', 'operator' => '<=', 'value' => $date_range['end']);
            }
        }

        return $this->models['alerts']->get_by_fields($conditions);
    }

    /**
     * Get monitoring data based on filters and date range.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $filters      Data filters.
     * @param    array    $date_range   Date range.
     * @return   array                 Monitoring data.
     */
    private function get_monitoring_data($filters, $date_range) {
        $conditions = array();
        
        if (!empty($date_range)) {
            if (isset($date_range['start'])) {
                $conditions[] = array('field' => 'detected_at', 'operator' => '>=', 'value' => $date_range['start']);
            }
            if (isset($date_range['end'])) {
                $conditions[] = array('field' => 'detected_at', 'operator' => '<=', 'value' => $date_range['end']);
            }
        }

        return $this->models['monitoring']->get_by_fields($conditions);
    }

    /**
     * Generate summary data from aggregated data.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $data    Aggregated data.
     * @return   array            Summary data.
     */
    private function generate_summary($data) {
        return array(
            'total_scans' => count($data['scans']),
            'total_vulnerabilities' => count($data['vulnerabilities']),
            'total_fixes' => count($data['fixes']),
            'total_alerts' => count($data['alerts']),
            'data_timeframe' => $this->calculate_data_timeframe($data),
            'last_updated' => current_time('mysql')
        );
    }

    // Additional helper methods would be implemented here...
    // (For brevity, including key methods but not all implementation details)

    /**
     * Calculate vulnerability impact score.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $vulnerabilities    Vulnerability data.
     * @return   int                         Impact score (0-100).
     */
    private function calculate_vulnerability_impact_score($vulnerabilities) {
        if (empty($vulnerabilities)) {
            return 100;
        }

        $severity_weights = array('critical' => 10, 'high' => 5, 'medium' => 2, 'low' => 1);
        $total_weight = 0;
        $max_possible = count($vulnerabilities) * $severity_weights['low']; // Assume all are low

        foreach ($vulnerabilities as $vuln) {
            $severity = strtolower($vuln['severity']);
            $total_weight += $severity_weights[$severity] ?? 1;
        }

        $impact_ratio = $total_weight / ($max_possible * 10); // Normalize to 0-1
        return max(0, 100 - ($impact_ratio * 100));
    }

    /**
     * Convert numeric score to letter grade.
     *
     * @since    1.0.0
     * @access   private
     * @param    int    $score    Numeric score (0-100).
     * @return   string          Letter grade.
     */
    private function score_to_grade($score) {
        if ($score >= 90) return 'A';
        if ($score >= 80) return 'B';
        if ($score >= 70) return 'C';
        if ($score >= 60) return 'D';
        return 'F';
    }

    /**
     * Convert numeric score to status description.
     *
     * @since    1.0.0
     * @access   private
     * @param    int    $score    Numeric score (0-100).
     * @return   string          Status description.
     */
    private function score_to_status($score) {
        if ($score >= 90) return 'excellent';
        if ($score >= 80) return 'good';
        if ($score >= 70) return 'fair';
        if ($score >= 60) return 'poor';
        return 'critical';
    }

    // Additional methods would continue here...
    // Including all calculation methods, analysis functions, etc.
}
