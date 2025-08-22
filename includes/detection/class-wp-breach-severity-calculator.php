<?php

/**
 * The severity calculation engine.
 *
 * This class handles vulnerability severity assessment and risk scoring
 * based on multiple factors and industry standards.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/detection
 */

/**
 * The severity calculator class.
 *
 * This class provides comprehensive severity assessment using CVSS-like
 * scoring and WordPress-specific risk factors.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/detection
 * @author     WP Breach Team
 */
class WP_Breach_Severity_Calculator {

    /**
     * CVSS base score weights.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $cvss_weights    CVSS scoring weights.
     */
    protected $cvss_weights;

    /**
     * WordPress-specific risk factors.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $wp_factors    WordPress risk factors.
     */
    protected $wp_factors;

    /**
     * Vulnerability type risk mapping.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $type_risks    Risk levels by vulnerability type.
     */
    protected $type_risks;

    /**
     * Initialize the severity calculator.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->init_cvss_weights();
        $this->init_wp_factors();
        $this->init_type_risks();
    }

    /**
     * Initialize CVSS scoring weights.
     *
     * @since    1.0.0
     */
    private function init_cvss_weights() {
        $this->cvss_weights = array(
            // Impact metrics
            'confidentiality' => array(
                'none' => 0.0,
                'low' => 0.22,
                'high' => 0.56
            ),
            'integrity' => array(
                'none' => 0.0,
                'low' => 0.22,
                'high' => 0.56
            ),
            'availability' => array(
                'none' => 0.0,
                'low' => 0.22,
                'high' => 0.56
            ),
            // Exploitability metrics
            'attack_vector' => array(
                'network' => 0.85,
                'adjacent' => 0.62,
                'local' => 0.55,
                'physical' => 0.2
            ),
            'attack_complexity' => array(
                'low' => 0.77,
                'high' => 0.44
            ),
            'privileges_required' => array(
                'none' => 0.85,
                'low' => 0.62,
                'high' => 0.27
            ),
            'user_interaction' => array(
                'none' => 0.85,
                'required' => 0.62
            ),
            'scope' => array(
                'unchanged' => 1.0,
                'changed' => 1.08
            )
        );
    }

    /**
     * Initialize WordPress-specific risk factors.
     *
     * @since    1.0.0
     */
    private function init_wp_factors() {
        $this->wp_factors = array(
            'file_type' => array(
                'core' => 1.5,      // WordPress core files
                'plugin' => 1.2,    // Plugin files
                'theme' => 1.1,     // Theme files
                'config' => 1.8,    // Configuration files
                'upload' => 0.8     // Upload directory files
            ),
            'location' => array(
                'admin' => 1.4,     // Admin area
                'public' => 1.2,    // Public facing
                'api' => 1.3,       // API endpoints
                'ajax' => 1.1,      // AJAX handlers
                'cron' => 0.9       // Cron jobs
            ),
            'permissions' => array(
                'admin' => 1.5,     // Admin privileges required
                'user' => 1.2,      // User privileges required
                'guest' => 1.0      // No privileges required
            ),
            'data_access' => array(
                'database' => 1.4,  // Database access
                'filesystem' => 1.3, // File system access
                'network' => 1.2,   // Network access
                'user_data' => 1.5, // User data access
                'config_data' => 1.6 // Configuration data
            ),
            'exposure' => array(
                'public' => 1.3,    // Publicly accessible
                'authenticated' => 1.1, // Requires authentication
                'internal' => 0.9   // Internal only
            )
        );
    }

    /**
     * Initialize vulnerability type risk mapping.
     *
     * @since    1.0.0
     */
    private function init_type_risks() {
        $this->type_risks = array(
            'sql-injection' => array(
                'base_score' => 8.5,
                'confidentiality' => 'high',
                'integrity' => 'high',
                'availability' => 'high',
                'attack_vector' => 'network',
                'attack_complexity' => 'low',
                'privileges_required' => 'none',
                'user_interaction' => 'none'
            ),
            'xss' => array(
                'base_score' => 6.1,
                'confidentiality' => 'low',
                'integrity' => 'low',
                'availability' => 'none',
                'attack_vector' => 'network',
                'attack_complexity' => 'low',
                'privileges_required' => 'none',
                'user_interaction' => 'required'
            ),
            'csrf' => array(
                'base_score' => 6.5,
                'confidentiality' => 'none',
                'integrity' => 'high',
                'availability' => 'none',
                'attack_vector' => 'network',
                'attack_complexity' => 'low',
                'privileges_required' => 'none',
                'user_interaction' => 'required'
            ),
            'file-inclusion' => array(
                'base_score' => 7.5,
                'confidentiality' => 'high',
                'integrity' => 'high',
                'availability' => 'high',
                'attack_vector' => 'network',
                'attack_complexity' => 'low',
                'privileges_required' => 'none',
                'user_interaction' => 'none'
            ),
            'auth-bypass' => array(
                'base_score' => 9.0,
                'confidentiality' => 'high',
                'integrity' => 'high',
                'availability' => 'high',
                'attack_vector' => 'network',
                'attack_complexity' => 'low',
                'privileges_required' => 'none',
                'user_interaction' => 'none'
            ),
            'path-traversal' => array(
                'base_score' => 7.5,
                'confidentiality' => 'high',
                'integrity' => 'low',
                'availability' => 'none',
                'attack_vector' => 'network',
                'attack_complexity' => 'low',
                'privileges_required' => 'none',
                'user_interaction' => 'none'
            ),
            'code-injection' => array(
                'base_score' => 9.0,
                'confidentiality' => 'high',
                'integrity' => 'high',
                'availability' => 'high',
                'attack_vector' => 'network',
                'attack_complexity' => 'low',
                'privileges_required' => 'none',
                'user_interaction' => 'none'
            ),
            'privilege-escalation' => array(
                'base_score' => 8.8,
                'confidentiality' => 'high',
                'integrity' => 'high',
                'availability' => 'high',
                'attack_vector' => 'network',
                'attack_complexity' => 'low',
                'privileges_required' => 'low',
                'user_interaction' => 'none'
            ),
            'information-disclosure' => array(
                'base_score' => 5.3,
                'confidentiality' => 'low',
                'integrity' => 'none',
                'availability' => 'none',
                'attack_vector' => 'network',
                'attack_complexity' => 'low',
                'privileges_required' => 'none',
                'user_interaction' => 'none'
            ),
            'weak-crypto' => array(
                'base_score' => 5.0,
                'confidentiality' => 'low',
                'integrity' => 'low',
                'availability' => 'none',
                'attack_vector' => 'network',
                'attack_complexity' => 'high',
                'privileges_required' => 'none',
                'user_interaction' => 'none'
            )
        );
    }

    /**
     * Calculate vulnerability severity.
     *
     * @since    1.0.0
     * @param    array     $vulnerability   Vulnerability data.
     * @param    array     $file_info       File information.
     * @return   array                      Severity assessment.
     */
    public function calculate_severity($vulnerability, $file_info) {
        // Get base CVSS score
        $cvss_score = $this->calculate_cvss_score($vulnerability);
        
        // Apply WordPress-specific factors
        $wp_score = $this->apply_wp_factors($cvss_score, $vulnerability, $file_info);
        
        // Calculate confidence-adjusted score
        $confidence = isset($vulnerability['confidence']) ? $vulnerability['confidence'] : 0.8;
        $adjusted_score = $wp_score * $confidence;
        
        // Determine severity level
        $severity = $this->score_to_severity($adjusted_score);
        
        // Calculate risk score (0-100)
        $risk_score = min(100, ($adjusted_score / 10) * 100);
        
        return array(
            'severity' => $severity,
            'cvss_score' => round($cvss_score, 1),
            'wp_adjusted_score' => round($wp_score, 1),
            'final_score' => round($adjusted_score, 1),
            'risk_score' => round($risk_score, 1),
            'confidence' => $confidence,
            'factors' => $this->get_applied_factors($vulnerability, $file_info)
        );
    }

    /**
     * Calculate CVSS base score.
     *
     * @since    1.0.0
     * @param    array     $vulnerability   Vulnerability data.
     * @return   float                      CVSS score.
     */
    private function calculate_cvss_score($vulnerability) {
        $type = isset($vulnerability['type']) ? $vulnerability['type'] : 'unknown';
        
        // Get base metrics for vulnerability type
        if (isset($this->type_risks[$type])) {
            $metrics = $this->type_risks[$type];
        } else {
            // Default metrics for unknown types
            $metrics = array(
                'confidentiality' => 'low',
                'integrity' => 'low',
                'availability' => 'none',
                'attack_vector' => 'network',
                'attack_complexity' => 'low',
                'privileges_required' => 'none',
                'user_interaction' => 'none'
            );
        }

        // Calculate impact score
        $conf_impact = $this->cvss_weights['confidentiality'][$metrics['confidentiality']];
        $integ_impact = $this->cvss_weights['integrity'][$metrics['integrity']];
        $avail_impact = $this->cvss_weights['availability'][$metrics['availability']];
        
        $impact_sub_score = 1 - ((1 - $conf_impact) * (1 - $integ_impact) * (1 - $avail_impact));
        $impact_score = 6.42 * $impact_sub_score;

        // Calculate exploitability score
        $attack_vector = $this->cvss_weights['attack_vector'][$metrics['attack_vector']];
        $attack_complexity = $this->cvss_weights['attack_complexity'][$metrics['attack_complexity']];
        $privileges_required = $this->cvss_weights['privileges_required'][$metrics['privileges_required']];
        $user_interaction = $this->cvss_weights['user_interaction'][$metrics['user_interaction']];
        
        $exploitability_score = 8.22 * $attack_vector * $attack_complexity * $privileges_required * $user_interaction;

        // Calculate base score
        if ($impact_score <= 0) {
            return 0;
        }

        $scope_changed = isset($metrics['scope']) && $metrics['scope'] === 'changed';
        
        if ($scope_changed) {
            $base_score = min(10, 1.08 * ($impact_score + $exploitability_score));
        } else {
            $base_score = min(10, $impact_score + $exploitability_score);
        }

        return max(0, $base_score);
    }

    /**
     * Apply WordPress-specific risk factors.
     *
     * @since    1.0.0
     * @param    float     $base_score      Base CVSS score.
     * @param    array     $vulnerability   Vulnerability data.
     * @param    array     $file_info       File information.
     * @return   float                      Adjusted score.
     */
    private function apply_wp_factors($base_score, $vulnerability, $file_info) {
        $multiplier = 1.0;

        // File type factor
        if ($file_info['is_wordpress_core']) {
            $multiplier *= $this->wp_factors['file_type']['core'];
        } elseif ($file_info['is_plugin']) {
            $multiplier *= $this->wp_factors['file_type']['plugin'];
        } elseif ($file_info['is_theme']) {
            $multiplier *= $this->wp_factors['file_type']['theme'];
        }

        // Configuration file factor
        if (strpos($file_info['name'], 'config') !== false || 
            strpos($file_info['name'], 'wp-config') !== false) {
            $multiplier *= $this->wp_factors['file_type']['config'];
        }

        // Location factor
        if (strpos($file_info['path'], '/admin/') !== false || 
            strpos($file_info['path'], 'wp-admin') !== false) {
            $multiplier *= $this->wp_factors['location']['admin'];
        } elseif (strpos($file_info['path'], '/api/') !== false) {
            $multiplier *= $this->wp_factors['location']['api'];
        } elseif (strpos($file_info['path'], 'ajax') !== false) {
            $multiplier *= $this->wp_factors['location']['ajax'];
        }

        // Data access factors
        if ($file_info['sql_queries'] > 0) {
            $multiplier *= $this->wp_factors['data_access']['database'];
        }

        if ($file_info['has_file_operations']) {
            $multiplier *= $this->wp_factors['data_access']['filesystem'];
        }

        if ($file_info['has_network_calls']) {
            $multiplier *= $this->wp_factors['data_access']['network'];
        }

        if ($file_info['has_user_input']) {
            $multiplier *= $this->wp_factors['data_access']['user_data'];
        }

        // Exposure factor
        if ($file_info['is_wordpress_core'] || strpos($file_info['path'], '/public/') !== false) {
            $multiplier *= $this->wp_factors['exposure']['public'];
        }

        // Vulnerability-specific adjustments
        $type = isset($vulnerability['type']) ? $vulnerability['type'] : '';
        switch ($type) {
            case 'sql-injection':
                if ($file_info['sql_queries'] > 5) {
                    $multiplier *= 1.2; // High SQL usage increases risk
                }
                break;
            case 'xss':
                if ($file_info['has_user_input']) {
                    $multiplier *= 1.15; // User input handling increases XSS risk
                }
                break;
            case 'file-inclusion':
                if ($file_info['has_file_operations']) {
                    $multiplier *= 1.3; // File operations increase inclusion risk
                }
                break;
        }

        return min(10, $base_score * $multiplier);
    }

    /**
     * Convert numerical score to severity level.
     *
     * @since    1.0.0
     * @param    float     $score           Numerical score.
     * @return   string                     Severity level.
     */
    private function score_to_severity($score) {
        if ($score >= 9.0) {
            return 'critical';
        } elseif ($score >= 7.0) {
            return 'high';
        } elseif ($score >= 4.0) {
            return 'medium';
        } elseif ($score >= 0.1) {
            return 'low';
        } else {
            return 'info';
        }
    }

    /**
     * Get applied risk factors.
     *
     * @since    1.0.0
     * @param    array     $vulnerability   Vulnerability data.
     * @param    array     $file_info       File information.
     * @return   array                      Applied factors.
     */
    private function get_applied_factors($vulnerability, $file_info) {
        $factors = array();

        // File type factors
        if ($file_info['is_wordpress_core']) {
            $factors['file_type'] = 'WordPress Core';
        } elseif ($file_info['is_plugin']) {
            $factors['file_type'] = 'Plugin';
        } elseif ($file_info['is_theme']) {
            $factors['file_type'] = 'Theme';
        }

        // Location factors
        if (strpos($file_info['path'], '/admin/') !== false) {
            $factors['location'] = 'Admin Area';
        } elseif (strpos($file_info['path'], '/api/') !== false) {
            $factors['location'] = 'API Endpoint';
        }

        // Data access factors
        $data_access = array();
        if ($file_info['sql_queries'] > 0) {
            $data_access[] = 'Database';
        }
        if ($file_info['has_file_operations']) {
            $data_access[] = 'File System';
        }
        if ($file_info['has_network_calls']) {
            $data_access[] = 'Network';
        }
        if ($file_info['has_user_input']) {
            $data_access[] = 'User Input';
        }

        if (!empty($data_access)) {
            $factors['data_access'] = $data_access;
        }

        return $factors;
    }

    /**
     * Calculate risk trend over time.
     *
     * @since    1.0.0
     * @param    array     $historical_data Historical vulnerability data.
     * @return   array                      Risk trend analysis.
     */
    public function calculate_risk_trend($historical_data) {
        if (empty($historical_data)) {
            return array(
                'trend' => 'stable',
                'change_percentage' => 0,
                'risk_velocity' => 0
            );
        }

        $scores = array_column($historical_data, 'risk_score');
        $timestamps = array_column($historical_data, 'timestamp');

        // Calculate trend
        $first_score = reset($scores);
        $last_score = end($scores);
        
        $change_percentage = $first_score > 0 ? (($last_score - $first_score) / $first_score) * 100 : 0;
        
        // Determine trend direction
        if ($change_percentage > 10) {
            $trend = 'increasing';
        } elseif ($change_percentage < -10) {
            $trend = 'decreasing';
        } else {
            $trend = 'stable';
        }

        // Calculate risk velocity (change per day)
        $time_span = max(1, (end($timestamps) - reset($timestamps)) / (24 * 3600)); // Days
        $risk_velocity = ($last_score - $first_score) / $time_span;

        return array(
            'trend' => $trend,
            'change_percentage' => round($change_percentage, 2),
            'risk_velocity' => round($risk_velocity, 2),
            'first_score' => $first_score,
            'last_score' => $last_score,
            'time_span_days' => round($time_span, 1)
        );
    }

    /**
     * Calculate composite risk score for multiple vulnerabilities.
     *
     * @since    1.0.0
     * @param    array     $vulnerabilities Array of vulnerabilities.
     * @return   array                      Composite risk assessment.
     */
    public function calculate_composite_risk($vulnerabilities) {
        if (empty($vulnerabilities)) {
            return array(
                'composite_score' => 0,
                'severity' => 'info',
                'total_vulnerabilities' => 0,
                'severity_breakdown' => array()
            );
        }

        $scores = array();
        $severity_counts = array('critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0);

        foreach ($vulnerabilities as $vuln) {
            $severity_data = $this->calculate_severity($vuln, isset($vuln['file_info']) ? $vuln['file_info'] : array());
            $scores[] = $severity_data['final_score'];
            
            $severity = $severity_data['severity'];
            if (isset($severity_counts[$severity])) {
                $severity_counts[$severity]++;
            }
        }

        // Calculate composite score using root mean square
        $sum_squares = array_sum(array_map(function($score) { return $score * $score; }, $scores));
        $composite_score = sqrt($sum_squares / count($scores));

        // Apply severity multipliers
        $multiplier = 1.0;
        $multiplier += $severity_counts['critical'] * 0.5;
        $multiplier += $severity_counts['high'] * 0.3;
        $multiplier += $severity_counts['medium'] * 0.1;

        $final_composite = min(10, $composite_score * $multiplier);

        return array(
            'composite_score' => round($final_composite, 2),
            'severity' => $this->score_to_severity($final_composite),
            'total_vulnerabilities' => count($vulnerabilities),
            'severity_breakdown' => $severity_counts,
            'average_score' => round(array_sum($scores) / count($scores), 2),
            'max_score' => max($scores),
            'min_score' => min($scores)
        );
    }

    /**
     * Get severity configuration.
     *
     * @since    1.0.0
     * @return   array                      Severity configuration.
     */
    public function get_severity_config() {
        return array(
            'cvss_weights' => $this->cvss_weights,
            'wp_factors' => $this->wp_factors,
            'type_risks' => $this->type_risks,
            'severity_thresholds' => array(
                'critical' => 9.0,
                'high' => 7.0,
                'medium' => 4.0,
                'low' => 0.1,
                'info' => 0.0
            )
        );
    }

    /**
     * Update severity configuration.
     *
     * @since    1.0.0
     * @param    array     $config          New configuration.
     * @return   bool                       Success status.
     */
    public function update_severity_config($config) {
        if (isset($config['cvss_weights'])) {
            $this->cvss_weights = array_merge($this->cvss_weights, $config['cvss_weights']);
        }

        if (isset($config['wp_factors'])) {
            $this->wp_factors = array_merge($this->wp_factors, $config['wp_factors']);
        }

        if (isset($config['type_risks'])) {
            $this->type_risks = array_merge($this->type_risks, $config['type_risks']);
        }

        return true;
    }
}
