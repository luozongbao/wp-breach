<?php

/**
 * The safety assessor for automated fixes.
 *
 * This class evaluates the safety and risk level of applying automated fixes
 * to ensure minimal disruption to WordPress installations.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/fixes
 */

/**
 * The safety assessor class.
 *
 * Provides comprehensive safety assessment for automated fixes including
 * risk analysis, impact assessment, and safety recommendations.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/fixes
 * @author     WP Breach Team
 */
class WP_Breach_Safety_Assessor {

    /**
     * Safety assessment configuration.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $config    Assessment configuration.
     */
    private $config;

    /**
     * Risk factors and weights.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $risk_factors    Risk factors with weights.
     */
    private $risk_factors;

    /**
     * Initialize the safety assessor.
     *
     * @since    1.0.0
     * @param    array    $config    Assessment configuration.
     */
    public function __construct($config = array()) {
        $this->config = wp_parse_args($config, $this->get_default_config());
        $this->initialize_risk_factors();
    }

    /**
     * Get default assessment configuration.
     *
     * @since    1.0.0
     * @return   array    Default configuration.
     */
    private function get_default_config() {
        return array(
            'safe_threshold' => 0.3,
            'moderate_threshold' => 0.6,
            'high_threshold' => 0.8,
            'enable_site_analysis' => true,
            'enable_backup_verification' => true,
            'consider_business_hours' => true,
            'staging_environment_bonus' => 0.2
        );
    }

    /**
     * Initialize risk factors and their weights.
     *
     * @since    1.0.0
     */
    private function initialize_risk_factors() {
        $this->risk_factors = array(
            'file_modification' => array(
                'core_files' => 0.9,
                'active_theme' => 0.7,
                'active_plugins' => 0.6,
                'inactive_plugins' => 0.3,
                'uploads' => 0.2,
                'configuration' => 0.8
            ),
            'database_changes' => array(
                'structure_changes' => 0.9,
                'user_data' => 0.8,
                'options_table' => 0.6,
                'meta_tables' => 0.4,
                'custom_tables' => 0.5
            ),
            'system_impact' => array(
                'requires_restart' => 0.7,
                'affects_authentication' => 0.9,
                'changes_permissions' => 0.8,
                'modifies_htaccess' => 0.7,
                'updates_wp_config' => 0.8
            ),
            'environment_factors' => array(
                'production_site' => 0.3,
                'high_traffic' => 0.4,
                'ecommerce_site' => 0.5,
                'membership_site' => 0.4,
                'business_hours' => 0.2
            ),
            'fix_complexity' => array(
                'multi_step_fix' => 0.4,
                'third_party_dependencies' => 0.6,
                'custom_code_changes' => 0.8,
                'requires_manual_verification' => 0.3,
                'irreversible_changes' => 0.9
            )
        );
    }

    /**
     * Assess the safety of applying a fix.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @param    array    $fix_strategy     Fix strategy information.
     * @param    array    $site_context     Site context information.
     * @return   array                     Safety assessment result.
     */
    public function assess_fix_safety($vulnerability, $fix_strategy = array(), $site_context = array()) {
        $assessment = array(
            'timestamp' => current_time('mysql'),
            'vulnerability_id' => $vulnerability['id'] ?? 0,
            'risk_level' => 0.0,
            'risk_category' => 'unknown',
            'safety_score' => 100,
            'risk_factors' => array(),
            'recommendations' => array(),
            'prerequisites' => array(),
            'estimated_downtime' => 0,
            'rollback_confidence' => 0.0,
            'manual_review_required' => false
        );

        try {
            // Analyze different risk categories
            $file_risk = $this->assess_file_modification_risk($vulnerability, $fix_strategy);
            $database_risk = $this->assess_database_risk($vulnerability, $fix_strategy);
            $system_risk = $this->assess_system_impact_risk($vulnerability, $fix_strategy);
            $environment_risk = $this->assess_environment_risk($vulnerability, $site_context);
            $complexity_risk = $this->assess_fix_complexity_risk($vulnerability, $fix_strategy);

            // Collect all risk factors
            $assessment['risk_factors'] = array(
                'file_modification' => $file_risk,
                'database_changes' => $database_risk,
                'system_impact' => $system_risk,
                'environment_factors' => $environment_risk,
                'fix_complexity' => $complexity_risk
            );

            // Calculate overall risk level
            $overall_risk = $this->calculate_overall_risk($assessment['risk_factors']);
            $assessment['risk_level'] = $overall_risk;
            $assessment['risk_category'] = $this->categorize_risk($overall_risk);
            $assessment['safety_score'] = max(0, 100 - ($overall_risk * 100));

            // Generate recommendations
            $assessment['recommendations'] = $this->generate_safety_recommendations($assessment);

            // Determine prerequisites
            $assessment['prerequisites'] = $this->determine_prerequisites($assessment);

            // Estimate downtime
            $assessment['estimated_downtime'] = $this->estimate_downtime($vulnerability, $fix_strategy, $assessment);

            // Assess rollback confidence
            $assessment['rollback_confidence'] = $this->assess_rollback_confidence($vulnerability, $fix_strategy);

            // Determine if manual review is required
            $assessment['manual_review_required'] = $this->requires_manual_review($assessment);

        } catch (Exception $e) {
            $assessment['error'] = $e->getMessage();
            $assessment['risk_level'] = 1.0; // Maximum risk on error
            $assessment['risk_category'] = 'critical';
            $assessment['manual_review_required'] = true;
        }

        return $assessment;
    }

    /**
     * Assess file modification risk.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @param    array    $fix_strategy     Fix strategy information.
     * @return   array                     File modification risk assessment.
     */
    private function assess_file_modification_risk($vulnerability, $fix_strategy) {
        $risk_data = array(
            'score' => 0.0,
            'factors' => array(),
            'affected_files' => array()
        );

        $affected_files = $vulnerability['affected_files'] ?? array();
        $fix_actions = $fix_strategy['actions'] ?? array();

        foreach ($affected_files as $file) {
            $file_risk = $this->analyze_file_risk($file);
            $risk_data['affected_files'][] = array(
                'file' => $file,
                'risk_score' => $file_risk['score'],
                'risk_type' => $file_risk['type']
            );
            $risk_data['score'] = max($risk_data['score'], $file_risk['score']);
        }

        // Analyze fix actions
        foreach ($fix_actions as $action) {
            $action_risk = $this->analyze_action_risk($action);
            $risk_data['factors'][] = $action_risk;
            $risk_data['score'] = max($risk_data['score'], $action_risk['score']);
        }

        return $risk_data;
    }

    /**
     * Analyze individual file risk.
     *
     * @since    1.0.0
     * @param    string    $file    File path.
     * @return   array             File risk analysis.
     */
    private function analyze_file_risk($file) {
        $normalized_file = wp_normalize_path($file);
        $wp_root = wp_normalize_path(ABSPATH);

        // WordPress core files
        if (strpos($normalized_file, $wp_root . 'wp-includes/') === 0 || 
            strpos($normalized_file, $wp_root . 'wp-admin/') === 0) {
            return array(
                'score' => $this->risk_factors['file_modification']['core_files'],
                'type' => 'core_files'
            );
        }

        // Configuration files
        if (basename($normalized_file) === 'wp-config.php' || 
            basename($normalized_file) === '.htaccess') {
            return array(
                'score' => $this->risk_factors['file_modification']['configuration'],
                'type' => 'configuration'
            );
        }

        // Active theme files
        $active_theme = get_stylesheet_directory();
        if (strpos($normalized_file, $active_theme) === 0) {
            return array(
                'score' => $this->risk_factors['file_modification']['active_theme'],
                'type' => 'active_theme'
            );
        }

        // Plugin files
        if (strpos($normalized_file, WP_PLUGIN_DIR) === 0) {
            $active_plugins = get_option('active_plugins', array());
            $plugin_file = str_replace(WP_PLUGIN_DIR . '/', '', $normalized_file);
            $plugin_dir = dirname($plugin_file);

            $is_active = false;
            foreach ($active_plugins as $active_plugin) {
                if (strpos($active_plugin, $plugin_dir) === 0) {
                    $is_active = true;
                    break;
                }
            }

            return array(
                'score' => $is_active ? 
                    $this->risk_factors['file_modification']['active_plugins'] : 
                    $this->risk_factors['file_modification']['inactive_plugins'],
                'type' => $is_active ? 'active_plugins' : 'inactive_plugins'
            );
        }

        // Upload files
        $upload_dir = wp_upload_dir();
        if (strpos($normalized_file, $upload_dir['basedir']) === 0) {
            return array(
                'score' => $this->risk_factors['file_modification']['uploads'],
                'type' => 'uploads'
            );
        }

        // Default for other files
        return array(
            'score' => 0.3,
            'type' => 'other'
        );
    }

    /**
     * Analyze fix action risk.
     *
     * @since    1.0.0
     * @param    array    $action    Fix action data.
     * @return   array              Action risk analysis.
     */
    private function analyze_action_risk($action) {
        $action_type = $action['type'] ?? 'unknown';
        $risk_score = 0.0;

        switch ($action_type) {
            case 'file_replace':
                $risk_score = 0.6;
                break;
            case 'file_patch':
                $risk_score = 0.4;
                break;
            case 'file_delete':
                $risk_score = 0.8;
                break;
            case 'permission_change':
                $risk_score = 0.5;
                break;
            case 'configuration_update':
                $risk_score = 0.7;
                break;
            default:
                $risk_score = 0.5;
        }

        return array(
            'action' => $action_type,
            'score' => $risk_score,
            'description' => $action['description'] ?? ''
        );
    }

    /**
     * Assess database modification risk.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @param    array    $fix_strategy     Fix strategy information.
     * @return   array                     Database risk assessment.
     */
    private function assess_database_risk($vulnerability, $fix_strategy) {
        $risk_data = array(
            'score' => 0.0,
            'factors' => array(),
            'affected_tables' => array()
        );

        $database_changes = $fix_strategy['database_changes'] ?? array();
        
        if (empty($database_changes)) {
            return $risk_data;
        }

        foreach ($database_changes as $change) {
            $change_risk = $this->analyze_database_change_risk($change);
            $risk_data['factors'][] = $change_risk;
            $risk_data['score'] = max($risk_data['score'], $change_risk['score']);
        }

        return $risk_data;
    }

    /**
     * Analyze database change risk.
     *
     * @since    1.0.0
     * @param    array    $change    Database change data.
     * @return   array              Change risk analysis.
     */
    private function analyze_database_change_risk($change) {
        $change_type = $change['type'] ?? 'unknown';
        $table = $change['table'] ?? '';
        $risk_score = 0.0;

        // Determine base risk by change type
        switch ($change_type) {
            case 'structure_change':
                $risk_score = $this->risk_factors['database_changes']['structure_changes'];
                break;
            case 'data_update':
                $risk_score = 0.4;
                break;
            case 'data_delete':
                $risk_score = 0.7;
                break;
            case 'data_insert':
                $risk_score = 0.2;
                break;
            default:
                $risk_score = 0.5;
        }

        // Adjust risk based on table importance
        if (strpos($table, 'users') !== false || strpos($table, 'usermeta') !== false) {
            $risk_score = max($risk_score, $this->risk_factors['database_changes']['user_data']);
        } elseif (strpos($table, 'options') !== false) {
            $risk_score = max($risk_score, $this->risk_factors['database_changes']['options_table']);
        } elseif (strpos($table, 'meta') !== false) {
            $risk_score = max($risk_score, $this->risk_factors['database_changes']['meta_tables']);
        }

        return array(
            'change_type' => $change_type,
            'table' => $table,
            'score' => $risk_score,
            'description' => $change['description'] ?? ''
        );
    }

    /**
     * Assess system impact risk.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @param    array    $fix_strategy     Fix strategy information.
     * @return   array                     System impact risk assessment.
     */
    private function assess_system_impact_risk($vulnerability, $fix_strategy) {
        $risk_data = array(
            'score' => 0.0,
            'factors' => array()
        );

        $system_requirements = $fix_strategy['system_requirements'] ?? array();

        foreach ($system_requirements as $requirement) {
            $impact_risk = $this->analyze_system_impact($requirement);
            $risk_data['factors'][] = $impact_risk;
            $risk_data['score'] = max($risk_data['score'], $impact_risk['score']);
        }

        return $risk_data;
    }

    /**
     * Analyze system impact.
     *
     * @since    1.0.0
     * @param    array    $requirement    System requirement.
     * @return   array                   Impact analysis.
     */
    private function analyze_system_impact($requirement) {
        $impact_type = $requirement['type'] ?? 'unknown';
        $risk_score = 0.0;

        switch ($impact_type) {
            case 'requires_restart':
                $risk_score = $this->risk_factors['system_impact']['requires_restart'];
                break;
            case 'affects_authentication':
                $risk_score = $this->risk_factors['system_impact']['affects_authentication'];
                break;
            case 'changes_permissions':
                $risk_score = $this->risk_factors['system_impact']['changes_permissions'];
                break;
            case 'modifies_htaccess':
                $risk_score = $this->risk_factors['system_impact']['modifies_htaccess'];
                break;
            case 'updates_wp_config':
                $risk_score = $this->risk_factors['system_impact']['updates_wp_config'];
                break;
            default:
                $risk_score = 0.3;
        }

        return array(
            'impact_type' => $impact_type,
            'score' => $risk_score,
            'description' => $requirement['description'] ?? ''
        );
    }

    /**
     * Assess environment risk factors.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @param    array    $site_context     Site context information.
     * @return   array                     Environment risk assessment.
     */
    private function assess_environment_risk($vulnerability, $site_context) {
        $risk_data = array(
            'score' => 0.0,
            'factors' => array()
        );

        // Check if this is a production environment
        if ($this->is_production_environment()) {
            $risk_data['factors'][] = array(
                'factor' => 'production_environment',
                'score' => $this->risk_factors['environment_factors']['production_site']
            );
            $risk_data['score'] = max($risk_data['score'], $this->risk_factors['environment_factors']['production_site']);
        }

        // Check traffic levels
        if ($this->is_high_traffic_site()) {
            $risk_data['factors'][] = array(
                'factor' => 'high_traffic',
                'score' => $this->risk_factors['environment_factors']['high_traffic']
            );
            $risk_data['score'] = max($risk_data['score'], $this->risk_factors['environment_factors']['high_traffic']);
        }

        // Check for e-commerce functionality
        if ($this->is_ecommerce_site()) {
            $risk_data['factors'][] = array(
                'factor' => 'ecommerce_site',
                'score' => $this->risk_factors['environment_factors']['ecommerce_site']
            );
            $risk_data['score'] = max($risk_data['score'], $this->risk_factors['environment_factors']['ecommerce_site']);
        }

        // Check for membership functionality
        if ($this->is_membership_site()) {
            $risk_data['factors'][] = array(
                'factor' => 'membership_site',
                'score' => $this->risk_factors['environment_factors']['membership_site']
            );
            $risk_data['score'] = max($risk_data['score'], $this->risk_factors['environment_factors']['membership_site']);
        }

        // Check business hours
        if ($this->config['consider_business_hours'] && $this->is_business_hours()) {
            $risk_data['factors'][] = array(
                'factor' => 'business_hours',
                'score' => $this->risk_factors['environment_factors']['business_hours']
            );
            $risk_data['score'] = max($risk_data['score'], $this->risk_factors['environment_factors']['business_hours']);
        }

        return $risk_data;
    }

    /**
     * Assess fix complexity risk.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @param    array    $fix_strategy     Fix strategy information.
     * @return   array                     Complexity risk assessment.
     */
    private function assess_fix_complexity_risk($vulnerability, $fix_strategy) {
        $risk_data = array(
            'score' => 0.0,
            'factors' => array()
        );

        $complexity_factors = $fix_strategy['complexity_factors'] ?? array();

        foreach ($complexity_factors as $factor) {
            $complexity_risk = $this->analyze_complexity_factor($factor);
            $risk_data['factors'][] = $complexity_risk;
            $risk_data['score'] = max($risk_data['score'], $complexity_risk['score']);
        }

        return $risk_data;
    }

    /**
     * Analyze complexity factor.
     *
     * @since    1.0.0
     * @param    array    $factor    Complexity factor.
     * @return   array              Factor analysis.
     */
    private function analyze_complexity_factor($factor) {
        $factor_type = $factor['type'] ?? 'unknown';
        $risk_score = 0.0;

        switch ($factor_type) {
            case 'multi_step_fix':
                $risk_score = $this->risk_factors['fix_complexity']['multi_step_fix'];
                break;
            case 'third_party_dependencies':
                $risk_score = $this->risk_factors['fix_complexity']['third_party_dependencies'];
                break;
            case 'custom_code_changes':
                $risk_score = $this->risk_factors['fix_complexity']['custom_code_changes'];
                break;
            case 'requires_manual_verification':
                $risk_score = $this->risk_factors['fix_complexity']['requires_manual_verification'];
                break;
            case 'irreversible_changes':
                $risk_score = $this->risk_factors['fix_complexity']['irreversible_changes'];
                break;
            default:
                $risk_score = 0.3;
        }

        return array(
            'factor_type' => $factor_type,
            'score' => $risk_score,
            'description' => $factor['description'] ?? ''
        );
    }

    /**
     * Calculate overall risk level.
     *
     * @since    1.0.0
     * @param    array    $risk_factors    All risk factors.
     * @return   float                    Overall risk score (0.0 to 1.0).
     */
    private function calculate_overall_risk($risk_factors) {
        $weights = array(
            'file_modification' => 0.25,
            'database_changes' => 0.25,
            'system_impact' => 0.20,
            'environment_factors' => 0.15,
            'fix_complexity' => 0.15
        );

        $weighted_risk = 0.0;
        $total_weight = 0.0;

        foreach ($risk_factors as $category => $risk_data) {
            if (isset($weights[$category])) {
                $weighted_risk += $risk_data['score'] * $weights[$category];
                $total_weight += $weights[$category];
            }
        }

        return $total_weight > 0 ? $weighted_risk / $total_weight : 0.0;
    }

    /**
     * Categorize risk level.
     *
     * @since    1.0.0
     * @param    float    $risk_score    Risk score (0.0 to 1.0).
     * @return   string                 Risk category.
     */
    private function categorize_risk($risk_score) {
        if ($risk_score <= $this->config['safe_threshold']) {
            return 'safe';
        } elseif ($risk_score <= $this->config['moderate_threshold']) {
            return 'moderate';
        } elseif ($risk_score <= $this->config['high_threshold']) {
            return 'high';
        } else {
            return 'critical';
        }
    }

    /**
     * Generate safety recommendations.
     *
     * @since    1.0.0
     * @param    array    $assessment    Safety assessment data.
     * @return   array                  Safety recommendations.
     */
    private function generate_safety_recommendations($assessment) {
        $recommendations = array();
        $risk_category = $assessment['risk_category'];

        // Base recommendations by risk category
        switch ($risk_category) {
            case 'safe':
                $recommendations[] = array(
                    'priority' => 'low',
                    'action' => 'proceed_with_automated_fix',
                    'description' => 'This fix has low risk and can be applied automatically.'
                );
                break;

            case 'moderate':
                $recommendations[] = array(
                    'priority' => 'medium',
                    'action' => 'create_backup_before_fix',
                    'description' => 'Create a comprehensive backup before applying this fix.'
                );
                $recommendations[] = array(
                    'priority' => 'medium',
                    'action' => 'monitor_after_fix',
                    'description' => 'Monitor the site closely for 24 hours after applying the fix.'
                );
                break;

            case 'high':
                $recommendations[] = array(
                    'priority' => 'high',
                    'action' => 'test_in_staging',
                    'description' => 'Test this fix in a staging environment before applying to production.'
                );
                $recommendations[] = array(
                    'priority' => 'high',
                    'action' => 'schedule_maintenance_window',
                    'description' => 'Schedule this fix during a maintenance window or low-traffic period.'
                );
                break;

            case 'critical':
                $recommendations[] = array(
                    'priority' => 'critical',
                    'action' => 'manual_review_required',
                    'description' => 'This fix requires manual review and should not be automated.'
                );
                $recommendations[] = array(
                    'priority' => 'critical',
                    'action' => 'expert_consultation',
                    'description' => 'Consult with a WordPress security expert before proceeding.'
                );
                break;
        }

        // Specific recommendations based on risk factors
        foreach ($assessment['risk_factors'] as $category => $risk_data) {
            if ($risk_data['score'] > 0.7) {
                $recommendations = array_merge($recommendations, $this->get_category_specific_recommendations($category, $risk_data));
            }
        }

        return $recommendations;
    }

    /**
     * Get category-specific recommendations.
     *
     * @since    1.0.0
     * @param    string    $category     Risk category.
     * @param    array     $risk_data    Risk data.
     * @return   array                   Specific recommendations.
     */
    private function get_category_specific_recommendations($category, $risk_data) {
        $recommendations = array();

        switch ($category) {
            case 'file_modification':
                if (isset($risk_data['affected_files'])) {
                    foreach ($risk_data['affected_files'] as $file_data) {
                        if ($file_data['risk_type'] === 'core_files') {
                            $recommendations[] = array(
                                'priority' => 'high',
                                'action' => 'verify_wordpress_integrity',
                                'description' => 'Verify WordPress core file integrity after the fix.'
                            );
                        }
                    }
                }
                break;

            case 'database_changes':
                $recommendations[] = array(
                    'priority' => 'high',
                    'action' => 'database_backup_verification',
                    'description' => 'Verify database backup integrity before proceeding.'
                );
                break;

            case 'system_impact':
                $recommendations[] = array(
                    'priority' => 'medium',
                    'action' => 'prepare_rollback_plan',
                    'description' => 'Prepare a detailed rollback plan in case of issues.'
                );
                break;
        }

        return $recommendations;
    }

    /**
     * Determine prerequisites for safe fix application.
     *
     * @since    1.0.0
     * @param    array    $assessment    Safety assessment data.
     * @return   array                  Prerequisites list.
     */
    private function determine_prerequisites($assessment) {
        $prerequisites = array();
        $risk_category = $assessment['risk_category'];

        // Base prerequisites
        $prerequisites[] = array(
            'type' => 'backup',
            'description' => 'Complete site backup must be created and verified',
            'required' => $risk_category !== 'safe'
        );

        // Additional prerequisites based on risk factors
        foreach ($assessment['risk_factors'] as $category => $risk_data) {
            if ($risk_data['score'] > 0.6) {
                $prerequisites = array_merge($prerequisites, $this->get_category_prerequisites($category, $risk_data));
            }
        }

        return $prerequisites;
    }

    /**
     * Get category-specific prerequisites.
     *
     * @since    1.0.0
     * @param    string    $category     Risk category.
     * @param    array     $risk_data    Risk data.
     * @return   array                   Prerequisites.
     */
    private function get_category_prerequisites($category, $risk_data) {
        $prerequisites = array();

        switch ($category) {
            case 'database_changes':
                $prerequisites[] = array(
                    'type' => 'database_backup',
                    'description' => 'Dedicated database backup with verification',
                    'required' => true
                );
                break;

            case 'system_impact':
                $prerequisites[] = array(
                    'type' => 'maintenance_mode',
                    'description' => 'Enable maintenance mode during fix application',
                    'required' => true
                );
                break;

            case 'environment_factors':
                if ($this->is_production_environment()) {
                    $prerequisites[] = array(
                        'type' => 'staging_test',
                        'description' => 'Test fix in staging environment first',
                        'required' => true
                    );
                }
                break;
        }

        return $prerequisites;
    }

    /**
     * Estimate downtime for fix application.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @param    array    $fix_strategy     Fix strategy information.
     * @param    array    $assessment       Safety assessment.
     * @return   int                       Estimated downtime in seconds.
     */
    private function estimate_downtime($vulnerability, $fix_strategy, $assessment) {
        $base_time = $fix_strategy['estimated_time'] ?? 60; // Default 1 minute
        $complexity_multiplier = 1.0;
        $safety_multiplier = 1.0;

        // Adjust for complexity
        if ($assessment['risk_factors']['fix_complexity']['score'] > 0.5) {
            $complexity_multiplier = 1.5;
        }

        // Adjust for safety requirements
        if ($assessment['risk_category'] === 'high' || $assessment['risk_category'] === 'critical') {
            $safety_multiplier = 2.0;
        }

        return (int) ($base_time * $complexity_multiplier * $safety_multiplier);
    }

    /**
     * Assess rollback confidence.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @param    array    $fix_strategy     Fix strategy information.
     * @return   float                     Rollback confidence (0.0 to 1.0).
     */
    private function assess_rollback_confidence($vulnerability, $fix_strategy) {
        $confidence = 1.0;

        // Reduce confidence for irreversible changes
        if (isset($fix_strategy['complexity_factors'])) {
            foreach ($fix_strategy['complexity_factors'] as $factor) {
                if ($factor['type'] === 'irreversible_changes') {
                    $confidence *= 0.2;
                }
            }
        }

        // Reduce confidence for complex database changes
        if (isset($fix_strategy['database_changes'])) {
            foreach ($fix_strategy['database_changes'] as $change) {
                if ($change['type'] === 'structure_change') {
                    $confidence *= 0.7;
                }
            }
        }

        return max(0.0, $confidence);
    }

    /**
     * Determine if manual review is required.
     *
     * @since    1.0.0
     * @param    array    $assessment    Safety assessment.
     * @return   bool                   True if manual review required.
     */
    private function requires_manual_review($assessment) {
        return $assessment['risk_category'] === 'critical' || 
               $assessment['rollback_confidence'] < 0.5 ||
               $assessment['risk_level'] > 0.8;
    }

    /**
     * Check if this is a production environment.
     *
     * @since    1.0.0
     * @return   bool    True if production environment.
     */
    private function is_production_environment() {
        // Check for staging indicators
        $staging_indicators = array(
            'staging', 'dev', 'test', 'development', 'sandbox'
        );

        $site_url = get_site_url();
        foreach ($staging_indicators as $indicator) {
            if (strpos(strtolower($site_url), $indicator) !== false) {
                return false;
            }
        }

        // Check WP environment constants
        if (defined('WP_ENVIRONMENT_TYPE')) {
            return WP_ENVIRONMENT_TYPE === 'production';
        }

        // Default to production if not clearly staging
        return true;
    }

    /**
     * Check if this is a high traffic site.
     *
     * @since    1.0.0
     * @return   bool    True if high traffic site.
     */
    private function is_high_traffic_site() {
        // This would typically integrate with analytics
        // For now, use a simple heuristic based on user count
        $user_count = count_users();
        return $user_count['total_users'] > 1000;
    }

    /**
     * Check if this is an e-commerce site.
     *
     * @since    1.0.0
     * @return   bool    True if e-commerce site.
     */
    private function is_ecommerce_site() {
        // Check for common e-commerce plugins
        $ecommerce_plugins = array(
            'woocommerce/woocommerce.php',
            'easy-digital-downloads/easy-digital-downloads.php',
            'wp-ecommerce/wp-shopping-cart.php'
        );

        $active_plugins = get_option('active_plugins', array());
        
        foreach ($ecommerce_plugins as $plugin) {
            if (in_array($plugin, $active_plugins)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if this is a membership site.
     *
     * @since    1.0.0
     * @return   bool    True if membership site.
     */
    private function is_membership_site() {
        // Check for common membership plugins
        $membership_plugins = array(
            'memberpress/memberpress.php',
            'restrict-content-pro/restrict-content-pro.php',
            'paid-memberships-pro/paid-memberships-pro.php'
        );

        $active_plugins = get_option('active_plugins', array());
        
        foreach ($membership_plugins as $plugin) {
            if (in_array($plugin, $active_plugins)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if current time is within business hours.
     *
     * @since    1.0.0
     * @return   bool    True if business hours.
     */
    private function is_business_hours() {
        $current_hour = (int) current_time('H');
        $current_day = (int) current_time('w'); // 0 = Sunday, 6 = Saturday

        // Weekend
        if ($current_day === 0 || $current_day === 6) {
            return false;
        }

        // Business hours: 9 AM to 5 PM
        return $current_hour >= 9 && $current_hour < 17;
    }
}
