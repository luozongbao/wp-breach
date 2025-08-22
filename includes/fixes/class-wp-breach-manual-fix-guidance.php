<?php

/**
 * Manual fix guidance system.
 *
 * This class provides comprehensive manual fix instructions and guidance
 * for vulnerabilities that cannot be automatically fixed.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/fixes
 */

/**
 * The manual fix guidance class.
 *
 * Generates detailed, step-by-step instructions for manual vulnerability fixes
 * with templates, validation steps, and expert guidance.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/fixes
 * @author     WP Breach Team
 */
class WP_Breach_Manual_Fix_Guidance {

    /**
     * Instruction templates.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $templates    Fix instruction templates.
     */
    private $templates;

    /**
     * Guidance configuration.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $config    Guidance configuration.
     */
    private $config;

    /**
     * Knowledge base.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $knowledge_base    Fix knowledge base.
     */
    private $knowledge_base;

    /**
     * Initialize the manual fix guidance system.
     *
     * @since    1.0.0
     * @param    array    $config    Guidance configuration.
     */
    public function __construct($config = array()) {
        $this->config = wp_parse_args($config, $this->get_default_config());
        $this->initialize_templates();
        $this->initialize_knowledge_base();
    }

    /**
     * Get default configuration.
     *
     * @since    1.0.0
     * @return   array    Default configuration.
     */
    private function get_default_config() {
        return array(
            'include_code_examples' => true,
            'include_screenshots' => false,
            'difficulty_levels' => array('beginner', 'intermediate', 'advanced'),
            'max_steps_per_section' => 10,
            'include_troubleshooting' => true,
            'include_verification' => true,
            'include_rollback' => true,
            'expert_contact_enabled' => true,
            'community_support_enabled' => true
        );
    }

    /**
     * Initialize instruction templates.
     *
     * @since    1.0.0
     */
    private function initialize_templates() {
        $this->templates = array(
            'wordpress_core' => $this->get_wordpress_core_templates(),
            'plugin_vulnerability' => $this->get_plugin_vulnerability_templates(),
            'theme_vulnerability' => $this->get_theme_vulnerability_templates(),
            'configuration' => $this->get_configuration_templates(),
            'file_permissions' => $this->get_file_permissions_templates(),
            'sql_injection' => $this->get_sql_injection_templates(),
            'xss' => $this->get_xss_templates(),
            'csrf' => $this->get_csrf_templates(),
            'authentication' => $this->get_authentication_templates(),
            'malware' => $this->get_malware_templates()
        );
    }

    /**
     * Initialize knowledge base.
     *
     * @since    1.0.0
     */
    private function initialize_knowledge_base() {
        $this->knowledge_base = array(
            'common_issues' => $this->load_common_issues(),
            'troubleshooting_guides' => $this->load_troubleshooting_guides(),
            'best_practices' => $this->load_best_practices(),
            'security_standards' => $this->load_security_standards(),
            'tool_recommendations' => $this->load_tool_recommendations()
        );
    }

    /**
     * Generate comprehensive manual fix instructions.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @param    array    $context          Additional context.
     * @return   array                     Complete manual fix guide.
     */
    public function generate_manual_fix_guide($vulnerability, $context = array()) {
        $guide = array(
            'vulnerability_id' => $vulnerability['id'] ?? 0,
            'title' => $this->generate_guide_title($vulnerability),
            'summary' => $this->generate_vulnerability_summary($vulnerability),
            'risk_assessment' => $this->generate_risk_assessment($vulnerability),
            'prerequisites' => $this->generate_prerequisites($vulnerability),
            'fix_instructions' => $this->generate_fix_instructions($vulnerability, $context),
            'verification_steps' => $this->generate_verification_steps($vulnerability),
            'troubleshooting' => $this->generate_troubleshooting_guide($vulnerability),
            'rollback_instructions' => $this->generate_rollback_instructions($vulnerability),
            'best_practices' => $this->generate_best_practices($vulnerability),
            'additional_resources' => $this->generate_additional_resources($vulnerability),
            'expert_support' => $this->generate_expert_support_info($vulnerability),
            'generated_at' => current_time('mysql'),
            'difficulty_level' => $this->assess_difficulty_level($vulnerability),
            'estimated_time' => $this->estimate_manual_fix_time($vulnerability)
        );

        return $guide;
    }

    /**
     * Generate guide title.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @return   string                    Guide title.
     */
    private function generate_guide_title($vulnerability) {
        $type = $vulnerability['type'] ?? 'Unknown';
        $severity = $vulnerability['severity'] ?? 'medium';
        $component = $vulnerability['affected_component'] ?? 'WordPress';

        $severity_label = ucfirst($severity);
        $type_label = str_replace('_', ' ', ucwords($type, '_'));

        return "Manual Fix Guide: {$severity_label} {$type_label} in {$component}";
    }

    /**
     * Generate vulnerability summary.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @return   array                     Vulnerability summary.
     */
    private function generate_vulnerability_summary($vulnerability) {
        return array(
            'description' => $vulnerability['description'] ?? 'Vulnerability detected in your WordPress installation',
            'severity' => $vulnerability['severity'] ?? 'medium',
            'type' => $vulnerability['type'] ?? 'unknown',
            'affected_component' => $vulnerability['affected_component'] ?? 'WordPress',
            'cve_id' => $vulnerability['cve_id'] ?? null,
            'discovery_date' => $vulnerability['discovered_at'] ?? current_time('mysql'),
            'impact' => $this->generate_impact_description($vulnerability),
            'attack_vector' => $this->generate_attack_vector_description($vulnerability)
        );
    }

    /**
     * Generate risk assessment.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @return   array                     Risk assessment.
     */
    private function generate_risk_assessment($vulnerability) {
        $severity = $vulnerability['severity'] ?? 'medium';
        $type = $vulnerability['type'] ?? 'unknown';

        $risk_levels = array(
            'critical' => array(
                'immediate_action_required' => true,
                'potential_impact' => 'Complete site compromise, data theft, malware infection',
                'urgency' => 'Fix immediately - within 24 hours',
                'risk_score' => 9
            ),
            'high' => array(
                'immediate_action_required' => true,
                'potential_impact' => 'Significant security breach, unauthorized access',
                'urgency' => 'Fix within 48-72 hours',
                'risk_score' => 7
            ),
            'medium' => array(
                'immediate_action_required' => false,
                'potential_impact' => 'Limited security exposure, potential for exploitation',
                'urgency' => 'Fix within 1 week',
                'risk_score' => 5
            ),
            'low' => array(
                'immediate_action_required' => false,
                'potential_impact' => 'Minor security concern, limited exposure',
                'urgency' => 'Fix when convenient, within 1 month',
                'risk_score' => 3
            )
        );

        $base_assessment = $risk_levels[$severity] ?? $risk_levels['medium'];

        // Add specific risk factors based on vulnerability type
        $base_assessment['risk_factors'] = $this->identify_risk_factors($vulnerability);
        $base_assessment['mitigation_priority'] = $this->calculate_mitigation_priority($vulnerability);

        return $base_assessment;
    }

    /**
     * Generate prerequisites.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @return   array                     Prerequisites list.
     */
    private function generate_prerequisites($vulnerability) {
        $prerequisites = array(
            'required' => array(),
            'recommended' => array(),
            'technical_requirements' => array()
        );

        // Universal prerequisites
        $prerequisites['required'][] = array(
            'item' => 'Complete site backup',
            'description' => 'Create a full backup of your website files and database before making any changes',
            'validation' => 'Verify backup can be restored successfully'
        );

        $prerequisites['required'][] = array(
            'item' => 'Administrative access',
            'description' => 'WordPress administrator privileges and server/hosting access',
            'validation' => 'Confirm you can access WordPress admin and hosting control panel'
        );

        // Staging environment (recommended)
        $prerequisites['recommended'][] = array(
            'item' => 'Staging environment',
            'description' => 'Test environment that mirrors your live site',
            'validation' => 'Apply fix to staging first and verify functionality'
        );

        // Type-specific prerequisites
        $type = $vulnerability['type'] ?? 'unknown';
        $type_prerequisites = $this->get_type_specific_prerequisites($type);
        
        $prerequisites['required'] = array_merge($prerequisites['required'], $type_prerequisites['required']);
        $prerequisites['recommended'] = array_merge($prerequisites['recommended'], $type_prerequisites['recommended']);
        $prerequisites['technical_requirements'] = $type_prerequisites['technical_requirements'];

        return $prerequisites;
    }

    /**
     * Generate fix instructions.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @param    array    $context          Additional context.
     * @return   array                     Fix instructions.
     */
    private function generate_fix_instructions($vulnerability, $context) {
        $type = $vulnerability['type'] ?? 'unknown';
        $template = $this->templates[$type] ?? $this->templates['configuration'];

        $instructions = array(
            'overview' => $template['overview'],
            'sections' => array()
        );

        // Generate step-by-step instructions
        foreach ($template['sections'] as $section_key => $section_template) {
            $section = array(
                'title' => $section_template['title'],
                'description' => $section_template['description'],
                'steps' => array(),
                'warnings' => $section_template['warnings'] ?? array(),
                'tips' => $section_template['tips'] ?? array()
            );

            // Generate context-specific steps
            $steps = $this->generate_context_specific_steps($section_template, $vulnerability, $context);
            $section['steps'] = $steps;

            $instructions['sections'][$section_key] = $section;
        }

        return $instructions;
    }

    /**
     * Generate context-specific steps.
     *
     * @since    1.0.0
     * @param    array    $section_template    Section template.
     * @param    array    $vulnerability       Vulnerability data.
     * @param    array    $context             Context data.
     * @return   array                         Generated steps.
     */
    private function generate_context_specific_steps($section_template, $vulnerability, $context) {
        $steps = array();
        $step_templates = $section_template['step_templates'] ?? array();

        foreach ($step_templates as $step_template) {
            $step = array(
                'number' => count($steps) + 1,
                'title' => $this->process_template_variables($step_template['title'], $vulnerability, $context),
                'description' => $this->process_template_variables($step_template['description'], $vulnerability, $context),
                'action' => $step_template['action'],
                'code_example' => null,
                'screenshot' => null,
                'validation' => null,
                'troubleshooting' => array()
            );

            // Add code examples if configured
            if ($this->config['include_code_examples'] && isset($step_template['code_example'])) {
                $step['code_example'] = $this->process_template_variables(
                    $step_template['code_example'], 
                    $vulnerability, 
                    $context
                );
            }

            // Add validation steps
            if (isset($step_template['validation'])) {
                $step['validation'] = $this->process_template_variables(
                    $step_template['validation'], 
                    $vulnerability, 
                    $context
                );
            }

            // Add step-specific troubleshooting
            if (isset($step_template['troubleshooting'])) {
                $step['troubleshooting'] = $step_template['troubleshooting'];
            }

            $steps[] = $step;
        }

        return $steps;
    }

    /**
     * Process template variables.
     *
     * @since    1.0.0
     * @param    string    $template        Template string.
     * @param    array     $vulnerability   Vulnerability data.
     * @param    array     $context         Context data.
     * @return   string                     Processed template.
     */
    private function process_template_variables($template, $vulnerability, $context) {
        $variables = array(
            '{{PLUGIN_NAME}}' => $vulnerability['affected_plugin'] ?? 'Unknown Plugin',
            '{{PLUGIN_FILE}}' => $vulnerability['affected_plugin'] ?? 'plugin-file.php',
            '{{THEME_NAME}}' => $vulnerability['affected_theme'] ?? get_stylesheet(),
            '{{WP_VERSION}}' => get_bloginfo('version'),
            '{{SITE_URL}}' => get_site_url(),
            '{{VULNERABILITY_TYPE}}' => $vulnerability['type'] ?? 'unknown',
            '{{SEVERITY}}' => $vulnerability['severity'] ?? 'medium',
            '{{CVE_ID}}' => $vulnerability['cve_id'] ?? 'N/A',
            '{{AFFECTED_FILES}}' => implode(', ', $vulnerability['affected_files'] ?? array()),
            '{{BACKUP_LOCATION}}' => $context['backup_location'] ?? '/path/to/backup',
            '{{STAGING_URL}}' => $context['staging_url'] ?? 'https://staging.yoursite.com'
        );

        return str_replace(array_keys($variables), array_values($variables), $template);
    }

    /**
     * Generate verification steps.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @return   array                     Verification steps.
     */
    private function generate_verification_steps($vulnerability) {
        $verification = array(
            'pre_fix_verification' => array(
                array(
                    'step' => 'Document current state',
                    'description' => 'Take screenshots and notes of current site functionality',
                    'command' => null
                ),
                array(
                    'step' => 'Test affected functionality',
                    'description' => 'Verify what specific features are affected by the vulnerability',
                    'command' => null
                ),
                array(
                    'step' => 'Confirm vulnerability exists',
                    'description' => 'Use security scanner to confirm the vulnerability is present',
                    'command' => null
                )
            ),
            'post_fix_verification' => array(
                array(
                    'step' => 'Test site functionality',
                    'description' => 'Verify all critical site functions work correctly',
                    'command' => null
                ),
                array(
                    'step' => 'Run security scan',
                    'description' => 'Use WP-Breach or another security scanner to verify fix',
                    'command' => null
                ),
                array(
                    'step' => 'Check error logs',
                    'description' => 'Review server and WordPress error logs for any issues',
                    'command' => 'tail -f /path/to/error.log'
                ),
                array(
                    'step' => 'Performance check',
                    'description' => 'Verify site performance has not been negatively impacted',
                    'command' => null
                )
            ),
            'automated_verification' => array(
                'wp_breach_scan' => 'Run WP-Breach security scan to confirm vulnerability is resolved',
                'plugin_check' => 'Use WordPress Plugin Checker if plugin-related',
                'security_headers' => 'Verify security headers are properly configured',
                'ssl_check' => 'Confirm SSL/TLS configuration is secure'
            )
        );

        // Add type-specific verification
        $type = $vulnerability['type'] ?? 'unknown';
        $type_verification = $this->get_type_specific_verification($type, $vulnerability);
        
        if (!empty($type_verification)) {
            $verification['type_specific'] = $type_verification;
        }

        return $verification;
    }

    /**
     * Generate troubleshooting guide.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @return   array                     Troubleshooting guide.
     */
    private function generate_troubleshooting_guide($vulnerability) {
        $troubleshooting = array(
            'common_issues' => array(),
            'error_scenarios' => array(),
            'recovery_procedures' => array(),
            'diagnostic_tools' => array()
        );

        $type = $vulnerability['type'] ?? 'unknown';

        // Add common issues for this vulnerability type
        $common_issues = $this->knowledge_base['common_issues'][$type] ?? array();
        $troubleshooting['common_issues'] = $common_issues;

        // Add general troubleshooting procedures
        $troubleshooting['error_scenarios'] = array(
            array(
                'scenario' => 'White Screen of Death (WSOD)',
                'symptoms' => 'Site shows blank white page',
                'diagnosis' => 'Check error logs, disable plugins, switch to default theme',
                'solution' => 'Restore from backup, fix syntax errors, increase memory limit'
            ),
            array(
                'scenario' => 'Site becomes inaccessible',
                'symptoms' => 'Cannot access admin or frontend',
                'diagnosis' => 'Check file permissions, server configuration, DNS settings',
                'solution' => 'Restore from backup, fix permissions, contact hosting provider'
            ),
            array(
                'scenario' => 'Database connection error',
                'symptoms' => 'Error establishing database connection',
                'diagnosis' => 'Check wp-config.php, database server status',
                'solution' => 'Verify database credentials, restore database backup'
            ),
            array(
                'scenario' => 'Plugin conflicts',
                'symptoms' => 'Site functionality breaks after fix',
                'diagnosis' => 'Deactivate plugins one by one to identify conflict',
                'solution' => 'Update conflicting plugins, find alternatives, or custom fix'
            )
        );

        // Add recovery procedures
        $troubleshooting['recovery_procedures'] = array(
            array(
                'procedure' => 'Emergency site recovery',
                'steps' => array(
                    'Access site via FTP/SFTP',
                    'Restore files from backup',
                    'Restore database from backup',
                    'Verify site functionality',
                    'Re-apply security fix carefully'
                )
            ),
            array(
                'procedure' => 'Partial rollback',
                'steps' => array(
                    'Identify which changes caused issues',
                    'Restore only affected files/database tables',
                    'Test functionality after each restoration',
                    'Apply alternative fix approach'
                )
            )
        );

        // Add diagnostic tools
        $troubleshooting['diagnostic_tools'] = array(
            array(
                'tool' => 'WordPress Debug Mode',
                'description' => 'Enable WP_DEBUG to see detailed error messages',
                'usage' => 'Add define(\'WP_DEBUG\', true); to wp-config.php'
            ),
            array(
                'tool' => 'Error Logs',
                'description' => 'Check server and WordPress error logs',
                'usage' => 'tail -f /path/to/error.log or check hosting panel'
            ),
            array(
                'tool' => 'Plugin Health Check',
                'description' => 'WordPress built-in tool for troubleshooting',
                'usage' => 'Install Health Check & Troubleshooting plugin'
            ),
            array(
                'tool' => 'Browser Developer Tools',
                'description' => 'Check for JavaScript errors and network issues',
                'usage' => 'Press F12 in browser, check Console and Network tabs'
            )
        );

        return $troubleshooting;
    }

    /**
     * Generate rollback instructions.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @return   array                     Rollback instructions.
     */
    private function generate_rollback_instructions($vulnerability) {
        return array(
            'when_to_rollback' => array(
                'Site becomes inaccessible after applying fix',
                'Critical functionality stops working',
                'New errors appear in logs',
                'Performance significantly degrades',
                'Users report login or functionality issues'
            ),
            'immediate_rollback' => array(
                'steps' => array(
                    array(
                        'action' => 'Stop making changes',
                        'description' => 'Do not attempt additional fixes until rollback is complete'
                    ),
                    array(
                        'action' => 'Access site via FTP/hosting panel',
                        'description' => 'Use alternative access method if admin is inaccessible'
                    ),
                    array(
                        'action' => 'Restore files from backup',
                        'description' => 'Replace modified files with backup versions'
                    ),
                    array(
                        'action' => 'Restore database if needed',
                        'description' => 'Restore database backup if database changes were made'
                    ),
                    array(
                        'action' => 'Test site functionality',
                        'description' => 'Verify site is working correctly after rollback'
                    )
                ),
                'estimated_time' => '15-30 minutes'
            ),
            'partial_rollback' => array(
                'description' => 'Roll back only specific changes that caused issues',
                'steps' => array(
                    'Identify which specific change caused the problem',
                    'Restore only the affected files or database tables',
                    'Test after each restoration step',
                    'Document what worked and what didn\'t for next attempt'
                )
            ),
            'prevention' => array(
                'Always work in staging environment first',
                'Make incremental changes and test each step',
                'Keep detailed notes of all changes made',
                'Have emergency contact information ready',
                'Know how to access site via FTP if admin fails'
            )
        );
    }

    /**
     * Generate best practices.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @return   array                     Best practices.
     */
    private function generate_best_practices($vulnerability) {
        $type = $vulnerability['type'] ?? 'unknown';
        
        $general_practices = array(
            'prevention' => array(
                'Keep WordPress core, plugins, and themes updated',
                'Use strong, unique passwords for all accounts',
                'Implement two-factor authentication',
                'Regular security scans and monitoring',
                'Limit login attempts and user permissions',
                'Use reputable plugins and themes only',
                'Regular backups with verified restoration'
            ),
            'security_hardening' => array(
                'Hide wp-config.php and other sensitive files',
                'Disable file editing from WordPress admin',
                'Change default database table prefix',
                'Remove WordPress version information',
                'Implement security headers',
                'Use SSL/TLS encryption',
                'Regular malware scanning'
            ),
            'maintenance' => array(
                'Monitor security advisories and CVE databases',
                'Test updates in staging environment first',
                'Keep detailed change logs',
                'Regular performance and security audits',
                'Maintain emergency response procedures',
                'Keep contact information for hosting and security experts',
                'Document all custom modifications'
            )
        );

        // Add type-specific best practices
        $type_practices = $this->knowledge_base['best_practices'][$type] ?? array();
        
        if (!empty($type_practices)) {
            $general_practices['type_specific'] = $type_practices;
        }

        return $general_practices;
    }

    /**
     * Generate additional resources.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @return   array                     Additional resources.
     */
    private function generate_additional_resources($vulnerability) {
        $type = $vulnerability['type'] ?? 'unknown';
        
        return array(
            'documentation' => array(
                array(
                    'title' => 'WordPress Security Guide',
                    'url' => 'https://wordpress.org/support/article/hardening-wordpress/',
                    'description' => 'Official WordPress security hardening guide'
                ),
                array(
                    'title' => 'OWASP WordPress Security',
                    'url' => 'https://owasp.org/www-project-wordpress-security/',
                    'description' => 'OWASP WordPress security best practices'
                ),
                array(
                    'title' => 'WP-CLI Documentation',
                    'url' => 'https://wp-cli.org/',
                    'description' => 'Command-line tool for WordPress management'
                )
            ),
            'tools' => array(
                array(
                    'name' => 'WP-Breach Security Scanner',
                    'description' => 'Comprehensive WordPress security scanning',
                    'type' => 'security_scanner'
                ),
                array(
                    'name' => 'Wordfence',
                    'description' => 'WordPress security plugin with firewall',
                    'type' => 'security_plugin'
                ),
                array(
                    'name' => 'UpdraftPlus',
                    'description' => 'WordPress backup plugin',
                    'type' => 'backup_plugin'
                ),
                array(
                    'name' => 'Health Check & Troubleshooting',
                    'description' => 'WordPress debugging and troubleshooting',
                    'type' => 'diagnostic_tool'
                )
            ),
            'communities' => array(
                array(
                    'name' => 'WordPress Support Forums',
                    'url' => 'https://wordpress.org/support/',
                    'description' => 'Official WordPress community support'
                ),
                array(
                    'name' => 'WordPress Security Facebook Group',
                    'url' => 'https://www.facebook.com/groups/wpsecurity/',
                    'description' => 'Community discussions on WordPress security'
                ),
                array(
                    'name' => 'Reddit r/wordpress',
                    'url' => 'https://reddit.com/r/wordpress',
                    'description' => 'WordPress community on Reddit'
                )
            ),
            'vulnerability_databases' => array(
                array(
                    'name' => 'WPScan Vulnerability Database',
                    'url' => 'https://wpscan.com/vulnerabilities',
                    'description' => 'Database of WordPress vulnerabilities'
                ),
                array(
                    'name' => 'CVE Details',
                    'url' => 'https://www.cvedetails.com/',
                    'description' => 'Common Vulnerabilities and Exposures database'
                ),
                array(
                    'name' => 'WordPress VulnDB',
                    'url' => 'https://www.wpwhitesecurity.com/wordpress-security-alerts-database/',
                    'description' => 'WordPress vulnerability alerts database'
                )
            )
        );
    }

    /**
     * Generate expert support information.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @return   array                     Expert support info.
     */
    private function generate_expert_support_info($vulnerability) {
        if (!$this->config['expert_contact_enabled']) {
            return array();
        }

        return array(
            'when_to_contact_expert' => array(
                'Vulnerability is critical and you\'re unsure about the fix',
                'Site contains sensitive data (e-commerce, membership, etc.)',
                'You\'re not comfortable with technical procedures',
                'Previous attempts to fix have failed',
                'Site is business-critical and downtime must be minimized'
            ),
            'preparation_for_expert_contact' => array(
                'Document the vulnerability details',
                'Gather site information (WordPress version, plugins, theme)',
                'Prepare access credentials (with proper authorization)',
                'List any previous fix attempts',
                'Define budget and timeline constraints'
            ),
            'expert_services' => array(
                array(
                    'service' => 'WordPress Security Specialists',
                    'description' => 'Professionals specializing in WordPress security',
                    'when_to_use' => 'Complex security issues, ongoing security management'
                ),
                array(
                    'service' => 'Hosting Provider Support',
                    'description' => 'Your hosting company\'s technical support team',
                    'when_to_use' => 'Server-level issues, hosting-specific problems'
                ),
                array(
                    'service' => 'WordPress Developers',
                    'description' => 'Developers experienced with WordPress',
                    'when_to_use' => 'Custom code vulnerabilities, theme/plugin issues'
                ),
                array(
                    'service' => 'Emergency Response Services',
                    'description' => '24/7 WordPress emergency response teams',
                    'when_to_use' => 'Critical vulnerabilities, active attacks, hacked sites'
                )
            ),
            'cost_expectations' => array(
                'basic_consultation' => '$100-300 per hour',
                'vulnerability_assessment' => '$500-1500 per site',
                'complete_security_audit' => '$1000-5000 per site',
                'emergency_response' => '$200-500 per hour',
                'ongoing_maintenance' => '$100-500 per month'
            ),
            'questions_to_ask_experts' => array(
                'What is your experience with this type of vulnerability?',
                'Can you provide references from similar projects?',
                'What is your approach to fixing this issue?',
                'How will you ensure minimal downtime?',
                'What ongoing security recommendations do you have?',
                'Do you provide any guarantees or warranties?'
            )
        );
    }

    /**
     * Assess difficulty level.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @return   string                    Difficulty level.
     */
    private function assess_difficulty_level($vulnerability) {
        $type = $vulnerability['type'] ?? 'unknown';
        $severity = $vulnerability['severity'] ?? 'medium';
        $affected_files = $vulnerability['affected_files'] ?? array();

        $difficulty_score = 0;

        // Base difficulty by type
        $type_difficulty = array(
            'configuration' => 1,
            'file_permissions' => 1,
            'plugin_vulnerability' => 2,
            'theme_vulnerability' => 2,
            'wordpress_core' => 3,
            'sql_injection' => 3,
            'xss' => 2,
            'csrf' => 2,
            'authentication' => 3,
            'malware' => 4
        );

        $difficulty_score += $type_difficulty[$type] ?? 2;

        // Adjust for severity
        $severity_modifiers = array(
            'low' => 0,
            'medium' => 0,
            'high' => 1,
            'critical' => 2
        );

        $difficulty_score += $severity_modifiers[$severity] ?? 0;

        // Adjust for number of affected files
        if (count($affected_files) > 5) {
            $difficulty_score += 1;
        }

        // Determine final difficulty level
        if ($difficulty_score <= 2) {
            return 'beginner';
        } elseif ($difficulty_score <= 4) {
            return 'intermediate';
        } else {
            return 'advanced';
        }
    }

    /**
     * Estimate manual fix time.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @return   array                     Time estimates.
     */
    private function estimate_manual_fix_time($vulnerability) {
        $difficulty = $this->assess_difficulty_level($vulnerability);
        $type = $vulnerability['type'] ?? 'unknown';

        $base_times = array(
            'beginner' => array(
                'minimum' => 30,    // 30 minutes
                'typical' => 60,    // 1 hour
                'maximum' => 120    // 2 hours
            ),
            'intermediate' => array(
                'minimum' => 60,    // 1 hour
                'typical' => 180,   // 3 hours
                'maximum' => 360    // 6 hours
            ),
            'advanced' => array(
                'minimum' => 180,   // 3 hours
                'typical' => 480,   // 8 hours
                'maximum' => 960    // 16 hours
            )
        );

        $time_estimate = $base_times[$difficulty];

        // Add type-specific modifiers
        $type_modifiers = array(
            'malware' => 2.0,
            'sql_injection' => 1.5,
            'authentication' => 1.5,
            'wordpress_core' => 1.3,
            'configuration' => 0.8,
            'file_permissions' => 0.7
        );

        $modifier = $type_modifiers[$type] ?? 1.0;

        return array(
            'minimum_minutes' => (int) ($time_estimate['minimum'] * $modifier),
            'typical_minutes' => (int) ($time_estimate['typical'] * $modifier),
            'maximum_minutes' => (int) ($time_estimate['maximum'] * $modifier),
            'difficulty_level' => $difficulty,
            'factors' => array(
                'vulnerability_type' => $type,
                'complexity_modifier' => $modifier,
                'includes_testing_time' => true,
                'includes_backup_time' => true
            )
        );
    }

    // Template generation methods would continue here...
    // Including all the specific templates for different vulnerability types
    // and knowledge base loading methods.

    /**
     * Get WordPress core templates.
     *
     * @since    1.0.0
     * @return   array    WordPress core templates.
     */
    private function get_wordpress_core_templates() {
        return array(
            'overview' => 'WordPress core vulnerabilities require careful handling to maintain site stability while addressing security issues.',
            'sections' => array(
                'preparation' => array(
                    'title' => 'Preparation and Backup',
                    'description' => 'Essential steps before making any changes to WordPress core',
                    'step_templates' => array(
                        array(
                            'title' => 'Create complete site backup',
                            'description' => 'Backup all files and database before proceeding',
                            'action' => 'backup',
                            'validation' => 'Verify backup can be restored'
                        ),
                        array(
                            'title' => 'Enable maintenance mode',
                            'description' => 'Put site in maintenance mode to prevent user access during fix',
                            'action' => 'maintenance',
                            'code_example' => 'Create .maintenance file in WordPress root directory'
                        )
                    )
                ),
                'core_update' => array(
                    'title' => 'WordPress Core Update',
                    'description' => 'Update WordPress to the latest secure version',
                    'step_templates' => array(
                        array(
                            'title' => 'Download latest WordPress',
                            'description' => 'Download the latest stable version from WordPress.org',
                            'action' => 'download',
                            'validation' => 'Verify download integrity'
                        ),
                        array(
                            'title' => 'Replace core files',
                            'description' => 'Replace WordPress core files while preserving wp-config.php and .htaccess',
                            'action' => 'replace',
                            'validation' => 'Check site functionality'
                        )
                    )
                )
            )
        );
    }

    /**
     * Additional template methods and knowledge base loaders would be implemented here...
     */
}
