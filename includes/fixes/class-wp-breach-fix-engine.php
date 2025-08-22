<?php

/**
 * The core automated fix engine.
 *
 * This class manages the automated vulnerability fixing process including
 * safety assessment, backup creation, fix application, validation, and rollback.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/fixes
 */

/**
 * The automated fix engine class.
 *
 * Coordinates the entire automated fix process with safety-first approach,
 * comprehensive backup system, and detailed logging of all operations.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/fixes
 * @author     WP Breach Team
 */
class WP_Breach_Fix_Engine {

    /**
     * The fix strategies registry.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $strategies    Registered fix strategies.
     */
    private $strategies = array();

    /**
     * The backup manager instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Breach_Backup_Manager    $backup_manager    Backup manager.
     */
    private $backup_manager;

    /**
     * The fix validator instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Breach_Fix_Validator    $validator    Fix validator.
     */
    private $validator;

    /**
     * The safety assessor instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Breach_Safety_Assessor    $safety_assessor    Safety assessor.
     */
    private $safety_assessor;

    /**
     * Fix engine configuration.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $config    Engine configuration settings.
     */
    private $config;

    /**
     * Current fix operation context.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $fix_context    Current operation context.
     */
    private $fix_context = array();

    /**
     * Initialize the fix engine.
     *
     * @since    1.0.0
     * @param    array    $config    Engine configuration.
     */
    public function __construct($config = array()) {
        $this->config = wp_parse_args($config, $this->get_default_config());
        $this->initialize_dependencies();
        $this->register_default_strategies();
    }

    /**
     * Get default engine configuration.
     *
     * @since    1.0.0
     * @return   array    Default configuration.
     */
    private function get_default_config() {
        return array(
            'max_concurrent_fixes' => 3,
            'backup_required' => true,
            'safety_threshold' => 0.7,
            'validation_required' => true,
            'rollback_on_failure' => true,
            'fix_timeout' => 300,
            'enable_logging' => true,
            'dry_run_mode' => false,
            'manual_approval_required' => array(
                'high_risk_fixes' => true,
                'critical_files' => true,
                'database_changes' => true
            )
        );
    }

    /**
     * Initialize dependencies.
     *
     * @since    1.0.0
     */
    private function initialize_dependencies() {
        $this->backup_manager = new WP_Breach_Backup_Manager();
        $this->validator = new WP_Breach_Fix_Validator();
        $this->safety_assessor = new WP_Breach_Safety_Assessor();
    }

    /**
     * Register default fix strategies.
     *
     * @since    1.0.0
     */
    private function register_default_strategies() {
        $this->register_strategy('wordpress_core', new WP_Breach_WordPress_Core_Fix_Strategy());
        $this->register_strategy('plugin_vulnerability', new WP_Breach_Plugin_Fix_Strategy());
        $this->register_strategy('configuration', new WP_Breach_Configuration_Fix_Strategy());
        $this->register_strategy('file_permissions', new WP_Breach_File_Permissions_Fix_Strategy());
        $this->register_strategy('code_injection', new WP_Breach_Code_Fix_Strategy());
    }

    /**
     * Register a fix strategy.
     *
     * @since    1.0.0
     * @param    string                              $type        Strategy type.
     * @param    WP_Breach_Fix_Strategy_Interface    $strategy    Strategy instance.
     * @return   bool                                             Registration success.
     */
    public function register_strategy($type, WP_Breach_Fix_Strategy_Interface $strategy) {
        if (empty($type) || !$strategy) {
            return false;
        }

        $this->strategies[$type] = $strategy;
        
        $this->log_operation('strategy_registered', array(
            'type' => $type,
            'strategy_info' => $strategy->get_strategy_info()
        ));

        return true;
    }

    /**
     * Process vulnerabilities for automated fixing.
     *
     * @since    1.0.0
     * @param    array    $vulnerabilities    Vulnerabilities to process.
     * @param    array    $options           Processing options.
     * @return   array                       Processing results.
     */
    public function process_vulnerabilities($vulnerabilities, $options = array()) {
        $options = wp_parse_args($options, array(
            'auto_fix_enabled' => true,
            'manual_fixes_only' => false,
            'safety_override' => false,
            'batch_size' => 10
        ));

        $results = array(
            'total_processed' => 0,
            'auto_fixed' => 0,
            'manual_required' => 0,
            'failed' => 0,
            'skipped' => 0,
            'fixes' => array(),
            'errors' => array()
        );

        if (empty($vulnerabilities)) {
            return $results;
        }

        $this->log_operation('batch_processing_started', array(
            'vulnerability_count' => count($vulnerabilities),
            'options' => $options
        ));

        // Process vulnerabilities in batches
        $batches = array_chunk($vulnerabilities, $options['batch_size']);
        
        foreach ($batches as $batch_index => $batch) {
            $batch_results = $this->process_vulnerability_batch($batch, $options);
            $results = $this->merge_batch_results($results, $batch_results);
            
            // Allow other processes to run between batches
            if ($batch_index < count($batches) - 1) {
                sleep(1);
            }
        }

        $this->log_operation('batch_processing_completed', $results);

        return $results;
    }

    /**
     * Process a batch of vulnerabilities.
     *
     * @since    1.0.0
     * @param    array    $vulnerabilities    Vulnerability batch.
     * @param    array    $options           Processing options.
     * @return   array                       Batch results.
     */
    private function process_vulnerability_batch($vulnerabilities, $options) {
        $batch_results = array(
            'auto_fixed' => 0,
            'manual_required' => 0,
            'failed' => 0,
            'skipped' => 0,
            'fixes' => array(),
            'errors' => array()
        );

        foreach ($vulnerabilities as $vulnerability) {
            $fix_result = $this->process_single_vulnerability($vulnerability, $options);
            
            $batch_results['fixes'][] = $fix_result;
            
            switch ($fix_result['status']) {
                case 'auto_fixed':
                    $batch_results['auto_fixed']++;
                    break;
                case 'manual_required':
                    $batch_results['manual_required']++;
                    break;
                case 'failed':
                    $batch_results['failed']++;
                    if (!empty($fix_result['error'])) {
                        $batch_results['errors'][] = $fix_result['error'];
                    }
                    break;
                case 'skipped':
                    $batch_results['skipped']++;
                    break;
            }
        }

        return $batch_results;
    }

    /**
     * Process a single vulnerability for fixing.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @param    array    $options         Processing options.
     * @return   array                     Fix result.
     */
    public function process_single_vulnerability($vulnerability, $options = array()) {
        $fix_result = array(
            'vulnerability_id' => $vulnerability['id'] ?? 0,
            'status' => 'pending',
            'timestamp' => current_time('mysql'),
            'strategy_used' => null,
            'fix_id' => null,
            'backup_id' => null,
            'safety_assessment' => null,
            'validation_result' => null,
            'manual_instructions' => null,
            'error' => null,
            'duration' => 0
        );

        $start_time = microtime(true);

        try {
            // Set fix context
            $this->fix_context = array(
                'vulnerability' => $vulnerability,
                'options' => $options,
                'start_time' => $start_time
            );

            // Step 1: Find appropriate strategy
            $strategy = $this->find_fix_strategy($vulnerability);
            if (!$strategy) {
                $fix_result['status'] = 'manual_required';
                $fix_result['manual_instructions'] = $this->generate_fallback_instructions($vulnerability);
                return $fix_result;
            }

            $fix_result['strategy_used'] = get_class($strategy);

            // Step 2: Check if auto-fix is possible
            if (!$strategy->can_auto_fix($vulnerability) || $options['manual_fixes_only']) {
                $fix_result['status'] = 'manual_required';
                $fix_result['manual_instructions'] = $strategy->generate_manual_instructions($vulnerability);
                return $fix_result;
            }

            // Step 3: Assess safety
            $safety_assessment = $strategy->assess_fix_safety($vulnerability);
            $fix_result['safety_assessment'] = $safety_assessment;

            if ($safety_assessment['risk_level'] > $this->config['safety_threshold'] && !$options['safety_override']) {
                $fix_result['status'] = 'manual_required';
                $fix_result['manual_instructions'] = $strategy->generate_manual_instructions($vulnerability);
                return $fix_result;
            }

            // Step 4: Create backup if required
            if ($this->config['backup_required']) {
                $backup_result = $this->backup_manager->create_fix_backup($vulnerability);
                if (!$backup_result['success']) {
                    throw new Exception('Backup creation failed: ' . $backup_result['error']);
                }
                $fix_result['backup_id'] = $backup_result['backup_id'];
            }

            // Step 5: Apply fix (dry run first if enabled)
            if ($this->config['dry_run_mode']) {
                $dry_run_result = $this->perform_dry_run($strategy, $vulnerability, $options);
                if (!$dry_run_result['success']) {
                    throw new Exception('Dry run failed: ' . $dry_run_result['error']);
                }
            }

            $apply_result = $strategy->apply_fix($vulnerability, $options);
            if (!$apply_result['success']) {
                throw new Exception('Fix application failed: ' . $apply_result['error']);
            }

            $fix_result['fix_id'] = $apply_result['fix_id'];

            // Step 6: Validate fix
            if ($this->config['validation_required']) {
                $validation_result = $strategy->validate_fix($vulnerability, $apply_result);
                $fix_result['validation_result'] = $validation_result;

                if (!$validation_result['success']) {
                    if ($this->config['rollback_on_failure'] && $fix_result['backup_id']) {
                        $this->rollback_fix($fix_result['fix_id'], $fix_result['backup_id']);
                    }
                    throw new Exception('Fix validation failed: ' . $validation_result['error']);
                }
            }

            $fix_result['status'] = 'auto_fixed';

        } catch (Exception $e) {
            $fix_result['status'] = 'failed';
            $fix_result['error'] = $e->getMessage();
            
            $this->log_operation('fix_failed', array(
                'vulnerability_id' => $vulnerability['id'] ?? 0,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ));
        } finally {
            $fix_result['duration'] = microtime(true) - $start_time;
            $this->fix_context = array();
        }

        return $fix_result;
    }

    /**
     * Find the appropriate fix strategy for a vulnerability.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @return   WP_Breach_Fix_Strategy_Interface|null    Strategy or null.
     */
    private function find_fix_strategy($vulnerability) {
        $vulnerability_type = $vulnerability['type'] ?? '';
        $vulnerability_category = $vulnerability['category'] ?? '';

        // Try exact type match first
        if (isset($this->strategies[$vulnerability_type])) {
            return $this->strategies[$vulnerability_type];
        }

        // Try category match
        if (isset($this->strategies[$vulnerability_category])) {
            return $this->strategies[$vulnerability_category];
        }

        // Try intelligent matching based on vulnerability properties
        foreach ($this->strategies as $type => $strategy) {
            if ($strategy->can_auto_fix($vulnerability)) {
                return $strategy;
            }
        }

        return null;
    }

    /**
     * Perform a dry run of the fix.
     *
     * @since    1.0.0
     * @param    WP_Breach_Fix_Strategy_Interface    $strategy       Fix strategy.
     * @param    array                              $vulnerability  Vulnerability data.
     * @param    array                              $options        Fix options.
     * @return   array                                              Dry run result.
     */
    private function perform_dry_run($strategy, $vulnerability, $options) {
        // Enable dry run mode for the strategy
        $dry_run_options = array_merge($options, array('dry_run' => true));
        
        try {
            $result = $strategy->apply_fix($vulnerability, $dry_run_options);
            return array(
                'success' => true,
                'changes' => $result['changes'] ?? array(),
                'estimated_time' => $strategy->get_estimated_time($vulnerability)
            );
        } catch (Exception $e) {
            return array(
                'success' => false,
                'error' => $e->getMessage()
            );
        }
    }

    /**
     * Rollback a fix.
     *
     * @since    1.0.0
     * @param    int      $fix_id      Fix ID.
     * @param    int      $backup_id   Backup ID.
     * @return   array                 Rollback result.
     */
    public function rollback_fix($fix_id, $backup_id) {
        try {
            $fix_data = $this->get_fix_data($fix_id);
            if (!$fix_data) {
                throw new Exception('Fix data not found');
            }

            $strategy = $this->strategies[$fix_data['strategy_type']] ?? null;
            if (!$strategy) {
                throw new Exception('Fix strategy not available for rollback');
            }

            $backup_data = $this->backup_manager->get_backup_data($backup_id);
            if (!$backup_data) {
                throw new Exception('Backup data not found');
            }

            $rollback_result = $strategy->rollback_fix($fix_id, $backup_data);
            
            if ($rollback_result['success']) {
                $this->update_fix_status($fix_id, 'rolled_back');
                $this->log_operation('fix_rolled_back', array(
                    'fix_id' => $fix_id,
                    'backup_id' => $backup_id
                ));
            }

            return $rollback_result;

        } catch (Exception $e) {
            $this->log_operation('rollback_failed', array(
                'fix_id' => $fix_id,
                'error' => $e->getMessage()
            ));

            return array(
                'success' => false,
                'error' => $e->getMessage()
            );
        }
    }

    /**
     * Generate fallback manual instructions.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @return   array                     Manual instructions.
     */
    private function generate_fallback_instructions($vulnerability) {
        return array(
            'title' => 'Manual Fix Required',
            'description' => 'This vulnerability requires manual intervention.',
            'steps' => array(
                'Review the vulnerability details carefully',
                'Consult security documentation for your specific case',
                'Create a backup before making any changes',
                'Test changes in a staging environment first',
                'Contact support if you need assistance'
            ),
            'resources' => array(
                'WordPress Security Guide',
                'Plugin/Theme Documentation',
                'Security Best Practices'
            )
        );
    }

    /**
     * Merge batch results.
     *
     * @since    1.0.0
     * @param    array    $overall    Overall results.
     * @param    array    $batch      Batch results.
     * @return   array                Merged results.
     */
    private function merge_batch_results($overall, $batch) {
        $overall['total_processed'] += count($batch['fixes']);
        $overall['auto_fixed'] += $batch['auto_fixed'];
        $overall['manual_required'] += $batch['manual_required'];
        $overall['failed'] += $batch['failed'];
        $overall['skipped'] += $batch['skipped'];
        $overall['fixes'] = array_merge($overall['fixes'], $batch['fixes']);
        $overall['errors'] = array_merge($overall['errors'], $batch['errors']);

        return $overall;
    }

    /**
     * Get fix data from database.
     *
     * @since    1.0.0
     * @param    int      $fix_id    Fix ID.
     * @return   array|null          Fix data or null.
     */
    private function get_fix_data($fix_id) {
        global $wpdb;
        
        return $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$wpdb->prefix}breach_fixes WHERE id = %d",
                $fix_id
            ),
            ARRAY_A
        );
    }

    /**
     * Update fix status.
     *
     * @since    1.0.0
     * @param    int      $fix_id    Fix ID.
     * @param    string   $status    New status.
     * @return   bool                Update success.
     */
    private function update_fix_status($fix_id, $status) {
        global $wpdb;
        
        return $wpdb->update(
            "{$wpdb->prefix}breach_fixes",
            array('status' => $status, 'updated_at' => current_time('mysql')),
            array('id' => $fix_id),
            array('%s', '%s'),
            array('%d')
        ) !== false;
    }

    /**
     * Log fix engine operations.
     *
     * @since    1.0.0
     * @param    string   $operation    Operation type.
     * @param    array    $data         Operation data.
     */
    private function log_operation($operation, $data = array()) {
        if (!$this->config['enable_logging']) {
            return;
        }

        $log_entry = array(
            'timestamp' => current_time('mysql'),
            'operation' => $operation,
            'data' => $data,
            'context' => $this->fix_context
        );

        // Log to WordPress error log or custom logging system
        error_log('[WP-Breach Fix Engine] ' . $operation . ': ' . wp_json_encode($log_entry));
    }

    /**
     * Get engine statistics.
     *
     * @since    1.0.0
     * @return   array    Engine statistics.
     */
    public function get_statistics() {
        global $wpdb;

        return array(
            'total_fixes_attempted' => $wpdb->get_var(
                "SELECT COUNT(*) FROM {$wpdb->prefix}breach_fixes"
            ),
            'successful_fixes' => $wpdb->get_var(
                "SELECT COUNT(*) FROM {$wpdb->prefix}breach_fixes WHERE status = 'completed'"
            ),
            'failed_fixes' => $wpdb->get_var(
                "SELECT COUNT(*) FROM {$wpdb->prefix}breach_fixes WHERE status = 'failed'"
            ),
            'rolled_back_fixes' => $wpdb->get_var(
                "SELECT COUNT(*) FROM {$wpdb->prefix}breach_fixes WHERE status = 'rolled_back'"
            ),
            'available_strategies' => count($this->strategies),
            'backup_success_rate' => $this->backup_manager->get_success_rate()
        );
    }
}
