<?php

/**
 * The automated fix engine interface.
 *
 * This interface defines the contract for all fix strategy implementations
 * to ensure consistent behavior across different vulnerability fix types.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/fixes
 */

/**
 * The fix strategy interface.
 *
 * All fix strategy classes must implement this interface to provide
 * standardized fix application, validation, and rollback capabilities.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/fixes
 * @author     WP Breach Team
 */
interface WP_Breach_Fix_Strategy_Interface {

    /**
     * Check if this strategy can automatically fix the vulnerability.
     *
     * @since    1.0.0
     * @param    array     $vulnerability    Vulnerability data from detection.
     * @return   bool                        True if can auto-fix, false otherwise.
     */
    public function can_auto_fix($vulnerability);

    /**
     * Calculate the safety level for applying this fix.
     *
     * @since    1.0.0
     * @param    array     $vulnerability    Vulnerability data.
     * @return   array                       Safety assessment with risk level and factors.
     */
    public function assess_fix_safety($vulnerability);

    /**
     * Apply the automated fix for the vulnerability.
     *
     * @since    1.0.0
     * @param    array     $vulnerability    Vulnerability data.
     * @param    array     $options          Fix options and parameters.
     * @return   array                       Fix result with success status and details.
     */
    public function apply_fix($vulnerability, $options = array());

    /**
     * Validate that the fix was successfully applied.
     *
     * @since    1.0.0
     * @param    array     $vulnerability    Original vulnerability data.
     * @param    array     $fix_result       Result from apply_fix().
     * @return   array                       Validation result with success status.
     */
    public function validate_fix($vulnerability, $fix_result);

    /**
     * Rollback the applied fix.
     *
     * @since    1.0.0
     * @param    int       $fix_id           Fix ID from database.
     * @param    array     $rollback_data    Rollback information.
     * @return   array                       Rollback result with success status.
     */
    public function rollback_fix($fix_id, $rollback_data);

    /**
     * Generate manual fix instructions for this vulnerability.
     *
     * @since    1.0.0
     * @param    array     $vulnerability    Vulnerability data.
     * @return   array                       Manual fix instructions and guidance.
     */
    public function generate_manual_instructions($vulnerability);

    /**
     * Get the fix strategy name and description.
     *
     * @since    1.0.0
     * @return   array                       Strategy information.
     */
    public function get_strategy_info();

    /**
     * Get estimated time for fix application.
     *
     * @since    1.0.0
     * @param    array     $vulnerability    Vulnerability data.
     * @return   int                         Estimated time in seconds.
     */
    public function get_estimated_time($vulnerability);

    /**
     * Check if rollback is available for this fix type.
     *
     * @since    1.0.0
     * @param    array     $vulnerability    Vulnerability data.
     * @return   bool                        True if rollback is possible.
     */
    public function supports_rollback($vulnerability);
}
