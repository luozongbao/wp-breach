<?php
/**
 * Executive Summary Report Template
 *
 * Template configuration for generating executive-level security reports
 * focused on high-level overview and key insights for management.
 */

return array(
    'name' => 'Executive Summary',
    'version' => '1.0.0',
    'description' => 'High-level security overview for executive stakeholders',
    'audience' => 'executive',
    'sections' => array(
        'overview' => array(
            'title' => 'Security Overview',
            'type' => 'overview',
            'priority' => 1,
            'required' => true,
            'description' => 'Overall security status and key metrics'
        ),
        'metrics' => array(
            'title' => 'Key Security Metrics',
            'type' => 'metrics',
            'priority' => 2,
            'required' => true,
            'description' => 'Primary security indicators and measurements'
        ),
        'risks' => array(
            'title' => 'Risk Assessment',
            'type' => 'vulnerabilities',
            'priority' => 3,
            'required' => true,
            'description' => 'Current risk level and vulnerability summary',
            'config' => array(
                'show_details' => false,
                'summary_only' => true,
                'max_items' => 5
            )
        ),
        'charts' => array(
            'title' => 'Security Visualizations',
            'type' => 'charts',
            'priority' => 4,
            'required' => false,
            'description' => 'Visual representation of security data'
        ),
        'recommendations' => array(
            'title' => 'Priority Recommendations',
            'type' => 'recommendations',
            'priority' => 5,
            'required' => true,
            'description' => 'Top security recommendations for immediate action',
            'config' => array(
                'max_items' => 5,
                'priority_filter' => array('critical', 'high')
            )
        ),
        'compliance' => array(
            'title' => 'Compliance Status',
            'type' => 'compliance',
            'priority' => 6,
            'required' => false,
            'description' => 'Security framework compliance overview'
        )
    ),
    'styling' => array(
        'theme' => 'executive',
        'colors' => array(
            'primary' => '#2271b1',
            'secondary' => '#135e96',
            'success' => '#00a32a',
            'warning' => '#dba617',
            'danger' => '#d63638',
            'text' => '#1d2327'
        ),
        'fonts' => array(
            'heading' => 'Arial, sans-serif',
            'body' => 'Arial, sans-serif',
            'size_base' => '14px'
        ),
        'layout' => array(
            'margins' => '20px',
            'spacing' => '15px',
            'page_break' => true
        )
    ),
    'export_formats' => array(
        'pdf' => array(
            'enabled' => true,
            'orientation' => 'portrait',
            'page_size' => 'A4'
        ),
        'html' => array(
            'enabled' => true,
            'responsive' => true
        ),
        'email' => array(
            'enabled' => true,
            'inline_css' => true
        )
    )
);
