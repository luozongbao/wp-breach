<?php
/**
 * Compliance Report Template
 *
 * Template configuration for generating compliance and audit reports
 * focused on security framework adherence and control effectiveness.
 */

return array(
    'name' => 'Compliance Report',
    'version' => '1.0.0',
    'description' => 'Security framework compliance assessment and audit documentation',
    'audience' => 'auditor',
    'sections' => array(
        'frameworks' => array(
            'title' => 'Security Framework Assessment',
            'type' => 'compliance',
            'priority' => 1,
            'required' => true,
            'description' => 'Compliance status against major security frameworks',
            'config' => array(
                'frameworks' => array('owasp', 'nist', 'iso27001', 'pci_dss'),
                'show_scores' => true,
                'include_gap_analysis' => true
            )
        ),
        'controls' => array(
            'title' => 'Security Control Effectiveness',
            'type' => 'control_assessment',
            'priority' => 2,
            'required' => true,
            'description' => 'Analysis of security control implementation and effectiveness',
            'config' => array(
                'control_categories' => array(
                    'access_control',
                    'authentication',
                    'encryption',
                    'monitoring',
                    'incident_response'
                ),
                'maturity_assessment' => true
            )
        ),
        'gaps' => array(
            'title' => 'Compliance Gaps',
            'type' => 'gap_analysis',
            'priority' => 3,
            'required' => true,
            'description' => 'Identified gaps in compliance and control implementation',
            'config' => array(
                'prioritize_by_risk' => true,
                'include_remediation_timeline' => true,
                'map_to_frameworks' => true
            )
        ),
        'audit_trail' => array(
            'title' => 'Audit Trail',
            'type' => 'audit_documentation',
            'priority' => 4,
            'required' => true,
            'description' => 'Documentation of security activities and changes',
            'config' => array(
                'include_scan_history' => true,
                'include_fix_history' => true,
                'include_configuration_changes' => true,
                'date_range_filter' => true
            )
        ),
        'compliance_charts' => array(
            'title' => 'Compliance Visualizations',
            'type' => 'charts',
            'priority' => 5,
            'required' => false,
            'description' => 'Visual representation of compliance metrics',
            'config' => array(
                'chart_types' => array('radar', 'heatmap', 'timeline'),
                'framework_comparison' => true
            )
        ),
        'recommendations' => array(
            'title' => 'Compliance Recommendations',
            'type' => 'recommendations',
            'priority' => 6,
            'required' => true,
            'description' => 'Recommendations for improving compliance posture',
            'config' => array(
                'focus_on_compliance' => true,
                'include_implementation_guidance' => true,
                'map_to_controls' => true
            )
        )
    ),
    'compliance_frameworks' => array(
        'owasp' => array(
            'name' => 'OWASP Top 10',
            'version' => '2021',
            'controls' => array(
                'A01_2021' => 'Broken Access Control',
                'A02_2021' => 'Cryptographic Failures',
                'A03_2021' => 'Injection',
                'A04_2021' => 'Insecure Design',
                'A05_2021' => 'Security Misconfiguration',
                'A06_2021' => 'Vulnerable and Outdated Components',
                'A07_2021' => 'Identification and Authentication Failures',
                'A08_2021' => 'Software and Data Integrity Failures',
                'A09_2021' => 'Security Logging and Monitoring Failures',
                'A10_2021' => 'Server-Side Request Forgery'
            )
        ),
        'nist' => array(
            'name' => 'NIST Cybersecurity Framework',
            'version' => '1.1',
            'functions' => array(
                'identify' => 'Identify',
                'protect' => 'Protect',
                'detect' => 'Detect',
                'respond' => 'Respond',
                'recover' => 'Recover'
            )
        ),
        'iso27001' => array(
            'name' => 'ISO 27001',
            'version' => '2013',
            'domains' => array(
                'A5' => 'Information Security Policies',
                'A6' => 'Organization of Information Security',
                'A7' => 'Human Resource Security',
                'A8' => 'Asset Management',
                'A9' => 'Access Control',
                'A10' => 'Cryptography',
                'A11' => 'Physical and Environmental Security',
                'A12' => 'Operations Security',
                'A13' => 'Communications Security',
                'A14' => 'System Acquisition, Development and Maintenance',
                'A15' => 'Supplier Relationships',
                'A16' => 'Information Security Incident Management',
                'A17' => 'Information Security Aspects of Business Continuity Management',
                'A18' => 'Compliance'
            )
        ),
        'pci_dss' => array(
            'name' => 'PCI DSS',
            'version' => '4.0',
            'requirements' => array(
                'R1' => 'Install and maintain network security controls',
                'R2' => 'Apply secure configurations to all system components',
                'R3' => 'Protect stored cardholder data',
                'R4' => 'Protect cardholder data with strong cryptography during transmission',
                'R5' => 'Protect all systems and networks from malicious software',
                'R6' => 'Develop and maintain secure systems and software',
                'R7' => 'Restrict access to cardholder data by business need to know',
                'R8' => 'Identify users and authenticate access to system components',
                'R9' => 'Restrict physical access to cardholder data',
                'R10' => 'Log and monitor all access to network resources and cardholder data',
                'R11' => 'Test security of systems and networks regularly',
                'R12' => 'Support information security with organizational policies and programs'
            )
        )
    ),
    'styling' => array(
        'theme' => 'compliance',
        'colors' => array(
            'primary' => '#0073aa',
            'secondary' => '#005177',
            'compliant' => '#00a32a',
            'non_compliant' => '#d63638',
            'partial' => '#dba617',
            'na' => '#8c8f94',
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
            'tables' => true,
            'formal_layout' => true
        )
    ),
    'export_formats' => array(
        'pdf' => array(
            'enabled' => true,
            'orientation' => 'portrait',
            'page_size' => 'A4',
            'watermark' => 'CONFIDENTIAL'
        ),
        'html' => array(
            'enabled' => true,
            'responsive' => true
        ),
        'csv' => array(
            'enabled' => true,
            'compliance_matrix' => true
        )
    )
);
