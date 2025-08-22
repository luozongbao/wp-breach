<?php
/**
 * Trend Analysis Report Template
 *
 * Template configuration for generating trend analysis reports
 * focused on historical data analysis and security predictions.
 */

return array(
    'name' => 'Trend Analysis Report',
    'version' => '1.0.0',
    'description' => 'Historical security metrics analysis and trend predictions',
    'audience' => 'analyst',
    'sections' => array(
        'trends' => array(
            'title' => 'Security Trends Analysis',
            'type' => 'trends',
            'priority' => 1,
            'required' => true,
            'description' => 'Analysis of security metrics over time',
            'config' => array(
                'timeframes' => array('7d', '30d', '90d', '1y'),
                'metrics' => array(
                    'vulnerability_discovery_rate',
                    'fix_rate',
                    'security_score_progression',
                    'scan_frequency',
                    'response_time'
                ),
                'include_seasonality' => true
            )
        ),
        'predictions' => array(
            'title' => 'Predictive Analysis',
            'type' => 'predictions',
            'priority' => 2,
            'required' => true,
            'description' => 'Predictive modeling and forecasting',
            'config' => array(
                'prediction_horizon' => '90d',
                'confidence_intervals' => true,
                'scenarios' => array('optimistic', 'realistic', 'pessimistic'),
                'prediction_models' => array('linear', 'polynomial', 'moving_average')
            )
        ),
        'improvements' => array(
            'title' => 'Security Improvements',
            'type' => 'improvement_analysis',
            'priority' => 3,
            'required' => true,
            'description' => 'Analysis of security posture improvements',
            'config' => array(
                'improvement_metrics' => array(
                    'vulnerability_reduction',
                    'fix_time_improvement',
                    'detection_accuracy',
                    'false_positive_reduction'
                ),
                'measure_effectiveness' => true,
                'roi_analysis' => true
            )
        ),
        'benchmarks' => array(
            'title' => 'Industry Benchmarking',
            'type' => 'benchmarks',
            'priority' => 4,
            'required' => false,
            'description' => 'Comparison against industry standards and best practices',
            'config' => array(
                'benchmark_categories' => array(
                    'vulnerability_density',
                    'mean_time_to_detection',
                    'mean_time_to_resolution',
                    'security_score'
                ),
                'industry_comparisons' => true,
                'percentile_rankings' => true
            )
        ),
        'trend_charts' => array(
            'title' => 'Trend Visualizations',
            'type' => 'charts',
            'priority' => 5,
            'required' => true,
            'description' => 'Visual representation of trends and predictions',
            'config' => array(
                'chart_types' => array('line', 'area', 'scatter', 'multi_series'),
                'time_series_analysis' => true,
                'trend_lines' => true,
                'confidence_bands' => true
            )
        ),
        'insights' => array(
            'title' => 'Key Insights',
            'type' => 'insights',
            'priority' => 6,
            'required' => true,
            'description' => 'Data-driven insights and recommendations',
            'config' => array(
                'statistical_significance' => true,
                'correlation_analysis' => true,
                'anomaly_detection' => true,
                'actionable_insights' => true
            )
        )
    ),
    'analysis_settings' => array(
        'statistical_methods' => array(
            'regression_analysis' => true,
            'moving_averages' => true,
            'seasonal_decomposition' => true,
            'correlation_analysis' => true,
            'anomaly_detection' => true
        ),
        'time_series_config' => array(
            'sampling_interval' => 'daily',
            'smoothing_factor' => 0.3,
            'seasonality_detection' => 'auto',
            'outlier_handling' => 'robust'
        ),
        'prediction_config' => array(
            'model_validation' => 'cross_validation',
            'accuracy_metrics' => array('mse', 'mae', 'mape'),
            'confidence_level' => 0.95,
            'prediction_intervals' => true
        )
    ),
    'styling' => array(
        'theme' => 'analytical',
        'colors' => array(
            'primary' => '#2c3e50',
            'secondary' => '#34495e',
            'trend_up' => '#27ae60',
            'trend_down' => '#e74c3c',
            'trend_stable' => '#3498db',
            'prediction' => '#9b59b6',
            'confidence' => '#95a5a6'
        ),
        'fonts' => array(
            'heading' => 'Arial, sans-serif',
            'body' => 'Arial, sans-serif',
            'data' => 'Consolas, Monaco, monospace',
            'size_base' => '13px'
        ),
        'layout' => array(
            'margins' => '18px',
            'spacing' => '14px',
            'grid_layout' => true,
            'chart_emphasis' => true
        )
    ),
    'export_formats' => array(
        'pdf' => array(
            'enabled' => true,
            'orientation' => 'landscape',
            'page_size' => 'A4',
            'chart_quality' => 'high'
        ),
        'html' => array(
            'enabled' => true,
            'responsive' => true,
            'interactive_charts' => true
        ),
        'csv' => array(
            'enabled' => true,
            'time_series_data' => true
        ),
        'json' => array(
            'enabled' => true,
            'api_format' => true
        )
    )
);
