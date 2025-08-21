# WP-Breach Plugin Entity Relationship Diagram

## Database Design Overview
This document outlines the database schema for the WP-Breach WordPress security plugin. The design focuses on efficiently storing scan results, vulnerability data, and configuration settings while maintaining data integrity and performance.

## Database Tables

### 1. Core Tables

#### 1.1 wp_breach_scans
Primary table for storing scan metadata and results.

```sql
CREATE TABLE wp_breach_scans (
    id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    scan_type ENUM('quick', 'full', 'custom') NOT NULL,
    status ENUM('pending', 'running', 'completed', 'failed', 'cancelled') NOT NULL DEFAULT 'pending',
    started_at DATETIME NOT NULL,
    completed_at DATETIME NULL,
    duration_seconds INT UNSIGNED NULL,
    total_checks INT UNSIGNED DEFAULT 0,
    vulnerabilities_found INT UNSIGNED DEFAULT 0,
    configuration JSON NULL,
    summary_data JSON NULL,
    created_by BIGINT(20) UNSIGNED NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_status (status),
    INDEX idx_scan_type (scan_type),
    INDEX idx_started_at (started_at),
    INDEX idx_created_by (created_by),
    FOREIGN KEY (created_by) REFERENCES wp_users(ID) ON DELETE CASCADE
);
```

#### 1.2 wp_breach_vulnerabilities
Stores detailed information about discovered vulnerabilities.

```sql
CREATE TABLE wp_breach_vulnerabilities (
    id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    scan_id BIGINT(20) UNSIGNED NOT NULL,
    vulnerability_type ENUM('sql_injection', 'xss', 'csrf', 'file_inclusion', 'directory_traversal', 'weak_password', 'outdated_software', 'file_permissions', 'configuration', 'other') NOT NULL,
    severity ENUM('critical', 'high', 'medium', 'low') NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    component_type ENUM('core', 'plugin', 'theme', 'database', 'file_system', 'user_account') NOT NULL,
    component_name VARCHAR(255) NULL,
    component_version VARCHAR(50) NULL,
    affected_file VARCHAR(500) NULL,
    line_number INT UNSIGNED NULL,
    cvss_score DECIMAL(3,1) NULL,
    cve_id VARCHAR(20) NULL,
    cwe_id VARCHAR(20) NULL,
    risk_level ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    status ENUM('open', 'fixed', 'ignored', 'false_positive') NOT NULL DEFAULT 'open',
    fix_available BOOLEAN DEFAULT FALSE,
    auto_fixable BOOLEAN DEFAULT FALSE,
    fix_complexity ENUM('easy', 'medium', 'hard') NULL,
    detected_at DATETIME NOT NULL,
    first_detected_at DATETIME NULL,
    last_seen_at DATETIME NULL,
    fix_applied_at DATETIME NULL,
    fixed_by BIGINT(20) UNSIGNED NULL,
    raw_data JSON NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_scan_id (scan_id),
    INDEX idx_severity (severity),
    INDEX idx_status (status),
    INDEX idx_component (component_type, component_name),
    INDEX idx_vulnerability_type (vulnerability_type),
    INDEX idx_detected_at (detected_at),
    FOREIGN KEY (scan_id) REFERENCES wp_breach_scans(id) ON DELETE CASCADE,
    FOREIGN KEY (fixed_by) REFERENCES wp_users(ID) ON DELETE SET NULL
);
```

#### 1.3 wp_breach_fixes
Tracks applied fixes and their results.

```sql
CREATE TABLE wp_breach_fixes (
    id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    vulnerability_id BIGINT(20) UNSIGNED NOT NULL,
    fix_type ENUM('automatic', 'manual', 'update', 'configuration', 'file_modification') NOT NULL,
    fix_method VARCHAR(100) NOT NULL,
    status ENUM('pending', 'in_progress', 'completed', 'failed', 'rolled_back') NOT NULL DEFAULT 'pending',
    applied_at DATETIME NULL,
    applied_by BIGINT(20) UNSIGNED NOT NULL,
    rollback_available BOOLEAN DEFAULT FALSE,
    rollback_data JSON NULL,
    fix_details JSON NULL,
    before_snapshot JSON NULL,
    after_snapshot JSON NULL,
    error_message TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_vulnerability_id (vulnerability_id),
    INDEX idx_status (status),
    INDEX idx_applied_at (applied_at),
    INDEX idx_applied_by (applied_by),
    FOREIGN KEY (vulnerability_id) REFERENCES wp_breach_vulnerabilities(id) ON DELETE CASCADE,
    FOREIGN KEY (applied_by) REFERENCES wp_users(ID) ON DELETE CASCADE
);
```

### 2. Configuration Tables

#### 2.1 wp_breach_settings
Stores plugin configuration and user preferences.

```sql
CREATE TABLE wp_breach_settings (
    id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    setting_key VARCHAR(100) NOT NULL UNIQUE,
    setting_value LONGTEXT NULL,
    setting_type ENUM('string', 'integer', 'boolean', 'json', 'array') NOT NULL DEFAULT 'string',
    is_encrypted BOOLEAN DEFAULT FALSE,
    user_id BIGINT(20) UNSIGNED NULL,
    description TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_setting_key (setting_key),
    INDEX idx_user_id (user_id),
    FOREIGN KEY (user_id) REFERENCES wp_users(ID) ON DELETE CASCADE
);
```

#### 2.2 wp_breach_schedules
Manages scheduled scan configurations.

```sql
CREATE TABLE wp_breach_schedules (
    id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    scan_type ENUM('quick', 'full', 'custom') NOT NULL,
    frequency ENUM('daily', 'weekly', 'monthly', 'custom') NOT NULL,
    frequency_details JSON NULL,
    next_run DATETIME NOT NULL,
    last_run DATETIME NULL,
    is_active BOOLEAN DEFAULT TRUE,
    configuration JSON NULL,
    created_by BIGINT(20) UNSIGNED NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_next_run (next_run),
    INDEX idx_is_active (is_active),
    INDEX idx_created_by (created_by),
    FOREIGN KEY (created_by) REFERENCES wp_users(ID) ON DELETE CASCADE
);
```

### 3. Monitoring and Alerting Tables

#### 3.1 wp_breach_alerts
Stores security alerts and notifications.

```sql
CREATE TABLE wp_breach_alerts (
    id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    alert_type ENUM('vulnerability_detected', 'scan_completed', 'fix_applied', 'system_error', 'threshold_exceeded') NOT NULL,
    severity ENUM('info', 'warning', 'error', 'critical') NOT NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    related_scan_id BIGINT(20) UNSIGNED NULL,
    related_vulnerability_id BIGINT(20) UNSIGNED NULL,
    target_users JSON NULL,
    delivery_methods JSON NULL,
    sent_at DATETIME NULL,
    acknowledged_at DATETIME NULL,
    acknowledged_by BIGINT(20) UNSIGNED NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_alert_type (alert_type),
    INDEX idx_severity (severity),
    INDEX idx_sent_at (sent_at),
    INDEX idx_is_read (is_read),
    FOREIGN KEY (related_scan_id) REFERENCES wp_breach_scans(id) ON DELETE SET NULL,
    FOREIGN KEY (related_vulnerability_id) REFERENCES wp_breach_vulnerabilities(id) ON DELETE SET NULL,
    FOREIGN KEY (acknowledged_by) REFERENCES wp_users(ID) ON DELETE SET NULL
);
```

#### 3.2 wp_breach_monitoring
Real-time monitoring data and file integrity checks.

```sql
CREATE TABLE wp_breach_monitoring (
    id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    monitor_type ENUM('file_integrity', 'login_attempt', 'permission_change', 'plugin_activation', 'theme_change') NOT NULL,
    file_path VARCHAR(500) NULL,
    file_hash VARCHAR(64) NULL,
    change_type ENUM('created', 'modified', 'deleted', 'permission_changed') NULL,
    old_value JSON NULL,
    new_value JSON NULL,
    user_id BIGINT(20) UNSIGNED NULL,
    ip_address VARCHAR(45) NULL,
    user_agent TEXT NULL,
    risk_level ENUM('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'low',
    is_suspicious BOOLEAN DEFAULT FALSE,
    detected_at DATETIME NOT NULL,
    processed_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_monitor_type (monitor_type),
    INDEX idx_detected_at (detected_at),
    INDEX idx_is_suspicious (is_suspicious),
    INDEX idx_file_path (file_path(255)),
    INDEX idx_user_id (user_id),
    FOREIGN KEY (user_id) REFERENCES wp_users(ID) ON DELETE SET NULL
);
```

### 4. Reference and Cache Tables

#### 4.1 wp_breach_vulnerability_db
Local cache of known vulnerabilities database.

```sql
CREATE TABLE wp_breach_vulnerability_db (
    id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL UNIQUE,
    cwe_id VARCHAR(20) NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    severity ENUM('critical', 'high', 'medium', 'low') NOT NULL,
    cvss_score DECIMAL(3,1) NULL,
    affected_software VARCHAR(255) NULL,
    affected_versions TEXT NULL,
    patch_available BOOLEAN DEFAULT FALSE,
    patch_version VARCHAR(50) NULL,
    exploit_available BOOLEAN DEFAULT FALSE,
    published_date DATE NULL,
    modified_date DATE NULL,
    source VARCHAR(100) NULL,
    references JSON NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_cve_id (cve_id),
    INDEX idx_affected_software (affected_software),
    INDEX idx_severity (severity),
    INDEX idx_published_date (published_date)
);
```

#### 4.2 wp_breach_scan_logs
Detailed logs for scan processes and debugging.

```sql
CREATE TABLE wp_breach_scan_logs (
    id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    scan_id BIGINT(20) UNSIGNED NOT NULL,
    log_level ENUM('debug', 'info', 'warning', 'error', 'critical') NOT NULL,
    component VARCHAR(100) NOT NULL,
    message TEXT NOT NULL,
    context JSON NULL,
    execution_time DECIMAL(10,4) NULL,
    memory_usage INT UNSIGNED NULL,
    logged_at DATETIME NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_scan_id (scan_id),
    INDEX idx_log_level (log_level),
    INDEX idx_logged_at (logged_at),
    FOREIGN KEY (scan_id) REFERENCES wp_breach_scans(id) ON DELETE CASCADE
);
```

### 5. Reporting Tables

#### 5.1 wp_breach_reports
Generated security reports metadata.

```sql
CREATE TABLE wp_breach_reports (
    id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    report_type ENUM('security_summary', 'vulnerability_details', 'compliance', 'trend_analysis') NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NULL,
    date_range_start DATE NULL,
    date_range_end DATE NULL,
    filters JSON NULL,
    file_path VARCHAR(500) NULL,
    file_size INT UNSIGNED NULL,
    format ENUM('pdf', 'html', 'csv', 'json') NOT NULL,
    status ENUM('generating', 'completed', 'failed') NOT NULL DEFAULT 'generating',
    generated_by BIGINT(20) UNSIGNED NOT NULL,
    generated_at DATETIME NULL,
    expires_at DATETIME NULL,
    download_count INT UNSIGNED DEFAULT 0,
    is_public BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_report_type (report_type),
    INDEX idx_generated_by (generated_by),
    INDEX idx_generated_at (generated_at),
    INDEX idx_expires_at (expires_at),
    FOREIGN KEY (generated_by) REFERENCES wp_users(ID) ON DELETE CASCADE
);
```

## Entity Relationships

### 1. Primary Relationships

```
wp_users ||--o{ wp_breach_scans : creates
wp_breach_scans ||--o{ wp_breach_vulnerabilities : contains
wp_breach_vulnerabilities ||--o{ wp_breach_fixes : has_fixes
wp_users ||--o{ wp_breach_fixes : applies

wp_users ||--o{ wp_breach_settings : owns
wp_users ||--o{ wp_breach_schedules : creates
wp_users ||--o{ wp_breach_reports : generates

wp_breach_scans ||--o{ wp_breach_alerts : triggers
wp_breach_vulnerabilities ||--o{ wp_breach_alerts : generates
wp_breach_scans ||--o{ wp_breach_scan_logs : logged_in
```

### 2. ER Diagram (Text Representation)

```
                    ┌─────────────┐
                    │   wp_users  │
                    │             │
                    │ ID (PK)     │
                    │ user_login  │
                    │ user_email  │
                    │ ...         │
                    └──────┬──────┘
                           │
                           │ (1:N)
                           │
            ┌─────────────────────────────────────────┐
            │              │              │           │
            ▼              ▼              ▼           ▼
   ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
   │breach_scans │ │breach_fixes │ │breach_settings│ │breach_schedules│
   │             │ │             │ │             │ │             │
   │ id (PK)     │ │ id (PK)     │ │ id (PK)     │ │ id (PK)     │
   │ scan_type   │ │ vuln_id(FK) │ │ setting_key │ │ name        │
   │ status      │ │ fix_type    │ │ setting_val │ │ scan_type   │
   │ started_at  │ │ status      │ │ user_id(FK) │ │ frequency   │
   │ created_by  │ │ applied_by  │ │             │ │ created_by  │
   │ (FK)        │ │ (FK)        │ │             │ │ (FK)        │
   └──────┬──────┘ └─────────────┘ └─────────────┘ └─────────────┘
          │
          │ (1:N)
          │
          ▼
   ┌─────────────────┐
   │breach_vulnerabil│
   │ities            │
   │                 │
   │ id (PK)         │
   │ scan_id (FK)    │────────┐
   │ vuln_type       │        │
   │ severity        │        │ (1:N)
   │ title           │        │
   │ component_type  │        ▼
   │ status          │ ┌─────────────┐
   │ detected_at     │ │breach_fixes │
   │ fixed_by (FK)   │ │             │
   └─────────┬───────┘ │ id (PK)     │
             │         │ vuln_id(FK) │
             │         │ fix_type    │
             │ (1:N)   │ status      │
             │         │ applied_by  │
             ▼         │ (FK)        │
   ┌─────────────────┐ └─────────────┘
   │ breach_alerts   │
   │                 │
   │ id (PK)         │
   │ alert_type      │
   │ severity        │
   │ related_scan_id │
   │ (FK)            │
   │ related_vuln_id │
   │ (FK)            │
   └─────────────────┘
```

## Database Indexes and Performance

### 1. Primary Indexes
- All tables have AUTO_INCREMENT primary keys
- Foreign key relationships are properly indexed
- Composite indexes on frequently queried columns

### 2. Query Optimization
- Date-based partitioning for large scan tables
- JSON column indexing for MySQL 5.7+
- Proper use of ENUM types for status fields

### 3. Data Retention
- Automated cleanup of old scan logs (90 days default)
- Archive strategy for historical vulnerability data
- Backup integration for critical security data

## Security Considerations

### 1. Data Protection
- Sensitive configuration data encryption
- User access control at database level
- Audit trail for all security-related changes

### 2. Data Integrity
- Foreign key constraints prevent orphaned records
- JSON schema validation for complex data
- Proper transaction handling for multi-table operations

### 3. Performance Monitoring
- Query performance tracking
- Index usage optimization
- Regular database maintenance procedures

## Migration and Versioning

### 1. Schema Versioning
- Version tracking in wp_breach_settings
- Incremental migration scripts
- Rollback procedures for failed migrations

### 2. Data Migration
- Safe upgrade procedures
- Data validation during migration
- Backup requirements before schema changes

This database design provides a robust foundation for the WP-Breach plugin, ensuring scalability, performance, and data integrity while supporting all the plugin's security scanning and management features.
