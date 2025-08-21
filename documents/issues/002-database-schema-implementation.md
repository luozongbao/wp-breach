# Issue #002: Database Schema Implementation

## Overview
Implement the complete database schema for WP-Breach plugin including all tables for scans, vulnerabilities, fixes, monitoring, alerts, and configuration data.

## Project Context
Based on the ER diagram specifications, this issue involves creating all database tables that will store scan results, vulnerability data, configuration settings, and monitoring information. This is a critical foundation for all plugin functionality.

## Task Breakdown

### 1. Core Database Tables Creation
**Priority:** Critical
**Estimated Time:** 6 hours

#### Tasks:
- [ ] Create `wp_breach_scans` table with proper structure and indexes
- [ ] Create `wp_breach_vulnerabilities` table with foreign key relationships
- [ ] Create `wp_breach_fixes` table linking to vulnerabilities
- [ ] Implement proper MySQL indexes for performance optimization
- [ ] Add foreign key constraints and referential integrity

### 2. Configuration and Settings Tables
**Priority:** Critical
**Estimated Time:** 3 hours

#### Tasks:
- [ ] Create `wp_breach_settings` table for plugin configuration
- [ ] Create `wp_breach_schedules` table for automated scan scheduling
- [ ] Implement encrypted storage for sensitive settings
- [ ] Add default configuration values during table creation

### 3. Monitoring and Alerting Tables
**Priority:** High
**Estimated Time:** 4 hours

#### Tasks:
- [ ] Create `wp_breach_alerts` table for notifications
- [ ] Create `wp_breach_monitoring` table for real-time monitoring
- [ ] Implement file integrity monitoring structure
- [ ] Add proper indexing for time-based queries

### 4. Reference and Cache Tables
**Priority:** Medium
**Estimated Time:** 3 hours

#### Tasks:
- [ ] Create `wp_breach_vulnerability_db` for CVE database cache
- [ ] Create `wp_breach_scan_logs` for detailed logging
- [ ] Create `wp_breach_reports` for generated reports metadata
- [ ] Implement proper data retention policies

### 5. Database Migration System
**Priority:** High
**Estimated Time:** 4 hours

#### Tasks:
- [ ] Create database migration framework
- [ ] Implement version tracking for schema changes
- [ ] Create rollback procedures for failed migrations
- [ ] Add database upgrade/downgrade utilities

## Database Schema Details

### Table Specifications:

#### wp_breach_scans
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
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

#### wp_breach_vulnerabilities
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
    detected_at DATETIME NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

## Implementation Requirements

### 1. Database Class Structure
**File:** `includes/class-wp-breach-database.php`

#### Methods to Implement:
- [ ] `create_tables()` - Create all tables
- [ ] `drop_tables()` - Remove all tables (for uninstall)
- [ ] `migrate_database()` - Handle schema migrations
- [ ] `get_database_version()` - Track schema version
- [ ] `update_database_version()` - Update schema version

### 2. Data Access Layer
**File:** `includes/database/` directory

#### Classes to Create:
- [ ] `class-wp-breach-scan-model.php` - Scan data operations
- [ ] `class-wp-breach-vulnerability-model.php` - Vulnerability operations
- [ ] `class-wp-breach-fix-model.php` - Fix tracking operations
- [ ] `class-wp-breach-settings-model.php` - Settings management
- [ ] `class-wp-breach-alert-model.php` - Alert operations

### 3. Database Utilities
**File:** `includes/utilities/class-wp-breach-db-utilities.php`

#### Utilities to Implement:
- [ ] Data validation functions
- [ ] Data sanitization functions
- [ ] Query optimization helpers
- [ ] Backup and restore utilities

## Performance Considerations

### 1. Indexing Strategy
- [ ] Primary keys on all tables
- [ ] Foreign key indexes for relationship optimization
- [ ] Composite indexes for frequently queried combinations
- [ ] Date/time indexes for chronological queries

### 2. Query Optimization
- [ ] Use prepared statements for all database operations
- [ ] Implement query caching where appropriate
- [ ] Optimize JOIN operations
- [ ] Consider partitioning for large tables

### 3. Data Retention
- [ ] Implement automated cleanup for old scan logs (90 days)
- [ ] Archive old vulnerability data
- [ ] Compress large JSON data
- [ ] Regular database maintenance routines

## Security Requirements

### 1. Data Protection
- [ ] Encrypt sensitive configuration data
- [ ] Use WordPress database abstraction layer ($wpdb)
- [ ] Implement proper user capability checks
- [ ] Sanitize all input data

### 2. SQL Injection Prevention
- [ ] Use prepared statements exclusively
- [ ] Validate all user inputs
- [ ] Escape output data
- [ ] Implement proper error handling

## Acceptance Criteria

### Must Have:
- [ ] All 11 database tables are created successfully
- [ ] Foreign key relationships work correctly
- [ ] Database migration system is functional
- [ ] All indexes are properly implemented
- [ ] Data validation and sanitization works
- [ ] Plugin activation creates tables without errors
- [ ] Plugin deactivation preserves data
- [ ] Plugin uninstall removes all tables cleanly

### Should Have:
- [ ] Database operations are optimized for performance
- [ ] Proper error logging for database operations
- [ ] Data backup utilities are implemented
- [ ] Database integrity checks are available

### Could Have:
- [ ] Database query profiling tools
- [ ] Advanced data migration utilities
- [ ] Database optimization recommendations

## Testing Requirements

### 1. Unit Tests
- [ ] Test table creation and structure
- [ ] Test foreign key constraints
- [ ] Test data validation functions
- [ ] Test migration procedures

### 2. Integration Tests
- [ ] Test database operations with WordPress
- [ ] Test multisite compatibility
- [ ] Test with different MySQL versions
- [ ] Test performance with large datasets

### 3. Data Integrity Tests
- [ ] Test referential integrity
- [ ] Test data corruption scenarios
- [ ] Test backup and restore procedures

## Files to Create/Modify

### New Database Files:
1. `includes/class-wp-breach-database.php` - Main database class
2. `includes/database/class-wp-breach-scan-model.php`
3. `includes/database/class-wp-breach-vulnerability-model.php`
4. `includes/database/class-wp-breach-fix-model.php`
5. `includes/database/class-wp-breach-settings-model.php`
6. `includes/database/class-wp-breach-alert-model.php`
7. `includes/utilities/class-wp-breach-db-utilities.php`

### Migration Files:
8. `includes/migrations/001-initial-schema.php`
9. `includes/migrations/migration-manager.php`

## Dependencies
- WordPress database abstraction layer ($wpdb)
- MySQL 5.6+ (for JSON column support)
- PHP 7.4+ (for proper type declarations)

## Documentation Requirements
- [ ] Database schema documentation
- [ ] Migration procedure documentation
- [ ] Data model relationships documentation
- [ ] Performance optimization guide

## Related Issues
**Prerequisite:** Issue #001 - Project Foundation Setup
**Enables:** 
- Issue #003 - Security Scanner Core Engine
- Issue #004 - Admin Dashboard Development
- Issue #005 - Vulnerability Detection System

## Notes for Developer
- Use WordPress $wpdb global for database operations
- Follow WordPress database table naming conventions
- Implement proper error handling and logging
- Consider database table prefixes for multisite installations
- Test thoroughly with different WordPress configurations
- Use dbDelta() function for table creation to ensure compatibility
