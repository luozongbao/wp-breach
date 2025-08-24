#!/bin/bash

# WP-Breach Test Runner Script
# This script sets up the testing environment and runs various test suites

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WP_TESTS_DIR="/tmp/wordpress-tests-lib"
WP_CORE_DIR="/tmp/wordpress"
DB_NAME="wp_breach_test"
DB_USER="root"
DB_PASS=""
DB_HOST="localhost"
WP_VERSION="latest"

# Functions
print_header() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Check if required tools are installed
check_requirements() {
    print_header "Checking Requirements"
    
    # Check PHP
    if ! command -v php &> /dev/null; then
        print_error "PHP is not installed or not in PATH"
        exit 1
    fi
    print_success "PHP found: $(php --version | head -n1)"
    
    # Check Composer
    if ! command -v composer &> /dev/null; then
        print_error "Composer is not installed or not in PATH"
        exit 1
    fi
    print_success "Composer found: $(composer --version)"
    
    # Check MySQL/MariaDB
    if ! command -v mysql &> /dev/null; then
        print_warning "MySQL/MariaDB not found - database tests may fail"
    else
        print_success "MySQL/MariaDB found"
    fi
    
    # Check PHPUnit
    if [ ! -f "$PLUGIN_DIR/vendor/bin/phpunit" ]; then
        print_warning "PHPUnit not found in vendor - will install dependencies"
    else
        print_success "PHPUnit found in vendor"
    fi
}

# Install dependencies
install_dependencies() {
    print_header "Installing Dependencies"
    
    cd "$PLUGIN_DIR"
    
    if [ ! -d "vendor" ]; then
        print_info "Installing Composer dependencies..."
        composer install --dev --no-interaction
        print_success "Dependencies installed"
    else
        print_info "Updating Composer dependencies..."
        composer update --dev --no-interaction
        print_success "Dependencies updated"
    fi
}

# Download WordPress test suite
install_wp_tests() {
    if [ -d "$WP_TESTS_DIR" ] && [ -d "$WP_CORE_DIR" ]; then
        print_info "WordPress test environment already exists"
        return
    fi
    
    print_header "Setting up WordPress Test Environment"
    
    # Download WordPress test suite
    if [ ! -d "$WP_TESTS_DIR" ]; then
        print_info "Downloading WordPress test suite..."
        svn co --quiet https://develop.svn.wordpress.org/trunk/tests/phpunit/includes/ "$WP_TESTS_DIR/includes/"
        svn co --quiet https://develop.svn.wordpress.org/trunk/tests/phpunit/data/ "$WP_TESTS_DIR/data/"
        
        # Download wp-tests-config.php
        if [ ! -f "$WP_TESTS_DIR/wp-tests-config.php" ]; then
            wget -nv -O "$WP_TESTS_DIR/wp-tests-config.php" \
                https://develop.svn.wordpress.org/trunk/wp-tests-config-sample.php
        fi
        print_success "WordPress test suite downloaded"
    fi
    
    # Download WordPress core
    if [ ! -d "$WP_CORE_DIR" ]; then
        print_info "Downloading WordPress core..."
        mkdir -p "$WP_CORE_DIR"
        wget -nv -O "/tmp/wordpress.tar.gz" https://wordpress.org/wordpress-${WP_VERSION}.tar.gz
        tar --strip-components=1 -zxf "/tmp/wordpress.tar.gz" -C "$WP_CORE_DIR"
        rm "/tmp/wordpress.tar.gz"
        print_success "WordPress core downloaded"
    fi
    
    # Configure WordPress tests
    print_info "Configuring WordPress test environment..."
    
    # Set up wp-tests-config.php
    sed -i "s/youremptytestdbnamehere/$DB_NAME/" "$WP_TESTS_DIR/wp-tests-config.php"
    sed -i "s/yourusernamehere/$DB_USER/" "$WP_TESTS_DIR/wp-tests-config.php"
    sed -i "s/yourpasswordhere/$DB_PASS/" "$WP_TESTS_DIR/wp-tests-config.php"
    sed -i "s|localhost|$DB_HOST|" "$WP_TESTS_DIR/wp-tests-config.php"
    
    # Add WordPress core path
    echo "define( 'ABSPATH', '$WP_CORE_DIR/' );" >> "$WP_TESTS_DIR/wp-tests-config.php"
    
    print_success "WordPress test environment configured"
}

# Create test database
create_test_database() {
    print_header "Setting up Test Database"
    
    # Check if database exists
    if mysql -u"$DB_USER" -p"$DB_PASS" -h"$DB_HOST" -e "USE $DB_NAME" 2>/dev/null; then
        print_info "Test database already exists"
        return
    fi
    
    print_info "Creating test database: $DB_NAME"
    
    # Create database
    mysql -u"$DB_USER" -p"$DB_PASS" -h"$DB_HOST" -e "CREATE DATABASE IF NOT EXISTS $DB_NAME;" 2>/dev/null || {
        print_warning "Could not create database - continuing anyway"
    }
    
    print_success "Test database ready"
}

# Run specific test suite
run_tests() {
    local test_suite="$1"
    local coverage="$2"
    
    cd "$PLUGIN_DIR"
    
    case "$test_suite" in
        "unit")
            print_header "Running Unit Tests"
            if [ "$coverage" = "true" ]; then
                vendor/bin/phpunit --testsuite=unit --coverage-text --coverage-html tests/coverage/html
            else
                vendor/bin/phpunit --testsuite=unit
            fi
            ;;
        "integration")
            print_header "Running Integration Tests"
            if [ "$coverage" = "true" ]; then
                vendor/bin/phpunit --testsuite=integration --coverage-text
            else
                vendor/bin/phpunit --testsuite=integration
            fi
            ;;
        "performance")
            print_header "Running Performance Tests"
            export WP_BREACH_TEST_PERFORMANCE=true
            vendor/bin/phpunit --testsuite=performance
            ;;
        "performance-large")
            print_header "Running Performance Tests with Large Datasets"
            export WP_BREACH_TEST_PERFORMANCE=true
            export WP_BREACH_TEST_LARGE_DATASETS=true
            vendor/bin/phpunit --testsuite=performance
            ;;
        "all")
            print_header "Running All Tests"
            if [ "$coverage" = "true" ]; then
                vendor/bin/phpunit --coverage-text --coverage-html tests/coverage/html
            else
                vendor/bin/phpunit
            fi
            ;;
        *)
            print_error "Unknown test suite: $test_suite"
            print_info "Available test suites: unit, integration, performance, performance-large, all"
            exit 1
            ;;
    esac
}

# Run code quality checks
run_quality_checks() {
    print_header "Running Code Quality Checks"
    
    cd "$PLUGIN_DIR"
    
    # Code standards check
    print_info "Checking code standards..."
    if vendor/bin/phpcs --standard=WordPress --extensions=php --ignore=vendor/,tests/coverage/,node_modules/ . --report=summary; then
        print_success "Code standards check passed"
    else
        print_warning "Code standards issues found"
    fi
    
    # Static analysis
    if [ -f "vendor/bin/phpstan" ]; then
        print_info "Running static analysis..."
        if vendor/bin/phpstan analyse --level=5 includes/ admin/ public/ --error-format=table; then
            print_success "Static analysis passed"
        else
            print_warning "Static analysis issues found"
        fi
    fi
    
    # Mess detection
    if [ -f "vendor/bin/phpmd" ]; then
        print_info "Running mess detection..."
        if vendor/bin/phpmd includes/,admin/,public/ text cleancode,codesize,design,naming,unusedcode; then
            print_success "Mess detection passed"
        else
            print_warning "Mess detection issues found"
        fi
    fi
}

# Generate performance report
generate_performance_report() {
    print_header "Generating Performance Report"
    
    cd "$PLUGIN_DIR"
    
    # Run performance tests with reporting
    export WP_BREACH_TEST_PERFORMANCE=true
    vendor/bin/phpunit --testsuite=performance --group=benchmark
    
    # Check if report was generated
    if [ -f "wp-content/wp-breach-performance-report.json" ]; then
        print_success "Performance report generated: wp-content/wp-breach-performance-report.json"
        
        # Display summary
        print_info "Performance Report Summary:"
        if command -v jq &> /dev/null; then
            jq '.performance_summary' wp-content/wp-breach-performance-report.json 2>/dev/null || {
                print_warning "Could not parse performance report (jq not available)"
            }
        else
            print_warning "Install 'jq' to see formatted performance summary"
        fi
    else
        print_warning "Performance report not found"
    fi
}

# Clean up test environment
cleanup() {
    print_header "Cleaning Up Test Environment"
    
    # Remove test database
    if [ "$1" = "full" ]; then
        print_info "Removing test database..."
        mysql -u"$DB_USER" -p"$DB_PASS" -h"$DB_HOST" -e "DROP DATABASE IF EXISTS $DB_NAME;" 2>/dev/null || {
            print_warning "Could not remove test database"
        }
        
        # Remove WordPress test files
        print_info "Removing WordPress test files..."
        rm -rf "$WP_TESTS_DIR" "$WP_CORE_DIR"
        
        print_success "Full cleanup completed"
    else
        # Just clean test artifacts
        print_info "Cleaning test artifacts..."
        rm -rf "$PLUGIN_DIR/tests/coverage"
        rm -f "$PLUGIN_DIR/wp-content/wp-breach-performance-report.json"
        
        print_success "Test artifacts cleaned"
    fi
}

# Show usage
show_usage() {
    echo "WP-Breach Test Runner"
    echo ""
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  setup                    Set up test environment"
    echo "  test [suite] [--coverage] Run tests (unit|integration|performance|performance-large|all)"
    echo "  quality                  Run code quality checks"
    echo "  performance-report       Generate performance report"
    echo "  cleanup [full]           Clean up test environment"
    echo "  help                     Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 setup                 # Set up test environment"
    echo "  $0 test unit             # Run unit tests"
    echo "  $0 test all --coverage   # Run all tests with coverage"
    echo "  $0 quality               # Run code quality checks"
    echo "  $0 performance-report    # Generate performance report"
    echo "  $0 cleanup full          # Full cleanup including database"
    echo ""
}

# Main script logic
main() {
    case "${1:-help}" in
        "setup")
            check_requirements
            install_dependencies
            install_wp_tests
            create_test_database
            print_success "Test environment setup completed!"
            ;;
        "test")
            check_requirements
            
            # Ensure environment is set up
            if [ ! -d "$WP_TESTS_DIR" ] || [ ! -d "$WP_CORE_DIR" ]; then
                print_info "Test environment not found, setting up..."
                install_wp_tests
                create_test_database
            fi
            
            # Check if coverage is requested
            coverage="false"
            if [ "$3" = "--coverage" ] || [ "$2" = "--coverage" ]; then
                coverage="true"
            fi
            
            # Determine test suite
            suite="${2:-all}"
            if [ "$suite" = "--coverage" ]; then
                suite="all"
            fi
            
            run_tests "$suite" "$coverage"
            ;;
        "quality")
            check_requirements
            install_dependencies
            run_quality_checks
            ;;
        "performance-report")
            check_requirements
            install_dependencies
            
            # Ensure environment is set up
            if [ ! -d "$WP_TESTS_DIR" ] || [ ! -d "$WP_CORE_DIR" ]; then
                print_info "Test environment not found, setting up..."
                install_wp_tests
                create_test_database
            fi
            
            generate_performance_report
            ;;
        "cleanup")
            cleanup "$2"
            ;;
        "help"|*)
            show_usage
            ;;
    esac
}

# Run main function with all arguments
main "$@"
