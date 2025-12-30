# Prowler Security Insights Dashboard Documentation

This document provides detailed technical information about the Prowler Security Insights Dashboard features, calculations, and implementation details.

![Dashboard Screenshot](sample-scan-insights/prowler_dashboard_screenshot.png)

## Table of Contents

1. [Dashboard Features & Calculations](#dashboard-features--calculations)
2. [Score Calculation Methodology](#score-calculation-methodology)
3. [Data Processing Pipeline](#data-processing-pipeline)
4. [Dashboard Generation & Usage](#dashboard-generation--usage)
5. [Architecture & Implementation](#architecture--implementation)
6. [Troubleshooting & Debugging](#troubleshooting--debugging)

---

## Dashboard Features & Calculations

### Summary Statistics Cards
Four key metric cards provide immediate visibility into security posture:

- **Critical Findings** (Red): Count of `STATUS = 'Failed'` and `SEVERITY = 'Critical'`
- **High Findings** (Orange): Count of `STATUS = 'Failed'` and `SEVERITY = 'High'`
- **Total Findings** (Blue): Total count of all security findings across accounts
- **AWS Accounts** (Green): Count of unique `ACCOUNT_UID` values

### Overall Security Score
**Formula**: `Security Score = 100 - (Weighted Penalty / Max Possible Penalty × 100)`

**Severity Weights**: Critical: 10, High: 7, Medium: 4, Low: 2, Info: 1

**Color Coding**: Green >80%, Yellow 60-80%, Red <60%

### Interactive Charts

- **Severity Distribution** (Pie): Failed findings grouped by severity with color coding
- **Account Security Comparison** (Stacked Bar): Top 10 accounts by risk with severity breakdown
- **Service Risk Analysis** (Dual-Axis): Risk scores (bars) and failure counts (line) per service
- **Top Failing Checks** (Horizontal Bar): Most frequent security check failures across accounts
- **Regional Distribution** (Pie): Failed findings by AWS region with summary table

All charts include hover tooltips, responsive design, and consistent color schemes.

### Account Analysis Table
- **Risk Score**: Weighted severity formula applied per account
- **Pass Rate**: `(Total - Failed) / Total × 100`
- **Features**: Real-time filtering, pagination, color-coded risk scores, severity badges

### Service Vulnerability Analysis Table
- **Risk Score**: Weighted calculation for failed findings per service
- **Failure Rate**: `Failed / Total × 100` per service
- **Features**: Text search, pagination, sorting by critical/high failures first

### Improvement Roadmap Widget
- **Priority Categorization**: Immediate (Critical/High), Short-term (Medium), Long-term (Low/Info)
- **Timeline Visualization**: Interactive chart showing effort distribution
- **Actionable Items**: Remediation tasks with effort estimates and timelines

### Security Insights & Recommendations
Automatically generated contextual insights:
- **Critical Issues**: Alerts when critical findings detected
- **Account Performance**: Identifies accounts with pass rate < 70%
- **High-Risk Services**: Lists services with risk score > 70
- **Overall Posture**: Score-based recommendations (Critical <60%, Warning 60-80%, Success >80%)

### Interactive Features
- **Global Status Filter**: Filter all widgets by finding status
- **Real-time Updates**: Dynamic chart and table updates
- **Responsive Design**: Mobile and desktop optimization
- **Navigation Sidebar**: Collapsible hamburger menu for section navigation

## Score Calculation Methodology

### Overall Security Score Formula
```
Security Score = 100 - (Weighted Penalty / Max Possible Penalty × 100)
```

### Risk Score Formula (Per Account/Service)
```
Risk Score = (Risk Penalty / Max Risk Penalty × 100)
```

### Severity Weights
| Severity | Weight |
|----------|--------|
| Critical | 10     |
| High     | 7      |
| Medium   | 4      |
| Low      | 2      |
| Info     | 1      |

### Score Interpretation
- **Green (>80%)**: Good security posture, maintain current controls
- **Yellow (60-80%)**: Moderate risk, continue strengthening security
- **Red (<60%)**: High risk, immediate comprehensive improvement needed


## Dashboard Generation & Usage

### Generation Process
1. **Data Discovery**: Scans `output/` directory for Prowler CSV files
2. **Data Processing**: Cleans, normalizes, and validates findings data
3. **Analytics Calculation**: Generates statistics, risk scores, and insights
4. **Chart Configuration**: Creates Chart.js configurations
5. **HTML Assembly**: Builds self-contained HTML file with embedded assets
6. **File Output**: Saves dashboard to specified location

### Usage Examples
```bash
# Basic generation
./venv/bin/python generate_prowler_scan_insights.py

# With company branding
./venv/bin/python generate_prowler_scan_insights.py --company-name "Your Company"

# Custom output location
./venv/bin/python generate_prowler_scan_insights.py --output-dir ./scans --dashboard-file report.html

# Debug mode
./venv/bin/python generate_prowler_scan_insights.py --log-level DEBUG
```

### Key Features
- **Self-Contained**: Single HTML file, no external dependencies
- **Cross-Platform**: Works in any modern web browser
- **Mobile Responsive**: Optimized for all device sizes
- **Professional Branding**: Optional company name integration

## Data Processing Pipeline

### Data Loading & Discovery
- **File Discovery**: Scans for `*.csv`, `*prowler*.csv`, `*security*.csv` files
- **Format Detection**: Handles comma and semicolon-delimited CSV files
- **Validation**: Checks required columns and data integrity
- **Error Handling**: Skips malformed files with warnings

### Data Cleaning & Normalization
- **Severity Standardization**: Converts various formats to `Critical`, `High`, `Medium`, `Low`, `Info`
- **Status Standardization**: Normalizes to `Failed`, `Passed`, `Manual`, `Info`
- **Account/Service Cleaning**: Uses names when available, falls back to IDs
- **Duplicate Removal**: Uses `FINDING_UID` or combination keys for deduplication

### Required CSV Columns
- **Core**: `FINDING_UID`, `ACCOUNT_UID`, `CHECK_ID`, `STATUS`, `SEVERITY`, `SERVICE_NAME`, `REGION`
- **Optional**: `ACCOUNT_NAME`, `CHECK_TITLE`, `DESCRIPTION`, `REMEDIATION_RECOMMENDATION_TEXT`

## Architecture & Implementation

### Core Components
- **DataLoader**: CSV file discovery and loading with validation
- **DataProcessor**: Data cleaning, normalization, and scoring
- **SecurityAnalytics**: Risk analysis and insights generation
- **ChartGenerator**: Interactive Chart.js visualizations
- **ReportBuilder**: HTML dashboard assembly with embedded assets
- **ChartGenerator**: Interactive Chart.js visualizations
- **ReportBuilder**: HTML dashboard assembly with embedded assets

### Dashboard Structure
Single HTML file with embedded Bootstrap CSS, Chart.js, and custom JavaScript:
- Header with company branding and overall security score
- Summary statistics cards
- Interactive charts (2x2 grid)
- Detailed analysis tables with filtering and pagination
- Security insights and improvement roadmap
- Score calculation methodology

### Key Features
- **Responsive Design**: Mobile-first with breakpoint adaptations
- **Interactive Filtering**: Global status filter updates all components
- **Color Consistency**: Standardized severity color scheme
- **Error Handling**: Graceful degradation with malformed data

## Troubleshooting & Debugging

### Logging System
- **Automatic Logs**: Timestamped log files saved to `logs/` directory
- **Log Levels**: DEBUG, INFO, WARNING, ERROR, CRITICAL
- **Debug Mode**: Use `--log-level DEBUG` for verbose processing information

### Common Issues & Solutions
| Issue | Solution |
|-------|----------|
| **No CSV files found** | Ensure Prowler CSV files are in `output/` directory |
| **Missing columns** | Verify CSV files contain required Prowler columns |
| **Dashboard appears empty** | Check browser console; validate CSV data format |
| **Memory issues** | Process smaller batches of CSV files |
| **Chart rendering issues** | Validate CSV data format; check browser console |

### Error Handling
- **Graceful Degradation**: Continues processing with malformed CSV files
- **File Skipping**: Invalid files skipped with warnings
- **Data Validation**: Comprehensive validation with detailed error messages
- **Recovery Suggestions**: Actionable error messages with suggested fixes

### Debug Commands
```bash
# Enable debug logging
./venv/bin/python generate_prowler_scan_insights.py --log-level DEBUG

# Verify project structure
./venv/bin/python tests/verify_project.py

# Run test suite
./venv/bin/python tests/run_all_tests.py
```

---

**Note**: This dashboard tool processes Prowler CSV output locally with no external dependencies or network requirements.
