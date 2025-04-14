# Content Security Policy Analysis Project

A comprehensive tool for collecting and analyzing Content Security Policy (CSP) and Subresource Integrity (SRI) implementation across websites.

## Project Overview

This project provides tools to:
1. Collect CSP and SRI data from a large sample of websites
2. Store the collected data in a structured JSON format
3. Analyze the data to determine statistics on CSP implementation patterns
4. Generate insights on the effectiveness and adoption of various CSP directives
5. Classify CSP implementations using a 6-component security framework
6. Visualize protection levels across different security components

## Components

- **Data Collection Tools**: 
  - `csp_collector.py`: Scrapes websites and stores data in JSON format
  - `csp_collector_db.py`: Database-backed collector for processing large datasets
- **Analysis Tools**: 
  - `csp_analyzer.py`: Processes JSON data to generate statistics and insights
  - `csp_analyzer_db.py`: Database-backed analyzer for large datasets with enhanced 6-component framework
  - `csp_classification_enrichment.py`: Applies component-based CSP classification framework
- **Visualization**: Automatically generates charts and graphs of the analysis results
- **Documentation**:
  - `docs/csp-component-classifications.md`: Enhanced 6-component CSP classification framework

## Getting Started

### Prerequisites

- Python 3.8+
- pip (Python package installer)

### Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/csp-analysis.git
   cd csp-analysis
   ```

2. Set up a virtual environment:
   ```
   python -m venv venv
   ```

3. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
   - Unix/MacOS: `source venv/bin/activate`

4. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

### Usage

#### Collection (SQLite)

If you don't have it already, download the list tranco list (https://tranco-list.eu/top-1m.csv.zip) and unzip it into ./data

```bash
# Process URLs in batches, storing in SQLite database
python csp_collector_db.py --input top-1m.csv --db data/results/csp_database.db --batch-size 1000 --concurrency 30

# Process a subset of URLs for testing
python csp_collector_db.py --input top-1m.csv --db data/results/csp_database.db --batch-size 10 --limit 50

# Resume collection from a specific batch (e.g., after interruption)
python csp_collector_db.py --input top-1m.csv --db data/results/csp_database.db --start-batch 633

# Retry only missing domains (skips domains already in the database)
python csp_collector_db.py --input top-1m.csv --db data/results/csp_database.db --retry-missing

# Export database to JSON if needed
python csp_collector_db.py --input top-1m.csv --db data/results/csp_database.db --output results_from_db.json
```

Arguments:
- `--input`: Path to a CSV file containing target websites (Tranco list format: rank,domain)
- `--db`: Path to the SQLite database file (will be created if it doesn't exist)
- `--output`: Optional path to export database contents as JSON
- `--batch-size`: Number of sites to process in each batch (default: 1000)
- `--concurrency`: Number of concurrent requests (default: 30)
- `--timeout`: Request timeout in seconds (default: 20)
- `--limit`: Limit the number of URLs to process (useful for testing)
- `--start-batch`: Start processing from this batch number (for resuming after interruptions)
- `--retry-missing`: Only process domains that aren't already in the database

#### Analysis (SQLite)

```bash
# Analyze data from the SQLite database
python csp_analyzer_db.py --db data/results/csp_database.db --output data/results/db_analysis_report.json

# Export to CSV for spreadsheet analysis
python csp_analyzer_db.py --db data/results/csp_database.db --csv data/results/db_csp_data.csv
```

Arguments:
- `--db`: Path to the SQLite database file
- `--output`: Path to save the analysis results
- `--csv`: Path to export a CSV file for spreadsheet analysis
- `--include-errors`: Include sites with errors in analysis (by default, they're excluded)

#### CSP Classification Enrichment

Apply the component-based CSP classification framework to enrich your database:

```bash
# Analyze and classify all CSP policies in the database
python csp_classification_enrichment.py --db data/results/csp_database.db

# Only generate summary without re-analyzing policies
python csp_classification_enrichment.py --db data/results/csp_database.db --summary-only

# Force re-analysis of already classified policies
python csp_classification_enrichment.py --db data/results/csp_database.db --overwrite
```

Arguments:
- `--db`: Path to the SQLite database file
- `--batch-size`: Number of sites to process in each batch (default: 1000)
- `--overwrite`: Overwrite existing classifications (default: false)
- `--summary-only`: Only generate summary without enrichment (default: false)

## Project Structure

```
csp-analysis/
│
├── csp_collector_db.py            # Database-backed collection tool (SQLite)
├── csp_analyzer_db.py             # Database-backed analysis tool
├── csp_classification_enrichment.py # Component-based CSP classification
├── requirements.txt               # Project dependencies
│
├── docs/
│   └── csp-component-classifications.md # Classification framework documentation
│
├── utils/               # Utility modules
│   ├── __init__.py
│   ├── parser.py        # CSP parsing utilities
│   ├── logger.py        # Logging utilities
│   └── database.py      # Database operations
│
├── data/                # Data directory
│   ├── sample/          # Sample datasets
│   ├── top-1m.csv       # Tranco list of top domains
│   └── results/         # Output directory for results
│                        # (including SQLite database files)
│
│
└── docs/                # Documentation
    └── csp-analysis-requirements.md
```

## Database Management

The database-backed collector (`csp_collector_db.py`) will **add to an existing database** by default rather than overwriting it. This allows for:

- **Resuming interrupted scans**: If your collection is interrupted, you can restart and continue
- **Incremental collection**: You can add more domains to the same database over time
- **Avoiding data loss**: You won't accidentally overwrite your previously collected data

If you want to start with a fresh database instead:

1. **Delete the database file manually** before running:
   ```powershell
   Remove-Item data/results/csp_database.db
   python csp_collector_db.py --input data/top-1m.csv --db data/results/csp_database.db
   ```

2. **Use a different database path** for each run:
   ```powershell
   python csp_collector_db.py --input data/top-1m.csv --db data/results/csp_database_new.db
   ```

## Scaling to Millions of Domains

The database-backed scripts are designed to efficiently handle very large datasets:

- **Batch Processing**: Data is processed and stored in batches to manage memory usage
- **SQLite Storage**: Data is stored in a SQLite database, which is efficient for large datasets
- **Incremental Analysis**: You can analyze data without loading everything into memory

For processing 1 million+ domains, recommended settings:

```bash
python csp_collector_db.py --input data/top-1m.csv --db data/results/csp_database.db --batch-size 1000 --concurrency 10
```

## Enhanced CSP Classification Framework

This project implements a comprehensive 6-component security classification framework for analyzing Content Security Policy effectiveness:

1. **Script Execution Control**: Evaluates protection against XSS via script-src directives
2. **Style Injection Control**: Analyzes protection against CSS-based attacks via style-src
3. **Object & Media Control**: Assesses protection against plugin-based attacks via object-src, media-src
4. **Frame Control**: Evaluates protection against clickjacking via frame-ancestors, frame-src
5. **Form Action Control**: Analyzes protection against form-based attacks via form-action
6. **Base URI Control**: Assesses protection against DOM-based attacks via base-uri

Each component is scored on a 3-tier scale (levels 1, 3, 5) representing ineffective, adequate, and exceptional protection, with the exception of Script Execution which uses a more granular 5-level scale.

### Analysis Outputs

The enhanced analyzer generates various visualizations and data exports including:

- **Protection Level Charts**: Pie charts showing the distribution of protection levels (Comprehensive, Substantial, Partial, Minimal, Ineffective)
- **Component Usage Charts**: Bar charts showing exceptional usage across components
- **CSV Reports**:
  - `protection_patterns.csv`: Lists all protection vector patterns with counts and percentages
  - `comprehensively_protected_sites.csv`: Lists sites with comprehensive protection
  - `component_score_distributions.csv`: Shows distribution of protection scores by component

These outputs provide insights into CSP implementation patterns and effectiveness across large web datasets.
