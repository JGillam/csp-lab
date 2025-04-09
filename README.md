# Content Security Policy Analysis Project

A comprehensive tool for collecting and analyzing Content Security Policy (CSP) and Subresource Integrity (SRI) implementation across websites.

## Project Overview

This project provides tools to:
1. Collect CSP and SRI data from a large sample of websites
2. Store the collected data in a structured JSON format
3. Analyze the data to determine statistics on CSP implementation patterns
4. Generate insights on the effectiveness and adoption of various CSP directives

## Components

- **Data Collection Tools**: 
  - `csp_collector.py`: Scrapes websites and stores data in JSON format
  - `csp_collector_db.py`: Database-backed collector for processing large datasets
- **Analysis Tools**: 
  - `csp_analyzer.py`: Processes JSON data to generate statistics and insights
  - `csp_analyzer_db.py`: Database-backed analyzer for large datasets
- **Visualization**: Automatically generates charts and graphs of the analysis results

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

#### Standard Data Collection (JSON-based)

```bash
# Process all URLs in the input file
python csp_collector_db.py --input top-1m.csv --output results.json --concurrency 5 --timeout 30

# Process only the first 25 URLs (for testing)
python csp_collector.py --input top-1m.csv --output results.json --concurrency 5 --timeout 30 --limit 25
```

Arguments:
- `--input`: Path to a CSV file containing target websites (in Tranco list format: rank,domain)
- `--output`: Path to save the JSON output
- `--concurrency`: Number of concurrent requests (default: 5)
- `--timeout`: Request timeout in seconds (default: 30)
- `--resume`: Resume an interrupted scan
- `--limit`: Limit the number of URLs to process (useful for testing with a subset of data)

#### Collection (SQLite)

If you don't have it already, download the list tranco list (https://tranco-list.eu/top-1m.csv.zip) and unzip it into ./data

```bash
# Process URLs in batches, storing in SQLite database
python csp_collector_db.py --input top-1m.csv --db data/results/csp_database.db --batch-size 100 --concurrency 10

# Process a subset of URLs for testing
python csp_collector_db.py --input top-1m.csv --db data/results/csp_database.db --batch-size 10 --limit 50

# Export database to JSON if needed
python csp_collector_db.py --input top-1m.csv --db data/results/csp_database.db --output results_from_db.json
```

Arguments:
- `--input`: Path to a CSV file containing target websites (Tranco list format: rank,domain)
- `--db`: Path to the SQLite database file (will be created if it doesn't exist)
- `--output`: Optional path to export database contents as JSON
- `--batch-size`: Number of sites to process in each batch (default: 100)
- `--concurrency`: Number of concurrent requests (default: 5)
- `--timeout`: Request timeout in seconds (default: 30)
- `--limit`: Limit the number of URLs to process (useful for testing)

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

## Project Structure

```
csp-analysis/
│
├── csp_collector_db.py  # Database-backed collection tool (SQLite)
├── csp_analyzer_db.py   # Database-backed analysis tool
├── requirements.txt     # Project dependencies
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
├── tests/               # Test scripts
│   ├── __init__.py
│   ├── test_collector.py
│   └── test_analyzer.py
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

## License

[MIT License](LICENSE)

## Contact

Your Name - email@example.com
