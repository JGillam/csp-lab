"""
Database utilities for the CSP Analysis project.

This module handles SQLite database operations for storing and retrieving CSP data.
"""
import json
import os
import sqlite3
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

import pandas as pd


class CSPDatabase:
    """
    SQLite database handler for CSP data.
    """
    
    def __init__(self, db_path: str):
        """
        Initialize the database connection.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        
        # Initialize database
        self._initialize_db()
    
    def _initialize_db(self):
        """Initialize the database schema if it doesn't exist."""
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        
        # Create metadata table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                id INTEGER PRIMARY KEY,
                date_collected TEXT,
                total_sites_attempted INTEGER,
                total_sites_succeeded INTEGER,
                tool_version TEXT
            )
        """)
        
        # Create sites table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS sites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                status_code INTEGER,
                csp_header TEXT,
                csp_report_only_header TEXT,
                script_tags_total INTEGER,
                script_tags_with_integrity INTEGER,
                link_tags_total INTEGER,
                link_tags_with_integrity INTEGER,
                error TEXT,
                batch_id INTEGER
            )
        """)
        
        # Create index on url for faster lookups
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_sites_url ON sites(url)
        """)
        
        # Create index on batch_id for batch operations
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_sites_batch ON sites(batch_id)
        """)
        
        # Create CSP directives table (for many-to-many relationship)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS csp_directives (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site_id INTEGER,
                directive TEXT NOT NULL,
                value TEXT,
                FOREIGN KEY (site_id) REFERENCES sites(id)
            )
        """)
        
        # Create index on site_id for faster lookups
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_directives_site ON csp_directives(site_id)
        """)
        
        self.conn.commit()
    
    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
            self.cursor = None
    
    def __enter__(self):
        """Context manager enter method."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit method."""
        self.close()
    
    def insert_metadata(self, metadata: Dict[str, Any]):
        """
        Insert or update metadata.
        
        Args:
            metadata: Metadata dictionary
        """
        # Check if metadata already exists
        self.cursor.execute("SELECT COUNT(*) FROM metadata")
        count = self.cursor.fetchone()[0]
        
        if count > 0:
            # Update existing metadata
            self.cursor.execute("""
                UPDATE metadata SET
                date_collected = ?,
                total_sites_attempted = ?,
                total_sites_succeeded = ?,
                tool_version = ?
                WHERE id = 1
            """, (
                metadata.get("date_collected", datetime.now().isoformat()),
                metadata.get("total_sites_attempted", 0),
                metadata.get("total_sites_succeeded", 0),
                metadata.get("tool_version", "1.0.0")
            ))
        else:
            # Insert new metadata
            self.cursor.execute("""
                INSERT INTO metadata (
                    date_collected,
                    total_sites_attempted,
                    total_sites_succeeded,
                    tool_version
                ) VALUES (?, ?, ?, ?)
            """, (
                metadata.get("date_collected", datetime.now().isoformat()),
                metadata.get("total_sites_attempted", 0),
                metadata.get("total_sites_succeeded", 0),
                metadata.get("tool_version", "1.0.0")
            ))
        
        self.conn.commit()
    
    def get_metadata(self) -> Dict[str, Any]:
        """
        Get metadata from the database.
        
        Returns:
            Metadata dictionary
        """
        self.cursor.execute("""
            SELECT date_collected, total_sites_attempted, total_sites_succeeded, tool_version
            FROM metadata
            WHERE id = 1
        """)
        
        row = self.cursor.fetchone()
        if not row:
            return {
                "date_collected": datetime.now().isoformat(),
                "total_sites_attempted": 0,
                "total_sites_succeeded": 0,
                "tool_version": "1.0.0"
            }
        
        return {
            "date_collected": row[0],
            "total_sites_attempted": row[1],
            "total_sites_succeeded": row[2],
            "tool_version": row[3]
        }
    
    def sanitize_string(self, value: Any) -> Optional[str]:
        """Sanitize a string value for database insertion.
        
        Args:
            value: The value to sanitize
            
        Returns:
            Sanitized string or None if value is None
        """
        if value is None:
            return None
            
        # Convert to string if not already
        if not isinstance(value, str):
            value = str(value)
            
        # Replace or remove problematic Unicode characters
        try:
            # This will fail if there are surrogate pairs
            return value.encode('utf-8').decode('utf-8')
        except UnicodeEncodeError:
            # Remove or replace problematic characters
            return value.encode('utf-8', 'replace').decode('utf-8')
    
    def insert_site(self, site_data: Dict[str, Any], batch_id: Optional[int] = None) -> int:
        """
        Insert site data into the database.
        
        Args:
            site_data: Site data dictionary
            batch_id: Optional batch identifier for grouping sites
            
        Returns:
            ID of the inserted site
        """
        # Extract CSP directives if present
        csp_directives = {}
        csp_header = site_data.get("headers", {}).get("content-security-policy")
        if csp_header:
            from utils.parser import parse_csp_header
            # Sanitize the CSP header first
            csp_header = self.sanitize_string(csp_header)
            csp_directives = parse_csp_header(csp_header)
        
        # Insert site data
        self.cursor.execute("""
            INSERT INTO sites (
                url,
                timestamp,
                status_code,
                csp_header,
                csp_report_only_header,
                script_tags_total,
                script_tags_with_integrity,
                link_tags_total,
                link_tags_with_integrity,
                error,
                batch_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            self.sanitize_string(site_data.get("url", "")),
            self.sanitize_string(site_data.get("timestamp", datetime.now().isoformat())),
            site_data.get("status_code"),
            self.sanitize_string(site_data.get("headers", {}).get("content-security-policy")),
            self.sanitize_string(site_data.get("headers", {}).get("content-security-policy-report-only")),
            site_data.get("sri_usage", {}).get("script_tags_total", 0),
            site_data.get("sri_usage", {}).get("script_tags_with_integrity", 0),
            site_data.get("sri_usage", {}).get("link_tags_total", 0),
            site_data.get("sri_usage", {}).get("link_tags_with_integrity", 0),
            self.sanitize_string(site_data.get("error")),
            batch_id
        ))
        
        # Get the ID of the inserted site
        site_id = self.cursor.lastrowid
        
        # Insert CSP directives
        for directive, values in csp_directives.items():
            for value in values:
                self.cursor.execute("""
                    INSERT INTO csp_directives (
                        site_id,
                        directive,
                        value
                    ) VALUES (?, ?, ?)
                """, (site_id, self.sanitize_string(directive), self.sanitize_string(value)))
        
        self.conn.commit()
        return site_id
    
    def batch_insert_sites(self, sites_data: List[Dict[str, Any]], batch_id: Optional[int] = None) -> List[int]:
        """
        Insert multiple sites in a batch.
        
        Args:
            sites_data: List of site data dictionaries
            batch_id: Optional batch identifier for grouping sites
            
        Returns:
            List of inserted site IDs
        """
        site_ids = []
        for site_data in sites_data:
            site_id = self.insert_site(site_data, batch_id)
            site_ids.append(site_id)
        
        return site_ids
    
    def get_site_count(self) -> int:
        """
        Get the total number of sites in the database.
        
        Returns:
            Number of sites
        """
        self.cursor.execute("SELECT COUNT(*) FROM sites")
        return self.cursor.fetchone()[0]
    
    def is_domain_processed(self, domain: str) -> bool:
        """Check if a specific domain has already been processed.
        
        This is much more memory efficient than getting all processed domains
        when dealing with large datasets.
        
        Args:
            domain: Domain name to check
            
        Returns:
            True if the domain has been processed, False otherwise
        """
        # Handle domain formats with or without protocol
        normalized_domain = domain
        if '://' in domain:
            normalized_domain = domain.split('://')[-1].split('/')[0]
        
        # Use LIKE query to match the domain within URLs in the database
        # This handles both http:// and https:// as well as www. prefixes
        self.cursor.execute(
            "SELECT 1 FROM sites WHERE url LIKE ? OR url LIKE ? OR url LIKE ? OR url LIKE ? LIMIT 1", 
            (f"%{normalized_domain}", f"%://{normalized_domain}%", f"%://www.{normalized_domain}%", normalized_domain)
        )
        
        return self.cursor.fetchone() is not None
        
    def get_processed_domains_batched(self, batch_size: int = 1000) -> Generator[str, None, None]:
        """Get processed domains in batches to minimize memory usage.
        
        Args:
            batch_size: Number of domains to retrieve in each batch
            
        Yields:
            Batches of domain names that have been processed
        """
        offset = 0
        while True:
            self.cursor.execute("SELECT url FROM sites LIMIT ? OFFSET ?", (batch_size, offset))
            rows = self.cursor.fetchall()
            if not rows:
                break
                
            domains = []
            for row in rows:
                url = row[0]
                if url:
                    # Extract domain from URL
                    if '://' in url:
                        domain = url.split('://')[-1].split('/')[0]
                    else:
                        domain = url.split('/')[0]
                    domains.append(domain)
            
            # Yield this batch of domains
            yield domains
            
            # Move to next batch
            offset += batch_size
    
    def get_sites(self, limit: Optional[int] = None, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Get sites from the database.
        
        Args:
            limit: Maximum number of sites to retrieve (None for all)
            offset: Starting offset
            
        Returns:
            List of site data dictionaries
        """
        if limit:
            self.cursor.execute("""
                SELECT * FROM sites
                ORDER BY id
                LIMIT ? OFFSET ?
            """, (limit, offset))
        else:
            self.cursor.execute("""
                SELECT * FROM sites
                ORDER BY id
                OFFSET ?
            """, (offset,))
        
        columns = [col[0] for col in self.cursor.description]
        sites = []
        
        for row in self.cursor.fetchall():
            site = dict(zip(columns, row))
            
            # Get CSP directives for this site
            site_id = site["id"]
            self.cursor.execute("""
                SELECT directive, value FROM csp_directives
                WHERE site_id = ?
            """, (site_id,))
            
            # Group directives
            directives = {}
            for directive, value in self.cursor.fetchall():
                if directive not in directives:
                    directives[directive] = []
                directives[directive].append(value)
            
            # Format site data to match original format
            sites.append({
                "url": site["url"],
                "timestamp": site["timestamp"],
                "status_code": site["status_code"],
                "headers": {
                    "content-security-policy": site["csp_header"],
                    "content-security-policy-report-only": site["csp_report_only_header"]
                },
                "sri_usage": {
                    "script_tags_total": site["script_tags_total"],
                    "script_tags_with_integrity": site["script_tags_with_integrity"],
                    "link_tags_total": site["link_tags_total"],
                    "link_tags_with_integrity": site["link_tags_with_integrity"]
                },
                "error": site["error"],
                "csp_directives": directives
            })
        
        return sites
    
    def export_to_json(self, output_file: str) -> None:
        """
        Export database contents to JSON format.
        
        Args:
            output_file: Path to the output JSON file
        """
        metadata = self.get_metadata()
        sites = self.get_sites()
        
        data = {
            "metadata": metadata,
            "sites": sites
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def import_from_json(self, input_file: str) -> None:
        """
        Import data from a JSON file.
        
        Args:
            input_file: Path to the input JSON file
        """
        with open(input_file, 'r') as f:
            data = json.load(f)
        
        # Insert metadata
        if "metadata" in data:
            self.insert_metadata(data["metadata"])
        
        # Insert sites
        if "sites" in data:
            self.batch_insert_sites(data["sites"])
    
    def get_sites_dataframe(self) -> pd.DataFrame:
        """
        Get sites data as a pandas DataFrame.
        
        Returns:
            DataFrame with site data
        """
        query = """
            SELECT s.*, 
                   (SELECT COUNT(*) FROM csp_directives cd WHERE cd.site_id = s.id) as directive_count
            FROM sites s
        """
        
        return pd.read_sql_query(query, self.conn)
    
    def get_directives_dataframe(self) -> pd.DataFrame:
        """
        Get directives data as a pandas DataFrame.
        
        Returns:
            DataFrame with directive data
        """
        query = """
            SELECT cd.*, s.url, s.status_code, s.error
            FROM csp_directives cd
            JOIN sites s ON cd.site_id = s.id
        """
        
        return pd.read_sql_query(query, self.conn)
    
    def get_analysis_stats(self) -> Dict[str, Any]:
        """
        Calculate analysis statistics.
        
        Returns:
            Dictionary with analysis statistics
        """
        # Get total counts
        self.cursor.execute("SELECT COUNT(*) FROM sites")
        total_sites = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(*) FROM sites WHERE csp_header IS NOT NULL")
        sites_with_csp = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(*) FROM sites WHERE csp_report_only_header IS NOT NULL")
        sites_with_report_only = self.cursor.fetchone()[0]
        
        self.cursor.execute("""
            SELECT COUNT(*) FROM sites 
            WHERE csp_header IS NOT NULL AND csp_report_only_header IS NOT NULL
        """)
        sites_with_both = self.cursor.fetchone()[0]
        
        self.cursor.execute("""
            SELECT COUNT(*) FROM sites 
            WHERE csp_header IS NULL AND csp_report_only_header IS NULL
        """)
        sites_with_no_csp = self.cursor.fetchone()[0]
        
        # Get SRI usage
        self.cursor.execute("""
            SELECT COUNT(*) FROM sites 
            WHERE script_tags_with_integrity > 0 OR link_tags_with_integrity > 0
        """)
        sites_with_sri = self.cursor.fetchone()[0]
        
        # Calculate percentages
        stats = {
            "total_sites": total_sites,
            "sites_with_csp": sites_with_csp,
            "sites_with_csp_percent": round(sites_with_csp / total_sites * 100, 2) if total_sites > 0 else 0,
            "sites_with_report_only": sites_with_report_only,
            "sites_with_report_only_percent": round(sites_with_report_only / total_sites * 100, 2) if total_sites > 0 else 0,
            "sites_with_both": sites_with_both,
            "sites_with_both_percent": round(sites_with_both / total_sites * 100, 2) if total_sites > 0 else 0,
            "sites_with_no_csp": sites_with_no_csp,
            "sites_with_no_csp_percent": round(sites_with_no_csp / total_sites * 100, 2) if total_sites > 0 else 0,
            "sites_with_sri": sites_with_sri,
            "sites_with_sri_percent": round(sites_with_sri / total_sites * 100, 2) if total_sites > 0 else 0
        }
        
        return stats
