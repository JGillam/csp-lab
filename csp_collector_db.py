#!/usr/bin/env python3
"""
CSP Collector (Database Version) - Tool for collecting Content Security Policy data from websites.

This script fetches HTTP headers and HTML content from a list of websites,
extracts CSP headers and SRI attributes, and stores the data in a SQLite database
for efficient storage and retrieval with large datasets.
"""
import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urlparse

import aiohttp
from aiohttp.client_exceptions import (
    ClientConnectorError, 
    ClientError, 
    ClientResponseError,
    TooManyRedirects,
    ServerTimeoutError
)
from bs4 import BeautifulSoup
import tqdm

from utils.logger import setup_logger
from utils.parser import parse_csp_header, parse_sri_attributes
from utils.database import CSPDatabase


# Setup logger
logger = setup_logger("csp_collector", log_file="csp_collector.log")


class CSPCollector:
    """
    Main class for collecting CSP data from websites with database storage.
    """
    
    def __init__(
        self,
        concurrency: int = 30,  # Increased from 5 to 30 for better performance
        timeout: int = 20,      # Reduced from 30 to 20 for faster failure handling
        user_agent: str = "CSP-Analysis-Tool/1.0.0",
        db_path: str = "data/results/csp_database.db",
        batch_size: int = 1000, # Increased from 100 to 1000 for better DB efficiency
    ):
        """
        Initialize the CSP Collector.
        
        Args:
            concurrency: Number of concurrent requests
            timeout: Request timeout in seconds
            user_agent: User-Agent header to use for requests
            db_path: Path to the SQLite database file
            batch_size: Number of sites to process in each batch
        """
        self.concurrency = concurrency
        self.timeout = timeout
        self.user_agent = user_agent
        self.db_path = db_path
        self.batch_size = batch_size
        self.processed_urls: Set[str] = set()
        
        # Initialize database
        self.db = CSPDatabase(db_path)
        
        # Get metadata for resuming
        metadata = self.db.get_metadata()
        self.metadata = {
            "date_collected": datetime.now().isoformat(),
            "total_sites_attempted": metadata.get("total_sites_attempted", 0),
            "total_sites_succeeded": metadata.get("total_sites_succeeded", 0),
            "tool_version": "1.0.0"
        }
        
    async def process_url(self, url: str) -> Dict[str, Any]:
        """
        Process a single URL to extract CSP headers and SRI attributes.
        
        Args:
            url: URL to process
            
        Returns:
            Dictionary with extracted data
        """
        # Initialize result structure
        result = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "status_code": None,
            "headers": {
                "content-security-policy": None,
                "content-security-policy-report-only": None
            },
            "sri_usage": {
                "script_tags_total": 0,
                "script_tags_with_integrity": 0,
                "link_tags_total": 0,
                "link_tags_with_integrity": 0
            },
            "error": None
        }
        
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            result["url"] = url
        
        # Skip if already processed
        normalized_url = urlparse(url).netloc
        if normalized_url in self.processed_urls:
            result["error"] = "Duplicate URL (already processed)"
            return result
            
        self.processed_urls.add(normalized_url)
        
        # Set up headers
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        
        try:
            # Initialize optimized aiohttp session
            timeout = aiohttp.ClientTimeout(total=self.timeout, connect=5)
            
            # Set up TCP connector with optimized settings
            connector = aiohttp.TCPConnector(
                limit=self.concurrency,
                enable_cleanup_closed=True,
                force_close=True
            )
            
            # Create a ClientSession with cookie_jar=None to skip cookie parsing
            # This prevents cookie parsing errors from crashing the entire batch
            async with aiohttp.ClientSession(
                headers=headers, 
                timeout=timeout, 
                connector=connector,
                cookie_jar=None  
            ) as session:
                try:
                    async with session.get(url, allow_redirects=True) as response:
                        result["status_code"] = response.status
                        
                        # Extract headers
                        headers_dict = {k.lower(): v for k, v in response.headers.items()}
                        
                        if "content-security-policy" in headers_dict:
                            result["headers"]["content-security-policy"] = headers_dict["content-security-policy"]
                        
                        if "content-security-policy-report-only" in headers_dict:
                            result["headers"]["content-security-policy-report-only"] = headers_dict["content-security-policy-report-only"]
                        
                        # Extract HTML content for SRI analysis
                        try:
                            html_content = await response.text()
                            sri_results = parse_sri_attributes(html_content)
                            result["sri_usage"] = {
                                "script_tags_total": sri_results[0],
                                "script_tags_with_integrity": sri_results[1],
                                "link_tags_total": sri_results[2],
                                "link_tags_with_integrity": sri_results[3]
                            }
                        except UnicodeDecodeError:
                            result["error"] = "Failed to decode HTML content"
                except Exception as e:
                    result["error"] = f"Response error: {str(e)}"
        except ClientConnectorError:
            result["error"] = "Connection error"
        except TooManyRedirects:
            result["error"] = "Too many redirects"
        except ServerTimeoutError:
            result["error"] = f"Timeout after {self.timeout}s"
        except ClientResponseError as e:
            result["error"] = f"HTTP error: {e.status}"
        except ClientError as e:
            result["error"] = f"Client error: {str(e)}"
        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"
            
        return result
    
    async def process_batch(self, urls: List[str], batch_id: int) -> None:
        """
        Process a batch of URLs concurrently and store results in the database.
        
        Args:
            urls: List of URLs to process
            batch_id: Batch identifier
        """
        # Create a semaphore to limit concurrency
        semaphore = asyncio.Semaphore(self.concurrency)
        
        # Process URLs with a rate limiter - reduced sleep time for better throughput
        async def rate_limited_process(url):
            async with semaphore:
                await asyncio.sleep(0.3)  # Reduced from 0.5 to 0.1 for better throughput
                return await self.process_url(url)
        
        # Create tasks for all URLs in this batch
        tasks = [rate_limited_process(url) for url in urls]
        
        # Process URLs with progress bar
        batch_results = []
        for future in tqdm.tqdm(asyncio.as_completed(tasks), total=len(tasks), desc=f"Batch {batch_id}"):
            result = await future
            batch_results.append(result)
            
            # Count successful requests
            if result["status_code"] == 200 and not result["error"]:
                self.metadata["total_sites_succeeded"] += 1
        
        # Store batch results in database
        self.db.batch_insert_sites(batch_results, batch_id)
        
    async def process_urls(self, urls: List[str]) -> None:
        """
        Process a list of URLs in batches.
        
        Args:
            urls: List of URLs to process
        """
        total_urls = len(urls)
        self.metadata["total_sites_attempted"] += total_urls
        logger.info(f"Processing {total_urls} URLs in batches of {self.batch_size}")
        
        # Process URLs in batches
        batches = [urls[i:i + self.batch_size] for i in range(0, len(urls), self.batch_size)]
        
        for i, batch_urls in enumerate(batches):
            logger.info(f"Processing batch {i+1}/{len(batches)} ({len(batch_urls)} URLs)")
            await self.process_batch(batch_urls, i+1)
            
            # Update metadata after each batch
            self.db.insert_metadata(self.metadata)
    
    def save_results(self) -> None:
        """Save metadata to the database."""
        self.db.insert_metadata(self.metadata)
        logger.info(f"Results saved to database: {self.db_path}")
        logger.info(f"Processed {self.metadata['total_sites_attempted']} sites")
        logger.info(f"Successfully processed {self.metadata['total_sites_succeeded']} sites")
    
    def close(self) -> None:
        """Close the database connection."""
        self.db.close()
    
    def export_to_json(self, output_file: str) -> None:
        """
        Export database contents to JSON format.
        
        Args:
            output_file: Path to the output JSON file
        """
        self.db.export_to_json(output_file)
        logger.info(f"Exported database to JSON: {output_file}")


async def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description="Collect CSP data from websites (Database Version)")
    
    parser.add_argument("--input", required=True, help="Path to input file with URLs (CSV format: rank,domain)")
    parser.add_argument("--db", default="data/results/csp_database.db", help="Path to SQLite database file")
    parser.add_argument("--output", help="Optional path to export results as JSON")
    parser.add_argument("--concurrency", type=int, default=5, help="Number of concurrent requests")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    parser.add_argument("--batch-size", type=int, default=100, help="Number of sites to process in each batch")
    parser.add_argument("--limit", type=int, help="Limit the number of URLs to process (for testing)")
    
    args = parser.parse_args()
    
    # Validate input file
    if not os.path.exists(args.input):
        logger.error(f"Input file not found: {args.input}")
        sys.exit(1)
    
    # Read URLs from input file
    with open(args.input, 'r') as f:
        # Parse CSV format (rank,domain) and extract only the domain part
        urls = [line.strip().split(',')[1] for line in f if line.strip() and ',' in line.strip()]
        
    # Apply limit if specified
    if args.limit and args.limit > 0:
        logger.info(f"Limiting to first {args.limit} URLs")
        urls = urls[:args.limit]
    
    if not urls:
        logger.error("No URLs found in input file")
        sys.exit(1)
    
    logger.info(f"Loaded {len(urls)} URLs from {args.input}")
    
    # Ensure the output directory exists
    os.makedirs(os.path.dirname(os.path.abspath(args.db)), exist_ok=True)
    
    # Initialize collector
    collector = CSPCollector(
        concurrency=args.concurrency,
        timeout=args.timeout,
        db_path=args.db,
        batch_size=args.batch_size
    )
    
    try:
        # Process URLs
        start_time = time.time()
        await collector.process_urls(urls)
        end_time = time.time()
        
        # Save results
        collector.save_results()
        
        # Export to JSON if requested
        if args.output:
            collector.export_to_json(args.output)
        
        logger.info(f"Collection completed in {end_time - start_time:.2f} seconds")
    finally:
        # Ensure database connection is closed
        collector.close()


if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
