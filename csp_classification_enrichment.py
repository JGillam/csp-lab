#!/usr/bin/env python3
"""
CSP Classification Enrichment Tool

This script applies the component-based CSP classification framework to 
existing database entries, enriching the data for more detailed analysis.
"""
import argparse
import os
import sys
import time
from typing import Dict, List, Any
from tqdm import tqdm
import pandas as pd

from utils.logger import setup_logger
from utils.parser import parse_csp_header, analyze_csp_components
from utils.database import CSPDatabase


# Setup logger
logger = setup_logger("csp_enrichment", log_file="csp_enrichment.log")


class CSPEnrichment:
    """
    Tool for enriching CSP data with component-based classifications.
    """
    
    def __init__(self, db_path: str, batch_size: int = 1000):
        """
        Initialize the CSP Enrichment tool.
        
        Args:
            db_path: Path to the SQLite database file
            batch_size: Number of sites to process in each batch
        """
        self.db_path = db_path
        self.batch_size = batch_size
        self.db = None
        
    def connect_db(self) -> None:
        """Connect to the database."""
        self.db = CSPDatabase(self.db_path)
    
    def close_db(self) -> None:
        """Close the database connection."""
        if self.db:
            self.db.close()
            self.db = None
    
    def enrich_classifications(self, overwrite: bool = False) -> None:
        """
        Analyze CSP headers and store component-based classifications.
        
        Args:
            overwrite: Whether to overwrite existing classifications
        """
        # Get sites with CSP headers
        query = """
        SELECT s.id, s.url, s.csp_header 
        FROM sites s
        LEFT JOIN csp_classifications c ON s.id = c.site_id
        WHERE s.csp_header IS NOT NULL
        """
        
        if not overwrite:
            # Only get sites without existing classifications
            query += " AND c.id IS NULL"
        
        # Count total sites to process
        count_query = query.replace("s.id, s.url, s.csp_header", "COUNT(*)")
        self.db.cursor.execute(count_query)
        total_sites = self.db.cursor.fetchone()[0]
        
        if total_sites == 0:
            logger.info("No sites to process.")
            return
        
        logger.info(f"Processing {total_sites} sites...")
        
        # Use pandas with batching for more efficient processing
        # This avoids potential cursor issues with large result sets
        sites_processed = 0
        batch_counter = 0
        
        # Process in chunks with clear batch boundaries
        with tqdm(total=total_sites, desc="Classifying CSP policies") as pbar:
            # Use SQLite's LIMIT and OFFSET for reliable batching
            while sites_processed < total_sites:
                # Create a batch query with proper pagination
                batch_query = f"{query} LIMIT {self.batch_size} OFFSET {batch_counter * self.batch_size}"
                batch_counter += 1
                
                # Execute the batch query
                batch_df = pd.read_sql_query(batch_query, self.db.conn)
                
                if batch_df.empty:
                    break
                
                # Process each row in the batch
                for _, row in batch_df.iterrows():
                    site_id = row['id']
                    url = row['url']
                    csp_header = row['csp_header']
                    
                    if csp_header:
                        # Parse CSP header
                        directives = parse_csp_header(csp_header)
                        
                        # Analyze components
                        scores = analyze_csp_components(directives)
                        
                        # Store classification
                        self.db.store_csp_classification(site_id, scores)
                
                # Update progress
                batch_size = len(batch_df)
                sites_processed += batch_size
                pbar.update(batch_size)
                
                # Log progress periodically
                if sites_processed % (self.batch_size * 10) == 0:
                    logger.info(f"Processed {sites_processed}/{total_sites} sites ({sites_processed/total_sites*100:.1f}%)")
        
        # Final log message after all processing is complete
        logger.info(f"Finished processing {sites_processed} sites.")
        
    def generate_summary(self) -> Dict[str, Any]:
        """
        Generate a summary of the component-based classifications.
        
        Returns:
            Dictionary with summary statistics
        """
        logger.info("Generating classification summary...")
        
        # Get all classifications
        df = self.db.get_csp_classifications()
        
        # Filter out NULL classifications
        df = df.dropna(subset=['script_execution_score', 'style_injection_score', 
                                'object_media_score', 'frame_control_score', 
                                'form_action_score', 'base_uri_score'])
        
        total_sites = len(df)
        if total_sites == 0:
            logger.warning("No classified sites found.")
            return {"error": "No classified sites found"}
        
        # Calculate component score distributions
        summary = {
            "total_sites_classified": total_sites,
            "components": {
                "script_execution": self._calculate_score_distribution(df.script_execution_score),
                "style_injection": self._calculate_score_distribution(df.style_injection_score),
                "object_media": self._calculate_score_distribution(df.object_media_score),
                "frame_control": self._calculate_score_distribution(df.frame_control_score),
                "form_action": self._calculate_score_distribution(df.form_action_score),
                "base_uri": self._calculate_score_distribution(df.base_uri_score)
            },
            "protection_levels": self._calculate_protection_levels(df),
            "vector_patterns": self._find_common_patterns(df)
        }
        
        # Log some key findings
        logger.info(f"Total sites classified: {total_sites}")
        
        for component, dist in summary["components"].items():
            logger.info(f"{component.replace('_', ' ').title()} - Strong(4-5): {dist[4] + dist[5]:.1f}%, Moderate(3): {dist[3]:.1f}%, Weak(1-2): {dist[1] + dist[2]:.1f}%")
        
        logger.info(f"Comprehensively protected sites: {summary['protection_levels']['comprehensive']:.1f}%")
        logger.info(f"Substantially protected sites: {summary['protection_levels']['substantial']:.1f}%")
        
        return summary
    
    def _calculate_score_distribution(self, scores) -> Dict[int, float]:
        """Calculate percentage distribution of scores."""
        total = len(scores)
        distribution = {score: 0 for score in range(1, 6)}
        
        for score in scores:
            distribution[score] += 1
        
        # Convert to percentages
        for score in distribution:
            distribution[score] = round(distribution[score] / total * 100, 1)
            
        return distribution
    
    def _calculate_protection_levels(self, df) -> Dict[str, float]:
        """Calculate sites at each protection threshold level."""
        total = len(df)
        
        # Comprehensively Protected: All areas at level 3 or higher
        comprehensive = df[(df.script_execution_score >= 3) & 
                           (df.style_injection_score >= 3) & 
                           (df.object_media_score >= 3) & 
                           (df.frame_control_score >= 3) & 
                           (df.form_action_score >= 3) & 
                           (df.base_uri_score >= 3)].shape[0]
        
        # Substantially Protected: At least four areas at level 3 or higher
        substantial = df[((df.script_execution_score >= 3).astype(int) + 
                         (df.style_injection_score >= 3).astype(int) + 
                         (df.object_media_score >= 3).astype(int) + 
                         (df.frame_control_score >= 3).astype(int) + 
                         (df.form_action_score >= 3).astype(int) + 
                         (df.base_uri_score >= 3).astype(int)) >= 4].shape[0]
        
        # Partially Protected: At least three areas at level 3 or higher
        partial = df[((df.script_execution_score >= 3).astype(int) + 
                      (df.style_injection_score >= 3).astype(int) + 
                      (df.object_media_score >= 3).astype(int) + 
                      (df.frame_control_score >= 3).astype(int) + 
                      (df.form_action_score >= 3).astype(int) + 
                      (df.base_uri_score >= 3).astype(int)) >= 3].shape[0]
        
        # Minimally Protected: At least one area at level 3 or higher
        minimal = df[((df.script_execution_score >= 3) | 
                      (df.style_injection_score >= 3) | 
                      (df.object_media_score >= 3) | 
                      (df.frame_control_score >= 3) | 
                      (df.form_action_score >= 3) | 
                      (df.base_uri_score >= 3))].shape[0]
        
        # Ineffective: All areas below level 3
        ineffective = total - minimal
        
        return {
            "comprehensive": round(comprehensive / total * 100, 1),
            "substantial": round(substantial / total * 100, 1),
            "partial": round(partial / total * 100, 1),
            "minimal": round(minimal / total * 100, 1),
            "ineffective": round(ineffective / total * 100, 1)
        }
    
    def _find_common_patterns(self, df, limit: int = 25) -> List[Dict[str, Any]]:
        """Find the most common protection vectors."""
        # Create protection vectors
        df['vector'] = df.apply(
            lambda row: f"[{row.script_execution_score},{row.style_injection_score},{row.object_media_score},{row.frame_control_score},{row.form_action_score},{row.base_uri_score}]", 
            axis=1
        )
        
        # Count occurrences
        vector_counts = df['vector'].value_counts().head(limit)
        
        # Format results
        patterns = []
        for vector, count in vector_counts.items():
            patterns.append({
                "vector": vector,
                "count": int(count),
                "percentage": round(count / len(df) * 100, 2)
            })
            
        return patterns


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description="CSP Classification Enrichment Tool")
    
    parser.add_argument("--db", required=True, help="Path to the SQLite database file")
    parser.add_argument("--batch-size", type=int, default=1000, help="Number of sites to process in each batch")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing classifications")
    parser.add_argument("--summary-only", action="store_true", help="Only generate summary without enrichment")
    
    args = parser.parse_args()
    
    # Ensure database directory exists
    os.makedirs(os.path.dirname(os.path.abspath(args.db)), exist_ok=True)
    
    # Initialize enrichment tool
    enrichment = CSPEnrichment(
        db_path=args.db,
        batch_size=args.batch_size
    )
    
    try:
        enrichment.connect_db()
        
        if not args.summary_only:
            # Perform enrichment
            start_time = time.time()
            enrichment.enrich_classifications(overwrite=args.overwrite)
            elapsed = time.time() - start_time
            logger.info(f"Enrichment completed in {elapsed:.2f} seconds")
        
        # Generate summary
        summary = enrichment.generate_summary()
        
        # Print top patterns
        print("\nTop CSP Protection Patterns:")
        print("---------------------------")
        for pattern in summary["vector_patterns"]:
            print(f"{pattern['vector']}: {pattern['count']} sites ({pattern['percentage']}%)")
        
        # Print protection levels
        print("\nProtection Levels:")
        print("----------------")
        print(f"Comprehensively Protected: {summary['protection_levels']['comprehensive']}%")
        print(f"Partially Protected: {summary['protection_levels']['partial']}%")
        print(f"Minimally Protected: {summary['protection_levels']['minimal']}%")
        print(f"Ineffective: {summary['protection_levels']['ineffective']}%")
        
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)
    finally:
        enrichment.close_db()


if __name__ == "__main__":
    main()
