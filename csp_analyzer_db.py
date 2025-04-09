#!/usr/bin/env python3
"""
CSP Analyzer (Database Version) - Tool for analyzing Content Security Policy data.

This script processes the SQLite database created by the CSP Collector 
and generates statistical analysis and insights on CSP and SRI implementation.
Optimized for analyzing large datasets efficiently.
"""
import argparse
import json
import os
import sys
import csv
from collections import Counter, defaultdict
from typing import Dict, List, Any, Tuple, Optional

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from utils.logger import setup_logger
from utils.parser import parse_csp_header, analyze_csp_effectiveness, detect_csp_misconfigurations
from utils.database import CSPDatabase


# Setup logger
logger = setup_logger("csp_analyzer", log_file="csp_analyzer.log")


class CSPAnalyzer:
    """
    Main class for analyzing CSP data collected from websites using database storage.
    """
    
    def __init__(
        self, 
        db_path: str, 
        output_file: str = "analysis_report.json",
        csv_output: str = None,
        skip_errors: bool = True
    ):
        """
        Initialize the CSP Analyzer.
        
        Args:
            db_path: Path to the SQLite database file
            output_file: Path to save analysis results
            csv_output: Path to export a CSV file for spreadsheet analysis
            skip_errors: Whether to exclude sites with errors from analysis
        """
        self.db_path = db_path
        self.output_file = output_file
        self.csv_output = csv_output
        self.skip_errors = skip_errors
        self.db = None
        
        # Results structure
        self.results = {
            "metadata": {
                "input_file": db_path,
                "sites_analyzed": 0
            },
            "adoption_stats": {},
            "csp_effectiveness": {},
            "sri_adoption": {},
            "directive_analysis": {},
            "common_misconfigurations": {}
        }
    
    def connect_db(self) -> None:
        """Connect to the database."""
        self.db = CSPDatabase(self.db_path)
    
    def close_db(self) -> None:
        """Close the database connection."""
        if self.db:
            self.db.close()
            self.db = None
    
    def analyze_adoption(self) -> None:
        """Analyze basic CSP adoption statistics using SQL queries."""
        # Get sites dataframe with error filtering if needed
        df = self.db.get_sites_dataframe()
        
        if self.skip_errors:
            valid_df = df[df.error.isna()]
            total_sites = len(valid_df)
            excluded_sites = len(df) - total_sites
            excluded_percent = round(excluded_sites / len(df) * 100, 2) if len(df) > 0 else 0
            
            # Log excluded sites
            logger.info(f"Sites with errors: {excluded_sites} out of {len(df)} sites ({excluded_percent}%)")
        else:
            valid_df = df
            total_sites = len(valid_df)
            excluded_sites = 0
            excluded_percent = 0
        
        # Calculate adoption statistics
        sites_with_csp = len(valid_df[valid_df.csp_header.notna()])
        sites_with_report_only = len(valid_df[valid_df.csp_report_only_header.notna()])
        sites_with_both = len(valid_df[(valid_df.csp_header.notna()) & (valid_df.csp_report_only_header.notna())])
        sites_with_no_csp = len(valid_df[(valid_df.csp_header.isna()) & (valid_df.csp_report_only_header.isna())])
        
        # Store results
        self.results["adoption_stats"] = {
            "total_sites_including_errors": len(df),
            "sites_with_errors": excluded_sites,
            "sites_with_errors_percent": excluded_percent,
            "total_valid_sites": total_sites,
            "sites_with_csp": sites_with_csp,
            "sites_with_csp_percent": round(sites_with_csp / total_sites * 100, 2) if total_sites > 0 else 0,
            "sites_with_report_only": sites_with_report_only,
            "sites_with_report_only_percent": round(sites_with_report_only / total_sites * 100, 2) if total_sites > 0 else 0,
            "sites_with_both": sites_with_both,
            "sites_with_both_percent": round(sites_with_both / total_sites * 100, 2) if total_sites > 0 else 0,
            "sites_with_no_csp": sites_with_no_csp,
            "sites_with_no_csp_percent": round(sites_with_no_csp / total_sites * 100, 2) if total_sites > 0 else 0
        }
        
        logger.info(f"CSP adoption: {sites_with_csp + sites_with_both} out of {total_sites} valid sites ({self.results['adoption_stats']['sites_with_csp_percent'] + self.results['adoption_stats']['sites_with_both_percent']}%)")
    
    def analyze_effectiveness(self) -> None:
        """Analyze the effectiveness of CSP implementations."""
        # Get data from database in batches to avoid memory issues
        effectiveness_counts = Counter()
        csp_categories = {
            "none": [],
            "minimal": [],
            "moderate": [],
            "strong": []
        }
        checkbox_csp_count = 0
        
        # Query database for sites with CSP headers
        df = self.db.get_sites_dataframe()
        
        if self.skip_errors:
            df = df[df.error.isna()]
        
        # Process each site's CSP header
        for _, site in df.iterrows():
            csp_header = site.get("csp_header")
            url = site.get("url")
            
            if not csp_header:
                effectiveness_counts["none"] += 1
                csp_categories["none"].append(url)
                continue
                
            # Parse CSP header
            directives = parse_csp_header(csp_header)
            
            # Check if it's a "checkbox" CSP (contains unsafe directives)
            is_checkbox = any(
                "unsafe-inline" in values or 
                "unsafe-eval" in values or 
                "*" in values
                for directive, values in directives.items()
                for value in values if isinstance(values, list)
            )
            
            if is_checkbox:
                checkbox_csp_count += 1
            
            # Analyze effectiveness
            effectiveness = analyze_csp_effectiveness(directives)
            effectiveness_counts[effectiveness] += 1
            csp_categories[effectiveness].append(url)
        
        # Calculate percentages
        total_with_csp = sum(effectiveness_counts.values())
        if total_with_csp == 0:
            total_with_csp = 1  # Avoid division by zero
            
        effectiveness_percentages = {
            category: round(count / total_with_csp * 100, 2)
            for category, count in effectiveness_counts.items()
        }
        
        self.results["csp_effectiveness"] = {
            "effectiveness_counts": dict(effectiveness_counts),
            "effectiveness_percentages": effectiveness_percentages,
            "checkbox_csp_count": checkbox_csp_count,
            "checkbox_csp_percent": round(checkbox_csp_count / total_with_csp * 100, 2),
            "effectiveness_examples": {
                category: urls[:5] if urls else []  # Include up to 5 examples for each category
                for category, urls in csp_categories.items()
            }
        }
        
        logger.info(f"CSP effectiveness: Strong {effectiveness_percentages.get('strong', 0)}%, Moderate {effectiveness_percentages.get('moderate', 0)}%")
    
    def analyze_sri_adoption(self) -> None:
        """Analyze Subresource Integrity (SRI) adoption."""
        # Get data from database
        df = self.db.get_sites_dataframe()
        
        if self.skip_errors:
            df = df[df.error.isna()]
        
        # Calculate SRI usage statistics
        sites_with_sri = len(df[(df.script_tags_with_integrity > 0) | (df.link_tags_with_integrity > 0)])
        
        # Calculate average SRI percentages
        df['script_sri_percent'] = df.apply(
            lambda row: (row.script_tags_with_integrity / row.script_tags_total * 100) 
            if row.script_tags_total > 0 else 0, 
            axis=1
        )
        
        df['link_sri_percent'] = df.apply(
            lambda row: (row.link_tags_with_integrity / row.link_tags_total * 100) 
            if row.link_tags_total > 0 else 0, 
            axis=1
        )
        
        # Calculate average percentages
        avg_script_sri = df[df.script_tags_total > 0].script_sri_percent.mean() if len(df[df.script_tags_total > 0]) > 0 else 0
        avg_link_sri = df[df.link_tags_total > 0].link_sri_percent.mean() if len(df[df.link_tags_total > 0]) > 0 else 0
        
        # Create correlation with CSP effectiveness
        df_with_csp = df[df.csp_header.notna()].copy()
        df_with_csp['effectiveness'] = df_with_csp.apply(
            lambda row: analyze_csp_effectiveness(parse_csp_header(row.csp_header)), 
            axis=1
        )
        
        # Prepare effectiveness counters
        sri_by_csp_effectiveness = Counter()
        csp_effectiveness_counts = Counter(df_with_csp.effectiveness)
        
        # Count sites with SRI by effectiveness
        for _, site in df_with_csp.iterrows():
            if site.script_tags_with_integrity > 0 or site.link_tags_with_integrity > 0:
                sri_by_csp_effectiveness[site.effectiveness] += 1
        
        # Calculate SRI adoption by CSP effectiveness
        sri_adoption_by_csp = {}
        for category, count in csp_effectiveness_counts.items():
            if count > 0:
                sri_adoption_by_csp[category] = round(sri_by_csp_effectiveness[category] / count * 100, 2)
            else:
                sri_adoption_by_csp[category] = 0
                
        total_sites = len(df)
        
        self.results["sri_adoption"] = {
            "sites_with_sri": sites_with_sri,
            "sites_with_sri_percent": round(sites_with_sri / total_sites * 100, 2) if total_sites > 0 else 0,
            "avg_script_sri_percent": round(avg_script_sri, 2),
            "avg_link_sri_percent": round(avg_link_sri, 2),
            "sri_adoption_by_csp_effectiveness": sri_adoption_by_csp
        }
        
        logger.info(f"SRI adoption: {sites_with_sri} out of {total_sites} valid sites ({self.results['sri_adoption']['sites_with_sri_percent']}%)")
    
    def analyze_directives(self) -> None:
        """Analyze the usage of CSP directives."""
        # Get directives data from database
        df_directives = self.db.get_directives_dataframe()
        
        if self.skip_errors:
            # Filter out sites with errors
            df_directives = df_directives[df_directives.error.isna()]
        
        # Count directives
        directive_counts = Counter(df_directives.directive)
        
        # Get sites dataframe to count total sites with CSP
        df_sites = self.db.get_sites_dataframe()
        if self.skip_errors:
            df_sites = df_sites[df_sites.error.isna()]
        
        total_sites_with_csp = len(df_sites[df_sites.csp_header.notna()])
        
        # Calculate percentages for directives
        directive_percentages = {
            directive: round(count / total_sites_with_csp * 100, 2)
            for directive, count in directive_counts.most_common(10)  # Top 10 directives
        } if total_sites_with_csp > 0 else {}
        
        # Count advanced directives
        advanced_directives = {
            "trusted-types": 0,
            "require-trusted-types-for": 0,
            "nonce-based": 0,
            "hash-based": 0,
            "strict-dynamic": 0
        }
        
        # Trusted types directives
        advanced_directives["trusted-types"] = len(df_directives[df_directives.directive == "trusted-types"])
        advanced_directives["require-trusted-types-for"] = len(df_directives[df_directives.directive == "require-trusted-types-for"])
        
        # Count sites with nonce, hash, and strict-dynamic
        for _, site in df_sites[df_sites.csp_header.notna()].iterrows():
            csp_header = site.csp_header
            directives = parse_csp_header(csp_header)
            
            # Check for nonce-based CSP
            has_nonce = any("'nonce-" in str(v) for d in directives.values() for v in d)
            if has_nonce:
                advanced_directives["nonce-based"] += 1
            
            # Check for hash-based CSP
            has_hash = any("'sha" in str(v) for d in directives.values() for v in d)
            if has_hash:
                advanced_directives["hash-based"] += 1
            
            # Check for strict-dynamic
            has_strict_dynamic = any("'strict-dynamic'" in str(v) for v in directives.values())
            if has_strict_dynamic:
                advanced_directives["strict-dynamic"] += 1
        
        # Calculate percentages for advanced directives
        advanced_directive_percentages = {
            directive: round(count / total_sites_with_csp * 100, 2)
            for directive, count in advanced_directives.items()
        } if total_sites_with_csp > 0 else {}
        
        self.results["directive_analysis"] = {
            "top_directives": dict(directive_counts.most_common(10)),
            "directive_percentages": directive_percentages,
            "advanced_directives": advanced_directives,
            "advanced_directive_percentages": advanced_directive_percentages
        }
        
        if directive_counts:
            logger.info(f"Most common CSP directive: {directive_counts.most_common(1)[0][0]} ({directive_percentages.get(directive_counts.most_common(1)[0][0], 0)}%)")
    
    def analyze_misconfigurations(self) -> None:
        """Analyze common CSP misconfigurations."""
        # Get sites with CSP headers from database
        df = self.db.get_sites_dataframe()
        
        if self.skip_errors:
            df = df[df.error.isna()]
        
        misconfiguration_counts = Counter()
        
        # Process each site's CSP header
        for _, site in df[df.csp_header.notna()].iterrows():
            csp_header = site.csp_header
            directives = parse_csp_header(csp_header)
            
            # Detect misconfigurations
            issues = detect_csp_misconfigurations(directives)
            
            for issue in issues:
                misconfiguration_counts[issue] += 1
        
        # Calculate percentages
        total_sites_with_csp = len(df[df.csp_header.notna()])
        
        misconfiguration_percentages = {
            issue: round(count / total_sites_with_csp * 100, 2)
            for issue, count in misconfiguration_counts.most_common()
        } if total_sites_with_csp > 0 else {}
        
        self.results["common_misconfigurations"] = {
            "issues": dict(misconfiguration_counts.most_common()),
            "issue_percentages": misconfiguration_percentages
        }
        
        if misconfiguration_counts:
            logger.info(f"Most common misconfiguration: {misconfiguration_counts.most_common(1)[0][0]} ({misconfiguration_percentages[misconfiguration_counts.most_common(1)[0][0]]}%)")
    
    def analyze_third_party_script_sources(self) -> None:
        """Analyze third-party script-src sources in CSP headers.
        
        This method identifies script sources that aren't same-origin and counts
        their frequency across all sites. These are likely trusted CDNs.
        """
        # Get sites with CSP headers from database
        df = self.db.get_sites_dataframe()
        
        if self.skip_errors:
            df = df[df.error.isna()]
        
        # Counter for third-party script sources
        third_party_sources = Counter()
        
        # Process each site's CSP header
        for _, site in df[df.csp_header.notna()].iterrows():
            # Extract domain from the site URL
            site_domain = site.url.split('://')[-1].split('/')[0]
            
            # Parse CSP header
            csp_header = site.csp_header
            directives = parse_csp_header(csp_header)
            
            # Look specifically at script-src directive (or default-src as fallback)
            script_sources = directives.get('script-src', [])
            if not script_sources and 'default-src' in directives:
                script_sources = directives.get('default-src', [])
            
            # Filter for third-party sources (not same origin)
            for source in script_sources:
                # Skip special keywords and hash/nonce values
                if source.startswith("'") or source == 'self' or source == '*':
                    continue
                    
                # Skip if it's the same domain or a subdomain
                if site_domain in source or source in site_domain:
                    continue
                
                # Skip URI schemes like 'blob:' and 'data:'
                if source.endswith(':'):
                    continue
                    
                # Count this as a third-party source
                third_party_sources[source] += 1
        
        self.results["third_party_script_sources"] = {
            "sources": dict(third_party_sources.most_common()),
            "total_unique_sources": len(third_party_sources)
        }
        
        # Export to CSV
        output_dir = "data/results"
        os.makedirs(output_dir, exist_ok=True)
        csv_path = os.path.join(output_dir, "third_party_script_sources.csv")
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Source', 'Count', 'Percentage'])
            
            total_sites_with_csp = len(df[df.csp_header.notna()])
            for source, count in third_party_sources.most_common():
                percentage = round((count / total_sites_with_csp) * 100, 2) if total_sites_with_csp > 0 else 0
                writer.writerow([source, count, f"{percentage}%"])
        
        logger.info(f"Exported {len(third_party_sources)} third-party script sources to {csv_path}")
        if third_party_sources:
            most_common = third_party_sources.most_common(1)[0]
            logger.info(f"Most common third-party script source: {most_common[0]} (used by {most_common[1]} sites)")
    
    def generate_visualizations(self, output_dir: str = "data/results") -> None:
        """
        Generate visualizations from the analysis results.
        
        Args:
            output_dir: Directory to save visualization images
        """
        os.makedirs(output_dir, exist_ok=True)
        
        # Set style
        sns.set(style="whitegrid")
        
        # 1. CSP Adoption Pie Chart
        plt.figure(figsize=(10, 6))
        adoption_data = [
            self.results["adoption_stats"]["sites_with_csp"],
            self.results["adoption_stats"]["sites_with_report_only"],
            self.results["adoption_stats"]["sites_with_both"],
            self.results["adoption_stats"]["sites_with_no_csp"]
        ]
        adoption_labels = [
            f"CSP Only ({self.results['adoption_stats']['sites_with_csp_percent']}%)",
            f"Report-Only ({self.results['adoption_stats']['sites_with_report_only_percent']}%)",
            f"Both ({self.results['adoption_stats']['sites_with_both_percent']}%)",
            f"No CSP ({self.results['adoption_stats']['sites_with_no_csp_percent']}%)"
        ]
        plt.pie(adoption_data, labels=adoption_labels, autopct='%1.1f%%', startangle=90, colors=sns.color_palette("Set2"))
        plt.title("CSP Adoption Distribution")
        
        # Add a text annotation with the total number of valid sites
        total_sites = self.results["adoption_stats"]["total_valid_sites"]
        plt.figtext(0.5, 0.01, f"Total domains analyzed: {total_sites}", ha="center", fontsize=10, 
                    bbox={"facecolor":"lightgrey", "alpha":0.5, "pad":5})
        
        plt.tight_layout(rect=[0, 0.03, 1, 0.95])  # Adjust layout to make room for the annotation
        plt.savefig(os.path.join(output_dir, "csp_adoption.png"))
        plt.close()
        
        # 2. CSP Effectiveness Pie Chart (changed from bar chart)
        plt.figure(figsize=(10, 6))
        effectiveness_data = self.results["csp_effectiveness"]["effectiveness_counts"]
        categories = ["none", "minimal", "moderate", "strong"]
        values = [effectiveness_data.get(cat, 0) for cat in categories]
        
        # Create nicer labels with percentages
        effect_labels = [
            f"None ({self.results['csp_effectiveness']['effectiveness_percentages'].get('none', 0)}%)",
            f"Minimal ({self.results['csp_effectiveness']['effectiveness_percentages'].get('minimal', 0)}%)",
            f"Moderate ({self.results['csp_effectiveness']['effectiveness_percentages'].get('moderate', 0)}%)",
            f"Strong ({self.results['csp_effectiveness']['effectiveness_percentages'].get('strong', 0)}%)"
        ]
        
        # Use a different color palette for this chart
        colors = sns.color_palette("YlOrRd", 4)
        plt.pie(values, labels=effect_labels, autopct='%1.1f%%', startangle=90, colors=colors)
        plt.title("CSP Implementation Effectiveness")
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, "csp_effectiveness.png"))
        plt.close()
        
        # 3. SRI Adoption Bar Chart
        plt.figure(figsize=(10, 6))
        plt.bar(["Script Tags", "Link Tags"], 
               [self.results["sri_adoption"]["avg_script_sri_percent"], 
                self.results["sri_adoption"]["avg_link_sri_percent"]])
        plt.title("Average SRI Usage")
        plt.xlabel("Resource Type")
        plt.ylabel("Average Percentage of Tags with SRI")
        plt.ylim(0, 100)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, "sri_adoption.png"))
        plt.close()
        
        # 4. Top CSP Directives
        plt.figure(figsize=(12, 8))
        top_directives = self.results["directive_analysis"]["top_directives"]
        directive_names = list(top_directives.keys())
        directive_counts = list(top_directives.values())
        
        # Sort by count
        sorted_indices = sorted(range(len(directive_counts)), key=lambda k: directive_counts[k], reverse=True)
        directive_names = [directive_names[i] for i in sorted_indices]
        directive_counts = [directive_counts[i] for i in sorted_indices]
        
        if directive_names and directive_counts:
            sns.barplot(x=directive_counts, y=directive_names)
            plt.title("Top CSP Directives")
            plt.xlabel("Number of Sites")
            plt.ylabel("Directive")
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, "top_directives.png"))
        plt.close()
        
        # 5. Advanced Directives Adoption
        plt.figure(figsize=(10, 6))
        advanced_directives = self.results["directive_analysis"]["advanced_directives"]
        plt.bar(advanced_directives.keys(), advanced_directives.values())
        plt.title("Advanced CSP Directives Adoption")
        plt.xlabel("Directive Type")
        plt.ylabel("Number of Sites")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, "advanced_directives.png"))
        plt.close()
        
        logger.info(f"Visualizations saved to {output_dir}")
    
    def export_to_csv(self) -> None:
        """Export data to CSV format for spreadsheet analysis."""
        if not self.csv_output:
            return
        
        # Use pandas for CSV export
        df = self.db.get_sites_dataframe()
        df_directives = self.db.get_directives_dataframe()
        
        if self.skip_errors:
            df = df[df.error.isna()]
            df_directives = df_directives[df_directives.error.isna()]
        
        # Create a pivot table of directives
        df_pivot = pd.pivot_table(
            df_directives, 
            index='site_id', 
            columns='directive', 
            values='value', 
            aggfunc=lambda x: ' '.join(x)
        )
        
        # Merge with sites data
        result_df = pd.merge(df, df_pivot, how='left', left_on='id', right_index=True)
        
        # Add calculated columns
        result_df['has_csp'] = result_df.csp_header.notna().map({True: 'Yes', False: 'No'})
        result_df['has_csp_report_only'] = result_df.csp_report_only_header.notna().map({True: 'Yes', False: 'No'})
        
        # Calculate SRI percentages
        result_df['script_sri_percent'] = result_df.apply(
            lambda row: (row.script_tags_with_integrity / row.script_tags_total * 100) 
            if row.script_tags_total > 0 else 0, 
            axis=1
        )
        
        result_df['link_sri_percent'] = result_df.apply(
            lambda row: (row.link_tags_with_integrity / row.link_tags_total * 100) 
            if row.link_tags_total > 0 else 0, 
            axis=1
        )
        
        # Add CSP effectiveness
        result_df['csp_effectiveness'] = result_df.apply(
            lambda row: analyze_csp_effectiveness(parse_csp_header(row.csp_header)) if pd.notna(row.csp_header) else 'none', 
            axis=1
        )
        
        # Select columns for export
        export_columns = [
            'url', 'has_csp', 'has_csp_report_only', 'csp_effectiveness',
            'script_tags_total', 'script_tags_with_integrity', 'script_sri_percent',
            'link_tags_total', 'link_tags_with_integrity', 'link_sri_percent',
            'status_code', 'error'
        ]
        
        # Add directive columns
        export_columns.extend([col for col in result_df.columns if col not in export_columns])
        
        # Export to CSV
        os.makedirs(os.path.dirname(os.path.abspath(self.csv_output)), exist_ok=True)
        result_df.to_csv(self.csv_output, index=False)
        
        logger.info(f"CSV data exported to {self.csv_output}")
    
    def analyze(self) -> None:
        """Run all analysis tasks."""
        # Connect to database
        self.connect_db()
        
        try:
            # Get site count
            site_count = self.db.get_site_count()
            self.results["metadata"]["sites_analyzed"] = site_count
            logger.info(f"Loaded data for {site_count} sites")
            
            # Run analysis tasks
            self.analyze_adoption()
            self.analyze_effectiveness()
            self.analyze_sri_adoption()
            self.analyze_directives()
            self.analyze_misconfigurations()
            self.analyze_third_party_script_sources()
            
            # Generate visualizations
            self.generate_visualizations()
            
            # Export to CSV if requested
            if self.csv_output:
                self.export_to_csv()
            
            # Save results
            with open(self.output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
                
            logger.info(f"Analysis results saved to {self.output_file}")
        finally:
            # Close database connection
            self.close_db()


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description="Analyze CSP data collected from websites (Database Version)")
    
    parser.add_argument("--db", required=True, help="Path to SQLite database file")
    parser.add_argument("--output", default="analysis_report.json", help="Path to output JSON file for analysis results")
    parser.add_argument("--csv", help="Export data to CSV file for spreadsheet analysis")
    parser.add_argument("--no-visualizations", action="store_true", help="Skip generating visualizations")
    parser.add_argument("--include-errors", action="store_true", help="Include sites with errors in analysis")
    
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = CSPAnalyzer(
        db_path=args.db, 
        output_file=args.output, 
        csv_output=args.csv,
        skip_errors=not args.include_errors
    )
    
    # Run analysis
    analyzer.analyze()


if __name__ == "__main__":
    main()
