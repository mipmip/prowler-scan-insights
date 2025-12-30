#!/usr/bin/env python3
"""
Data Loader Module - CSV file discovery and loading for Prowler security scan data.
"""

import os
import pandas as pd
import logging
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any

logger = logging.getLogger(__name__)

class DataLoader:
    """Handles discovery and loading of Prowler CSV files."""

    def __init__(self, output_dir: str = "output", output_directory: str = None):
        """Initialize the data loader.

        Args:
            output_dir: Directory containing Prowler CSV files
        """
        # Handle both output_dir and output_directory parameters for compatibility
        if output_directory is not None:
            self.output_dir = Path(output_directory)
        else:
            self.output_dir = Path(output_dir)

        self.required_columns = [
            'FINDING_UID', 'ACCOUNT_UID', 'CHECK_ID', 'STATUS',
            'SEVERITY', 'SERVICE_NAME', 'REGION'
        ]

    def discover_csv_files(self) -> List[Path]:
        """Discover CSV files in the output directory.

        Returns:
            List of CSV file paths
        """
        if not self.output_dir.exists():
            logger.warning(f"Output directory does not exist: {self.output_dir}")
            return []

        csv_files = []
        patterns = ['*.csv', '*prowler*.csv', '*security*.csv']

        for pattern in patterns:
            csv_files.extend(self.output_dir.glob(pattern))

        # Remove duplicates while preserving order
        seen = set()
        unique_files = []
        for file in csv_files:
            if file not in seen:
                seen.add(file)
                unique_files.append(file)

        logger.info(f"Discovered {len(unique_files)} CSV files")
        return unique_files

    def load_csv_file(self, file_path: Path) -> Optional[pd.DataFrame]:
        """Load a single CSV file.

        Args:
            file_path: Path to the CSV file

        Returns:
            DataFrame or None if loading failed
        """
        try:
            logger.debug(f"Loading CSV file: {file_path}")
            df = pd.read_csv(file_path, sep=';', low_memory=False)

            if df.empty:
                logger.warning(f"Empty CSV file: {file_path}")
                return None

            # Normalize column names to uppercase
            df.columns = df.columns.str.upper()

            # Check for required columns
            missing_cols = [col for col in self.required_columns if col not in df.columns]
            if missing_cols:
                logger.warning(f"Missing required columns in {file_path}: {missing_cols}")

            logger.info(f"Loaded {len(df)} rows from {file_path}")
            return df

        except Exception as e:
            logger.error(f"Failed to load CSV file {file_path}: {e}")
            return None

    def load_all_data(self) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """Load and combine all CSV files.

        Returns:
            Tuple of (Combined DataFrame with all security findings, loading statistics)
        """
        csv_files = self.discover_csv_files()

        if not csv_files:
            logger.error(f"No CSV files found in directory: {self.output_dir}")
            return pd.DataFrame(), {'files_loaded': 0, 'total_files': 0, 'files_found': 0, 'total_findings': 0, 'total_rows': 0}

        dataframes = []
        for file_path in csv_files:
            df = self.load_csv_file(file_path)
            if df is not None:
                df['SOURCE_FILE'] = file_path.name
                dataframes.append(df)

        if not dataframes:
            logger.error("No valid CSV files could be loaded")
            return pd.DataFrame(), {'files_loaded': 0, 'total_files': len(csv_files), 'files_found': len(csv_files), 'total_findings': 0, 'total_rows': 0}

        combined_df = pd.concat(dataframes, ignore_index=True)
        logger.info(f"Combined data: {len(combined_df)} total findings from {len(dataframes)} files")

        stats = {
            'files_loaded': len(dataframes),
            'total_files': len(csv_files),
            'files_found': len(csv_files),
            'total_findings': len(combined_df),
            'total_rows': len(combined_df)
        }

        return combined_df, stats

