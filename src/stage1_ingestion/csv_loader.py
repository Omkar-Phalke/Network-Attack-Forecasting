"""Stage 1: CSV Ingestion Engine for CSE-CIC-IDS2018 dataset."""

import os
from pathlib import Path
from typing import Generator, List, Optional, Union
import pandas as pd
from src.utils.logger import get_logger

logger = get_logger("CSVLoader")

class CICIDS2018Loader:
    """Robust chunked loader for CSE-CIC-IDS2018 CSV files."""

    def __init__(self, data_path: Union[str, Path]):
        self.data_path = Path(data_path)

    def find_csv_files(self) -> List[Path]:
        """Finds all CSV files in the designated directory or returns the single file."""
        if self.data_path.is_file() and self.data_path.suffix.lower() == ".csv":
            return [self.data_path]
        if self.data_path.is_dir():
            csv_files = sorted(list(self.data_path.glob("*.csv")))
            logger.info(f"Found {len(csv_files)} CSV files in {self.data_path}")
            return csv_files
        return []

    def load_sample(self, n_rows: int = 10000) -> pd.DataFrame:
        """Loads a representative sample dataframe from available CSV files."""
        csv_files = self.find_csv_files()
        if not csv_files:
            raise FileNotFoundError(f"No CSV files found in {self.data_path}")

        frames = []
        rows_per_file = max(100, n_rows // max(1, len(csv_files)))
        for file in csv_files:
            try:
                df = pd.read_csv(file, nrows=rows_per_file, low_memory=False)
                # Strip leading/trailing whitespaces from column headers
                df.columns = df.columns.str.strip()
                frames.append(df)
            except Exception as e:
                logger.warning(f"Failed to read {file.name}: {e}")

        if not frames:
            raise ValueError("Failed to load any records from CSV files.")

        combined = pd.concat(frames, ignore_index=True)
        logger.info(f"Loaded sample dataset with {len(combined)} rows and {len(combined.columns)} columns.")
        return combined

    def stream_chunks(self, chunksize: int = 50000) -> Generator[pd.DataFrame, None, None]:
        """Streams large multi-gigabyte CSV files in memory-efficient chunks."""
        csv_files = self.find_csv_files()
        for file in csv_files:
            logger.info(f"Streaming chunks from {file.name} (chunksize={chunksize})...")
            try:
                for chunk in pd.read_csv(file, chunksize=chunksize, low_memory=False):
                    chunk.columns = chunk.columns.str.strip()
                    yield chunk
            except Exception as e:
                logger.error(f"Error reading chunk from {file.name}: {e}")
