"""Stage 1: Streaming Telemetry Simulator for Live SOC Monitoring and Forecasting."""

from typing import Generator, Dict, Any, Optional
import time
import pandas as pd
from src.utils.logger import get_logger

logger = get_logger("StreamSimulator")

class NetworkStreamSimulator:
    """Simulates real-time network flow ingestion with controllable playback speeds."""

    def __init__(self, dataframe: pd.DataFrame, playback_speed: float = 1.0):
        self.df = dataframe.copy()
        self.playback_speed = playback_speed
        self._current_index = 0

        # Ensure chronological ordering if timestamp exists
        if "Timestamp" in self.df.columns:
            try:
                self.df["_sort_time"] = pd.to_datetime(self.df["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce")
                self.df = self.df.sort_values("_sort_time").drop(columns=["_sort_time"])
            except Exception:
                pass
        self.df = self.df.reset_index(drop=True)

    def total_flows(self) -> int:
        return len(self.df)

    def get_next_batch(self, batch_size: int = 10) -> pd.DataFrame:
        """Fetches the next sequential batch of network flows."""
        if self._current_index >= len(self.df):
            self._current_index = 0  # Loop back for continuous SOC telemetry simulation

        start = self._current_index
        end = min(start + batch_size, len(self.df))
        self._current_index = end
        return self.df.iloc[start:end].copy()

    def stream_flows(self, delay_seconds: float = 0.1) -> Generator[Dict[str, Any], None, None]:
        """Generator that yields individual network flow dictionaries with pacing."""
        for _, row in self.df.iterrows():
            if delay_seconds > 0:
                time.sleep(delay_seconds / self.playback_speed)
            yield row.to_dict()

    def reset(self):
        """Resets the playback pointer to the start."""
        self._current_index = 0
