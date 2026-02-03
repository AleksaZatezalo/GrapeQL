"""
GrapeQL Response Baseline Tracker
Author: Aleksa Zatezalo
Version: 3.0
Date: February 2025
Description: Tracks response times across modules, computes running average and
             standard deviation, and provides a baseline threshold for the DoS
             tester to compare against.
"""

import math
import threading
from typing import Dict, List, Optional, Tuple


class BaselineTracker:
    """
    Thread-safe collector of response-time samples.

    Any module (fingerprinter, injection tester, info tester) records its
    response times here.  The DoS tester then reads the aggregate baseline
    before deciding whether a slow response is truly anomalous.

    Usage:
        baseline = BaselineTracker()

        # During testing — every module records its times
        baseline.record("InjectionTester", 0.342)
        baseline.record("InfoTester", 0.128)

        # DoS tester reads the aggregate
        avg, std = baseline.get_aggregate_stats()    # across all modules
        threshold = baseline.get_dos_threshold()      # avg + 3*std (configurable)
    """

    def __init__(self, sigma_multiplier: float = 3.0):
        """
        Args:
            sigma_multiplier: Number of standard deviations above the mean
                              to use as the DoS vulnerability threshold.
        """
        self._lock = threading.Lock()
        self._samples: Dict[str, List[float]] = {}
        self._sigma_multiplier = sigma_multiplier

    # ------------------------------------------------------------------ #
    #  Recording
    # ------------------------------------------------------------------ #

    def record(self, module: str, duration: float) -> None:
        """
        Record a single response-time sample.

        Args:
            module:   Module name (e.g. "InjectionTester").
            duration: Response time in seconds.
        """
        with self._lock:
            self._samples.setdefault(module, []).append(duration)

    def record_batch(self, module: str, durations: List[float]) -> None:
        """Record multiple samples at once."""
        with self._lock:
            self._samples.setdefault(module, []).extend(durations)

    # ------------------------------------------------------------------ #
    #  Per-module stats
    # ------------------------------------------------------------------ #

    def get_module_stats(self, module: str) -> Tuple[float, float, int]:
        """
        Get statistics for a single module.

        Returns:
            (mean, stddev, sample_count)
        """
        with self._lock:
            samples = self._samples.get(module, [])
        return self._compute_stats(samples)

    # ------------------------------------------------------------------ #
    #  Aggregate stats (all modules combined)
    # ------------------------------------------------------------------ #

    def get_aggregate_stats(self) -> Tuple[float, float, int]:
        """
        Get statistics across all modules.

        Returns:
            (mean, stddev, total_sample_count)
        """
        with self._lock:
            all_samples = [s for samples in self._samples.values() for s in samples]
        return self._compute_stats(all_samples)

    # ------------------------------------------------------------------ #
    #  DoS threshold
    # ------------------------------------------------------------------ #

    def get_dos_threshold(self, min_threshold: float = 5.0) -> float:
        """
        Compute the response-time threshold above which a request is
        considered a potential DoS indicator.

        Formula:  max(min_threshold, mean + sigma_multiplier * stddev)

        If no baseline samples exist yet, returns ``min_threshold``.

        Args:
            min_threshold: Floor value — even with a fast baseline, we won't
                           flag anything under this many seconds.

        Returns:
            Threshold in seconds.
        """
        mean, stddev, count = self.get_aggregate_stats()
        if count == 0:
            return min_threshold
        computed = mean + self._sigma_multiplier * stddev
        return max(min_threshold, computed)

    def has_baseline(self) -> bool:
        """Return True if at least some samples have been recorded."""
        with self._lock:
            return any(len(v) > 0 for v in self._samples.values())

    def summary(self) -> Dict[str, Dict[str, float]]:
        """
        Return a summary dict keyed by module name.

        Example::

            {
                "InjectionTester": {"mean": 0.32, "stddev": 0.05, "count": 120},
                "InfoTester":      {"mean": 0.18, "stddev": 0.03, "count": 7},
                "_aggregate":      {"mean": 0.29, "stddev": 0.08, "count": 127},
            }
        """
        result: Dict[str, Dict[str, float]] = {}
        with self._lock:
            modules = list(self._samples.keys())
        for mod in modules:
            mean, std, cnt = self.get_module_stats(mod)
            result[mod] = {"mean": mean, "stddev": std, "count": cnt}
        agg_mean, agg_std, agg_cnt = self.get_aggregate_stats()
        result["_aggregate"] = {"mean": agg_mean, "stddev": agg_std, "count": agg_cnt}
        return result

    # ------------------------------------------------------------------ #
    #  Internals
    # ------------------------------------------------------------------ #

    @staticmethod
    def _compute_stats(samples: List[float]) -> Tuple[float, float, int]:
        n = len(samples)
        if n == 0:
            return 0.0, 0.0, 0
        mean = sum(samples) / n
        if n < 2:
            return mean, 0.0, n
        variance = sum((x - mean) ** 2 for x in samples) / (n - 1)
        return mean, math.sqrt(variance), n
