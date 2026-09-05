"""Offline game-integrity / anti-cheat anomaly analysis for owned telemetry.

This is a defensive, offline heuristic: it reads a CSV of gameplay telemetry or
event logs that you own and flags values that are physically impossible or
statistically anomalous — the kind of signal that separates a tampered client
or cheat (speed hacks, score injection, teleport, time scaling) from normal
play. It never contacts a game, server, or player; it only does arithmetic on a
file you point it at.

It is a triage aid, not a full anti-cheat runtime: it surfaces rows worth a
human's attention, with the evidence for why, and deliberately favours a low
false-positive rate over completeness.
"""

import csv
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional


class IntegrityAnalyzerError(ValueError):
    """Raised when the telemetry input cannot be analyzed safely."""


class IntegrityAnalyzer:
    """Flag impossible or anomalous values in an owned telemetry CSV."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = (config or {}).get('integrity', {})
        self.max_rows = int(self.config.get('max_rows', 200000))
        self.mad_threshold = float(self.config.get('mad_threshold', 6.0))
        self.max_samples = int(self.config.get('max_samples_per_finding', 10))
        # Optional hard physical bounds: {column: {"min": x, "max": y}}.
        self.bounds: Dict[str, Dict[str, float]] = self.config.get('bounds', {}) or {}
        # Columns to run robust-outlier detection on; empty means auto-detect.
        self.outlier_columns: List[str] = self.config.get('outlier_columns', []) or []

    # ------------------------------------------------------------------ stats
    @staticmethod
    def _median(values: List[float]) -> float:
        ordered = sorted(values)
        n = len(ordered)
        mid = n // 2
        if n % 2:
            return ordered[mid]
        return (ordered[mid - 1] + ordered[mid]) / 2.0

    @classmethod
    def _mad(cls, values: List[float], median: float) -> float:
        return cls._median([abs(v - median) for v in values])

    @staticmethod
    def _finding(ftype, title, severity, description, evidence, signature):
        return {
            'type': ftype,
            'title': title,
            'severity': severity,
            'url': '',
            'description': description,
            'evidence': evidence,
            'signature': signature,
            'confidence': 'medium',
        }

    # ------------------------------------------------------------------ parse
    def _read(self, source: Path):
        columns: Dict[str, List[Dict[str, Any]]] = {}
        invalid_rows = 0
        total_rows = 0
        with source.open('r', encoding='utf-8-sig', newline='') as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames:
                raise IntegrityAnalyzerError('Telemetry CSV has no header row')
            for row_index, row in enumerate(reader, start=1):
                if row_index > self.max_rows:
                    raise IntegrityAnalyzerError('Telemetry CSV exceeds max_rows')
                total_rows += 1
                row_had_number = False
                for name, raw in row.items():
                    if raw in (None, ''):
                        continue
                    try:
                        value = float(raw)
                    except (TypeError, ValueError):
                        continue
                    if value != value or value in (float('inf'), float('-inf')):
                        continue
                    row_had_number = True
                    columns.setdefault(name, []).append(
                        {'row': row_index, 'value': value}
                    )
                if not row_had_number:
                    invalid_rows += 1
        return columns, total_rows, invalid_rows

    # ---------------------------------------------------------------- analyze
    def analyze(self, csv_path: str) -> Dict[str, Any]:
        source = Path(csv_path)
        if not source.is_file():
            raise IntegrityAnalyzerError(f'Telemetry file not found: {csv_path}')
        if source.suffix.lower() not in {'.csv', '.tsv', '.log'}:
            raise IntegrityAnalyzerError('Integrity input must be a .csv/.tsv/.log file')

        columns, total_rows, invalid_rows = self._read(source)
        if not columns:
            raise IntegrityAnalyzerError('No numeric telemetry columns found')

        findings: List[Dict[str, Any]] = []

        # 1) Hard physical bounds -> impossible values (strong tamper signal).
        for name, limit in self.bounds.items():
            samples = columns.get(name, [])
            violations = []
            for item in samples:
                v = item['value']
                if 'min' in limit and v < float(limit['min']):
                    violations.append(item)
                elif 'max' in limit and v > float(limit['max']):
                    violations.append(item)
            if violations:
                findings.append(self._finding(
                    'integrity_bound_violation',
                    f'"{name}" outside physical bounds ({len(violations)} rows)',
                    'high',
                    f'{len(violations)} value(s) of "{name}" fall outside the '
                    f'configured plausible range {limit}. Impossible values are a '
                    f'strong indicator of a tampered client or injected data.',
                    {'column': name, 'bounds': limit,
                     'violation_count': len(violations),
                     'samples': violations[:self.max_samples]},
                    signature=f'integrity|bound|{name}',
                ))

        # 2) Frame-time time-manipulation heuristic.
        if 'frame_time_ms' in columns:
            zeros = [i for i in columns['frame_time_ms'] if i['value'] < 0.1]
            if zeros:
                findings.append(self._finding(
                    'integrity_time_anomaly',
                    f'Near-zero frame times ({len(zeros)} rows)',
                    'medium',
                    f'{len(zeros)} frame(s) report a sub-0.1ms frame time, which is '
                    'not physically plausible and can indicate time scaling / speed '
                    'manipulation.',
                    {'column': 'frame_time_ms', 'count': len(zeros),
                     'samples': zeros[:self.max_samples]},
                    signature='integrity|frametime|near-zero',
                ))

        # 3) Robust statistical outliers (MAD) per numeric column.
        target_cols = self.outlier_columns or list(columns.keys())
        for name in target_cols:
            samples = columns.get(name, [])
            values = [i['value'] for i in samples]
            if len(values) < 8:
                continue
            median = self._median(values)
            mad = self._mad(values, median)
            if mad <= 0:
                continue
            scale = 1.4826 * mad
            outliers = [
                {**item, 'robust_z': round(abs(item['value'] - median) / scale, 2)}
                for item in samples
                if abs(item['value'] - median) / scale > self.mad_threshold
            ]
            if outliers:
                outliers.sort(key=lambda x: x['robust_z'], reverse=True)
                findings.append(self._finding(
                    'integrity_statistical_outlier',
                    f'"{name}" statistical outliers ({len(outliers)} rows)',
                    'low',
                    f'{len(outliers)} value(s) of "{name}" are more than '
                    f'{self.mad_threshold} robust standard deviations from the '
                    f'median (median={round(median, 4)}). Review for anomalous or '
                    'manipulated gameplay.',
                    {'column': name, 'median': round(median, 4),
                     'mad': round(mad, 4), 'threshold': self.mad_threshold,
                     'outlier_count': len(outliers),
                     'samples': outliers[:self.max_samples]},
                    signature=f'integrity|outlier|{name}',
                ))

        severity_rank = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        findings.sort(key=lambda f: severity_rank.get(f['severity'], 5))

        return {
            'mode': 'offline-integrity-analysis',
            'source': str(source),
            'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
            'rows_analyzed': total_rows,
            'invalid_rows': invalid_rows,
            'numeric_columns': sorted(columns.keys()),
            'finding_count': len(findings),
            'findings': findings,
            'note': 'Offline heuristic anomaly triage on owned telemetry; not a '
                    'full anti-cheat runtime and makes no network contact.',
        }
