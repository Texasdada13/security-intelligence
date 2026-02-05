"""File Analyzer for CSV/Excel Data Analysis - Security Intelligence"""
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import json
import io
import csv


@dataclass
class ColumnAnalysis:
    """Analysis of a single column."""
    name: str
    dtype: str  # 'numeric', 'text', 'date', 'boolean'
    sample_values: List[Any]
    unique_count: int
    null_count: int
    min_value: Any = None
    max_value: Any = None
    mean_value: float = None


@dataclass
class FileAnalysisResult:
    """Result of file analysis."""
    filename: str
    file_type: str
    row_count: int
    column_count: int
    columns: List[ColumnAnalysis]
    data_summary: str
    sample_rows: List[Dict[str, Any]]
    detected_metrics: Dict[str, Any]
    context_json: Dict[str, Any]
    insights: List[str]
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'filename': self.filename,
            'file_type': self.file_type,
            'row_count': self.row_count,
            'column_count': self.column_count,
            'columns': [
                {
                    'name': c.name,
                    'dtype': c.dtype,
                    'sample_values': c.sample_values[:3],
                    'unique_count': c.unique_count,
                    'null_count': c.null_count
                }
                for c in self.columns
            ],
            'data_summary': self.data_summary,
            'sample_rows': self.sample_rows[:5],
            'detected_metrics': self.detected_metrics,
            'insights': self.insights
        }


class FileAnalyzer:
    """Analyzes uploaded CSV/Excel files for chat context."""

    SUPPORTED_FORMATS = ['csv', 'tsv', 'json']
    MAX_ROWS = 1000
    MAX_SAMPLE_ROWS = 10

    # Security-specific metric patterns
    SECURITY_METRIC_PATTERNS = {
        'vulnerability': ['vulnerability', 'vuln', 'cve', 'weakness'],
        'severity': ['severity', 'critical', 'high', 'medium', 'low', 'cvss'],
        'risk': ['risk', 'risk_score', 'risk_level', 'threat'],
        'asset': ['asset', 'host', 'ip', 'hostname', 'server', 'endpoint'],
        'incident': ['incident', 'alert', 'event', 'detection'],
        'compliance': ['compliance', 'control', 'framework', 'audit'],
        'status': ['status', 'state', 'remediation', 'resolved'],
        'user': ['user', 'username', 'account', 'identity'],
        'access': ['access', 'permission', 'privilege', 'role'],
        'date': ['date', 'time', 'timestamp', 'discovered', 'detected'],
    }

    def __init__(self):
        pass

    def analyze_file(self, content: bytes, filename: str) -> FileAnalysisResult:
        """Analyze an uploaded file and return analysis result."""
        file_type = self._detect_file_type(filename)

        if file_type == 'csv':
            return self._analyze_csv(content, filename)
        elif file_type == 'tsv':
            return self._analyze_csv(content, filename, delimiter='\t')
        elif file_type == 'json':
            return self._analyze_json(content, filename)
        else:
            raise ValueError(f"Unsupported file type: {file_type}")

    def _detect_file_type(self, filename: str) -> str:
        """Detect file type from filename."""
        lower_name = filename.lower()
        if lower_name.endswith('.csv'):
            return 'csv'
        elif lower_name.endswith('.tsv'):
            return 'tsv'
        elif lower_name.endswith('.json'):
            return 'json'
        else:
            return 'csv'

    def _analyze_csv(self, content: bytes, filename: str, delimiter: str = ',') -> FileAnalysisResult:
        """Analyze a CSV file."""
        try:
            text = content.decode('utf-8-sig')
        except UnicodeDecodeError:
            text = content.decode('latin-1')

        reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
        rows = []
        for i, row in enumerate(reader):
            if i >= self.MAX_ROWS:
                break
            rows.append(row)

        if not rows:
            return self._create_empty_result(filename, 'csv')

        columns = self._analyze_columns(rows)
        detected_metrics = self._detect_security_metrics(columns, rows)
        insights = self._generate_insights(columns, rows, detected_metrics)
        summary = self._create_summary(filename, rows, columns, detected_metrics)
        context_json = self._build_context_json(columns, rows, detected_metrics)

        return FileAnalysisResult(
            filename=filename,
            file_type='csv',
            row_count=len(rows),
            column_count=len(columns),
            columns=columns,
            data_summary=summary,
            sample_rows=rows[:self.MAX_SAMPLE_ROWS],
            detected_metrics=detected_metrics,
            context_json=context_json,
            insights=insights
        )

    def _analyze_json(self, content: bytes, filename: str) -> FileAnalysisResult:
        """Analyze a JSON file."""
        data = json.loads(content.decode('utf-8'))

        if isinstance(data, list):
            rows = data[:self.MAX_ROWS]
        elif isinstance(data, dict):
            if 'data' in data:
                rows = data['data'][:self.MAX_ROWS]
            elif 'results' in data:
                rows = data['results'][:self.MAX_ROWS]
            elif 'vulnerabilities' in data:
                rows = data['vulnerabilities'][:self.MAX_ROWS]
            elif 'incidents' in data:
                rows = data['incidents'][:self.MAX_ROWS]
            else:
                rows = [data]
        else:
            rows = []

        if not rows or not isinstance(rows[0], dict):
            return self._create_empty_result(filename, 'json')

        columns = self._analyze_columns(rows)
        detected_metrics = self._detect_security_metrics(columns, rows)
        insights = self._generate_insights(columns, rows, detected_metrics)
        summary = self._create_summary(filename, rows, columns, detected_metrics)
        context_json = self._build_context_json(columns, rows, detected_metrics)

        return FileAnalysisResult(
            filename=filename,
            file_type='json',
            row_count=len(rows),
            column_count=len(columns),
            columns=columns,
            data_summary=summary,
            sample_rows=rows[:self.MAX_SAMPLE_ROWS],
            detected_metrics=detected_metrics,
            context_json=context_json,
            insights=insights
        )

    def _analyze_columns(self, rows: List[Dict[str, Any]]) -> List[ColumnAnalysis]:
        """Analyze each column in the data."""
        if not rows:
            return []

        columns = []
        all_keys = set()
        for row in rows:
            all_keys.update(row.keys())

        for key in all_keys:
            values = [row.get(key) for row in rows]
            non_null_values = [v for v in values if v is not None and v != '']
            dtype = self._infer_dtype(non_null_values)
            unique_count = len(set(str(v) for v in non_null_values))
            null_count = len(values) - len(non_null_values)

            col = ColumnAnalysis(
                name=key,
                dtype=dtype,
                sample_values=non_null_values[:5],
                unique_count=unique_count,
                null_count=null_count
            )

            if dtype == 'numeric' and non_null_values:
                try:
                    numeric_vals = [float(v) for v in non_null_values]
                    col.min_value = min(numeric_vals)
                    col.max_value = max(numeric_vals)
                    col.mean_value = sum(numeric_vals) / len(numeric_vals)
                except (ValueError, TypeError):
                    pass

            columns.append(col)

        return columns

    def _infer_dtype(self, values: List[Any]) -> str:
        """Infer data type from values."""
        if not values:
            return 'text'

        numeric_count = 0
        for v in values[:20]:
            try:
                float(str(v).replace(',', '').replace('$', '').replace('%', ''))
                numeric_count += 1
            except (ValueError, TypeError):
                pass

        if numeric_count > len(values[:20]) * 0.8:
            return 'numeric'

        bool_values = {'true', 'false', 'yes', 'no', '1', '0'}
        if all(str(v).lower() in bool_values for v in values[:20]):
            return 'boolean'

        return 'text'

    def _detect_security_metrics(
        self,
        columns: List[ColumnAnalysis],
        rows: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Detect security-related metrics in the data."""
        detected = {}

        for col in columns:
            col_lower = col.name.lower()

            for metric_type, patterns in self.SECURITY_METRIC_PATTERNS.items():
                if any(p in col_lower for p in patterns):
                    if col.dtype == 'numeric' and col.mean_value is not None:
                        detected[metric_type] = {
                            'column': col.name,
                            'mean': round(col.mean_value, 2),
                            'min': col.min_value,
                            'max': col.max_value
                        }
                    else:
                        # Count severity levels if present
                        if metric_type == 'severity':
                            severity_counts = {}
                            for row in rows:
                                val = str(row.get(col.name, '')).lower()
                                if val in ['critical', 'high', 'medium', 'low', 'info']:
                                    severity_counts[val] = severity_counts.get(val, 0) + 1
                            detected[metric_type] = {
                                'column': col.name,
                                'distribution': severity_counts
                            }
                        else:
                            detected[metric_type] = {
                                'column': col.name,
                                'unique_values': col.unique_count
                            }
                    break

        return detected

    def _generate_insights(
        self,
        columns: List[ColumnAnalysis],
        rows: List[Dict[str, Any]],
        detected_metrics: Dict[str, Any]
    ) -> List[str]:
        """Generate insights from the data."""
        insights = []

        insights.append(f"Dataset contains {len(rows)} rows and {len(columns)} columns.")

        if detected_metrics:
            metric_names = list(detected_metrics.keys())
            insights.append(f"Detected security data types: {', '.join(metric_names)}")

        # Severity distribution insight
        if 'severity' in detected_metrics:
            dist = detected_metrics['severity'].get('distribution', {})
            if dist:
                critical = dist.get('critical', 0)
                high = dist.get('high', 0)
                if critical > 0 or high > 0:
                    insights.append(f"Critical findings: {critical}, High severity: {high}")

        # Vulnerability count
        if 'vulnerability' in detected_metrics:
            insights.append(f"Contains vulnerability data with {len(rows)} entries")

        return insights[:10]

    def _create_summary(
        self,
        filename: str,
        rows: List[Dict[str, Any]],
        columns: List[ColumnAnalysis],
        detected_metrics: Dict[str, Any]
    ) -> str:
        """Create a text summary of the data."""
        parts = [f"File: {filename}", f"Rows: {len(rows)}, Columns: {len(columns)}"]

        if detected_metrics:
            parts.append(f"Security data: {', '.join(detected_metrics.keys())}")

        return " | ".join(parts)

    def _build_context_json(
        self,
        columns: List[ColumnAnalysis],
        rows: List[Dict[str, Any]],
        detected_metrics: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build context JSON for AI prompts."""
        return {
            'schema': [
                {
                    'name': c.name,
                    'type': c.dtype,
                    'sample': c.sample_values[:2]
                }
                for c in columns
            ],
            'metrics': detected_metrics,
            'sample_data': rows[:3],
            'row_count': len(rows)
        }

    def _create_empty_result(self, filename: str, file_type: str) -> FileAnalysisResult:
        """Create an empty result for files with no data."""
        return FileAnalysisResult(
            filename=filename,
            file_type=file_type,
            row_count=0,
            column_count=0,
            columns=[],
            data_summary="No data found in file",
            sample_rows=[],
            detected_metrics={},
            context_json={},
            insights=["File appears to be empty or has no recognizable data structure"]
        )


def create_file_analyzer() -> FileAnalyzer:
    return FileAnalyzer()
