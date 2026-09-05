"""Declarative, rule-based anti-cheat checks over owned telemetry.

Each game has its own physics and economy, so cheating shows up as rules being
broken: a speed above the engine cap, a score jumping faster than any legit
action allows, a rewinding timestamp, an item id that does not exist. Rather than
guess those rules, you declare them in config (``integrity.rules``) and this
engine evaluates them, offline, over a parsed telemetry table.

Rules are data, never code — there is no expression eval — so a config file can
never execute anything. Supported rule ``type`` values:

  max / min          {type, column, value}           value crosses a hard cap
  max_delta          {type, column, value}           |row - previous row| > value
  max_rate           {type, column, per, value}       change per unit of `per` col
  monotonic          {type, column, direction}        increasing|nondecreasing|
                                                       decreasing|nonincreasing
  allowed_set        {type, column, values:[...]}     value outside an allowed set

Optional per-rule keys: ``id``, ``severity`` (default high; monotonic medium),
``description``.
"""

from typing import Any, Dict, List


class AntiCheatRuleEngine:
    """Evaluate declarative anti-cheat rules over parsed telemetry columns."""

    def __init__(self, rules: List[Dict[str, Any]], max_samples: int = 10):
        self.rules = rules or []
        self.max_samples = max_samples

    def evaluate(self, columns: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for rule in self.rules:
            if not isinstance(rule, dict):
                continue
            handler = getattr(self, f"_rule_{rule.get('type', '')}", None)
            column = rule.get('column')
            if handler is None or column not in columns:
                continue
            violations = handler(rule, columns)
            if violations:
                findings.append(self._finding(rule, violations))
        return findings

    # ------------------------------------------------------------- rule types
    @staticmethod
    def _rule_max(rule, columns):
        limit = float(rule['value'])
        return [i for i in columns[rule['column']] if i['value'] > limit]

    @staticmethod
    def _rule_min(rule, columns):
        limit = float(rule['value'])
        return [i for i in columns[rule['column']] if i['value'] < limit]

    @staticmethod
    def _rule_max_delta(rule, columns):
        limit = float(rule['value'])
        series = columns[rule['column']]
        out = []
        for prev, cur in zip(series, series[1:]):
            if abs(cur['value'] - prev['value']) > limit:
                out.append({**cur, 'delta': round(cur['value'] - prev['value'], 4)})
        return out

    @staticmethod
    def _rule_max_rate(rule, columns):
        per = rule.get('per')
        if per not in columns:
            return []
        limit = float(rule['value'])
        value_by_row = {i['row']: i['value'] for i in columns[rule['column']]}
        per_by_row = {i['row']: i['value'] for i in columns[per]}
        rows = sorted(set(value_by_row) & set(per_by_row))
        out = []
        for prev_row, cur_row in zip(rows, rows[1:]):
            dt = per_by_row[cur_row] - per_by_row[prev_row]
            if dt <= 0:
                continue
            rate = (value_by_row[cur_row] - value_by_row[prev_row]) / dt
            if abs(rate) > limit:
                out.append({'row': cur_row, 'value': value_by_row[cur_row],
                            'rate': round(rate, 4)})
        return out

    @staticmethod
    def _rule_monotonic(rule, columns):
        direction = rule.get('direction', 'nondecreasing')
        series = columns[rule['column']]
        out = []
        for prev, cur in zip(series, series[1:]):
            a, b = prev['value'], cur['value']
            broken = (
                (direction == 'increasing' and not b > a) or
                (direction == 'nondecreasing' and b < a) or
                (direction == 'decreasing' and not b < a) or
                (direction == 'nonincreasing' and b > a)
            )
            if broken:
                out.append({**cur, 'previous': a})
        return out

    @staticmethod
    def _rule_allowed_set(rule, columns):
        allowed = {float(v) for v in rule.get('values', [])}
        return [i for i in columns[rule['column']] if i['value'] not in allowed]

    # ---------------------------------------------------------------- finding
    def _finding(self, rule, violations):
        rule_type = rule['type']
        column = rule['column']
        rule_id = rule.get('id') or f'{rule_type}:{column}'
        severity = rule.get('severity') or ('medium' if rule_type == 'monotonic' else 'high')
        description = rule.get('description') or (
            f'Rule "{rule_id}" was violated by {len(violations)} row(s): '
            f'{rule_type} on column "{column}". Impossible or out-of-policy values '
            'are a strong indicator of a tampered client or injected telemetry.'
        )
        return {
            'type': 'anticheat_rule_violation',
            'title': f'Anti-cheat rule "{rule_id}" violated ({len(violations)} rows)',
            'severity': severity,
            'url': '',
            'description': description,
            'evidence': {
                'rule': {k: rule[k] for k in rule if k != 'description'},
                'violation_count': len(violations),
                'samples': violations[:self.max_samples],
            },
            'signature': f'anticheat|{rule_id}',
            'confidence': 'high',
        }
