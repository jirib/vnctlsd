import json
import logging
import re

log = logging.getLogger(__name__)


def _parse_output(raw: str, fmt: str) -> object:
    """Parse raw command output according to declared format."""
    fmt = fmt.lower() if fmt else 'raw'
    if fmt == 'json':
        try:
            return json.loads(raw)
        except json.JSONDecodeError as e:
            raise ValueError(f"Command output is not valid JSON: {e}")
    elif fmt == 'lines':
        return [l for l in raw.splitlines() if l.strip()]
    else:  # raw
        return raw


def apply_filter(raw: str, fmt: str, filter_def: dict | None) -> dict:
    """
    Parse raw output and apply filter to produce a normalized structure.
    If no filter is defined, wraps the parsed output in a string structure.
    """
    try:
        parsed = _parse_output(raw, fmt)
    except ValueError as e:
        return {'type': 'string', 'value': f"[parse error: {e}]\n{raw}"}

    if not filter_def:
        if fmt == 'lines' and isinstance(parsed, list):
            return {'type': 'list', 'items': parsed}
        return {'type': 'string', 'value': str(parsed).strip()}

    out_type = filter_def.get('type', 'string')

    if out_type == 'string':
        tmpl = filter_def.get('value', '{output}')
        if isinstance(parsed, dict):
            try:
                value = tmpl.format_map({**parsed, 'output': raw.strip()})
            except KeyError:
                value = raw.strip()
        else:
            value = tmpl.format(output=str(parsed).strip())
        return {'type': 'string', 'value': value}

    elif out_type == 'list':
        items_expr = filter_def.get('items', '')
        if items_expr and isinstance(parsed, list):
            field = items_expr.lstrip('[].').strip()
            if field:
                items = [str(el.get(field, ''))
                         for el in parsed if isinstance(el, dict)]
            else:
                items = [str(el) for el in parsed]
        elif isinstance(parsed, list):
            items = [str(el) for el in parsed]
        else:
            items = [str(parsed)]
        return {'type': 'list', 'items': [i for i in items if i]}

    elif out_type == 'table':
        rows = []
        row_defs = filter_def.get('rows', [])
        for row in row_defs:
            if not isinstance(row, (list, tuple)) or len(row) != 2:
                continue
            label, expr = row
            if isinstance(parsed, dict):
                try:
                    value = str(expr).format_map(
                        {**parsed, 'output': raw.strip()})
                except KeyError:
                    value = '?'
            else:
                value = str(expr).format(output=str(parsed).strip())
            rows.append((str(label), value))
        return {'type': 'table', 'rows': rows}

    elif out_type == 'status':
        ok_pattern = filter_def.get('ok_if', '')
        if ok_pattern:
            ok = bool(re.search(ok_pattern, raw))
        else:
            ok = True
        msg_tmpl = filter_def.get('message', '{output}')
        if isinstance(parsed, dict):
            try:
                message = msg_tmpl.format_map(
                    {**parsed, 'output': raw.strip()})
            except KeyError:
                message = raw.strip()
        else:
            message = msg_tmpl.format(output=raw.strip())
        return {'type': 'status', 'ok': ok, 'message': message}

    return {'type': 'string', 'value': str(parsed).strip()}


def render_normalized(result: dict) -> str:
    """Render a normalized structure to a terminal-ready string (\\r\\n endings)."""
    t = result.get('type', 'string')

    if t == 'string':
        return result.get('value', '').rstrip() + '\r\n'

    elif t == 'list':
        items = result.get('items', [])
        if not items:
            return '(empty)\r\n'
        return ''.join(f"  {item}\r\n" for item in items)

    elif t == 'table':
        rows = result.get('rows', [])
        if not rows:
            return '(empty)\r\n'
        width = max(len(k) for k, _ in rows)
        return ''.join(f"  {k:<{width}}  {v}\r\n" for k, v in rows)

    elif t == 'status':
        prefix = '✓' if result.get('ok') else '✗'
        return f"{prefix} {result.get('message', '')}\r\n"

    return str(result) + '\r\n'
