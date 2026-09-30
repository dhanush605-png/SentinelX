from __future__ import annotations
import csv
import html
import json
from pathlib import Path


def _no_findings_message(sec: dict) -> str:
    if sec.get('not_applicable'):
        return sec['not_applicable']
    return f"No findings for {sec['title']} -- nothing to report."


def _write_json(report: dict, out: Path) -> None:
    (out / 'report.json').write_text(json.dumps(report, indent=2, default=str), encoding='utf8')


def _write_csv(report: dict, out: Path) -> None:
    csv_dir = out / 'csv'
    csv_dir.mkdir(parents=True, exist_ok=True)

    # One CSV per feature, so each is independently shareable/greppable.
    for sec in report['sections']:
        path = csv_dir / f"{sec['id']}.csv"
        with path.open('w', newline='', encoding='utf8') as f:
            w = csv.DictWriter(f, fieldnames=sec['columns'])
            w.writeheader()
            if sec['rows']:
                for row in sec['rows']:
                    w.writerow({col: row.get(col, '') for col in sec['columns']})
            else:
                w.writerow({col: '' for col in sec['columns']})
                f.write(f"# {_no_findings_message(sec)}\n")

    # A one-line-per-feature summary, useful for quickly seeing coverage.
    with (csv_dir / '_summary.csv').open('w', newline='', encoding='utf8') as f:
        w = csv.writer(f)
        w.writerow(['Feature', 'Findings', 'Status'])
        for sec in report['sections']:
            if sec.get('not_applicable'):
                status = 'Not applicable'
            elif sec['count'] == 0:
                status = 'No findings'
            else:
                status = 'Findings present'
            w.writerow([sec['title'], sec['count'], status])


def _render_table(sec: dict) -> str:
    if not sec['rows']:
        return f'<p class="empty">{html.escape(_no_findings_message(sec))}</p>'
    head = ''.join(f'<th>{html.escape(c)}</th>' for c in sec['columns'])
    body_rows = []
    for row in sec['rows']:
        cells = ''.join(f'<td>{html.escape(str(row.get(c, "")))}</td>' for c in sec['columns'])
        body_rows.append(f'<tr>{cells}</tr>')
    return f'<table><thead><tr>{head}</tr></thead><tbody>{"".join(body_rows)}</tbody></table>'


def _write_html(report: dict, out: Path) -> None:
    nav_items = []
    section_html = []
    for sec in report['sections']:
        badge_class = 'na' if sec.get('not_applicable') else ('empty' if sec['count'] == 0 else 'found')
        badge_text = 'N/A' if sec.get('not_applicable') else str(sec['count'])
        nav_items.append(
            f'<li><a href="#{sec["id"]}">{html.escape(sec["title"])}</a> '
            f'<span class="badge {badge_class}">{badge_text}</span></li>'
        )
        section_html.append(f'''
        <section id="{sec['id']}">
          <h2>{html.escape(sec['title'])} <span class="badge {badge_class}">{badge_text}</span></h2>
          <p class="desc">{html.escape(sec['description'])}</p>
          {_render_table(sec)}
        </section>''')

    body = f'''<!doctype html>
<html><head><meta charset="utf8"><title>SentinelX Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background: #f7f7f8; color: #1a1a1a; }}
  header {{ background: #1a1a2e; color: white; padding: 24px 32px; }}
  header h1 {{ margin: 0 0 4px 0; }}
  header p {{ margin: 0; color: #b8b8c8; }}
  .layout {{ display: flex; }}
  nav {{ width: 280px; flex-shrink: 0; padding: 24px; background: #fff; border-right: 1px solid #e2e2e2; height: 100vh; position: sticky; top: 0; overflow-y: auto; }}
  nav ul {{ list-style: none; padding: 0; margin: 0; }}
  nav li {{ display: flex; justify-content: space-between; align-items: center; padding: 6px 0; }}
  nav a {{ color: #1a1a2e; text-decoration: none; font-size: 14px; }}
  nav a:hover {{ text-decoration: underline; }}
  main {{ flex: 1; padding: 24px 32px; max-width: 1000px; }}
  section {{ background: #fff; border: 1px solid #e2e2e2; border-radius: 8px; padding: 20px 24px; margin-bottom: 24px; }}
  h2 {{ margin-top: 0; display: flex; align-items: center; gap: 10px; font-size: 18px; }}
  .desc {{ color: #666; font-size: 13px; margin-top: -8px; margin-bottom: 16px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 6px 10px; border-bottom: 1px solid #eee; vertical-align: top; }}
  th {{ background: #f0f0f3; }}
  .empty {{ color: #777; font-style: italic; font-size: 13px; }}
  .badge {{ font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 10px; }}
  .badge.found {{ background: #fbe2e2; color: #a10000; }}
  .badge.empty {{ background: #e6f4ea; color: #1e7a34; }}
  .badge.na {{ background: #eee; color: #666; }}
</style></head>
<body>
<header>
  <h1>SentinelX Report</h1>
  <p>Target: {html.escape(report['target'])} &middot; Pages crawled: {report['pages_crawled']}</p>
</header>
<div class="layout">
  <nav><ul>{''.join(nav_items)}</ul></nav>
  <main>{''.join(section_html)}</main>
</div>
</body></html>'''
    (out / 'report.html').write_text(body, encoding='utf8')


def write_reports(report: dict, out='reports', formats=('html', 'json', 'csv')) -> None:
    p = Path(out)
    p.mkdir(parents=True, exist_ok=True)
    if 'json' in formats:
        _write_json(report, p)
    if 'csv' in formats:
        _write_csv(report, p)
    if 'html' in formats:
        _write_html(report, p)
