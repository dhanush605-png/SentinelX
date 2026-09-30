import csv
import json

from reporting.writers import write_reports


def make_report(sections):
    return {'target': 'https://example.com', 'pages_crawled': 3, 'sections': sections}


def sec(id='crawl', title='Crawling -- Pages Found', rows=None, columns=None, not_applicable=None):
    return {
        'id': id,
        'title': title,
        'description': 'test section',
        'columns': columns or ['URL', 'Status'],
        'rows': rows or [],
        'count': len(rows or []),
        'not_applicable': not_applicable,
    }


SAMPLE_REPORT = make_report([
    sec(rows=[{'URL': 'https://example.com/', 'Status': 200}]),
    sec(id='broken_links', title='Broken Links', columns=['URL', 'Status', 'Error'], rows=[
        {'URL': 'https://example.com/missing', 'Status': 404, 'Error': None},
    ]),
    sec(id='cors', title='CORS Analysis', columns=['URL'], rows=[]),  # empty on purpose
    sec(id='passive_subdomains', title='Passive Subdomain Discovery', columns=['Subdomain'], rows=[],
        not_applicable="Not applicable: 'example.com' has no findings for this test."),
])


def test_writes_json_report_with_full_section_structure(tmp_path):
    out = tmp_path / 'reports'
    write_reports(SAMPLE_REPORT, out=str(out), formats=('json',))
    report = json.loads((out / 'report.json').read_text(encoding='utf8'))
    assert report['target'] == 'https://example.com'
    assert [s['id'] for s in report['sections']] == ['crawl', 'broken_links', 'cors', 'passive_subdomains']


def test_writes_one_csv_per_section_plus_summary(tmp_path):
    out = tmp_path / 'reports'
    write_reports(SAMPLE_REPORT, out=str(out), formats=('csv',))
    csv_dir = out / 'csv'
    assert (csv_dir / 'crawl.csv').exists()
    assert (csv_dir / 'broken_links.csv').exists()
    assert (csv_dir / 'cors.csv').exists()
    assert (csv_dir / 'passive_subdomains.csv').exists()
    assert (csv_dir / '_summary.csv').exists()


def test_csv_summary_lists_every_feature_with_a_status(tmp_path):
    out = tmp_path / 'reports'
    write_reports(SAMPLE_REPORT, out=str(out), formats=('csv',))
    with (out / 'csv' / '_summary.csv').open(encoding='utf8') as f:
        rows = list(csv.DictReader(f))
    statuses = {r['Feature']: r['Status'] for r in rows}
    assert statuses['Crawling -- Pages Found'] == 'Findings present'
    assert statuses['CORS Analysis'] == 'No findings'
    assert statuses['Passive Subdomain Discovery'] == 'Not applicable'


def test_csv_for_a_section_with_no_rows_still_has_a_header_and_a_note(tmp_path):
    out = tmp_path / 'reports'
    write_reports(SAMPLE_REPORT, out=str(out), formats=('csv',))
    text = (out / 'csv' / 'cors.csv').read_text(encoding='utf8')
    assert text.splitlines()[0] == 'URL'
    assert 'No findings for CORS Analysis' in text


def test_writes_html_report_with_a_section_per_feature(tmp_path):
    out = tmp_path / 'reports'
    write_reports(SAMPLE_REPORT, out=str(out), formats=('html',))
    body = (out / 'report.html').read_text(encoding='utf8')
    assert 'Broken Links' in body
    assert 'https://example.com/missing' in body
    # empty section shows an explicit no-findings message, not a blank table
    assert 'No findings for CORS Analysis' in body
    # not_applicable section shows its custom note, not the generic message
    # (html.escape turns the apostrophes into &#x27; -- check for the substring around them)
    assert 'Not applicable:' in body and 'has no findings for this test.' in body


def test_html_escapes_section_content():
    out_report = make_report([
        sec(rows=[{'URL': 'https://example.com/<script>alert(1)</script>', 'Status': 200}]),
    ])
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        write_reports(out_report, out=d, formats=('html',))
        body = (__import__('pathlib').Path(d) / 'report.html').read_text(encoding='utf8')
        assert '<script>alert(1)</script>' not in body
        assert '&lt;script&gt;' in body


def test_writes_all_formats_by_default(tmp_path):
    out = tmp_path / 'reports'
    write_reports(SAMPLE_REPORT, out=str(out))
    assert (out / 'report.json').exists()
    assert (out / 'report.html').exists()
    assert (out / 'csv' / 'crawl.csv').exists()


def test_creates_output_directory_if_missing(tmp_path):
    out = tmp_path / 'nested' / 'reports'
    write_reports(SAMPLE_REPORT, out=str(out), formats=('json',))
    assert out.exists()
