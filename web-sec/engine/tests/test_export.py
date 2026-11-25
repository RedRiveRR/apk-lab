"""PDF and DOCX exports: valid containers, the report's content, honest about lost glyphs."""
from __future__ import annotations

import io
import json
import re
import zipfile

from test_cli import _fake_scan_result, run
from websec import cli as websec_cli
from websec import report as report_module
from websec.export import outline, to_docx, to_pdf


def _document(**extra):
    document = report_module.build(_fake_scan_result(), cover={"client": "Acme", "title": "Quarterly review"})
    document.update(extra)
    return document


def test_docx_is_a_word_package_with_the_findings():
    data = to_docx(_document())
    with zipfile.ZipFile(io.BytesIO(data)) as package:
        names = set(package.namelist())
        assert {"[Content_Types].xml", "_rels/.rels", "word/document.xml", "word/styles.xml"} <= names
        body = package.read("word/document.xml").decode("utf-8")
    assert "Quarterly review" in body and "Prepared for Acme" in body
    assert "Content-Security-Policy is missing" in body and "CWE-693" in body
    assert 'w:val="Heading1"' in body


def test_docx_escapes_markup_and_drops_control_characters():
    document = _document()
    document["findings"][0]["detail"] = "<script>&\x07"
    body = zipfile.ZipFile(io.BytesIO(to_docx(document))).read("word/document.xml").decode()
    assert "&lt;script&gt;&amp;" in body and "\x07" not in body


def test_pdf_is_well_formed_and_paginates():
    document = _document()
    document["findings"] = document["findings"] * 80  # force several pages
    data = to_pdf(document)
    assert data.startswith(b"%PDF-1.4") and data.rstrip().endswith(b"%%EOF")
    pages = int(re.search(rb"/Count (\d+)", data).group(1))
    assert pages > 1
    xref = int(re.search(rb"startxref\n(\d+)", data).group(1))
    assert data[xref:xref + 4] == b"xref"
    # every object offset in the table points at "<n> 0 obj"
    table = data[xref:].split(b"\n")[3:]
    for number, row in enumerate(table, 1):
        if not row.endswith(b" n "):
            break
        offset = int(row[:10])
        assert data[offset:].startswith(b"%d 0 obj" % number)
    assert b"Content-Security-Policy is missing" in data


def test_pdf_marks_characters_it_cannot_draw():
    document = _document()
    document["findings"][0]["title"] = "Başlık — 标题"
    data = to_pdf(document)
    assert b"Ba\xfelik - ??" in data or b"Ba?l" in data
    assert b"the HTML export keeps them" in data


def test_outline_follows_the_markdown_order():
    styles = [style for style, _ in outline(_document())]
    assert styles[0] == "title" and styles.index("h1") < styles.index("h2")


def test_report_cli_writes_pdf_and_docx(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBSEC_STORAGE", str(tmp_path / "storage"))
    monkeypatch.setattr(websec_cli, "run_scan", lambda options, progress=None: _fake_scan_result())
    run(["scan", "example.test", "--json"])
    from websec.history import History
    name = History().list("example.test")[0]["name"]
    for fmt, magic in (("pdf", b"%PDF"), ("docx", b"PK")):
        out = tmp_path / f"report.{fmt}"
        code, _, err = run(["report", "--target", "example.test", "--name", name, "--format", fmt, "--out", str(out)])
        assert code == 0, err
        assert out.read_bytes().startswith(magic)
    code, _, err = run(["report", "--target", "example.test", "--name", name, "--format", "pdf"])
    assert code == 2 and "--out" in err  # the test stdout has no binary buffer
    out = tmp_path / "scan.pdf"
    code, _, _ = run(["scan", "example.test", "--no-history", "--format", "pdf", "--out", str(out)])
    assert code == 0 and out.read_bytes().startswith(b"%PDF")
