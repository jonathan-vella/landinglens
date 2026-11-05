"""Static tracker snapshots, with no formulas, external links or hidden raw data."""

import csv
import io
import re
from typing import Any
from xml.etree import ElementTree as ET
from zipfile import ZIP_DEFLATED, ZipFile

from .terraform import InputError

HEADERS = (
    "Control ID",
    "Display ID",
    "Design area",
    "Severity",
    "Recommendation",
    "Automation",
    "Target",
    "Mode",
    "Evidence tier",
    "Outcome",
    "Reason",
    "Freshness",
    "Exception disposition",
    "Review status",
    "Evidence references",
    "Comparison",
)


def safe_text(value: Any) -> str:
    text = "" if value is None else str(value)
    if len(text) > 32767 or re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", text):
        raise InputError(
            "Tracker cell contains invalid XML control characters or exceeds Excel's text bound"
        )
    if text.lstrip(" \t\r\n\ufeff").startswith(("=", "+", "-", "@")):
        text = "'" + text
    return text


def tracker_rows(model: dict[str, Any]) -> list[list[str]]:
    result = [list(HEADERS)]
    for row in model["results"]:
        for mode in ("planned", "observed"):
            body = row.get(mode)
            if body is None:
                continue
            if any(not isinstance(link, str) for link in body["evidence_links"]):
                raise InputError("Tracker evidence references must be explicit strings")
            result.append(
                [
                    safe_text(value)
                    for value in (
                        row["control_id"],
                        row["upstream_id"],
                        row["design_area"],
                        row.get("severity", "Unknown"),
                        row["recommendation"],
                        row.get("automation", "Unknown"),
                        row.get("arm_id") or row["logical_id"],
                        mode,
                        body.get("evidence_tier"),
                        body["outcome"],
                        body["reason"],
                        body["freshness"],
                        body.get("exception_disposition"),
                        "not-recorded"
                        if not body.get("reviews")
                        else (
                            "requires-review"
                            if any(review.get("requires_review") for review in body["reviews"])
                            else "recorded"
                        ),
                        "\n".join(body["evidence_links"]),
                        row.get("comparison"),
                    )
                ]
            )
    return result


def csv_tracker(model: dict[str, Any]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, quoting=csv.QUOTE_ALL, lineterminator="\n")
    writer.writerows(tracker_rows(model))
    return stream.getvalue()


def column(index: int) -> str:
    value = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        value = chr(65 + remainder) + value
    return value


def sheet(rows: list[list[str]], *, filter_rows: bool = False) -> bytes:
    namespace = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    root = ET.Element("worksheet", xmlns=namespace)
    views = ET.SubElement(root, "sheetViews")
    view = ET.SubElement(views, "sheetView", workbookViewId="0")
    ET.SubElement(
        view, "pane", ySplit="1", topLeftCell="A2", activePane="bottomLeft", state="frozen"
    )
    cols = ET.SubElement(root, "cols")
    ET.SubElement(cols, "col", min="1", max=str(len(rows[0])), width="24", customWidth="1")
    data = ET.SubElement(root, "sheetData")
    for number, values in enumerate(rows, 1):
        row = ET.SubElement(data, "row", r=str(number))
        for i, value in enumerate(values, 1):
            cell = ET.SubElement(
                row, "c", r=f"{column(i)}{number}", t="inlineStr", s="1" if number == 1 else "0"
            )
            text = ET.SubElement(ET.SubElement(cell, "is"), "t")
            text.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
            text.text = safe_text(value)
    if filter_rows:
        ET.SubElement(root, "autoFilter", ref=f"A1:{column(len(rows[0]))}{len(rows)}")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def xlsx_tracker(model: dict[str, Any]) -> bytes:
    rows = tracker_rows(model)
    notes = [
        ["LandingLens tracker", "Source"],
        ["Catalog", model["catalog_version"]],
        ["Evaluation time", model["generated_at"]],
        ["Content", "Static snapshot of the shared assessment model; one row per target/mode."],
        ["Outcomes", "Signals are not passes. Exceptions never rewrite technical results."],
        [
            "Safety",
            "All cells are text; leading formula-like text is prefixed. "
            "No formulas, macros or links.",
        ],
        [
            "Privacy",
            "Minimised trackers withhold resource identities and private evidence references.",
        ],
    ]
    content_types = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" '
        'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/styles.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '<Override PartName="/xl/worksheets/sheet2.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        "</Types>"
    )
    relationships = (
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/>'
        "</Relationships>"
    )
    workbook = (
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="Tracker" sheetId="1" r:id="rId1"/>'
        '<sheet name="Notes" sheetId="2" r:id="rId2"/></sheets></workbook>'
    )
    book_relationships = (
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        'Target="worksheets/sheet1.xml"/>'
        '<Relationship Id="rId2" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        'Target="worksheets/sheet2.xml"/>'
        '<Relationship Id="rId3" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
        "</Relationships>"
    )
    styles = (
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
        '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
        '<fills count="2"><fill><patternFill patternType="none"/></fill>'
        '<fill><patternFill patternType="gray125"/></fill></fills>'
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/>'
        "</cellStyleXfs>"
        '<cellXfs count="2"><xf numFmtId="49" fontId="0" fillId="0" borderId="0" '
        'xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>'
        '<xf numFmtId="49" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>'
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
        "</styleSheet>"
    )
    stream = io.BytesIO()
    with ZipFile(stream, "w", compression=ZIP_DEFLATED) as archive:
        for name, value in {
            "[Content_Types].xml": content_types.encode(),
            "_rels/.rels": relationships.encode(),
            "xl/workbook.xml": workbook.encode(),
            "xl/_rels/workbook.xml.rels": book_relationships.encode(),
            "xl/styles.xml": styles.encode(),
            "xl/worksheets/sheet1.xml": sheet(rows, filter_rows=True),
            "xl/worksheets/sheet2.xml": sheet(notes),
        }.items():
            archive.writestr(name, value)
    return stream.getvalue()
