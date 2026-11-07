import unittest
from html.parser import HTMLParser

from test_contracts import evidence

from alz_assessor.catalog import load_catalog
from alz_assessor.engine import assess
from alz_assessor.html_report import FILTER_SCRIPT, THEME_SCRIPT
from alz_assessor.reports import render, report_model


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.ids = []
        self.links = []
        self.findings = 0
        self.scripts = []
        self.in_script = False

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        self.tags.append((tag, values))
        if values.get("id"):
            self.ids.append(values["id"])
        if tag == "a":
            self.links.append(values.get("href", ""))
        if tag == "article" and values.get("class") == "finding":
            self.findings += 1
        if tag == "script":
            self.in_script = True
            self.scripts.append("")

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False

    def handle_data(self, data):
        if self.in_script:
            self.scripts[-1] += data


class HtmlReportTests(unittest.TestCase):
    def setUp(self):
        self.report = assess(evidence(), load_catalog(), at="2026-11-04T00:00:00Z")

    def test_all_dispositions_areas_metrics_and_links_are_static_and_accessible(self):
        page = Page()
        text = render(self.report, "html")
        page.feed(text)
        model = report_model(self.report)
        self.assertEqual(page.findings, len(model["results"]))
        self.assertEqual(page.scripts, [THEME_SCRIPT, FILTER_SCRIPT])
        self.assertEqual(len(page.ids), len(set(page.ids)))
        for href in page.links:
            if href.startswith("#"):
                self.assertIn(href[1:], page.ids)
            else:
                self.assertTrue(href.startswith("https://"))
        for tag, attrs in page.tags:
            if tag in {"script", "link", "img", "iframe", "form"}:
                self.assertNotIn("src", attrs)
                self.assertNotIn("href", attrs)
        for row in model["results"]:
            self.assertIn(row["control_id"], text)
            self.assertIn(row["design_area"], text)
        for label in (
            "Active controls",
            "Automated controls",
            "Resource instances",
            "Result instances",
            "completion",
            "subset_pass_rate",
            "Human review",
            "Provenance",
            "Freshness",
            "@media print",
            "beforeprint",
            "afterprint",
            "details open",
            'aria-live="polite"',
        ):
            self.assertIn(label, text)
        for forbidden in ("fetch(", "XMLHttpRequest", "eval(", "innerHTML", "https://cdn"):
            self.assertNotIn(forbidden, text)

    def test_malicious_strings_are_text_not_markup_or_executable_links(self):
        attack = '</script><img src=x onerror="alert(1)"><script>alert(2)</script>'
        self.report["results"][0]["recommendation"] = attack
        self.report["results"][0]["references"] = [
            {"guidance": "javascript:alert(1)", "source_url": attack},
            {"guidance": "//evil.example/script.js"},
        ]
        text = render(self.report, "html")
        page = Page()
        page.feed(text)
        self.assertEqual(page.scripts, [THEME_SCRIPT, FILTER_SCRIPT])
        self.assertNotIn(attack, text)
        self.assertNotIn("<img", text)
        self.assertNotIn("<script>", text)
        self.assertFalse(any(h.startswith(("javascript:", "//")) for h in page.links))
        self.assertIn("&lt;script&gt;", text)
        minimized = render(self.report, "html", minimize=True)
        self.assertIn("Minimized presentation only", minimized)
        self.assertNotIn("/resourcegroups/test", minimized.lower())

    def test_smart_collapse_heatmap_buttons_and_semantic_findings(self):
        self.report["results"][0]["planned"]["outcome"] = "fail"
        self.report["results"][1]["planned"]["outcome"] = "pass"
        text = render(self.report, "html")
        page = Page()
        page.feed(text)
        self.assertNotIn("border-left: 4px solid", text)
        self.assertIn(
            "<details open><summary>Shared coverage model and denominators</summary>", text
        )
        fail_id = self.report["results"][0]["upstream_id"]
        pass_id = self.report["results"][1]["upstream_id"]
        self.assertIn(f"<details open><summary>{fail_id}:", text)
        self.assertIn(f"<details><summary>{pass_id}:", text)
        heatmap_btns = [
            attrs
            for tag, attrs in page.tags
            if tag == "button" and "heatmap-btn" in attrs.get("class", "").split()
        ]
        self.assertTrue(heatmap_btns)
        self.assertTrue(
            all("data-filter-area" in b and "data-filter-status" in b for b in heatmap_btns)
        )
        self.assertTrue(any("zero" in b.get("class", "").split() for b in heatmap_btns))
        self.assertIn("No recorded human reviews.", text)
