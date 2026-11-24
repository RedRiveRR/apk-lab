"""Search and social metadata (WebAnalyzer ``SEO Analysis``; 13 upstream categories)."""
from __future__ import annotations

from typing import List

from ..models import Finding
from ..registry import module
from .common import parse_html


@module("seo_analysis", label="SEO and metadata",
        description="Title, description, canonical, Open Graph, headings, sitemap and structured data",
        group="recon", weight="medium", order=40, upstream="SEO Analysis")
def seo_analysis(ctx):
    response = ctx.page("/")
    if response.error or response.status >= 400:
        return {"available": False, "reason": response.error or f"HTTP {response.status}",
                "status": response.status}, []
    page = parse_html(response.text)
    robots = ctx.page("/robots.txt")
    sitemap = ctx.page("/sitemap.xml")
    canonical = next((link["href"] for link in page.links if "canonical" in link["rel"]), "")
    description = page.meta.get("description", "")
    og = {key: value for key, value in page.meta.items() if key.startswith("og:")}
    twitter = {key: value for key, value in page.meta.items() if key.startswith("twitter:")}
    missing_alt = sum(1 for image in page.images if not image["alt"].strip())
    headings = {level: sum(1 for tag, _ in page.headings if tag == level) for level in ("h1", "h2", "h3")}
    words = len(page.text.split())
    data = {
        "available": True,
        "title": page.title,
        "title_length": len(page.title),
        "description": description[:300],
        "description_length": len(description),
        "canonical": canonical,
        "lang": page.lang,
        "open_graph": sorted(og),
        "twitter_card": sorted(twitter),
        "robots_meta": page.meta.get("robots", ""),
        "headings": headings,
        "images": len(page.images),
        "images_missing_alt": missing_alt,
        "internal_links": sum(1 for link in page.anchors if link.startswith("/") or ctx.target in link),
        "external_links": sum(1 for link in page.anchors if link.startswith("http") and ctx.target not in link),
        "words": words,
        "structured_data_blocks": len(page.jsonld),
        "robots_txt": robots.status == 200 and not robots.error,
        "sitemap": sitemap.status == 200 and not sitemap.error,
    }
    findings: List[Finding] = []
    if not page.title:
        findings.append(Finding(module="seo_analysis", severity="medium",
                                title="The page has no title element",
                                detail="Search results and tabs show the URL instead of a name.",
                                remediation="Add a unique 30–60 character <title>."))
    elif not 30 <= len(page.title) <= 65:
        findings.append(Finding(module="seo_analysis", severity="low",
                                title="The page title is outside the usual length",
                                detail=f"{len(page.title)} characters: “{page.title}”",
                                remediation="Aim for 30–60 characters so the title is not truncated."))
    if not description:
        findings.append(Finding(module="seo_analysis", severity="low",
                                title="The page has no meta description",
                                detail="Search engines will invent a snippet from page text.",
                                remediation="Add a 50–160 character description that names the page."))
    elif not 50 <= len(description) <= 160:
        findings.append(Finding(module="seo_analysis", severity="low",
                                title="The meta description is outside the usual length",
                                detail=f"{len(description)} characters.",
                                remediation="Keep the description between 50 and 160 characters."))
    if not canonical:
        findings.append(Finding(module="seo_analysis", severity="info",
                                title="No canonical URL is declared",
                                detail="Duplicated entry points may compete in search results.",
                                remediation="Add <link rel=\"canonical\"> with the preferred absolute URL."))
    if not page.lang:
        findings.append(Finding(module="seo_analysis", severity="low",
                                title="The html element declares no language",
                                detail="Screen readers and translation tools rely on it.",
                                remediation="Add a lang attribute such as lang=\"en\" to <html>."))
    if headings["h1"] == 0:
        findings.append(Finding(module="seo_analysis", severity="low",
                                title="The page has no h1 heading",
                                detail="No top-level heading was found in the served HTML.",
                                remediation="Give the page one descriptive h1."))
    elif headings["h1"] > 1:
        findings.append(Finding(module="seo_analysis", severity="info",
                                title="The page has more than one h1",
                                detail=f"{headings['h1']} h1 elements.",
                                remediation="Keep one h1 per page and use h2 for sections."))
    if missing_alt:
        findings.append(Finding(module="seo_analysis", severity="low",
                                title="Images without alternative text",
                                detail=f"{missing_alt} of {len(page.images)} images have an empty alt attribute.",
                                remediation="Describe informative images; mark decorative ones with alt=\"\"."))
    if not data["sitemap"]:
        findings.append(Finding(module="seo_analysis", severity="info",
                                title="No sitemap was found at /sitemap.xml",
                                detail="Crawlers may miss pages that are not linked from the home page.",
                                remediation="Publish a sitemap and reference it from robots.txt."))
    return data, findings
