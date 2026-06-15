"""
cve.py — CVE Sorgulama modülü
  - NVD API v2.0  (primary)   : https://services.nvd.nist.gov/rest/json/cves/2.0
  - CVE.org API   (fallback)  : https://cveawg.mitre.org/api/cve/{id}
  - CVE-ID ile tekil sorgu
  - Ürün / keyword ile liste sorgusu
"""

import os
import re
import asyncio
import urllib.request
import urllib.parse
import urllib.error
import json
from typing import Any

# ── Sabitler ─────────────────────────────────────────────────────────────────
NVD_BASE   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVEORG_BASE = "https://cveawg.mitre.org/api/cve"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")          # opsiyonel, hız arttırır
REQUEST_TIMEOUT = 10                                 # saniye
CVE_ID_RE  = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}


class CVEError(Exception):
    pass


# ── HTTP yardımcısı (sync, executor içinde çalışır) ───────────────────────────
def _get(url: str, params: dict | None = None) -> dict:
    if params:
        url = url + "?" + urllib.parse.urlencode(params)
    headers = {"Accept": "application/json"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise CVEError(f"HTTP {exc.code}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise CVEError(f"Bağlantı hatası: {exc.reason}") from exc


async def _async_get(url: str, params: dict | None = None) -> dict:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: _get(url, params))


# ── NVD yanıtını normalize et ─────────────────────────────────────────────────
def _parse_nvd_item(raw: dict) -> dict:
    cve = raw.get("cve", {})

    # Açıklama (İngilizce tercihli)
    descs = cve.get("descriptions", [])
    description = next((d["value"] for d in descs if d.get("lang") == "en"), "Açıklama yok.")

    # CVSS (v3.1 → v3.0 → v2 sırasıyla dene)
    metrics  = cve.get("metrics", {})
    cvss_score    = None
    cvss_severity = "UNKNOWN"
    cvss_vector   = None
    cvss_version  = None

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            cvss_score    = data.get("baseScore")
            cvss_severity = data.get("baseSeverity", "UNKNOWN").upper()
            cvss_vector   = data.get("vectorString")
            cvss_version  = data.get("version")
            break

    # Referanslar
    refs = [
        {"url": r.get("url", ""), "source": r.get("source", "")}
        for r in cve.get("references", [])[:10]
    ]

    # Etkilenen ürünler (CPE'den basit liste)
    affected: list[str] = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    cpe = match.get("criteria", "")
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        vendor  = parts[3].replace("_", " ").title()
                        product = parts[4].replace("_", " ").title()
                        version = parts[5] if len(parts) > 5 and parts[5] not in ("*", "-", "") else ""
                        label   = f"{vendor} {product}" + (f" {version}" if version else "")
                        if label not in affected:
                            affected.append(label)
            if len(affected) >= 8:
                break

    return {
        "id":           cve.get("id", ""),
        "description":  description,
        "cvss_score":   cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector":  cvss_vector,
        "cvss_version": cvss_version,
        "published":    cve.get("published", ""),
        "modified":     cve.get("lastModified", ""),
        "references":   refs,
        "affected":     affected,
        "source":       "NVD",
    }


# ── CVE.org fallback ──────────────────────────────────────────────────────────
def _parse_cveorg_item(raw: dict) -> dict:
    meta  = raw.get("cveMetadata", {})
    adp   = raw.get("containers", {})
    cna   = adp.get("cna", {})

    descs = cna.get("descriptions", [])
    description = next((d["value"] for d in descs if d.get("lang", "").startswith("en")), "Açıklama yok.")

    metrics = cna.get("metrics", [])
    cvss_score = cvss_severity = cvss_vector = cvss_version = None
    for m in metrics:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if key in m:
                d = m[key]
                cvss_score    = d.get("baseScore")
                cvss_severity = d.get("baseSeverity", "UNKNOWN").upper()
                cvss_vector   = d.get("vectorString")
                cvss_version  = d.get("version")
                break
        if cvss_score:
            break

    refs = [{"url": r.get("url", ""), "source": "CVE.org"}
            for r in cna.get("references", [])[:10]]

    return {
        "id":            meta.get("cveId", ""),
        "description":   description,
        "cvss_score":    cvss_score,
        "cvss_severity": cvss_severity or "UNKNOWN",
        "cvss_vector":   cvss_vector,
        "cvss_version":  cvss_version,
        "published":     meta.get("datePublished", ""),
        "modified":      meta.get("dateUpdated", ""),
        "references":    refs,
        "affected":      [],
        "source":        "CVE.org",
    }


# ── Genel API ─────────────────────────────────────────────────────────────────

async def lookup_cve(cve_id: str) -> dict:
    """Tek CVE sorgula. NVD → CVE.org fallback."""
    cve_id = cve_id.strip().upper()
    if not CVE_ID_RE.match(cve_id):
        raise CVEError(f"Geçersiz CVE formatı: '{cve_id}'. Örn: CVE-2024-1234")

    # NVD dene
    try:
        data = await _async_get(NVD_BASE, {"cveId": cve_id})
        vulns = data.get("vulnerabilities", [])
        if vulns:
            return _parse_nvd_item(vulns[0])
    except CVEError:
        pass

    # CVE.org fallback
    try:
        data = await _async_get(f"{CVEORG_BASE}/{cve_id}")
        return _parse_cveorg_item(data)
    except CVEError as exc:
        raise CVEError(f"{cve_id} bulunamadı. ({exc})") from exc


async def search_cves(keyword: str, limit: int = 20) -> list[dict]:
    """Ürün / keyword ile NVD'de arama yap."""
    keyword = keyword.strip()
    if not keyword:
        raise CVEError("Arama terimi boş olamaz.")
    if len(keyword) < 2:
        raise CVEError("Arama terimi en az 2 karakter olmalı.")

    params: dict[str, Any] = {
        "keywordSearch": keyword,
        "resultsPerPage": min(limit, 50),
        "startIndex": 0,
    }
    try:
        data = await _async_get(NVD_BASE, params)
    except CVEError as exc:
        raise CVEError(f"NVD arama hatası: {exc}") from exc

    vulns = data.get("vulnerabilities", [])
    results = [_parse_nvd_item(v) for v in vulns]

    # CVSS skoru yüksekten düşüğe sırala
    results.sort(key=lambda x: (
        SEVERITY_ORDER.get(x["cvss_severity"], 5),
        -(x["cvss_score"] or 0),
    ))
    return results
