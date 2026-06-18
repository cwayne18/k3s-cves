#!/usr/bin/env python3
"""Convert scan-*.md Trivy reports to styled HTML themed after k3s.io."""

import sys
import os
import re
import json
import math
import sqlite3
import html as html_lib
import urllib.request
import urllib.error
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# k3s.io colour palette
# Brand gold #FFC61C on a deep navy, with a teal-blue link accent — pulled from
# the k3s.io site theme (Docusaurus --ifm-color-primary variants).
# ---------------------------------------------------------------------------
CSS = """
@import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&family=Lato:ital,wght@0,400;0,700;1,400&family=Roboto+Mono:wght@400;500&display=swap');

:root {
  --body-bg:          #FFFFFF;
  --body-text:        #1B1F2A;
  --muted:            #5C6470;
  --border:           #E0E3E8;
  --box-bg:           #F6F7F9;
  --header-bg:        #1B1F2A;
  --header-border:    #FFC61C;
  --link:             #06527A;
  --code-bg:          #F6F7F9;
  --table-header-bg:  #F6F7F9;
  --table-hover-bg:   #FFF8E6;

  /* k3s brand */
  --brand-gold:        #FFC61C;
  --brand-gold-dark:   #FFBA00;
  --brand-navy:        #1B1F2A;

  /* Severity */
  --sev-critical-bg:     #B13333;
  --sev-critical-text:   #FFFFFF;
  --sev-critical-border: #7C0015;
  --sev-high-bg:         #E45C1E;
  --sev-high-text:       #FFFFFF;
  --sev-high-border:     #B03A0A;
  --sev-medium-bg:       #FFE47A;
  --sev-medium-text:     #473900;
  --sev-medium-border:   #E5A200;
  --sev-low-bg:          #E6F2F8;
  --sev-low-text:        #06527A;
  --sev-low-border:      #086B9F;
  --sev-unknown-bg:      #EDEFF3;
  --sev-unknown-text:    #5C6470;
  --sev-unknown-border:  #E0E3E8;

  /* Status badges */
  --status-needs-bg:     #E45C1E;
  --status-needs-text:   #FFFFFF;
  --status-needs-border: #B03A0A;
  --status-ok-bg:        #27AE60;
  --status-ok-text:      #FFFFFF;
  --status-ok-border:    #1A7A41;
}

*, *::before, *::after { box-sizing: border-box; }

html, body {
  margin: 0; padding: 0;
  background: var(--body-bg);
  color: var(--body-text);
  font-family: 'Lato', arial, helvetica, sans-serif;
  font-size: 14px;
  line-height: 1.6;
}

/* ---- Header ---- */
.page-header {
  background: var(--header-bg);
  border-bottom: 3px solid var(--header-border);
  padding: 0 32px;
  height: 55px;
  display: flex;
  align-items: center;
  gap: 12px;
  position: sticky;
  top: 0;
  z-index: 100;
  box-shadow: 0 1px 4px rgba(0,0,0,.18);
}
.page-header .brand {
  font-family: 'Poppins', sans-serif;
  font-weight: 600;
  font-size: 17px;
  color: #FFFFFF;
  display: flex;
  align-items: center;
  gap: 10px;
}
.page-header .brand svg { width: 28px; height: 28px; flex-shrink: 0; }
.page-header .subtitle {
  font-size: 13px;
  color: var(--brand-gold);
  margin-left: 4px;
}

/* ---- Layout ---- */
.page-content {
  max-width: 1280px;
  margin: 0 auto;
  padding: 32px 24px 64px;
}

/* ---- Headings ---- */
h1, h2, h3, h4 {
  font-family: 'Poppins', sans-serif;
  color: var(--body-text);
  margin-top: 0;
}
h1 {
  font-size: 24px; font-weight: 600;
  margin-bottom: 24px;
  padding-bottom: 12px;
  border-bottom: 2px solid var(--border);
}
h2 {
  font-size: 17px; font-weight: 600;
  margin-top: 36px; margin-bottom: 10px;
}
.anchored-heading {
  display: flex;
  align-items: center;
  gap: 8px;
}
.heading-anchor {
  color: var(--muted);
  text-decoration: none;
  font-size: 12px;
  opacity: 0;
  transition: opacity .15s ease;
}
.anchored-heading:hover .heading-anchor,
.anchored-heading:focus-within .heading-anchor {
  opacity: 1;
}
.heading-anchor:hover {
  color: var(--link);
}
h2 code {
  font-family: 'Roboto Mono', monospace;
  font-size: 13px;
  background: var(--code-bg);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 2px 7px;
  font-weight: 400;
}
h3 {
  font-size: 15px; font-weight: 600;
  margin-top: 24px; margin-bottom: 8px;
}

/* ---- Images list ---- */
ul.images-list {
  list-style: none;
  padding: 0; margin: 0 0 24px;
  display: flex; flex-wrap: wrap; gap: 6px;
}
ul.images-list li code {
  font-family: 'Roboto Mono', monospace;
  font-size: 12px;
  background: var(--code-bg);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 3px 8px;
  display: inline-block;
}

/* Generic list */
ul.generic-list { margin: 8px 0 16px; padding-left: 20px; }
ul.generic-list li { margin-bottom: 3px; }
ul.generic-list li code {
  font-family: 'Roboto Mono', monospace;
  font-size: 12px;
  background: var(--code-bg);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 1px 5px;
}

/* ---- Scan result card ---- */
.scan-card {
  border: 1px solid var(--border);
  border-radius: 6px;
  overflow: hidden;
  margin-bottom: 8px;
}

/* ---- Tables ---- */
.report-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
  background: var(--body-bg);
}
.report-table thead tr { background: var(--table-header-bg); }
.report-table th {
  padding: 10px 14px;
  text-align: left;
  font-family: 'Poppins', sans-serif;
  font-weight: 600;
  font-size: 11px;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: .05em;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
}
.report-table td {
  padding: 10px 14px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
  word-break: break-word;
}
.report-table tbody tr:last-child td { border-bottom: none; }
.report-table tbody tr:hover { background: var(--table-hover-bg); }
.report-table a {
  color: var(--link);
  text-decoration: none;
}
.report-table a:hover { text-decoration: underline; }
.report-table a.image-scan-link { display: inline-block; }
.report-table a.image-scan-link code {
  color: var(--link);
  cursor: pointer;
  transition: border-color .15s, background .15s;
}
.report-table a.image-scan-link:hover code {
  border-color: var(--link);
  text-decoration: underline;
}
.report-table .num { text-align: center; font-variant-numeric: tabular-nums; }
.table-wrap { margin: 8px 0 14px; }
.table-collapsible {
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--body-bg);
  overflow: hidden;
}
.table-collapsible summary {
  cursor: pointer;
  list-style: none;
  font-family: 'Poppins', sans-serif;
  font-size: 12px;
  font-weight: 600;
  color: var(--muted);
  background: var(--table-header-bg);
  border-bottom: 1px solid var(--border);
  padding: 10px 14px;
}
.table-collapsible summary::-webkit-details-marker { display: none; }
.table-collapsible .toggle-label::before {
  content: "▾";
  display: inline-block;
  margin-right: 8px;
  transition: transform .15s ease;
}
.table-collapsible:not([open]) .toggle-label::before {
  transform: rotate(-90deg);
}

/* scan target box used as the collapsible header */
.scan-collapsible summary.scan-summary {
  display: flex;
  align-items: flex-start;
  gap: 6px;
  padding: 0;
  background: var(--box-bg);
  border-bottom: none;
}
.scan-collapsible[open] summary.scan-summary {
  border-bottom: 1px solid var(--border);
}
.scan-collapsible summary.scan-summary .toggle-label {
  padding: 14px 0 0 14px;
  color: var(--muted);
}
.scan-collapsible summary.scan-summary .toggle-label::before {
  margin-right: 0;
}
.scan-collapsible summary.scan-summary pre.raw-output {
  flex: 1;
  padding-left: 6px;
}

/* vuln count colouring */
.vuln-count { font-weight: 700; }
.vuln-count.has-vulns { color: #B13333; }

/* ---- Severity badges ---- */
.sev {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .04em;
  white-space: nowrap;
  border-width: 1px;
  border-style: solid;
}
.sev-CRITICAL { background: var(--sev-critical-bg); color: var(--sev-critical-text); border-color: var(--sev-critical-border); }
.sev-HIGH     { background: var(--sev-high-bg);     color: var(--sev-high-text);     border-color: var(--sev-high-border);     }
.sev-MEDIUM   { background: var(--sev-medium-bg);   color: var(--sev-medium-text);   border-color: var(--sev-medium-border);   }
.sev-LOW      { background: var(--sev-low-bg);      color: var(--sev-low-text);      border-color: var(--sev-low-border);      }
.sev-UNKNOWN  { background: var(--sev-unknown-bg);  color: var(--sev-unknown-text);  border-color: var(--sev-unknown-border);  }

/* ---- Status badges (check-images) ---- */
.status {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .04em;
  white-space: nowrap;
  border-width: 1px;
  border-style: solid;
}
.status-NEEDS_UPDATE { background: var(--status-needs-bg); color: var(--status-needs-text); border-color: var(--status-needs-border); }
.status-UP_TO_DATE   { background: var(--status-ok-bg);    color: var(--status-ok-text);    border-color: var(--status-ok-border);    }
.status-UNKNOWN      { background: var(--sev-unknown-bg);  color: var(--sev-unknown-text);  border-color: var(--sev-unknown-border);  }

/* ---- All-clean banner ---- */
.all-clean-banner {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 14px 18px;
  background: #EAF7EF;
  border: 1px solid var(--status-ok-border);
  border-radius: 6px;
  color: #1A7A41;
  font-weight: 600;
  font-size: 13px;
  margin-bottom: 8px;
}
.all-clean-banner .all-clean-icon {
  font-size: 18px;
  line-height: 1;
}

/* ---- Optional (non-default) add-on images section ---- */
.optional-section {
  margin-top: 36px;
  border: 1px solid var(--border);
  border-left: 4px solid #B8860B;
  border-radius: 8px;
  background: #FBF8EF;
  padding: 18px 20px 8px;
}
/* The toggle checkbox is visually hidden; the styled label/switch drives it. */
.optional-toggle-input {
  position: absolute;
  width: 1px;
  height: 1px;
  opacity: 0;
  pointer-events: none;
}
.optional-banner {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-bottom: 8px;
}
.optional-toggle-label {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  cursor: pointer;
  font-weight: 600;
  font-size: 14px;
  color: #7A5C00;
  user-select: none;
  width: fit-content;
}
.optional-switch {
  position: relative;
  flex: 0 0 auto;
  width: 40px;
  height: 22px;
  border-radius: 999px;
  background: #C9CBD6;
  transition: background .15s ease;
}
.optional-switch::after {
  content: "";
  position: absolute;
  top: 2px;
  left: 2px;
  width: 18px;
  height: 18px;
  border-radius: 50%;
  background: #FFFFFF;
  box-shadow: 0 1px 2px rgba(0,0,0,.25);
  transition: transform .15s ease;
}
.optional-toggle-input:checked ~ .optional-banner .optional-switch {
  background: #1A7A41;
}
.optional-toggle-input:checked ~ .optional-banner .optional-switch::after {
  transform: translateX(18px);
}
.optional-toggle-input:focus-visible ~ .optional-banner .optional-switch {
  outline: 2px solid var(--link);
  outline-offset: 2px;
}
.optional-note {
  margin: 0;
  color: var(--muted);
  font-size: 13px;
  line-height: 1.5;
}
.optional-body {
  border-top: 1px dashed var(--border);
  padding-top: 4px;
}
.optional-toggle-input:not(:checked) ~ .optional-body {
  display: none;
}

/* ---- Blockquote / callout ---- */
blockquote.callout {
  margin: 0 0 16px;
  padding: 10px 14px;
  border-left: 3px solid var(--link);
  background: var(--box-bg);
  border-radius: 0 6px 6px 0;
  color: var(--muted);
  font-size: 13px;
  line-height: 1.5;
}

/* ---- Pre / fallback ---- */
pre.raw-output {
  background: var(--box-bg);
  margin: 0;
  padding: 14px 16px;
  font-family: 'Roboto Mono', monospace;
  font-size: 12px;
  color: var(--muted);
  white-space: pre-wrap;
  word-break: break-all;
  overflow-x: auto;
}

/* ---- Code inline ---- */
code {
  font-family: 'Roboto Mono', monospace;
  font-size: 12px;
  background: var(--code-bg);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 1px 5px;
}

/* ---- Footer ---- */
.page-footer {
  margin-top: 48px;
  padding-top: 16px;
  border-top: 1px solid var(--border);
  text-align: center;
  color: var(--muted);
  font-size: 12px;
}
.page-footer code {
  font-family: 'Roboto Mono', monospace;
  font-size: 11px;
}

/* ---- Legend ---- */
.legend {
  font-size: 12px;
  color: var(--muted);
  padding: 8px 14px;
  background: var(--box-bg);
  border-top: 1px solid var(--border);
}

/* ---- Suggested actions ---- */
.suggested-actions {
  border: 1px solid var(--border);
  border-radius: 8px;
  background: #F8FAFF;
  padding: 18px 20px 8px;
  margin-bottom: 22px;
}
.suggested-actions h2 {
  margin: 0 0 10px;
}
.suggested-actions ul {
  margin: 0;
  padding-left: 20px;
}
.suggested-actions li {
  margin-bottom: 8px;
}

/* ---- VEX candidates ---- */
.vex-candidates {
  border: 1px solid var(--border);
  border-radius: 8px;
  background: #F5FFF8;
  padding: 18px 20px 12px;
  margin-bottom: 22px;
}
.vex-candidates h2 {
  margin: 0 0 4px;
}
.vex-candidates .vex-intro {
  color: var(--muted);
  font-size: 13px;
  margin-bottom: 12px;
}
.vex-candidates .vex-intro a {
  color: var(--link);
}
.vex-candidates table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
.vex-candidates th {
  background: var(--table-header-bg);
  text-align: left;
  padding: 6px 10px;
  border: 1px solid var(--border);
  font-family: 'Poppins', sans-serif;
  font-size: 12px;
}
.vex-candidates td {
  padding: 6px 10px;
  border: 1px solid var(--border);
  vertical-align: top;
}
.vex-candidates tr:nth-child(even) td {
  background: var(--box-bg);
}
.vex-status {
  display: inline-block;
  padding: 2px 7px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  background: #D4EDDA;
  color: #155724;
  border: 1px solid #C3E6CB;
}

/* ---- CVE trend line chart ---- */
.cve-trend {
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--body-bg);
  padding: 18px 20px 14px;
  margin: 8px 0 22px;
}
.cve-trend h3 {
  margin: 0 0 4px;
}
.cve-trend .chart-subtitle {
  margin: 0 0 12px;
  font-size: 12px;
  color: var(--muted);
}
.cve-trend-figure {
  position: relative;
}
.cve-trend-svg {
  width: 100%;
  height: auto;
  display: block;
  overflow: visible;
  font-family: 'Lato', sans-serif;
}
.cve-trend-svg .grid-line {
  stroke: var(--border);
  stroke-width: 1;
}
.cve-trend-svg .axis-line {
  stroke: var(--border);
  stroke-width: 1;
}
.cve-trend-svg .axis-label {
  fill: var(--muted);
  font-size: 10px;
}
.cve-trend-svg .series-line {
  fill: none;
  stroke-width: 2;
  stroke-linecap: round;
  stroke-linejoin: round;
}
.cve-trend-svg .series-point {
  cursor: pointer;
  transition: r .1s ease;
}
.cve-trend-svg .series-point:hover {
  r: 6;
}
.cve-trend-svg .series-hidden {
  display: none;
}
.cve-trend-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 16px;
  margin-top: 12px;
}
.cve-trend-legend .legend-item {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--body-text);
  cursor: pointer;
  user-select: none;
  padding: 2px 4px;
  border-radius: 4px;
}
.cve-trend-legend .legend-item.legend-off {
  color: var(--muted);
  opacity: .55;
}
.cve-trend-legend .legend-swatch {
  width: 14px;
  height: 3px;
  border-radius: 2px;
  display: inline-block;
}
.cve-trend-tooltip {
  position: absolute;
  pointer-events: none;
  background: var(--body-text);
  color: #FFFFFF;
  font-size: 11px;
  line-height: 1.5;
  padding: 6px 9px;
  border-radius: 6px;
  white-space: nowrap;
  transform: translate(-50%, -115%);
  opacity: 0;
  transition: opacity .1s ease;
  z-index: 5;
  box-shadow: 0 2px 8px rgba(0,0,0,.18);
}
.cve-trend-tooltip.visible {
  opacity: 1;
}
.cve-trend-tooltip .tt-date {
  font-weight: 700;
  margin-bottom: 2px;
}
.cve-trend-empty {
  color: var(--muted);
  font-size: 13px;
  padding: 12px 0;
}
"""

# Dark-mode overrides + theme-toggle button styling. Kept as a separate
# constant so it can also be injected into pre-rendered sample reports.
_DARK_CSS = """
/* ---- Dark mode ---- */
:root[data-theme="dark"] {
  --body-bg:          #16171C;
  --body-text:        #E6E6EC;
  --muted:            #9B9BA6;
  --border:           #2D2F39;
  --box-bg:           #1E1F26;
  --header-bg:        #1A1B21;
  --header-border:    #2D2F39;
  --link:             #5B9BFF;
  --code-bg:          #22232B;
  --table-header-bg:  #22232B;
  --table-hover-bg:   #24262F;

  /* Severity */
  --sev-low-bg:          #1E2A40;
  --sev-low-text:        #8FB6FF;
  --sev-low-border:      #2673A6;
  --sev-unknown-bg:      #2A2C35;
  --sev-unknown-text:    #9B9BA6;
  --sev-unknown-border:  #3A3C46;
}

:root[data-theme="dark"] .page-header {
  box-shadow: 0 1px 4px rgba(0,0,0,.4);
}
:root[data-theme="dark"] .cve-trend-tooltip {
  background: #000000;
  color: #E6E6EC;
  box-shadow: 0 2px 8px rgba(0,0,0,.5);
}

/* Themed banner boxes that use hard-coded light fills */
:root[data-theme="dark"] .all-clean-banner {
  background: #15291E;
  color: #5FCF8C;
}
:root[data-theme="dark"] .optional-section {
  background: #241F14;
}
:root[data-theme="dark"] .optional-toggle-label {
  color: #E0B84D;
}
:root[data-theme="dark"] .optional-switch {
  background: #3A3C46;
}
:root[data-theme="dark"] .suggested-actions {
  background: #161B26;
}
:root[data-theme="dark"] .vex-candidates {
  background: #14241B;
}
:root[data-theme="dark"] .vex-status {
  background: #1B3A28;
  color: #7FD8A0;
  border-color: #2E5C40;
}

/* ---- Theme toggle ---- */
.theme-toggle {
  margin-left: auto;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 34px;
  height: 34px;
  padding: 0;
  font-size: 16px;
  line-height: 1;
  cursor: pointer;
  background: var(--box-bg);
  color: var(--body-text);
  border: 1px solid var(--border);
  border-radius: 8px;
  transition: background .15s ease, border-color .15s ease;
}
.theme-toggle:hover {
  border-color: var(--link);
}
.theme-toggle .theme-icon-dark { display: none; }
:root[data-theme="dark"] .theme-toggle .theme-icon-light { display: none; }
:root[data-theme="dark"] .theme-toggle .theme-icon-dark { display: inline; }
"""

CSS += _DARK_CSS

# Applies the persisted (or system-preferred) theme before first paint to
# avoid a flash of the wrong theme. Placed in <head>.
_THEME_HEAD_SCRIPT = """<script>
(function () {
  try {
    var stored = localStorage.getItem('theme');
    var prefersDark = window.matchMedia &&
      window.matchMedia('(prefers-color-scheme: dark)').matches;
    if (stored === 'dark' || (!stored && prefersDark)) {
      document.documentElement.setAttribute('data-theme', 'dark');
    }
  } catch (e) {}
})();
</script>"""

# Dark-mode toggle button rendered in the page header.
_THEME_TOGGLE_HTML = (
    '<button type="button" class="theme-toggle" aria-label="Toggle dark mode" '
    'title="Toggle dark mode" '
    'onclick="(function(){var d=document.documentElement;'
    "var dark=d.getAttribute('data-theme')==='dark';"
    "if(dark){d.removeAttribute('data-theme');}"
    "else{d.setAttribute('data-theme','dark');}"
    "try{localStorage.setItem('theme',dark?'light':'dark');}catch(e){}"
    '})()">'
    '<span class="theme-icon-light" aria-hidden="true">&#127769;</span>'
    '<span class="theme-icon-dark" aria-hidden="true">&#9728;</span>'
    '</button>'
)

# ---------------------------------------------------------------------------
# ASCII table parser
# ---------------------------------------------------------------------------

def _split_row(line):
    """Split a │-delimited table row into stripped cell strings."""
    parts = line.split("│")
    # parts[0] is before first │, parts[-1] is after last │
    return [p.strip() for p in parts[1:-1]]


def _is_full_separator(line):
    """True for lines like ├────┼────┤ or └────┴────┘ or ┌────┬────┐."""
    s = line.strip()
    return s and s[0] in ("├", "└", "┌") and all(
        c in "├─┤└┘┌┐┼┴┬" for c in s
    )


def _is_partial_separator(line):
    """True for lines like │   ├────┤   │ — an intra-row CVE separator."""
    return line.startswith("│") and ("├" in line or "┤" in line)


def parse_ascii_table(lines):
    """
    Parse a Trivy ASCII box-drawing table.

    Returns (headers: list[str], rows: list[dict[str,str]]) or (None, None).
    Multi-line cells are joined with a newline.  Rows sharing a library
    (inner ├──┤ separators) inherit empty columns from the previous row.
    """
    headers = None
    rows = []
    current = None          # dict of {header: value}
    prev_complete = None    # last fully-saved row (for inheritance)

    def save_current():
        nonlocal current, prev_complete
        if current is not None:
            rows.append(current)
            prev_complete = current
            current = None

    for line in lines:
        if not line:
            continue

        if _is_full_separator(line):
            # ┌ top border — nothing saved yet; ├ header/row sep; └ end
            if line.strip()[0] == "└":
                save_current()
            elif headers is not None:
                save_current()
            continue

        if not line.startswith("│"):
            # Non-table text (e.g. legend lines)
            save_current()
            continue

        if _is_partial_separator(line):
            # Inner CVE separator: save current row, next row inherits
            save_current()
            continue

        cells = _split_row(line)
        if not cells:
            continue

        if headers is None:
            headers = cells
            continue

        # Pad or trim to match header count
        while len(cells) < len(headers):
            cells.append("")
        cells = cells[: len(headers)]

        if current is None:
            # Start a new row; inherit empty cells from previous row
            current = {}
            for h, c in zip(headers, cells):
                if c:
                    current[h] = c
                elif prev_complete and h in prev_complete:
                    current[h] = prev_complete[h]
                else:
                    current[h] = ""
        else:
            # Continuation line: append non-empty cells
            for h, c in zip(headers, cells):
                if c:
                    sep = "\n" if current.get(h) else ""
                    current[h] = current.get(h, "") + sep + c

    save_current()
    return headers, rows if headers else (None, None)


# ---------------------------------------------------------------------------
# Markdown pipe-table parser  (used for check-*.md reports)
# ---------------------------------------------------------------------------

def parse_md_table(lines):
    """
    Parse a standard GitHub-flavoured markdown pipe table.

    *lines* is a list of raw strings (or a single string that will be split).
    Returns (headers: list[str], rows: list[dict]) or (None, None).
    Separator rows (|---|---|) are skipped.
    """
    if isinstance(lines, str):
        lines = lines.split("\n")

    table_lines = [l for l in lines if l.strip().startswith("|")]
    if not table_lines:
        return None, None

    def split_row(line):
        parts = line.strip().split("|")
        # strip leading/trailing empty strings from outer pipes
        if parts and parts[0].strip() == "":
            parts = parts[1:]
        if parts and parts[-1].strip() == "":
            parts = parts[:-1]
        return [p.strip() for p in parts]

    import re as _re

    headers = None
    rows = []
    for line in table_lines:
        cells = split_row(line)
        if headers is None:
            headers = cells
            continue
        # Skip separator row (cells like ---, :--:, etc.)
        if all(_re.match(r"^:?-+:?$", c) for c in cells if c):
            continue
        while len(cells) < len(headers):
            cells.append("")
        rows.append(dict(zip(headers, cells[: len(headers)])))

    if not headers or not rows:
        return None, None
    return headers, rows

def esc(text):
    return html_lib.escape(str(text))


def render_inline(text):
    """Escape text and convert inline markdown spans to HTML."""
    escaped = esc(text)
    # Bold: **text** → <strong>text</strong>
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    # Backtick code: `code` → <code>code</code>
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    return escaped


def _slugify_heading(text):
    clean = re.sub(r"`([^`]+)`", r"\1", text)
    slug = re.sub(r"[^a-z0-9]+", "-", clean.lower()).strip("-")
    return slug or "section"


def _collect_scan_anchors(md):
    """Map each scanned image name to the HTML id of its ``## Scan Results`` heading.

    The ids mirror exactly what :func:`_render_heading` produces (same base slug
    and duplicate-suffix counter), so links built from this map resolve to the
    corresponding scan section even when the table is rendered before the heading.
    """
    anchors = {}
    counts = {}
    for line in md.split("\n"):
        m = re.match(r"##\s+Scan Results:\s*`([^`]+)`\s*$", line)
        if not m:
            continue
        image = m.group(1).strip()
        base = _slugify_heading(f"Scan Results: `{image}`")
        count = counts.get(base, 0) + 1
        counts[base] = count
        hid = base if count == 1 else f"{base}-{count}"
        anchors.setdefault(image, hid)
    return anchors


def _render_heading(level, title, heading_ids):
    base = _slugify_heading(title)
    count = heading_ids.get(base, 0) + 1
    heading_ids[base] = count
    hid = base if count == 1 else f"{base}-{count}"
    return (
        f'<h{level} id="{esc(hid)}" class="anchored-heading">'
        f"{render_inline(title)}"
        f'<a class="heading-anchor" href="#{esc(hid)}" aria-label="Link to section">#</a>'
        f"</h{level}>"
    )


def _render_collapsible_table(table_html, label, row_count):
    return (
        '<div class="table-wrap">'
        '<details class="table-collapsible" open>'
        f'<summary><span class="toggle-label">{esc(label)} ({row_count} rows)</span></summary>'
        f"{table_html}"
        "</details>"
        "</div>"
    )


def _render_scan_collapsible(table_html, header_text, row_count):
    """Collapsible whose summary is the Trivy target box (image name + Total line)."""
    return (
        '<div class="table-wrap">'
        '<details class="table-collapsible scan-collapsible" open>'
        '<summary class="scan-summary">'
        '<span class="toggle-label" aria-hidden="true"></span>'
        f'<pre class="raw-output">{esc(header_text)}</pre>'
        "</summary>"
        f"{table_html}"
        "</details>"
        "</div>"
    )


def _severity_badge(severity):
    s = severity.strip().upper()
    css = s if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "UNKNOWN"
    return f'<span class="sev sev-{css}">{esc(severity.strip())}</span>'


def _status_badge(status):
    """Render a check-images Status cell (NEEDS_UPDATE / UP_TO_DATE / UNKNOWN)."""
    s = status.strip().upper()
    css = s if s in ("NEEDS_UPDATE", "UP_TO_DATE", "UNKNOWN") else "UNKNOWN"
    return f'<span class="status status-{css}">{esc(status.strip())}</span>'


def _vuln_count_cell(val):
    stripped = val.strip()
    try:
        n = int(stripped)
        cls = "vuln-count has-vulns" if n > 0 else "vuln-count"
    except ValueError:
        cls = "vuln-count"
    return f'<span class="{cls}">{esc(stripped)}</span>'


def _render_title_cell(text):
    """Render the Title column: turn https:// lines into links."""
    parts = text.split("\n")
    rendered = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if p.startswith("https://"):
            rendered.append(
                f'<a href="{esc(p)}" target="_blank" rel="noopener noreferrer">{esc(p)}</a>'
            )
        else:
            rendered.append(esc(p))
    return "<br>".join(rendered)


def render_table(headers, rows, header_text=None):
    """Render (headers, rows) as an HTML table."""
    if not headers or not rows:
        return ""

    # Detect column roles by normalised header name
    hlo = [h.lower().replace(" ", "") for h in headers]

    def col_html(h, h_norm, val):
        if h_norm == "severity":
            return _severity_badge(val) if val.strip() else ""
        if h_norm in ("vulnerabilities", "secrets"):
            return _vuln_count_cell(val)
        if h_norm == "vulnerability":
            v = val.strip()
            if re.match(r"CVE-\d{4}-\d+", v, re.I):
                url = f"https://avd.aquasec.com/nvd/{v.lower()}"
                return f'<a href="{esc(url)}" target="_blank" rel="noopener noreferrer">{esc(v)}</a>'
            return esc(v)
        if h_norm == "title":
            return _render_title_cell(val)
        return esc(val)

    out = ['<table class="report-table">']
    out.append("<thead><tr>")
    for h in headers:
        out.append(f"<th>{esc(h)}</th>")
    out.append("</tr></thead><tbody>")

    for row in rows:
        out.append("<tr>")
        for h, h_norm in zip(headers, hlo):
            val = row.get(h, "")
            td_class = ' class="num"' if h_norm in ("vulnerabilities", "secrets") else ""
            out.append(f"<td{td_class}>{col_html(h, h_norm, val)}</td>")
        out.append("</tr>")

    out.append("</tbody></table>")
    table_html = "\n".join(out)
    if header_text:
        return _render_scan_collapsible(table_html, header_text, len(rows))
    return _render_collapsible_table(table_html, "Scan Findings", len(rows))


def render_md_table(headers, rows, scan_anchors=None):
    """Render a parsed markdown pipe table as HTML with check-images aware styling.

    When *scan_anchors* maps an image name to the id of its ``## Scan Results``
    section, the Image cell is rendered as a link to that section.
    """
    if not headers or not rows:
        return ""

    hlo = [h.lower().replace(" ", "").replace("(", "").replace(")", "") for h in headers]

    def col_html(h_norm, val):
        if h_norm == "status":
            return _status_badge(val) if val.strip() else ""
        if h_norm == "image":
            # Strip surrounding backticks if the cell value is a markdown code span
            clean = val.strip()
            if clean.startswith("`") and clean.endswith("`") and len(clean) > 1:
                clean = clean[1:-1]
            code_html = f'<code style="font-size:11px;word-break:break-all">{esc(clean)}</code>'
            if scan_anchors and clean in scan_anchors:
                href = "#" + scan_anchors[clean]
                return (
                    f'<a class="image-scan-link" href="{esc(href)}" '
                    f'title="Jump to scan results for {esc(clean)}">{code_html}</a>'
                )
            return code_html
        if h_norm in ("buildrepo",):
            repo = val.strip()
            if repo and repo != "N/A":
                repo_path = repo if "/" in repo else f"rancher/{repo}"
                url = f"https://github.com/{repo_path}"
                return (
                    f'<a href="{esc(url)}" target="_blank" rel="noopener noreferrer">'
                    f"{esc(val)}</a>"
                )
        return render_inline(val)

    out = ['<table class="report-table">']
    out.append("<thead><tr>")
    for h in headers:
        out.append(f"<th>{render_inline(h)}</th>")
    out.append("</tr></thead><tbody>")

    for row in rows:
        out.append("<tr>")
        for h, h_norm in zip(headers, hlo):
            val = row.get(h, "")
            out.append(f"<td>{col_html(h_norm, val)}</td>")
        out.append("</tr>")

    out.append("</tbody></table>")
    return _render_collapsible_table("\n".join(out), "Table", len(rows))

def _process_trivy_block(content):
    """
    Process the raw text inside a ```text ... ``` fence.

    Finds every ASCII table and converts it to HTML; surrounding text is
    emitted as <pre class="raw-output">.  Legend lines are styled separately.
    """
    lines = content.split("\n")
    html_parts = []
    non_table_buf = []
    table_buf = []
    in_table = False
    legend_lines = []

    def take_non_table():
        text = "\n".join(non_table_buf).strip()
        non_table_buf.clear()
        return text

    def flush_non_table():
        text = take_non_table()
        if text:
            html_parts.append(f'<pre class="raw-output">{esc(text)}</pre>')

    pending_header = None

    for line in lines:
        # Legend lines (outside tables)
        if not in_table and re.match(r"^[-•]\s+'?[-0]'?:", line):
            legend_lines.append(line)
            continue

        if not in_table:
            if line.startswith("┌"):
                # Capture the target box (image name / ==== / Total) that
                # immediately precedes this table; it becomes the collapsible header.
                pending_header = take_non_table()
                in_table = True
                table_buf = [line]
            else:
                non_table_buf.append(line)
        else:
            table_buf.append(line)
            if line.startswith("└"):
                in_table = False
                headers, rows = parse_ascii_table(table_buf)
                table_buf = []
                if headers:
                    html_parts.append(render_table(headers, rows, header_text=pending_header or None))
                elif pending_header:
                    html_parts.append(f'<pre class="raw-output">{esc(pending_header)}</pre>')
                pending_header = None

    if table_buf:
        if pending_header:
            non_table_buf.insert(0, pending_header)
        non_table_buf.extend(table_buf)
    flush_non_table()

    if legend_lines:
        legend_text = esc("\n".join(legend_lines))
        html_parts.append(f'<div class="legend">{legend_text}</div>')

    return "\n".join(html_parts)


# ---------------------------------------------------------------------------
# Markdown-format converter
# ---------------------------------------------------------------------------

_OPTIONAL_START_MARKER = "<!--OPTIONAL-START-->"
_OPTIONAL_END_MARKER = "<!--OPTIONAL-END-->"

_OPTIONAL_SECTION_OPEN = (
    '<section class="optional-section" id="optional-images">'
    '<input type="checkbox" id="optional-toggle" class="optional-toggle-input" checked>'
    '<div class="optional-banner">'
    '<label class="optional-toggle-label" for="optional-toggle">'
    '<span class="optional-switch" aria-hidden="true"></span>'
    '<span>Show non-default (add-on) images</span>'
    '</label>'
    '<p class="optional-note">These images are <strong>not</strong> part of the '
    'default k3s airgap image set. Toggle off to view only the default '
    'images.</p>'
    '</div>'
    '<div class="optional-body">'
)

_OPTIONAL_SECTION_CLOSE = "</div></section>"


def _convert_markdown(md):
    """Convert the structured scan/check-images markdown to an HTML body string."""
    lines = md.split("\n")
    out = []
    i = 0
    in_ul = False
    in_images_list = False  # the "## Images Scanned" bullet list
    in_code = False
    code_lang = ""
    code_lines = []
    in_pipe_table = False
    pipe_table_lines = []
    in_scan_result = False  # True while inside a "## Scan Results: `…`" section
    heading_ids = {}
    scan_anchors = _collect_scan_anchors(md)

    def close_ul():
        nonlocal in_ul, in_images_list
        if in_ul:
            out.append("</ul>")
            in_images_list = False
            in_ul = False

    def close_pipe_table():
        nonlocal in_pipe_table, pipe_table_lines
        if in_pipe_table:
            headers, rows = parse_md_table(pipe_table_lines)
            if headers and rows:
                out.append('<div class="scan-card">')
                out.append(render_md_table(headers, rows, scan_anchors))
                out.append("</div>")
            in_pipe_table = False
            pipe_table_lines = []

    while i < len(lines):
        line = lines[i]

        # ---- fenced code block ----
        if line.startswith("```"):
            if not in_code:
                close_ul()
                close_pipe_table()
                in_code = True
                code_lang = line[3:].strip()
                code_lines = []
            else:
                in_code = False
                block_content = "\n".join(code_lines)
                processed = _process_trivy_block(block_content)
                if processed.strip():
                    out.append(f'<div class="scan-card">{processed}</div>')
                    if in_scan_result and "<table" not in processed:
                        out.append(
                            '<div class="all-clean-banner">'
                            '<span class="all-clean-icon">✓</span>'
                            "No vulnerabilities found — this image is clean"
                            "</div>"
                        )
                elif in_scan_result:
                    out.append(
                        '<div class="all-clean-banner">'
                        '<span class="all-clean-icon">✓</span>'
                        "No vulnerabilities found — this image is clean"
                        "</div>"
                    )
                in_scan_result = False
                code_lines = []
            i += 1
            continue

        if in_code:
            code_lines.append(line)
            i += 1
            continue

        # ---- optional (non-default) add-on section markers ----
        if line.strip() == _OPTIONAL_START_MARKER:
            close_ul()
            close_pipe_table()
            in_scan_result = False
            out.append(_OPTIONAL_SECTION_OPEN)
            i += 1
            continue
        if line.strip() == _OPTIONAL_END_MARKER:
            close_ul()
            close_pipe_table()
            in_scan_result = False
            out.append(_OPTIONAL_SECTION_CLOSE)
            i += 1
            continue

        # ---- markdown pipe table ----
        if line.strip().startswith("|"):
            close_ul()
            in_pipe_table = True
            pipe_table_lines.append(line)
            i += 1
            continue

        # Any non-pipe line closes an open pipe table
        close_pipe_table()

        # ---- headings ----
        if line.startswith("# "):
            close_ul()
            in_scan_result = False
            out.append(_render_heading(1, line[2:].strip(), heading_ids))
        elif line.startswith("## "):
            close_ul()
            title = line[3:].strip()
            out.append(_render_heading(2, title, heading_ids))
            in_images_list = title.lower().startswith("images scanned")
            in_scan_result = bool(re.match(r"Scan Results:\s*`[^`]+`", title))
        elif line.startswith("### "):
            close_ul()
            in_scan_result = False
            out.append(_render_heading(3, line[4:].strip(), heading_ids))

        # ---- blockquote / callout ----
        elif line.lstrip().startswith(">"):
            close_ul()
            quote = line.lstrip()[1:].strip()
            out.append(f'<blockquote class="callout">{render_inline(quote)}</blockquote>')

        # ---- bullet list ----
        elif re.match(r"^[-*] ", line):
            item = line[2:].strip()
            if not in_ul:
                ul_cls = "images-list" if in_images_list else "generic-list"
                out.append(f'<ul class="{ul_cls}">')
                in_ul = True
            out.append(f"<li><code>{esc(item)}</code></li>" if in_images_list
                       else f"<li>{render_inline(item)}</li>")

        # ---- blank line ----
        elif not line.strip():
            close_ul()

        # ---- paragraph ----
        else:
            close_ul()
            stripped = line.strip()
            if stripped:
                out.append(f"<p>{render_inline(stripped)}</p>")

        i += 1

    close_pipe_table()
    close_ul()
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Raw-text converter (no markdown structure)
# ---------------------------------------------------------------------------

def _convert_raw(text):
    """
    Fallback converter for raw Trivy text files (no markdown headers).
    Finds ASCII tables and renders them; everything else is <pre>.
    """
    processed = _process_trivy_block(text)
    return f'<div class="scan-card">{processed}</div>' if processed.strip() else f'<pre class="raw-output">{esc(text)}</pre>'


# ---------------------------------------------------------------------------
# Markdown pre-processing helpers
# ---------------------------------------------------------------------------

def _move_summary_to_top(md):
    """
    Move the ``## Summary`` section from the bottom of the markdown to just
    after the opening ``# …`` title heading, so it appears at the top of the
    rendered page.
    """
    lines = md.split("\n")

    # Locate the ## Summary section
    summary_start = None
    for i, line in enumerate(lines):
        if line.strip() == "## Summary":
            summary_start = i
            break

    if summary_start is None:
        return md  # nothing to move

    # Determine where the Summary section ends (next ## heading or EOF)
    summary_end = len(lines)
    for i in range(summary_start + 1, len(lines)):
        if lines[i].startswith("## "):
            summary_end = i
            break

    summary_lines = lines[summary_start:summary_end]
    # Remove the summary block from its original location
    remaining = lines[:summary_start] + lines[summary_end:]

    # Find insertion point: right after the first # heading line
    insert_at = 1  # fallback: just after line 0
    for i, line in enumerate(remaining):
        if line.startswith("# "):
            insert_at = i + 1
            break

    # Skip any blank lines immediately following the heading
    while insert_at < len(remaining) and not remaining[insert_at].strip():
        insert_at += 1

    new_lines = remaining[:insert_at] + [""] + summary_lines + [""] + remaining[insert_at:]
    return "\n".join(new_lines)


def _extract_summary_total_cves(md):
    """Extract total CVEs from the markdown summary table.

    Only the default-image ``### CVEs by Severity`` section is considered. The
    optional add-on ``### Optional CVEs by Severity`` section is deliberately
    excluded so that the CVE delta tracks the default tarball numbers and stays
    consistent with the ``CVEs by Severity`` summary.
    """
    # Restrict the search to the default-image "CVEs by Severity" section so the
    # optional add-on counts (which live under "Optional CVEs by Severity") do
    # not leak into the delta calculation.
    section = re.search(
        r"^###\s+CVEs by Severity\s*$(.*?)(?=^###?\s|\Z)",
        md,
        re.MULTILINE | re.DOTALL,
    )
    scope = section.group(1) if section else md

    m = re.search(r"^\|\s*\*\*Total\*\*\s*\|\s*\*\*(\d+)\*\*\s*\|", scope, re.MULTILINE)
    if m:
        return int(m.group(1))

    critical = re.search(r"^\|\s*CRITICAL\s*\|\s*(\d+)\s*\|", scope, re.MULTILINE)
    high = re.search(r"^\|\s*HIGH\s*\|\s*(\d+)\s*\|", scope, re.MULTILINE)
    if critical and high:
        return int(critical.group(1)) + int(high.group(1))
    return None


def _count_images_scanned(md):
    """Count entries in the '## Images Scanned' section."""
    lines = md.split("\n")
    start = None
    for i, line in enumerate(lines):
        if line.strip() == "## Images Scanned":
            start = i + 1
            break
    if start is None:
        return 0

    count = 0
    for i in range(start, len(lines)):
        line = lines[i]
        if line.startswith("## "):
            break
        if re.match(r"^\s*[-*]\s+`[^`]+`\s*$", line):
            count += 1
    return count


def _count_binaries_with_findings(md):
    """Count gobinary/binary targets that have reported findings in Trivy scan output.

    NOTE: This only counts binaries that appear in the severity-filtered Trivy
    table output (i.e. binaries *with* CRITICAL/HIGH findings). It is NOT the
    total number of binaries scanned. Use the value written by scan.sh into the
    ``### Scan Coverage`` markdown section for the authoritative total.
    """
    return len(re.findall(r"(?im)^\s*.+\((?:go)?binary\)\s*$", md))


def _count_binaries_from_summary_tables(md):
    """Count all gobinary/binary targets in Trivy 'Report Summary' ASCII tables.

    Older reports embed a full 'Report Summary' box-drawing table per image that
    lists every scanned target (including those with 0 vulnerabilities) with its
    type.  Counting rows whose type cell is 'gobinary' or 'binary' gives the true
    total number of binaries scanned, equivalent to the value scan.sh writes into
    the ``### Scan Coverage`` section of newer reports.

    Returns 0 when no such tables are present (e.g. reports that already carry a
    ``### Scan Coverage`` section, or reports in the findings-only format).
    """
    return len(re.findall(r"│[^│\n]+│\s*(?:go)?binary\s*│[^│\n]+│", md))


def _metrics_db_path(input_path):
    """Resolve the metrics DB location."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root_db = os.path.abspath(os.path.join(script_dir, "..", "..", "reports", "scan_metrics.db"))
    if os.path.isfile(repo_root_db):
        return repo_root_db

    sibling_db = os.path.join(os.path.dirname(os.path.abspath(input_path)), "scan_metrics.db")
    if os.path.isfile(sibling_db):
        return sibling_db
    return None


def _recent_cve_totals_from_db(input_path):
    """Return most recent CVE totals from metrics DB (latest first)."""
    db_path = _metrics_db_path(input_path)
    if not db_path:
        return []
    try:
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT (critical_cves + high_cves) AS total_cves
                FROM scan_metrics
                ORDER BY scanned_at DESC, id DESC
                LIMIT 2
                """
            )
            rows = [int(r[0]) for r in cur.fetchall() if r and r[0] is not None]
            return rows
    except sqlite3.Error:
        return []


# ---------------------------------------------------------------------------
# CVE trend chart (interactive SVG line graph)
# ---------------------------------------------------------------------------

# Number of most-recent scans plotted on the trend chart.
_TREND_HISTORY_LIMIT = 30

# Metadata comment scan.sh embeds in the report header so the converter can
# recover the scan's source (branch / release tag / PR) and filter the trend
# chart to comparable scans.
_SOURCE_REF_RE = re.compile(r"<!--\s*scan-source-ref:\s*(.*?)\s*-->")
_SCAN_METADATA_RE = re.compile(
    r"^[ \t]*<!--\s*scan-source-(?:ref|desc):.*?-->[ \t]*\n?",
    re.MULTILINE,
)


def _scan_source_group(source_ref):
    """Map a scan ``source_ref`` to a ``(group_key, human_label)`` tuple.

    Scans are bucketed so the trend chart only plots comparable history:

    * release tags are grouped by minor version, e.g. every ``v1.36.x`` release
      shares one bucket;
    * branch scans are grouped per branch (``master``, ``release-1.32``, ...);
    * PR scans are grouped per PR number.

    Returns ``(None, None)`` when the ref is empty or unrecognised so the caller
    falls back to the global (unfiltered) trend.
    """
    ref = (source_ref or "").strip()
    if not ref:
        return None, None

    if ref.startswith("release:"):
        version = ref[len("release:"):]
        m = re.match(r"v?(\d+)\.(\d+)", version)
        if m:
            minor = f"v{m.group(1)}.{m.group(2)}"
            return f"release-minor:{minor}", f"{minor} release"
        return f"release:{version}", f"release {version}"

    m = re.match(r"refs/pull/(\d+)/head", ref)
    if m:
        return f"pr:{m.group(1)}", f"PR #{m.group(1)}"

    m = re.match(r"refs/heads/(.+)", ref)
    if m:
        branch = m.group(1)
        return f"branch:{branch}", f"branch '{branch}'"

    return f"ref:{ref}", ref


def _extract_source_ref_from_md(md):
    """Return the ``scan-source-ref`` value embedded in *md*, or ``None``."""
    m = _SOURCE_REF_RE.search(md or "")
    return m.group(1).strip() if m else None


def _infer_source_ref_from_filename(basename):
    """Best-effort source ref for reports that predate embedded metadata.

    ``pr-<num>`` and release-tagged ``scan-<token>-<n>`` filenames carry enough
    information to bucket the report. Date-based scheduled filenames
    (``scan-<YYYYMMDD>-<n>``) do not encode their branch, so ``None`` is
    returned and the caller falls back to the global trend.
    """
    name = os.path.splitext(os.path.basename(basename))[0]

    m = re.match(r"pr-(\d+)$", name)
    if m:
        return f"refs/pull/{m.group(1)}/head"

    m = re.match(r"scan-(.+)-\d+$", name)
    if m:
        token = m.group(1)
        if re.fullmatch(r"\d{8}", token):
            return None
        return f"release:{token}"

    return None


def _resolve_scan_source(md, input_path):
    """Resolve the ``(group_key, label)`` for the report being converted."""
    source_ref = _extract_source_ref_from_md(md)
    if not source_ref:
        source_ref = _infer_source_ref_from_filename(os.path.basename(input_path))
    return _scan_source_group(source_ref)


def _strip_scan_metadata(md):
    """Remove embedded ``scan-source-*`` comment lines from report markdown."""
    return _SCAN_METADATA_RE.sub("", md or "")


def _trend_history_rows(input_path, crit_col, high_col, source_group, limit):
    """Fetch trend history rows, optionally filtered to a single source group.

    *crit_col* / *high_col* are column names baked into the query from code (not
    user input). When *source_group* is ``None`` the global most-recent history
    is returned, preserving the original cross-source behaviour.
    """
    db_path = _metrics_db_path(input_path)
    if not db_path:
        return []
    try:
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                f"""
                SELECT scanned_at, source_ref, source_desc, {crit_col}, {high_col}
                FROM scan_metrics
                ORDER BY scanned_at DESC, id DESC
                """
            )
            rows = cur.fetchall()
    except sqlite3.Error:
        return []

    history = []
    # rows come newest-first; collect up to *limit* matches then reverse so the
    # chart reads left-to-right in time.
    for scanned_at, source_ref, source_desc, critical, high in rows:
        if source_group is not None:
            grp, _label = _scan_source_group(source_ref)
            if grp != source_group:
                continue
        try:
            crit = int(critical)
            hi = int(high)
        except (TypeError, ValueError):
            continue
        history.append(
            {
                "scanned_at": scanned_at or "",
                "source_desc": source_desc or "",
                "critical": crit,
                "high": hi,
                "total": crit + hi,
            }
        )
        if len(history) >= limit:
            break
    history.reverse()
    return history


def _cve_trend_history_from_db(input_path, source_group=None, limit=_TREND_HISTORY_LIMIT):
    """Return recent CVE history from the metrics DB, oldest first.

    Each entry is a dict with ``scanned_at`` (ISO timestamp), ``source_desc``
    (human label such as ``branch 'master'``), ``critical``, ``high`` and
    ``total`` (critical + high) counts. When *source_group* is provided only
    scans in that group are included (see :func:`_scan_source_group`). Returns
    an empty list when the DB is missing or unreadable so the caller can skip
    the chart gracefully.
    """
    return _trend_history_rows(
        input_path, "critical_cves", "high_cves", source_group, int(limit)
    )


def _optional_cve_trend_history_from_db(input_path, source_group=None, limit=_TREND_HISTORY_LIMIT):
    """Return recent optional add-on CVE history from the metrics DB, oldest first.

    Mirrors :func:`_cve_trend_history_from_db` but reads the
    ``optional_critical_cves`` / ``optional_high_cves`` columns so the optional
    add-on section can plot its own trend. Returns an empty list when the DB is
    missing, unreadable, or predates the optional-image columns so the caller
    can skip the chart gracefully.
    """
    return _trend_history_rows(
        input_path,
        "optional_critical_cves",
        "optional_high_cves",
        source_group,
        int(limit),
    )


def _format_trend_date(iso_ts):
    """Format an ISO timestamp for axis/tooltip display (YYYY-MM-DD)."""
    if not iso_ts:
        return ""
    try:
        return datetime.strptime(iso_ts[:10], "%Y-%m-%d").strftime("%Y-%m-%d")
    except ValueError:
        return iso_ts[:10]


# Series plotted on the trend chart: (key, label, colour).
_TREND_SERIES = (
    ("total", "Total (Critical + High)", "#1F67DB"),
    ("critical", "Critical", "#B13333"),
    ("high", "High", "#E45C1E"),
)


def render_cve_trend_chart(
    history,
    chart_id="cve-trend",
    heading_title="CVE Trend Over Time",
    heading_anchor="cve-trend-over-time",
    subtitle_subject="Critical &amp; High CVE counts",
    empty_message="No historical scan metrics are available yet to plot a trend.",
    scope_label=None,
):
    """Render an interactive SVG line chart of CVE counts over time.

    *history* is the list returned by :func:`_cve_trend_history_from_db`
    (oldest first). The returned markup is fully self-contained: an inline SVG
    with one polyline per severity series, hover tooltips, and a clickable
    legend that toggles series visibility. Styling relies on the shared report
    CSS so the chart matches the rest of the dashboard.

    The heading text/anchor, subtitle subject and empty-state message are
    parameterised so the same renderer can drive both the default-image chart
    and the optional add-on chart. *chart_id* must be unique per page because
    the inline script scopes its behaviour to each ``.cve-trend`` section.
    """
    heading = (
        f'<h3 id="{esc(heading_anchor)}" class="anchored-heading">'
        f"{esc(heading_title)}"
        f'<a class="heading-anchor" href="#{esc(heading_anchor)}" '
        'aria-label="Link to section">#</a></h3>'
    )

    if not history:
        return (
            f'<section class="cve-trend" id="{esc(chart_id)}">'
            f"{heading}"
            f'<p class="cve-trend-empty">{esc(empty_message)}</p>'
            "</section>"
        )

    # --- geometry -----------------------------------------------------------
    width, height = 760, 300
    pad_left, pad_right = 48, 20
    pad_top, pad_bottom = 24, 56
    plot_w = width - pad_left - pad_right
    plot_h = height - pad_top - pad_bottom

    n = len(history)
    max_val = max((pt["total"] for pt in history), default=0)
    if max_val <= 0:
        max_val = 1
    # Round the axis maximum up to a "nice" number for readable gridlines.
    step = max(1, int(math.ceil(max_val / 4.0)))
    y_max = step * 4

    def x_for(idx):
        if n == 1:
            return pad_left + plot_w / 2.0
        return pad_left + plot_w * idx / (n - 1)

    def y_for(val):
        return pad_top + plot_h * (1 - (val / y_max))

    # --- axes & gridlines ---------------------------------------------------
    svg = [
        f'<svg class="cve-trend-svg" viewBox="0 0 {width} {height}" '
        f'role="img" aria-label="CVE counts over recent scans" '
        'preserveAspectRatio="xMidYMid meet">'
    ]

    for tick in range(5):
        val = y_max - step * tick
        y = y_for(val)
        svg.append(
            f'<line class="grid-line" x1="{pad_left}" y1="{y:.1f}" '
            f'x2="{pad_left + plot_w}" y2="{y:.1f}"></line>'
        )
        svg.append(
            f'<text class="axis-label" x="{pad_left - 8}" y="{y + 3:.1f}" '
            f'text-anchor="end">{val}</text>'
        )

    # X axis baseline.
    base_y = y_for(0)
    svg.append(
        f'<line class="axis-line" x1="{pad_left}" y1="{base_y:.1f}" '
        f'x2="{pad_left + plot_w}" y2="{base_y:.1f}"></line>'
    )

    # X axis labels: show a limited number of evenly-spaced date ticks so they
    # do not overlap when many scans are present.
    max_ticks = 8
    tick_every = max(1, int(math.ceil(n / float(max_ticks))))
    for idx, pt in enumerate(history):
        if idx % tick_every and idx != n - 1:
            continue
        x = x_for(idx)
        label = _format_trend_date(pt["scanned_at"])
        svg.append(
            f'<text class="axis-label" x="{x:.1f}" y="{base_y + 16:.1f}" '
            f'text-anchor="middle" transform="rotate(0 {x:.1f} '
            f'{base_y + 16:.1f})">{esc(label)}</text>'
        )

    # --- series -------------------------------------------------------------
    for key, _label, colour in _TREND_SERIES:
        points = [(x_for(idx), y_for(pt[key])) for idx, pt in enumerate(history)]
        if len(points) >= 2:
            d = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
            svg.append(
                f'<polyline class="series-line series-{key}" '
                f'data-series="{key}" points="{d}" stroke="{colour}"></polyline>'
            )
        for idx, (x, y) in enumerate(points):
            pt = history[idx]
            date_label = _format_trend_date(pt["scanned_at"])
            source = pt.get("source_desc", "")
            tip = f"{date_label} · {source}".strip(" ·") if source else date_label
            svg.append(
                f'<circle class="series-point series-{key}" '
                f'data-series="{key}" cx="{x:.1f}" cy="{y:.1f}" r="3.5" '
                f'fill="{colour}" data-label="{esc(tip)}" '
                f'data-series-name="{esc(_label)}" '
                f'data-value="{pt[key]}"></circle>'
            )

    svg.append("</svg>")

    # --- legend -------------------------------------------------------------
    legend_items = []
    for key, label, colour in _TREND_SERIES:
        legend_items.append(
            f'<span class="legend-item" data-series="{key}" role="button" '
            f'tabindex="0" aria-pressed="true">'
            f'<span class="legend-swatch" style="background:{colour}"></span>'
            f"{esc(label)}</span>"
        )
    legend = '<div class="cve-trend-legend">' + "".join(legend_items) + "</div>"

    scan_noun = f"{esc(scope_label)} scan" if scope_label else "recorded scan"
    subtitle = (
        f'<p class="chart-subtitle">{subtitle_subject} across the '
        f"last {n} {scan_noun}{'s' if n != 1 else ''}. Hover a point for "
        f"details; click a legend entry to toggle a series.</p>"
    )

    return (
        f'<section class="cve-trend" id="{esc(chart_id)}">'
        f"{heading}"
        f"{subtitle}"
        '<div class="cve-trend-figure">'
        f"{''.join(svg)}"
        '<div class="cve-trend-tooltip" aria-hidden="true"></div>'
        "</div>"
        f"{legend}"
        f"{_CVE_TREND_SCRIPT}"
        "</section>"
    )


# Inline behaviour for the trend chart: hover tooltips and legend toggling.
# Scoped per-section so multiple charts on one page do not interfere.
_CVE_TREND_SCRIPT = """<script>
(function () {
  function initTrend(section) {
    if (section.dataset.trendReady) return;
    section.dataset.trendReady = "1";
    var figure = section.querySelector(".cve-trend-figure");
    var svg = section.querySelector(".cve-trend-svg");
    var tip = section.querySelector(".cve-trend-tooltip");
    if (!figure || !svg || !tip) return;

    section.querySelectorAll(".series-point").forEach(function (pt) {
      pt.addEventListener("mouseenter", function () {
        var name = pt.getAttribute("data-series-name") || "";
        var value = pt.getAttribute("data-value") || "";
        var label = pt.getAttribute("data-label") || "";
        tip.innerHTML =
          '<div class="tt-date">' + label + "</div>" +
          name + ": " + value;
        var fr = figure.getBoundingClientRect();
        var pr = pt.getBoundingClientRect();
        tip.style.left = (pr.left - fr.left + pr.width / 2) + "px";
        tip.style.top = (pr.top - fr.top) + "px";
        tip.classList.add("visible");
      });
      pt.addEventListener("mouseleave", function () {
        tip.classList.remove("visible");
      });
    });

    function toggle(item) {
      var key = item.getAttribute("data-series");
      var off = item.classList.toggle("legend-off");
      item.setAttribute("aria-pressed", off ? "false" : "true");
      section
        .querySelectorAll('[data-series="' + key + '"].series-line, ' +
                          '[data-series="' + key + '"].series-point')
        .forEach(function (el) { el.classList.toggle("series-hidden", off); });
    }

    section.querySelectorAll(".legend-item").forEach(function (item) {
      item.addEventListener("click", function () { toggle(item); });
      item.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          toggle(item);
        }
      });
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      document.querySelectorAll(".cve-trend").forEach(initTrend);
    });
  } else {
    document.querySelectorAll(".cve-trend").forEach(initTrend);
  }
})();
</script>"""


def _augment_scan_summary(md, input_path):
    """Add extra scan metrics sections into the markdown Summary section."""
    lines = md.split("\n")
    summary_start = None
    for i, line in enumerate(lines):
        if line.strip() == "## Summary":
            summary_start = i
            break
    if summary_start is None:
        return md

    summary_end = len(lines)
    for i in range(summary_start + 1, len(lines)):
        if lines[i].startswith("## "):
            summary_end = i
            break

    summary_lines = lines[summary_start:summary_end]
    summary_text = "\n".join(summary_lines)
    add_lines = []

    if "### CVE Delta vs Previous Scan" not in summary_text:
        current_total = _extract_summary_total_cves(md)
        recent_totals = _recent_cve_totals_from_db(input_path)

        previous_total = None
        delta_value = None
        if recent_totals:
            if current_total is None:
                current_total = recent_totals[0]
            if len(recent_totals) >= 2:
                previous_total = recent_totals[1] if current_total == recent_totals[0] else recent_totals[0]
                delta_value = current_total - previous_total if current_total is not None else None

        delta_display = f"{delta_value:+d}" if delta_value is not None else "N/A"
        add_lines.extend(
            [
                "",
                "### CVE Delta vs Previous Scan",
                "",
                "| Metric | Count |",
                "| --- | ---: |",
                f"| Previous scan CVEs | {previous_total if previous_total is not None else 'N/A'} |",
                f"| Current scan CVEs | {current_total if current_total is not None else 'N/A'} |",
                f"| **Delta** | **{delta_display}** |",
                "",
            ]
        )

    if "### Scan Coverage" not in summary_text:
        image_count = _count_images_scanned(md)
        binary_count = _count_binaries_from_summary_tables(md)
        coverage_rows = [
            "### Scan Coverage",
            "",
            "| Metric | Count |",
            "| --- | ---: |",
            f"| Images scanned | {image_count} |",
        ]
        if binary_count:
            total = image_count + binary_count
            coverage_rows.append(f"| Binaries scanned | {binary_count} |")
            coverage_rows.append(f"| **Total scanned targets** | **{total}** |")
        coverage_rows.append("")
        add_lines.extend(coverage_rows)

    if not add_lines:
        return md

    updated_summary = summary_lines + add_lines
    new_lines = lines[:summary_start] + updated_summary + lines[summary_end:]
    return "\n".join(new_lines)


def _extract_ascii_tables_from_text(text):
    """Return all parsed ASCII tables found in *text*."""
    tables = []
    lines = text.split("\n")
    table_buf = []
    in_table = False
    for line in lines:
        if not in_table and line.startswith("┌"):
            in_table = True
            table_buf = [line]
            continue
        if in_table:
            table_buf.append(line)
            if line.startswith("└"):
                headers, rows = parse_ascii_table(table_buf)
                if headers and rows:
                    tables.append((headers, rows))
                table_buf = []
                in_table = False
    return tables


def _extract_scan_findings(md):
    """Extract scan findings grouped by image from a scan markdown report."""
    findings_by_image = {}
    lines = md.split("\n")
    current_image = None
    in_code = False
    code_lines = []

    for line in lines:
        m = re.match(r"^##\s+Scan Results:\s+`([^`]+)`", line.strip())
        if m:
            current_image = m.group(1).strip()
            findings_by_image.setdefault(current_image, [])
            continue

        if line.startswith("```"):
            if not in_code:
                in_code = True
                code_lines = []
            else:
                in_code = False
                if current_image:
                    for headers, rows in _extract_ascii_tables_from_text("\n".join(code_lines)):
                        hmap = {h.lower().replace(" ", ""): h for h in headers}
                        lib_key = hmap.get("library")
                        vuln_key = hmap.get("vulnerability")
                        sev_key = hmap.get("severity")
                        status_key = hmap.get("status")
                        inst_key = hmap.get("installedversion")
                        fix_key = hmap.get("fixedversion")
                        title_key = hmap.get("title")
                        for row in rows:
                            vuln = row.get(vuln_key, "").strip() if vuln_key else ""
                            if not re.match(r"^CVE-\d{4}-\d+", vuln, re.I):
                                continue
                            findings_by_image[current_image].append(
                                {
                                    "library": row.get(lib_key, "").strip() if lib_key else "",
                                    "vulnerability": vuln,
                                    "severity": row.get(sev_key, "").strip() if sev_key else "",
                                    "status": row.get(status_key, "").strip() if status_key else "",
                                    "installed_version": row.get(inst_key, "").strip() if inst_key else "",
                                    "fixed_version": row.get(fix_key, "").strip() if fix_key else "",
                                    "title": row.get(title_key, "").strip() if title_key else "",
                                }
                            )
                code_lines = []
            continue

        if in_code:
            code_lines.append(line)

    return findings_by_image


def _fallback_suggested_actions(findings_by_image):
    """Generate deterministic suggested actions from parsed findings."""
    actions = []
    for image, findings in findings_by_image.items():
        if not findings:
            continue

        stdlib_high = [
            f for f in findings
            if f.get("library", "").lower() == "stdlib"
            and f.get("severity", "").upper() in ("CRITICAL", "HIGH")
        ]
        if stdlib_high:
            actions.append(
                f"For `{image}`, Go stdlib CVEs were detected; bump Go/toolchain to a fixed release and rebuild/publish the image."
            )

        fixed_versions = sorted(
            {
                f["fixed_version"]
                for f in findings
                if f.get("fixed_version")
            }
        )
        if fixed_versions:
            actions.append(
                f"For `{image}`, update vulnerable components to available fixed versions ({', '.join(fixed_versions[:3])}) and regenerate the image SBOM/scan."
            )

    if not actions:
        return ["No actionable CVEs were found in this report."]
    return actions[:6]


def _parse_actions_from_copilot_text(text):
    text = text.strip()
    if not text:
        return []

    try:
        payload = json.loads(text)
        if isinstance(payload, list):
            parsed = [str(x).strip() for x in payload if str(x).strip()]
            if parsed:
                return parsed
    except json.JSONDecodeError:
        pass

    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        line = re.sub(r"^[-*]\s+", "", line)
        line = re.sub(r"^\d+\.\s+", "", line)
        if line:
            out.append(line)
    return out


def _copilot_suggested_actions(title, findings_by_image):
    """Ask Copilot/GitHub Models for suggested actions; fallback on local rules."""
    fallback_actions = _fallback_suggested_actions(findings_by_image)
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        return fallback_actions

    findings_summary = []
    for image, findings in findings_by_image.items():
        if not findings:
            continue
        cves = sorted({f["vulnerability"] for f in findings if f.get("vulnerability")})
        libs = sorted({f["library"] for f in findings if f.get("library")})
        severities = sorted({f["severity"].upper() for f in findings if f.get("severity")})
        fixed_versions = sorted({f["fixed_version"] for f in findings if f.get("fixed_version")})
        findings_summary.append(
            {
                "image": image,
                "cves": cves[:20],
                "libraries": libs[:10],
                "severities": severities[:10],
                "fixed_versions": fixed_versions[:10],
            }
        )

    if not findings_summary:
        return fallback_actions

    model = os.getenv("COPILOT_MODEL", "openai/gpt-4.1-mini")
    user_prompt = (
        "Suggest concise remediation actions for this Trivy scan report.\n"
        "Return JSON only: an array of plain strings, 2-6 items, no markdown.\n"
        "Prefer image-specific rebuild/update actions.\n"
        f"Report title: {title}\n"
        f"Findings summary: {json.dumps(findings_summary, ensure_ascii=False)}"
    )
    payload = {
        "model": model,
        "temperature": 0.2,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are GitHub Copilot helping with container vulnerability remediation. "
                    "Prioritize concrete actions such as dependency bumps and image rebuilds."
                ),
            },
            {"role": "user", "content": user_prompt},
        ],
    }

    req = urllib.request.Request(
        "https://models.github.ai/inference/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8")
        decoded = json.loads(raw)
        content = (
            decoded.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )
        actions = _parse_actions_from_copilot_text(content)
        return actions[:6] if actions else fallback_actions
    except (
        urllib.error.URLError,
        json.JSONDecodeError,
        KeyError,
        IndexError,
        AttributeError,
        TimeoutError,
        ConnectionResetError,
    ):
        return fallback_actions


def _render_suggested_actions(actions):
    if not actions:
        return ""
    items = "\n".join(f"<li>{esc(a)}</li>" for a in actions)
    return (
        '<section class="suggested-actions">'
        "<h2>Suggested Actions</h2>"
        f"<ul>{items}</ul>"
        "</section>"
    )


# ---------------------------------------------------------------------------
# VEX candidate helpers
# ---------------------------------------------------------------------------

# Libraries associated with interpreted/scripting runtimes that are typically
# absent from the execution path in statically compiled (Go/Rust/C) workloads.
_INTERP_RUNTIME_LIBS = re.compile(
    r"(python|libpython|ruby|libruby|perl|libperl|nodejs|node\.js|npm|php|libphp"
    r"|lua|liblua|tcl|libtcl|openjdk|java|jre|jdk)",
    re.IGNORECASE,
)

# Libraries that indicate the image contains a Go binary.
_GO_BINARY_INDICATORS = {"stdlib", "k8s.io", "github.com", "golang.org", "google.golang.org"}


def _image_has_go_binaries(findings):
    """Return True if the findings suggest this image contains Go binaries."""
    for f in findings:
        lib = f.get("library", "")
        if lib.lower() == "stdlib":
            return True
        for indicator in _GO_BINARY_INDICATORS:
            if lib.lower().startswith(indicator):
                return True
    return False


def _fallback_vex_candidates(findings_by_image):
    """Generate deterministic VEX candidate suggestions from parsed findings.

    Applies simple heuristics:
    - Interpreter/scripting-runtime libraries (libpython, libruby, …) in images
      whose findings include Go-binary packages (stdlib, k8s.io/…) are likely
      not in the execution path of the workload.
    """
    candidates = []
    for image, findings in findings_by_image.items():
        if not findings:
            continue
        is_go = _image_has_go_binaries(findings)
        if not is_go:
            continue
        for f in findings:
            lib = f.get("library", "")
            if _INTERP_RUNTIME_LIBS.search(lib):
                candidates.append(
                    {
                        "cve": f.get("vulnerability", ""),
                        "image": image,
                        "library": lib,
                        "status": "not_affected",
                        "justification": "vulnerable_code_not_in_execute_path",
                        "note": (
                            f"Library `{lib}` is an interpreted-runtime component "
                            f"not present in the execution path of this statically "
                            f"compiled Go workload."
                        ),
                    }
                )
    return candidates


def _parse_vex_candidates_from_copilot_text(text):
    """Parse the LLM response for VEX candidates.

    Expects a JSON array of objects with keys: cve, image, library, status,
    justification, note.  Returns an empty list on parse failure.
    """
    text = text.strip()
    if not text:
        return []
    # Strip markdown code fences if present
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"```\s*$", "", text, flags=re.MULTILINE)
    text = text.strip()
    try:
        payload = json.loads(text)
        if not isinstance(payload, list):
            return []
        out = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            cve = str(item.get("cve", "")).strip()
            if not cve:
                continue
            out.append(
                {
                    "cve": cve,
                    "image": str(item.get("image", "")).strip(),
                    "library": str(item.get("library", "")).strip(),
                    "status": str(item.get("status", "not_affected")).strip(),
                    "justification": str(item.get("justification", "")).strip(),
                    "note": str(item.get("note", "")).strip(),
                }
            )
        return out
    except json.JSONDecodeError:
        return []


def _copilot_vex_candidates(title, findings_by_image):
    """Ask the LLM to identify likely VEX candidates; fall back to local rules."""
    fallback = _fallback_vex_candidates(findings_by_image)
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        return fallback

    findings_summary = []
    for image, findings in findings_by_image.items():
        if not findings:
            continue
        entries = [
            {
                "cve": f["vulnerability"],
                "library": f["library"],
                "severity": f["severity"],
                "title": f.get("title", ""),
            }
            for f in findings
            if f.get("vulnerability")
        ]
        if entries:
            findings_summary.append({"image": image, "findings": entries[:30]})

    if not findings_summary:
        return fallback

    model = os.getenv("COPILOT_MODEL", "openai/gpt-4.1-mini")
    user_prompt = (
        "Analyze the following Trivy scan findings from a k3s Kubernetes distribution "
        "and identify CVEs that are likely NOT exploitable in a typical k3s installation.\n\n"
        "Focus on:\n"
        "- Base-image OS packages (e.g. libpython, libruby, libperl, liblua, openjdk) present "
        "in images whose workloads are statically compiled Go, Rust, or C binaries — these "
        "libraries are not in the application execution path.\n"
        "- Libraries included in the image layer but never loaded by the container's primary "
        "process (e.g. scripting-language runtimes in a pure-Go service).\n"
        "- CVEs that require an interpreted language runtime to be reachable when no such "
        "runtime is invoked by the workload.\n\n"
        "For each candidate, propose an OpenVEX-compliant statement. "
        "Valid OpenVEX status values: not_affected, affected, fixed, under_investigation. "
        "Valid justification values (from the OpenVEX spec): "
        "component_not_present, vulnerable_code_not_present, "
        "vulnerable_code_not_in_execute_path, "
        "vulnerable_code_cannot_be_controlled_by_adversary, "
        "inline_mitigations_already_exist.\n\n"
        "Return ONLY a JSON array (no markdown, no extra text). Each element must have these "
        "keys: cve, image, library, status, justification, note.\n"
        "Limit your response to the 10 most confident candidates.\n\n"
        f"Report title: {title}\n"
        f"Findings: {json.dumps(findings_summary, ensure_ascii=False)}"
    )
    payload = {
        "model": model,
        "temperature": 0.1,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a container security analyst specialising in OpenVEX and "
                    "k3s/Kubernetes workload analysis. You help teams identify CVEs that "
                    "are not exploitable due to the workload's runtime characteristics, "
                    "following the automation patterns used in rancher/image-scanning. "
                    "Respond only with valid JSON."
                ),
            },
            {"role": "user", "content": user_prompt},
        ],
    }

    req = urllib.request.Request(
        "https://models.github.ai/inference/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
        decoded = json.loads(raw)
        content = (
            decoded.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )
        candidates = _parse_vex_candidates_from_copilot_text(content)
        return candidates if candidates else fallback
    except (
        urllib.error.URLError,
        json.JSONDecodeError,
        KeyError,
        IndexError,
        AttributeError,
        TimeoutError,
        ConnectionResetError,
    ):
        return fallback


def _render_vex_candidates(candidates):
    """Render the Potential VEX Candidates section as an HTML string."""
    if not candidates:
        return ""
    rows = []
    for c in candidates:
        cve = c.get("cve", "")
        cve_link = (
            f'<a href="https://avd.aquasec.com/nvd/{cve.lower()}" '
            f'target="_blank" rel="noopener noreferrer">{esc(cve)}</a>'
            if re.match(r"^CVE-\d{4}-\d+$", cve, re.I)
            else esc(cve)
        )
        image = esc(c.get("image", ""))
        library = esc(c.get("library", ""))
        status = esc(c.get("status", "not_affected"))
        justification = esc(c.get("justification", ""))
        note = esc(c.get("note", ""))
        rows.append(
            f"<tr>"
            f"<td>{cve_link}</td>"
            f'<td><code style="font-size:11px;word-break:break-all">{image}</code></td>'
            f"<td><code>{library}</code></td>"
            f'<td><span class="vex-status">{status}</span></td>'
            f"<td>{justification}</td>"
            f"<td>{note}</td>"
            f"</tr>"
        )
    rows_html = "\n".join(rows)
    return (
        '<section class="vex-candidates">'
        '<h2 id="potential-vex-candidates-automated-recommendations" class="anchored-heading">'
        "Potential VEX Candidates (Automated Recommendations)"
        '<a class="heading-anchor" href="#potential-vex-candidates-automated-recommendations" aria-label="Link to section">#</a>'
        "</h2>"
        '<p class="vex-intro">'
        "The following CVEs may be suitable for "
        '<a href="https://openvex.dev/" target="_blank" rel="noopener noreferrer">OpenVEX</a> '
        "<code>not_affected</code> statements based on workload characteristics. "
        "Review each entry before submitting a formal VEX statement. "
        "Inspired by the <em>auto-vex-*</em> workflows in "
        '<a href="https://github.com/rancher/image-scanning" target="_blank" rel="noopener noreferrer">'
        "rancher/image-scanning</a>."
        "</p>"
        '<div class="table-wrap"><details class="table-collapsible" open>'
        f'<summary><span class="toggle-label">Potential VEX Candidates ({len(candidates)} rows)</span></summary>'
        '<table class="report-table">'
        "<thead><tr>"
        "<th>CVE</th>"
        "<th>Image</th>"
        "<th>Library</th>"
        "<th>Proposed Status</th>"
        "<th>Justification</th>"
        "<th>Note</th>"
        "</tr></thead>"
        f"<tbody>{rows_html}</tbody>"
        "</table>"
        "</details></div>"
        "</section>"
    )


# ---------------------------------------------------------------------------
# Full HTML document builder
# ---------------------------------------------------------------------------

_RANCHER_LOGO_SVG = (
    '<svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">'
    '<rect x="1" y="1" width="30" height="30" rx="7" fill="#FFC61C"/>'
    '<text x="16" y="21" font-family="Poppins, sans-serif" font-size="13" '
    'font-weight="700" fill="#1B1F2A" text-anchor="middle">k3s</text>'
    '</svg>'
)


def build_html(title, body_html, source_filename, subtitle="— Report"):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{esc(title)}</title>
  <style>{CSS}</style>
  {_THEME_HEAD_SCRIPT}
</head>
<body>
  <header class="page-header">
    <div class="brand">
      {_RANCHER_LOGO_SVG}
      K3s CVEs
    </div>
    <span class="subtitle">{esc(subtitle)}</span>
    {_THEME_TOGGLE_HTML}
  </header>
  <main class="page-content">
    {body_html}
    <div class="page-footer">
      Generated from <code>{esc(source_filename)}</code> &nbsp;·&nbsp; {esc(now)}
    </div>
  </main>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _insert_cve_trend_chart(body_html, input_path, source_group=None, scope_label=None):
    """Insert the interactive CVE trend chart into a converted scan report.

    The chart is placed immediately before the ``CVE Delta vs Previous Scan``
    section (both live in the Summary block) so the historical trend sits next
    to the single-step delta. When that heading is absent the chart is appended
    after the first ``</h1>`` so it still appears near the top of the report.

    When *source_group* is provided the trend is filtered to scans of that same
    type (branch / release minor version / PR) instead of all recent scans.
    """
    history = _cve_trend_history_from_db(input_path, source_group=source_group)
    chart = render_cve_trend_chart(history, scope_label=scope_label)

    anchor = '<h3 id="cve-delta-vs-previous-scan"'
    idx = body_html.find(anchor)
    if idx != -1:
        return body_html[:idx] + chart + body_html[idx:]

    h1_end = body_html.find("</h1>")
    if h1_end != -1:
        h1_end += len("</h1>")
        return body_html[:h1_end] + chart + body_html[h1_end:]

    return chart + body_html


def _insert_optional_cve_trend_chart(body_html, input_path, source_group=None, scope_label=None):
    """Insert the optional add-on CVE trend chart into the optional section.

    The chart mirrors the default-image trend chart but plots the optional
    add-on CVE counts. It is placed immediately before the ``Optional CVEs by
    Severity`` heading so the historical trend sits at the top of the optional
    section. When the optional section is absent the body is returned unchanged.

    When *source_group* is provided the trend is filtered to scans of that same
    type instead of all recent scans.
    """
    if 'id="optional-images"' not in body_html:
        return body_html

    history = _optional_cve_trend_history_from_db(input_path, source_group=source_group)
    chart = render_cve_trend_chart(
        history,
        chart_id="optional-cve-trend",
        heading_title="Optional CVE Trend Over Time",
        heading_anchor="optional-cve-trend-over-time",
        subtitle_subject="Critical &amp; High CVE counts for optional add-on images",
        empty_message=(
            "No historical optional add-on scan metrics are available yet to "
            "plot a trend."
        ),
        scope_label=scope_label,
    )

    anchor = '<h3 id="optional-cves-by-severity"'
    idx = body_html.find(anchor)
    if idx != -1:
        return body_html[:idx] + chart + body_html[idx:]

    # Fall back to the top of the optional body when the heading is absent.
    open_marker = '<div class="optional-body">'
    oidx = body_html.find(open_marker)
    if oidx != -1:
        oidx += len(open_marker)
        return body_html[:oidx] + chart + body_html[oidx:]

    return body_html


def convert(input_path, output_path=None):
    with open(input_path, encoding="utf-8") as fh:
        content = fh.read()

    basename = os.path.basename(input_path)

    # Detect report type from filename prefix
    if basename.startswith("check-"):
        subtitle = "— Check Images Report"
    else:
        subtitle = "— Trivy Scan Report"

    # Detect format: markdown if first non-blank line starts with #
    first_line = next((l for l in content.splitlines() if l.strip()), "")
    is_markdown = first_line.startswith("#")

    if is_markdown:
        source_group, scope_label = _resolve_scan_source(content, input_path)
        content = _strip_scan_metadata(content)
        if basename.startswith("scan-"):
            content = _augment_scan_summary(content, input_path)
        if not basename.startswith("check-"):
            content = _move_summary_to_top(content)
        body_html = _convert_markdown(content)
        title_match = re.search(r"^# (.+)$", content, re.MULTILINE)
        title = title_match.group(1).strip() if title_match else "Report"
        if basename.startswith("scan-"):
            body_html = _insert_cve_trend_chart(
                body_html, input_path, source_group=source_group, scope_label=scope_label
            )
            body_html = _insert_optional_cve_trend_chart(
                body_html, input_path, source_group=source_group, scope_label=scope_label
            )
            findings_by_image = _extract_scan_findings(content)
            suggested_actions = _copilot_suggested_actions(title, findings_by_image)
            vex_candidates = _copilot_vex_candidates(title, findings_by_image)
            body_html = (
                _render_suggested_actions(suggested_actions)
                + _render_vex_candidates(vex_candidates)
                + body_html
            )
    else:
        body_html = _convert_raw(content)
        title = os.path.splitext(basename)[0]

    full_html = build_html(title, body_html, basename, subtitle)

    if output_path is None:
        base = os.path.splitext(input_path)[0]
        output_path = base + ".html"

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(full_html)

    return output_path


# ---------------------------------------------------------------------------
# Index page generator
# ---------------------------------------------------------------------------

_INDEX_CSS_EXTRA = """
/* ---- Index card grid ---- */
.index-intro {
  color: var(--muted);
  margin-bottom: 32px;
  font-size: 14px;
}
.reports-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 16px;
  margin-top: 16px;
}
.report-card {
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--body-bg);
  padding: 20px 22px;
  display: flex;
  flex-direction: column;
  gap: 8px;
  transition: box-shadow .15s, border-color .15s;
  text-decoration: none;
  color: inherit;
}
.report-card:hover {
  box-shadow: 0 4px 16px rgba(0,0,0,.10);
  border-color: var(--link);
}
.report-card .rc-name {
  font-family: 'Roboto Mono', monospace;
  font-size: 13px;
  font-weight: 500;
  color: var(--link);
  word-break: break-all;
}
.report-card .rc-date {
  font-size: 12px;
  color: var(--muted);
}
.report-card .rc-arrow {
  margin-left: auto;
  color: var(--muted);
  font-size: 16px;
  align-self: flex-start;
}
.rc-header {
  display: flex;
  align-items: flex-start;
  gap: 8px;
}
.empty-state {
  color: var(--muted);
  font-size: 14px;
  padding: 48px 0;
  text-align: center;
}

/* ---- Interactive index trend chart controls ---- */
.index-trend {
  margin-top: 8px;
}
.trend-controls {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 16px 24px;
  margin: 4px 0 16px;
}
.trend-control {
  display: flex;
  align-items: center;
  gap: 8px;
}
.trend-control-label {
  font-size: 12px;
  font-weight: 700;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: .03em;
}
.trend-select {
  font-family: 'Lato', sans-serif;
  font-size: 13px;
  color: var(--body-text);
  background: var(--body-bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 6px 28px 6px 10px;
  cursor: pointer;
  appearance: none;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%236C6C76' stroke-width='1.5' fill='none' stroke-linecap='round'/%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: right 10px center;
}
.trend-select:hover { border-color: var(--link); }
.trend-range {
  display: inline-flex;
  border: 1px solid var(--border);
  border-radius: 6px;
  overflow: hidden;
}
.trend-range-btn {
  font-family: 'Lato', sans-serif;
  font-size: 12px;
  color: var(--body-text);
  background: var(--body-bg);
  border: none;
  border-left: 1px solid var(--border);
  padding: 6px 12px;
  cursor: pointer;
  transition: background .12s, color .12s;
}
.trend-range-btn:first-child { border-left: none; }
.trend-range-btn:hover { background: var(--box-bg); }
.trend-range-btn.active {
  background: var(--link);
  color: #FFFFFF;
}

/* ---- Index toolbar (search) ---- */
.index-toolbar {
  display: flex;
  align-items: center;
  gap: 12px;
  margin: 28px 0 4px;
}
.index-search {
  position: relative;
  flex: 1;
  max-width: 420px;
}
.index-search input {
  width: 100%;
  font-family: 'Lato', sans-serif;
  font-size: 14px;
  color: var(--body-text);
  background: var(--body-bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 9px 12px 9px 36px;
}
.index-search input:focus {
  outline: none;
  border-color: var(--link);
  box-shadow: 0 0 0 3px rgba(31,103,219,.12);
}
.index-search svg {
  position: absolute;
  left: 11px;
  top: 50%;
  transform: translateY(-50%);
  width: 16px;
  height: 16px;
  pointer-events: none;
}
.search-count {
  font-size: 12px;
  color: var(--muted);
  white-space: nowrap;
}

/* ---- Report subsections / badges / collapse ---- */
.report-subsection { margin-top: 22px; }
.report-subsection.is-empty { display: none; }
.report-subhead {
  display: flex;
  align-items: baseline;
  gap: 10px;
  margin: 0 0 8px;
}
.report-subhead h3 {
  font-family: 'Poppins', sans-serif;
  font-size: 14px;
  font-weight: 600;
  margin: 0;
}
.report-subhead .sub-count {
  font-size: 12px;
  color: var(--muted);
}
.report-card .rc-badge {
  display: inline-block;
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .04em;
  padding: 2px 7px;
  border-radius: 999px;
  margin-top: 2px;
  align-self: flex-start;
}
.rc-badge.badge-scheduled { background: var(--sev-low-bg); color: var(--sev-low-text); }
.rc-badge.badge-release { background: var(--status-ok-bg); color: var(--status-ok-text); }
.rc-badge.badge-pr { background: var(--sev-medium-bg); color: var(--sev-medium-text); }
.rc-badge.badge-check { background: var(--box-bg); color: var(--muted); }
.report-card.rc-hidden { display: none; }
.reports-grid .rc-extra { display: none; }
.reports-grid.show-all .rc-extra { display: flex; }
.show-more-btn {
  font-family: 'Lato', sans-serif;
  font-size: 13px;
  font-weight: 700;
  color: var(--link);
  background: none;
  border: none;
  cursor: pointer;
  padding: 10px 2px 0;
}
.show-more-btn:hover { text-decoration: underline; }
.show-more-btn.is-hidden { display: none; }
.no-results {
  color: var(--muted);
  font-size: 14px;
  padding: 24px 0;
  display: none;
}
.no-results.visible { display: block; }

/* ---- Resolved (fixed) CVE stats + mini bar graph ---- */
.trend-resolved {
  margin-top: 18px;
  padding-top: 16px;
  border-top: 1px solid var(--border);
}
.trend-resolved-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 12px;
}
.trend-resolved-head h3 {
  font-family: 'Poppins', sans-serif;
  font-size: 14px;
  font-weight: 600;
  margin: 0;
}
.trend-resolved-head .chart-subtitle { margin: 0; }
.resolved-stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
  margin-bottom: 14px;
}
.resolved-stat {
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--box-bg);
  padding: 12px 14px;
}
.resolved-stat .rs-value {
  font-family: 'Poppins', sans-serif;
  font-size: 26px;
  font-weight: 600;
  line-height: 1.1;
  display: flex;
  align-items: baseline;
  gap: 6px;
}
.resolved-stat .rs-label {
  font-size: 12px;
  color: var(--muted);
  margin-top: 4px;
}
.resolved-stat.stat-resolved .rs-value { color: var(--status-ok-bg); }
.resolved-stat.stat-introduced .rs-value { color: var(--sev-high-bg); }
.resolved-stat .rs-trend { font-size: 13px; font-weight: 600; }
.rs-trend.trend-down { color: var(--status-ok-bg); }
.rs-trend.trend-up { color: var(--sev-critical-bg); }
.rs-trend.trend-flat { color: var(--muted); }
.resolved-bars-figure { position: relative; }
.resolved-bars-svg {
  width: 100%;
  height: auto;
  display: block;
  overflow: visible;
  font-family: 'Lato', sans-serif;
}
.resolved-bars-svg .grid-line { stroke: var(--border); stroke-width: 1; }
.resolved-bars-svg .axis-line { stroke: var(--border); stroke-width: 1; }
.resolved-bars-svg .axis-label { fill: var(--muted); font-size: 10px; }
.resolved-bars-svg .resolved-bar {
  fill: var(--status-ok-bg);
  cursor: pointer;
  transition: fill .1s ease;
}
.resolved-bars-svg .resolved-bar:hover { fill: var(--status-ok-border); }
.resolved-bars-empty {
  color: var(--muted);
  font-size: 13px;
  padding: 10px 0;
}
"""


def _parse_date_from_filename(name):
    """
    Try to parse a date from filenames like scan-20260515-1.html.
    Returns a datetime or datetime.min so sorting always works.
    """
    m = re.search(r"(\d{8})", name)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y%m%d")
        except ValueError:
            pass
    return datetime.min


# Range presets offered by the interactive index chart. ``count`` keeps the
# last N scans (matching the per-report chart's default); ``days`` keeps scans
# within N days of the selected series' most recent scan.
_INDEX_TREND_RANGES = (
    ("30", "Last 30 scans", "count", 30, True),
    ("1m", "1M", "days", 30, False),
    ("3m", "3M", "days", 90, False),
    ("6m", "6M", "days", 180, False),
    ("1y", "1Y", "days", 365, False),
)


def _index_trend_dataset(html_dir):
    """Build the per-source CVE history dataset embedded in the index page.

    Reads every row from the metrics DB and buckets it by source group (see
    :func:`_scan_source_group`) so the client-side chart can switch between
    branches / release lines. Returns ``None`` when the DB is missing/unreadable
    or holds no usable rows. The returned structure is intentionally compact::

        {"default": "branch:master",
         "groups": [{"key": ..., "label": ..., "points": [[iso, desc, crit, high], ...]}]}

    ``points`` are oldest-first so the chart reads left-to-right in time.
    """
    db_path = _metrics_db_path(os.path.join(html_dir, "index.html"))
    if not db_path:
        return None
    try:
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT scanned_at, source_ref, source_desc, critical_cves, high_cves
                FROM scan_metrics
                ORDER BY scanned_at ASC, id ASC
                """
            )
            rows = cur.fetchall()
    except sqlite3.Error:
        return None

    groups = {}
    order = []
    for scanned_at, source_ref, source_desc, critical, high in rows:
        grp, label = _scan_source_group(source_ref)
        if grp is None:
            grp, label = "other", "Other scans"
        try:
            crit = int(critical)
            hi = int(high)
        except (TypeError, ValueError):
            continue
        if grp not in groups:
            groups[grp] = {"key": grp, "label": label or grp, "points": []}
            order.append(grp)
        groups[grp]["points"].append(
            [scanned_at or "", source_desc or label or "", crit, hi]
        )

    if not order:
        return None

    # Default to the master branch when present, else the busiest series.
    default_key = "branch:master" if "branch:master" in groups else max(
        order, key=lambda k: len(groups[k]["points"])
    )

    # Default series first, then most-populated series, then alphabetical.
    ordered = sorted(
        (groups[k] for k in order),
        key=lambda g: (g["key"] != default_key, -len(g["points"]), g["label"].lower()),
    )
    return {"default": default_key, "groups": ordered}


def _render_index_trend_section(dataset):
    """Render the interactive CVE trend section (controls + chart shell + data).

    The chart itself is drawn client-side by :data:`_INDEX_TREND_SCRIPT` from
    the embedded JSON so the source and history-range selectors can redraw it
    without a page reload. Returns an empty string when no data is available so
    the index simply omits the section.
    """
    if not dataset or not dataset.get("groups"):
        return ""

    options = []
    for grp in dataset["groups"]:
        sel = " selected" if grp["key"] == dataset["default"] else ""
        options.append(
            f'<option value="{esc(grp["key"])}"{sel}>{esc(grp["label"])}</option>'
        )

    range_btns = []
    for rid, label, mode, value, active in _INDEX_TREND_RANGES:
        cls = "trend-range-btn active" if active else "trend-range-btn"
        range_btns.append(
            f'<button type="button" class="{cls}" data-range="{esc(rid)}" '
            f'data-mode="{mode}" data-value="{value}" '
            f'aria-pressed="{"true" if active else "false"}">{esc(label)}</button>'
        )

    legend_items = []
    for key, label, colour in _TREND_SERIES:
        legend_items.append(
            f'<span class="legend-item" data-series="{key}" role="button" '
            f'tabindex="0" aria-pressed="true">'
            f'<span class="legend-swatch" style="background:{colour}"></span>'
            f"{esc(label)}</span>"
        )

    data_json = json.dumps(dataset, separators=(",", ":"))

    return (
        '<section class="cve-trend index-trend" id="index-cve-trend">'
        '<h2 id="cve-trends" class="anchored-heading">CVE Trends'
        '<a class="heading-anchor" href="#cve-trends" aria-label="Link to section">#</a>'
        "</h2>"
        '<p class="chart-subtitle" id="index-trend-subtitle"></p>'
        '<div class="trend-controls">'
        '<div class="trend-control">'
        '<label class="trend-control-label" for="trend-source-select">Source</label>'
        '<select class="trend-select" id="trend-source-select" '
        'aria-label="Scan source">'
        + "".join(options)
        + "</select></div>"
        '<div class="trend-control">'
        '<span class="trend-control-label">History</span>'
        '<div class="trend-range" role="group" aria-label="History range">'
        + "".join(range_btns)
        + "</div></div></div>"
        '<div class="cve-trend-figure">'
        '<div class="index-trend-canvas"></div>'
        '<div class="cve-trend-tooltip" aria-hidden="true"></div>'
        "</div>"
        '<div class="cve-trend-legend">' + "".join(legend_items) + "</div>"
        '<div class="trend-resolved">'
        '<div class="trend-resolved-head">'
        '<h3 id="cves-resolved">CVEs Resolved</h3>'
        '<p class="chart-subtitle" id="resolved-subtitle"></p>'
        "</div>"
        '<div class="resolved-stats" id="resolved-stats"></div>'
        '<div class="resolved-bars-figure">'
        '<div class="resolved-bars-canvas"></div>'
        '<div class="cve-trend-tooltip" id="resolved-tooltip" aria-hidden="true"></div>'
        "</div>"
        "</div>"
        f'<script type="application/json" id="index-trend-data">{data_json}</script>'
        f"{_INDEX_TREND_SCRIPT}"
        "</section>"
    )


# Client-side renderer for the interactive index trend chart. Mirrors the
# geometry of render_cve_trend_chart() but redraws on source/range changes.
_INDEX_TREND_SCRIPT = """<script>
(function () {
  var SERIES = [
    { key: "total",    name: "Total (Critical + High)", color: "#1F67DB",
      val: function (p) { return p[2] + p[3]; } },
    { key: "critical", name: "Critical", color: "#B13333",
      val: function (p) { return p[2]; } },
    { key: "high",     name: "High", color: "#E45C1E",
      val: function (p) { return p[3]; } }
  ];

  function esc(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function fmtDate(iso) { return iso ? String(iso).slice(0, 10) : ""; }
  function dayMs(iso) { return Date.parse(String(iso).slice(0, 10) + "T00:00:00Z"); }

  function filterPoints(all, mode, value) {
    if (!all.length) return all;
    if (mode === "count") return all.slice(Math.max(0, all.length - value));
    var ref = dayMs(all[all.length - 1][0]);
    var cutoff = ref - value * 86400000;
    return all.filter(function (p) { return dayMs(p[0]) >= cutoff; });
  }

  function buildSvg(points, hidden) {
    var W = 760, H = 300, pl = 48, pr = 20, pt = 24, pb = 56;
    var pw = W - pl - pr, ph = H - pt - pb, n = points.length;
    var maxVal = 0;
    points.forEach(function (p) { var t = p[2] + p[3]; if (t > maxVal) maxVal = t; });
    if (maxVal <= 0) maxVal = 1;
    var step = Math.max(1, Math.ceil(maxVal / 4));
    var yMax = step * 4;
    function xFor(i) { return n === 1 ? pl + pw / 2 : pl + pw * i / (n - 1); }
    function yFor(v) { return pt + ph * (1 - v / yMax); }

    var out = ['<svg class="cve-trend-svg" viewBox="0 0 ' + W + ' ' + H +
      '" role="img" aria-label="CVE counts over recent scans" ' +
      'preserveAspectRatio="xMidYMid meet">'];

    for (var k = 0; k < 5; k++) {
      var val = yMax - step * k, y = yFor(val);
      out.push('<line class="grid-line" x1="' + pl + '" y1="' + y.toFixed(1) +
        '" x2="' + (pl + pw) + '" y2="' + y.toFixed(1) + '"></line>');
      out.push('<text class="axis-label" x="' + (pl - 8) + '" y="' +
        (y + 3).toFixed(1) + '" text-anchor="end">' + val + "</text>");
    }
    var baseY = yFor(0);
    out.push('<line class="axis-line" x1="' + pl + '" y1="' + baseY.toFixed(1) +
      '" x2="' + (pl + pw) + '" y2="' + baseY.toFixed(1) + '"></line>');

    var maxTicks = 8, every = Math.max(1, Math.ceil(n / maxTicks));
    points.forEach(function (p, i) {
      if (i % every && i !== n - 1) return;
      var x = xFor(i);
      out.push('<text class="axis-label" x="' + x.toFixed(1) + '" y="' +
        (baseY + 16).toFixed(1) + '" text-anchor="middle">' +
        esc(fmtDate(p[0])) + "</text>");
    });

    SERIES.forEach(function (s) {
      var off = hidden[s.key] ? " series-hidden" : "";
      var pts = points.map(function (p, i) { return [xFor(i), yFor(s.val(p))]; });
      if (pts.length >= 2) {
        var d = pts.map(function (xy) {
          return xy[0].toFixed(1) + "," + xy[1].toFixed(1);
        }).join(" ");
        out.push('<polyline class="series-line series-' + s.key + off +
          '" data-series="' + s.key + '" points="' + d +
          '" stroke="' + s.color + '"></polyline>');
      }
      pts.forEach(function (xy, i) {
        var p = points[i];
        var src = p[1] || "";
        var tip = src ? fmtDate(p[0]) + " \\u00b7 " + src : fmtDate(p[0]);
        out.push('<circle class="series-point series-' + s.key + off +
          '" data-series="' + s.key + '" cx="' + xy[0].toFixed(1) +
          '" cy="' + xy[1].toFixed(1) + '" r="3.5" fill="' + s.color +
          '" data-label="' + esc(tip) + '" data-series-name="' + esc(s.name) +
          '" data-value="' + s.val(p) + '"></circle>');
      });
    });

    out.push("</svg>");
    return out.join("");
  }

  function total(p) { return p[2] + p[3]; }

  // Derive "resolved" CVEs from the drop in Critical+High between consecutive
  // scans. resolved sums the per-step decreases, introduced sums the increases,
  // and net is the overall change across the window (positive = net reduction).
  function computeResolved(points) {
    var resolved = 0, introduced = 0, events = [];
    for (var i = 1; i < points.length; i++) {
      var delta = total(points[i - 1]) - total(points[i]);
      if (delta > 0) resolved += delta;
      else if (delta < 0) introduced += -delta;
      events.push({ point: points[i], fixed: delta > 0 ? delta : 0 });
    }
    var net = points.length ? total(points[0]) - total(points[points.length - 1]) : 0;
    return { resolved: resolved, introduced: introduced, net: net, events: events };
  }

  function buildResolvedBars(events) {
    if (!events.length) {
      return '<p class="resolved-bars-empty">Need at least two scans in this ' +
        'range to chart resolved CVEs.</p>';
    }
    var W = 760, H = 150, pl = 48, pr = 20, pt = 16, pb = 40;
    var pw = W - pl - pr, ph = H - pt - pb, n = events.length;
    var maxVal = 0;
    events.forEach(function (e) { if (e.fixed > maxVal) maxVal = e.fixed; });
    if (maxVal <= 0) maxVal = 1;
    var step = Math.max(1, Math.ceil(maxVal / 4));
    var yMax = step * 4;
    var slot = pw / n;
    var bw = Math.max(2, Math.min(22, slot * 0.6));
    function yFor(v) { return pt + ph * (1 - v / yMax); }

    var out = ['<svg class="resolved-bars-svg" viewBox="0 0 ' + W + ' ' + H +
      '" role="img" aria-label="CVEs resolved per scan" ' +
      'preserveAspectRatio="xMidYMid meet">'];
    for (var k = 0; k < 5; k++) {
      var val = yMax - step * k, y = yFor(val);
      out.push('<line class="grid-line" x1="' + pl + '" y1="' + y.toFixed(1) +
        '" x2="' + (pl + pw) + '" y2="' + y.toFixed(1) + '"></line>');
      out.push('<text class="axis-label" x="' + (pl - 8) + '" y="' +
        (y + 3).toFixed(1) + '" text-anchor="end">' + val + "</text>");
    }
    var baseY = yFor(0);
    out.push('<line class="axis-line" x1="' + pl + '" y1="' + baseY.toFixed(1) +
      '" x2="' + (pl + pw) + '" y2="' + baseY.toFixed(1) + '"></line>');

    var every = Math.max(1, Math.ceil(n / 8));
    events.forEach(function (e, i) {
      var cx = pl + slot * (i + 0.5);
      if (e.fixed > 0) {
        var y = yFor(e.fixed);
        var src = e.point[1] || "";
        var tipTxt = fmtDate(e.point[0]) + (src ? " \\u00b7 " + src : "");
        out.push('<rect class="resolved-bar" x="' + (cx - bw / 2).toFixed(1) +
          '" y="' + y.toFixed(1) + '" width="' + bw.toFixed(1) +
          '" height="' + (baseY - y).toFixed(1) + '" rx="2" ' +
          'data-label="' + esc(tipTxt) + '" data-value="' + e.fixed +
          '"></rect>');
      }
      if (i % every === 0 || i === n - 1) {
        out.push('<text class="axis-label" x="' + cx.toFixed(1) + '" y="' +
          (baseY + 15).toFixed(1) + '" text-anchor="middle">' +
          esc(fmtDate(e.point[0])) + "</text>");
      }
    });
    out.push("</svg>");
    return out.join("");
  }

  function initIndexTrend(section) {
    var dataEl = document.getElementById("index-trend-data");
    if (!dataEl) return;
    var data;
    try { data = JSON.parse(dataEl.textContent); } catch (e) { return; }
    var byKey = {};
    data.groups.forEach(function (g) { byKey[g.key] = g; });

    var select = section.querySelector("#trend-source-select");
    var rangeBtns = Array.prototype.slice.call(
      section.querySelectorAll(".trend-range-btn"));
    var canvas = section.querySelector(".index-trend-canvas");
    var figure = section.querySelector(".cve-trend-figure");
    var tip = section.querySelector(".cve-trend-tooltip");
    var subtitle = section.querySelector("#index-trend-subtitle");
    var resolvedStats = section.querySelector("#resolved-stats");
    var resolvedCanvas = section.querySelector(".resolved-bars-canvas");
    var resolvedFigure = section.querySelector(".resolved-bars-figure");
    var resolvedTip = section.querySelector("#resolved-tooltip");
    var resolvedSubtitle = section.querySelector("#resolved-subtitle");
    if (!select || !canvas || !figure || !tip) return;

    var hidden = { total: false, critical: false, high: false };
    var current = data.default;
    var range = { mode: "count", value: 30 };

    function attachTips() {
      section.querySelectorAll(".series-point").forEach(function (point) {
        point.addEventListener("mouseenter", function () {
          tip.innerHTML = '<div class="tt-date">' +
            (point.getAttribute("data-label") || "") + "</div>" +
            (point.getAttribute("data-series-name") || "") + ": " +
            (point.getAttribute("data-value") || "");
          var fr = figure.getBoundingClientRect();
          var pgr = point.getBoundingClientRect();
          tip.style.left = (pgr.left - fr.left + pgr.width / 2) + "px";
          tip.style.top = (pgr.top - fr.top) + "px";
          tip.classList.add("visible");
        });
        point.addEventListener("mouseleave", function () {
          tip.classList.remove("visible");
        });
      });
    }

    function attachResolvedTips() {
      if (!resolvedFigure || !resolvedTip) return;
      section.querySelectorAll(".resolved-bar").forEach(function (bar) {
        bar.addEventListener("mouseenter", function () {
          var v = bar.getAttribute("data-value") || "0";
          resolvedTip.innerHTML = '<div class="tt-date">' +
            (bar.getAttribute("data-label") || "") + "</div>" +
            v + " resolved";
          var fr = resolvedFigure.getBoundingClientRect();
          var br = bar.getBoundingClientRect();
          resolvedTip.style.left = (br.left - fr.left + br.width / 2) + "px";
          resolvedTip.style.top = (br.top - fr.top) + "px";
          resolvedTip.classList.add("visible");
        });
        bar.addEventListener("mouseleave", function () {
          resolvedTip.classList.remove("visible");
        });
      });
    }

    function renderResolved(pts, label) {
      if (!resolvedStats || !resolvedCanvas) return;
      var stats = computeResolved(pts);
      var netCls, netArrow, netText;
      if (stats.net > 0) {
        netCls = "trend-down"; netArrow = "\\u2193";
        netText = stats.net + " fewer";
      } else if (stats.net < 0) {
        netCls = "trend-up"; netArrow = "\\u2191";
        netText = (-stats.net) + " more";
      } else {
        netCls = "trend-flat"; netArrow = "\\u2192"; netText = "no change";
      }
      resolvedStats.innerHTML =
        '<div class="resolved-stat stat-resolved"><div class="rs-value">' +
          stats.resolved + '</div><div class="rs-label">CVEs resolved ' +
          '(Critical + High)</div></div>' +
        '<div class="resolved-stat stat-introduced"><div class="rs-value">' +
          stats.introduced + '</div><div class="rs-label">New CVEs ' +
          'introduced</div></div>' +
        '<div class="resolved-stat"><div class="rs-value">' +
          '<span class="rs-trend ' + netCls + '">' + netArrow + '</span>' +
          Math.abs(stats.net) + '</div><div class="rs-label">Net change ' +
          '(' + netText + ')</div></div>';
      resolvedCanvas.innerHTML = buildResolvedBars(stats.events);
      attachResolvedTips();
      if (resolvedSubtitle) {
        resolvedSubtitle.textContent = pts.length > 1
          ? "Resolved per scan for " + label +
            ", derived from drops in Critical + High counts between scans."
          : "";
      }
    }

    function render() {
      var group = byKey[current] || data.groups[0];
      var pts = filterPoints(group.points, range.mode, range.value);
      if (!pts.length) {
        canvas.innerHTML = '<p class="cve-trend-empty">' +
          'No scans for this source in the selected range.</p>';
        if (subtitle) subtitle.textContent = "";
        if (resolvedStats) resolvedStats.innerHTML = "";
        if (resolvedCanvas) {
          resolvedCanvas.innerHTML = '<p class="resolved-bars-empty">' +
            'No scans for this source in the selected range.</p>';
        }
        if (resolvedSubtitle) resolvedSubtitle.textContent = "";
        return;
      }
      canvas.innerHTML = buildSvg(pts, hidden);
      attachTips();
      if (subtitle) {
        subtitle.textContent = "Critical & High CVE counts for " + group.label +
          " across the last " + pts.length + " scan" +
          (pts.length === 1 ? "" : "s") +
          ". Hover a point for details; click a legend entry to toggle a series.";
      }
      renderResolved(pts, group.label);
    }

    select.addEventListener("change", function () {
      current = select.value;
      render();
    });

    rangeBtns.forEach(function (btn) {
      btn.addEventListener("click", function () {
        rangeBtns.forEach(function (b) {
          b.classList.remove("active");
          b.setAttribute("aria-pressed", "false");
        });
        btn.classList.add("active");
        btn.setAttribute("aria-pressed", "true");
        range = {
          mode: btn.getAttribute("data-mode"),
          value: parseInt(btn.getAttribute("data-value"), 10)
        };
        render();
      });
    });

    function toggleSeries(item) {
      var key = item.getAttribute("data-series");
      hidden[key] = !hidden[key];
      item.classList.toggle("legend-off", hidden[key]);
      item.setAttribute("aria-pressed", hidden[key] ? "false" : "true");
      section.querySelectorAll('[data-series="' + key + '"].series-line, ' +
        '[data-series="' + key + '"].series-point').forEach(function (el) {
        el.classList.toggle("series-hidden", hidden[key]);
      });
    }
    section.querySelectorAll(".legend-item").forEach(function (item) {
      item.addEventListener("click", function () { toggleSeries(item); });
      item.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          toggleSeries(item);
        }
      });
    });

    render();
  }

  function boot() {
    var section = document.getElementById("index-cve-trend");
    if (section) initIndexTrend(section);
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
</script>"""


# Client-side search + collapse behaviour for the report card lists.
_INDEX_LIST_SCRIPT = """<script>
(function () {
  var input = document.getElementById("report-search");
  var countEl = document.getElementById("search-count");
  var cards = Array.prototype.slice.call(document.querySelectorAll(".report-card"));
  var subsections = Array.prototype.slice.call(
    document.querySelectorAll(".report-subsection"));
  var noResults = document.getElementById("no-results");

  document.querySelectorAll(".reports-grid").forEach(function (grid) {
    var limit = parseInt(grid.getAttribute("data-collapse") || "0", 10);
    if (!limit) return;
    var items = Array.prototype.slice.call(grid.querySelectorAll(".report-card"));
    if (items.length <= limit) return;
    items.slice(limit).forEach(function (c) { c.classList.add("rc-extra"); });
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "show-more-btn";
    btn.textContent = "Show all " + items.length + " reports";
    btn.addEventListener("click", function () {
      var open = grid.classList.toggle("show-all");
      btn.textContent = open ? "Show fewer reports"
        : "Show all " + items.length + " reports";
    });
    grid.parentNode.insertBefore(btn, grid.nextSibling);
    grid._showMoreBtn = btn;
  });

  function apply() {
    var q = (input ? input.value : "").trim().toLowerCase();
    var visible = 0;
    cards.forEach(function (card) {
      var hay = card.getAttribute("data-name") || "";
      var match = !q || hay.indexOf(q) !== -1;
      card.classList.toggle("rc-hidden", !match);
      if (match) visible++;
    });
    subsections.forEach(function (sec) {
      var any = sec.querySelectorAll(".report-card:not(.rc-hidden)").length > 0;
      sec.classList.toggle("is-empty", !any);
    });
    // While searching, reveal collapsed matches and hide the toggles.
    document.querySelectorAll(".reports-grid").forEach(function (grid) {
      if (!grid._showMoreBtn) return;
      if (q) {
        grid.classList.add("show-all");
        grid._showMoreBtn.classList.add("is-hidden");
      } else {
        grid.classList.remove("show-all");
        grid._showMoreBtn.classList.remove("is-hidden");
        grid._showMoreBtn.textContent = "Show all " +
          grid.querySelectorAll(".report-card").length + " reports";
      }
    });
    if (countEl) {
      countEl.textContent = q
        ? visible + " of " + cards.length + " match"
        : cards.length + " reports";
    }
    if (noResults) noResults.classList.toggle("visible", q && visible === 0);
  }

  if (input) input.addEventListener("input", apply);
  apply();
})();
</script>"""


def generate_index(html_dir):
    """
    Scan *html_dir* for *.html files (excluding index.html itself) and write a
    styled index.html. The page leads with an interactive CVE trend chart
    (source- and history-range selectable, defaulting to the master branch and
    the last 30 scans) followed by searchable, categorized report lists:
    Trivy scan reports (scheduled / release / PR) and check-images reports.

    Returns the path of the written index file.
    """
    html_dir = os.path.abspath(html_dir)
    all_entries = sorted(
        [
            f
            for f in os.listdir(html_dir)
            if f.endswith(".html") and f != "index.html"
        ],
        key=lambda f: (_parse_date_from_filename(f), f),
        reverse=True,
    )

    scan_entries = [f for f in all_entries if f.startswith("scan-")]
    check_entries = [f for f in all_entries if f.startswith("check-")]
    pr_entries = [f for f in all_entries if re.match(r"pr-\d+", f)]

    # Split Trivy scans by provenance so release lines aren't buried among the
    # daily scheduled runs.
    release_scans = [f for f in scan_entries if not re.match(r"scan-\d{8}-\d+", f)]
    scheduled_scans = [f for f in scan_entries if re.match(r"scan-\d{8}-\d+", f)]

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    _BADGES = {
        "scheduled": ("badge-scheduled", "Scheduled"),
        "release": ("badge-release", "Release"),
        "pr": ("badge-pr", "PR"),
        "check": ("badge-check", "Check"),
    }

    def _make_card(fname, kind):
        m = re.search(r"(\d{8})", fname)
        date_str = ""
        if m:
            try:
                date_str = datetime.strptime(m.group(1), "%Y%m%d").strftime(
                    "%B %d, %Y"
                )
            except ValueError:
                pass

        stem = os.path.splitext(fname)[0]
        badge_cls, badge_label = _BADGES.get(kind, ("badge-check", kind.title()))
        search_key = f"{stem} {date_str} {badge_label}".lower()
        return (
            f'<a class="report-card" href="{esc(fname)}" '
            f'data-name="{esc(search_key)}">'
            f'<div class="rc-header">'
            f"<div>"
            f'<div class="rc-name">{esc(stem)}</div>'
            + (f'<div class="rc-date">{esc(date_str)}</div>' if date_str else "")
            + f'<span class="rc-badge {badge_cls}">{esc(badge_label)}</span>'
            f"</div>"
            f'<span class="rc-arrow">&#8594;</span>'
            f"</div>"
            f"</a>"
        )

    def _subsection(title, entries, kind, collapse=12):
        if not entries:
            return ""
        cards = "\n".join(_make_card(f, kind) for f in entries)
        count = len(entries)
        attr = f' data-collapse="{collapse}"' if count > collapse else ""
        return (
            '<div class="report-subsection">'
            '<div class="report-subhead">'
            f"<h3>{esc(title)}</h3>"
            f'<span class="sub-count">{count}</span>'
            "</div>"
            f'<div class="reports-grid"{attr}>\n{cards}\n</div>'
            "</div>"
        )

    def _section(title, anchor, subsections, empty_msg):
        inner = "".join(subsections)
        if not inner.strip():
            inner = f'<p class="empty-state">{esc(empty_msg)}</p>'
        return (
            f'<h2 id="{esc(anchor)}" class="anchored-heading">{esc(title)}'
            f'<a class="heading-anchor" href="#{esc(anchor)}" '
            'aria-label="Link to section">#</a></h2>'
            f"{inner}"
        )

    total_reports = len(scan_entries) + len(check_entries) + len(pr_entries)

    toolbar = (
        '<div class="index-toolbar">'
        '<div class="index-search">'
        '<svg viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">'
        '<circle cx="7" cy="7" r="5" stroke="#6C6C76" stroke-width="1.5"/>'
        '<path d="M11 11l4 4" stroke="#6C6C76" stroke-width="1.5" '
        'stroke-linecap="round"/></svg>'
        '<input type="search" id="report-search" '
        'placeholder="Filter reports by name, date, or type\u2026" '
        'aria-label="Filter reports" autocomplete="off">'
        "</div>"
        f'<span class="search-count" id="search-count">{total_reports} reports</span>'
        "</div>"
        '<p class="no-results" id="no-results">No reports match your search.</p>'
    )

    trivy_section = _section(
        "Trivy Scan Reports",
        "trivy-scan-reports",
        [
            _subsection("Scheduled scans", scheduled_scans, "scheduled"),
            _subsection("Release scans", release_scans, "release"),
            _subsection("Pull request scans", pr_entries, "pr"),
        ],
        "No scan reports found yet.",
    )
    body_html = (
        "<h1>K3s CVE Reports</h1>\n"
        + _render_index_trend_section(_index_trend_dataset(html_dir))
        + "\n"
        + toolbar
        + "\n"
        + trivy_section
        + f'\n<div class="page-footer">Index generated &nbsp;·&nbsp; {esc(now)}</div>'
        + _INDEX_LIST_SCRIPT
    )

    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>K3s CVEs — Reports</title>
  <style>{CSS}{_INDEX_CSS_EXTRA}</style>
  {_THEME_HEAD_SCRIPT}
</head>
<body>
  <header class="page-header">
    <div class="brand">
      {_RANCHER_LOGO_SVG}
      K3s CVEs
    </div>
    <span class="subtitle">— Reports</span>
    {_THEME_TOGGLE_HTML}
  </header>
  <main class="page-content">
    {body_html}
  </main>
</body>
</html>"""

    index_path = os.path.join(html_dir, "index.html")
    with open(index_path, "w", encoding="utf-8") as fh:
        fh.write(full_html)

    return index_path


def main():
    if len(sys.argv) < 2:
        print(
            f"Usage: {sys.argv[0]} <scan-file.md> [output.html]\n"
            f"       {sys.argv[0]} --index <html-dir>",
            file=sys.stderr,
        )
        sys.exit(1)

    if sys.argv[1] == "--index":
        if len(sys.argv) < 3:
            print(f"Usage: {sys.argv[0]} --index <html-dir>", file=sys.stderr)
            sys.exit(1)
        html_dir = sys.argv[2]
        if not os.path.isdir(html_dir):
            print(f"Error: directory not found: {html_dir}", file=sys.stderr)
            sys.exit(1)
        out = generate_index(html_dir)
        print(f"Index written to: {out}")
        return

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    if not os.path.isfile(input_file):
        print(f"Error: file not found: {input_file}", file=sys.stderr)
        sys.exit(1)

    out = convert(input_file, output_file)
    print(f"HTML report written to: {out}")


if __name__ == "__main__":
    main()
