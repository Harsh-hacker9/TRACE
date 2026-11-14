// Builds the downloadable report: one self-contained HTML file, no scripts,
// no external assets, printable to PDF. Everything is escaped because findings
// quote headers and source lines from the scanned target.

import type { Attack } from './attacks'
import {
  type CategoryScore,
  type Finding,
  SEVERITIES,
  type ScanResult,
  type Severity,
  attackMatrix,
  categoryScores,
  countBySeverity,
} from './audit'

const ESCAPES: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }
const esc = (value: unknown) => String(value ?? '').replace(/[&<>"']/g, (char) => ESCAPES[char])

const SEV_COLOR: Record<Severity, string> = {
  critical: '#be123c',
  high: '#b45309',
  medium: '#6d28d9',
  low: '#475569',
  info: '#6b7280',
}

const dateOf = (timestamp: number) =>
  new Date(timestamp).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' }) + ' UTC'

export function reportFilename(result: ScanResult) {
  const host = (() => {
    try {
      return new URL(result.finalUrl ?? result.target).host
    } catch {
      return result.target
    }
  })()
  const safe = host.replace(/[^a-z0-9.-]+/gi, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'scan'
  const date = new Date(result.scannedAt).toISOString().slice(0, 10)
  return `trace-report-${safe}-${date}.html`
}

function scoreRow(item: CategoryScore) {
  const color = item.worst ? SEV_COLOR[item.worst] : '#16a34a'
  return `<tr>
    <td class="cat">${esc(item.category)}</td>
    <td class="bar-cell"><span class="bar"><span style="width:${item.score}%;background:${color}"></span></span></td>
    <td class="num">${item.score}</td>
    <td class="muted">${item.findings === 0 ? 'clean' : `${item.findings} finding${item.findings === 1 ? '' : 's'}`}</td>
  </tr>`
}

function findingBlock(finding: Finding, index: number) {
  const color = SEV_COLOR[finding.severity]
  return `<article class="finding" id="finding-${index + 1}">
    <div class="finding-head">
      <span class="sev" style="color:${color};border-color:${color}">${esc(finding.severity)}</span>
      <h3>${esc(finding.title)}</h3>
    </div>
    <p class="meta">${esc(finding.category)}${finding.cwe ? ` · ${esc(finding.cwe)}` : ''}</p>
    <p>${esc(finding.detail)}</p>
    ${
      finding.evidence?.length
        ? `<h4>Evidence</h4><ul class="evidence">${finding.evidence.map((item) => `<li><code>${esc(item)}</code></li>`).join('')}</ul>`
        : ''
    }
    <h4>Attacks this enables</h4>
    <p class="chips">${finding.attacks.map((id) => `<span class="chip">${esc(id.replace(/_/g, ' '))}</span>`).join('')}</p>
    <div class="fix">
      <h4>Fix</h4>
      <p>${esc(finding.fix)}</p>
      ${finding.code ? `<pre><code>${esc(finding.code)}</code></pre>` : ''}
    </div>
  </article>`
}

function attackRow(attack: Attack, exposed: boolean, count: number) {
  return `<tr>
    <td><span class="dot" style="background:${exposed ? SEV_COLOR[attack.severity] : '#cbd5e1'}"></span>${esc(attack.name)}</td>
    <td>${exposed ? `<span class="exposed">Exposed · ${count}</span>` : '<span class="clear">No evidence</span>'}</td>
    <td class="muted">${esc(attack.tagline)}</td>
  </tr>`
}

function defenses(rows: { attack: Attack; exposed: boolean; findings: Finding[] }[]) {
  const exposed = rows.filter((row) => row.exposed)
  if (!exposed.length) return ''
  return `<section>
    <h2>How to close the exposed attacks</h2>
    ${exposed
      .map(
        (row) => `<div class="defense">
          <h3>${esc(row.attack.name)}</h3>
          <ul>${row.attack.defenses.map((item) => `<li>${esc(item)}</li>`).join('')}</ul>
        </div>`,
      )
      .join('')}
  </section>`
}

export function buildReportHtml(result: ScanResult): string {
  const counts = countBySeverity(result.findings)
  const categories = categoryScores(result.findings, result.kind)
  const attacks = attackMatrix(result.findings)
  const exposed = attacks.filter((row) => row.exposed)
  const passing = result.checks.filter((check) => check.status === 'pass').length
  const host = (() => {
    try {
      return new URL(result.finalUrl ?? result.target).host
    } catch {
      return result.target
    }
  })()

  const summaryCells = (['critical', 'high', 'medium', 'low', 'info'] as Severity[])
    .map(
      (severity) => `<div class="cell">
        <p class="label" style="color:${SEV_COLOR[severity]}">${severity}</p>
        <p class="value">${counts[severity]}</p>
      </div>`,
    )
    .join('')

  const metadata =
    result.kind === 'site'
      ? `<section>
          <h2>Response</h2>
          ${
            result.redirects?.length
              ? `<h3>Redirect chain</h3><ol class="chain">${[result.target, ...result.redirects].map((hop) => `<li><code>${esc(hop)}</code></li>`).join('')}</ol>`
              : ''
          }
          <h3>Headers</h3>
          <table class="kv">${(result.headers ?? []).map((header) => `<tr><th>${esc(header.name)}</th><td><code>${esc(header.value)}</code></td></tr>`).join('')}</table>
          <h3>Set-Cookie</h3>
          ${
            result.cookies?.length
              ? `<ul class="evidence">${result.cookies.map((cookie) => `<li><code>${esc(cookie)}</code></li>`).join('')}</ul>`
              : '<p class="muted">No cookies set on this response.</p>'
          }
        </section>`
      : `<section>
          <h2>Files read · ${result.files?.length ?? 0}</h2>
          <ul class="evidence">${(result.files ?? []).map((file) => `<li><code>${esc(file.path)}</code> <span class="muted">${(file.bytes / 1024).toFixed(1)} KB</span></li>`).join('')}</ul>
        </section>`

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Trace report — ${esc(host)}</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; background: #f4f4f5; color: #18181b; font: 14px/1.62 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  .wrap { max-width: 960px; margin: 0 auto; padding: 40px 24px 72px; }
  a { color: inherit; }
  h1, h2, h3, h4 { margin: 0; line-height: 1.25; }
  code, pre, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  header.top { display: flex; flex-wrap: wrap; align-items: baseline; justify-content: space-between; gap: 12px; border-bottom: 2px solid #18181b; padding-bottom: 14px; }
  .brand { font-size: 15px; font-weight: 700; letter-spacing: .16em; text-transform: uppercase; }
  .brand span { color: #71717a; font-weight: 400; letter-spacing: .08em; margin-left: 10px; text-transform: none; }
  .target h1 { font-size: 26px; letter-spacing: -.02em; margin-top: 26px; }
  .target .url { margin: 6px 0 0; color: #52525b; font-size: 12.5px; word-break: break-all; }
  .target .meta { margin: 6px 0 0; color: #71717a; font-size: 12px; }
  .scorecard { display: grid; grid-template-columns: 200px 1fr; gap: 0; border: 1px solid #d4d4d8; background: #fff; margin-top: 24px; }
  .score { padding: 22px; border-right: 1px solid #d4d4d8; }
  .score .big { font-size: 54px; font-weight: 650; letter-spacing: -.05em; line-height: 1; margin: 0; }
  .score .big small { font-size: 16px; font-weight: 400; color: #71717a; }
  .score .grade { margin: 8px 0 0; font-size: 12px; color: #52525b; }
  .cells { display: grid; grid-template-columns: repeat(5, 1fr); }
  .cell { padding: 16px 14px; border-right: 1px solid #e4e4e7; }
  .cell:last-child { border-right: 0; }
  .cell .label { margin: 0; font-size: 10px; letter-spacing: .12em; text-transform: uppercase; font-weight: 600; }
  .cell .value { margin: 6px 0 0; font-size: 22px; font-weight: 600; }
  section { margin-top: 34px; page-break-inside: auto; }
  h2 { font-size: 18px; letter-spacing: -.01em; padding-bottom: 8px; border-bottom: 1px solid #d4d4d8; }
  h3 { font-size: 14.5px; margin-top: 18px; }
  h4 { font-size: 11px; text-transform: uppercase; letter-spacing: .12em; color: #52525b; margin-top: 16px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  td, th { text-align: left; padding: 7px 8px; border-bottom: 1px solid #e4e4e7; vertical-align: top; }
  .kv th { width: 34%; font-weight: 500; color: #52525b; font-family: ui-monospace, Menlo, monospace; font-size: 11.5px; }
  .kv td code { font-size: 11.5px; word-break: break-all; }
  .cat { width: 26%; }
  .bar-cell { width: 40%; }
  .bar { display: block; height: 6px; background: #e4e4e7; }
  .bar span { display: block; height: 100%; }
  .num { width: 44px; text-align: right; font-variant-numeric: tabular-nums; }
  .muted { color: #71717a; }
  .dot { display: inline-block; width: 7px; height: 7px; margin-right: 8px; }
  .exposed { color: #be123c; border: 1px solid #fda4af; padding: 1px 6px; font-size: 11px; white-space: nowrap; }
  .clear { color: #16a34a; border: 1px solid #bbf7d0; padding: 1px 6px; font-size: 11px; white-space: nowrap; }
  .finding { border: 1px solid #d4d4d8; background: #fff; padding: 18px 20px; margin-top: 14px; page-break-inside: avoid; }
  .finding-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .finding h3 { margin: 0; font-size: 16px; }
  .finding p { margin: 10px 0 0; }
  .sev { font-size: 9.5px; letter-spacing: .1em; text-transform: uppercase; border: 1px solid; padding: 2px 6px; font-weight: 600; }
  .finding .meta { font-size: 11.5px; color: #71717a; margin-top: 4px; }
  ul.evidence { list-style: none; padding: 0; margin: 8px 0 0; }
  ul.evidence li { border: 1px solid #e4e4e7; background: #fafafa; padding: 6px 10px; margin-top: 4px; font-size: 11.5px; word-break: break-all; }
  .chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
  .chip { border: 1px solid #d4d4d8; padding: 2px 8px; font-size: 11.5px; color: #3f3f46; text-transform: capitalize; }
  .fix { border: 1px solid #e4e4e7; background: #fafafa; padding: 10px 14px; margin-top: 14px; }
  .fix h4 { margin-top: 0; }
  pre { background: #18181b; color: #f4f4f5; padding: 12px 14px; overflow-x: auto; margin: 10px 0 0; }
  pre code { font-size: 11.5px; }
  .checks { list-style: none; padding: 0; margin: 8px 0 0; display: grid; grid-template-columns: 1fr 1fr; gap: 0 18px; }
  .checks li { padding: 5px 0; border-bottom: 1px solid #f0f0f1; font-size: 12.5px; }
  .st-pass { color: #16a34a; }
  .st-warn { color: #b45309; }
  .st-fail { color: #be123c; }
  .defense { margin-top: 14px; }
  .defense ul { margin: 6px 0 0; padding-left: 18px; }
  .defense li { margin-top: 4px; }
  .chain { padding-left: 18px; font-size: 12px; }
  footer { margin-top: 44px; border-top: 1px solid #d4d4d8; padding-top: 14px; color: #71717a; font-size: 11.5px; }
  @media print {
    body { background: #fff; }
    .wrap { max-width: none; padding: 0; }
    .finding, .scorecard { break-inside: avoid; }
    section { break-inside: auto; }
  }
  @media (max-width: 640px) {
    .scorecard { grid-template-columns: 1fr; }
    .score { border-right: 0; border-bottom: 1px solid #d4d4d8; }
    .cells { grid-template-columns: repeat(3, 1fr); }
    .checks { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <p class="brand">Trace <span>Security report</span></p>
    <p class="muted" style="margin:0;font-size:12px">${esc(dateOf(result.scannedAt))}</p>
  </header>

  <div class="target">
    <h1>${esc(result.title || result.target)}</h1>
    <p class="url">${esc(result.finalUrl ?? result.target)}</p>
    <p class="meta">${result.kind === 'site' ? 'Live site · passive scan' : 'Uploaded source · analysed locally'}${result.status ? ` · HTTP ${result.status}` : ''}</p>
  </div>

  <div class="scorecard">
    <div class="score">
      <p class="big">${result.score}<small>/100</small></p>
      <p class="grade">Grade ${esc(result.grade)} · ${result.findings.length} finding${result.findings.length === 1 ? '' : 's'} · ${passing}/${result.checks.length} checks passing</p>
    </div>
    <div class="cells">${summaryCells}</div>
  </div>

  <section>
    <h2>Score by area</h2>
    <table>${categories.map(scoreRow).join('')}</table>
  </section>

  <section>
    <h2>Attack matrix · ${exposed.length}/${attacks.length} exposed</h2>
    <table>
      ${attacks.map((row) => attackRow(row.attack, row.exposed, row.findings.length)).join('')}
    </table>
    <p class="muted" style="font-size:11.5px">“No evidence” means nothing in this report maps to that attack class. It is not proof the application is immune.</p>
  </section>

  <section>
    <h2>Findings · ${result.findings.length}</h2>
    ${result.findings.length ? result.findings.map(findingBlock).join('') : '<p class="muted">No issues from these checks.</p>'}
  </section>

  ${defenses(attacks)}

  <section>
    <h2>Checks · ${passing}/${result.checks.length} passing</h2>
    <ul class="checks">${result.checks
      .map((check) => `<li><span class="st-${check.status}">${{ pass: 'PASS', warn: 'WARN', fail: 'FAIL' }[check.status]}</span> · ${esc(check.label)}</li>`)
      .join('')}</ul>
  </section>

  ${metadata}

  <section>
    <h2>Scope and limits</h2>
    <ul>${result.notes.map((note) => `<li>${esc(note)}</li>`).join('')}</ul>
    <p class="muted" style="font-size:11.5px">Scan only sites and code you own or have written permission to test. Trace sends ordinary requests, never exploit payloads.</p>
  </section>

  <footer>
    Generated by Trace · passive security review · ${esc(SEVERITIES.length)} severity bands, ${result.kind === 'site' ? 'site' : 'source'} checks. This report is a starting point, not a penetration test.
  </footer>
</div>
</body>
</html>`
}

export function downloadReport(result: ScanResult) {
  const html = buildReportHtml(result)
  const blob = new Blob([html], { type: 'text/html;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = reportFilename(result)
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}
