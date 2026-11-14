import { AlertTriangle, Check, ChevronDown, Download, RefreshCw, ShieldAlert, Wrench, X } from 'lucide-react'
import { useState } from 'react'

import { Panel } from '@/components/Section'
import { SegmentedControl } from '@/components/SegmentedControl'
import { attackById } from '@/lib/attacks'
import { type Finding, type ScanResult, type Severity, attackMatrix, categoryScores, countBySeverity } from '@/lib/audit'
import { cn } from '@/lib/cn'
import { downloadReport } from '@/lib/report'
import { Link } from '@/lib/router'
import { SEVERITY_META, SeverityChip } from './severity'

type Filter = 'all' | 'urgent' | 'medium' | 'low'

const FILTERS: { value: Filter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'urgent', label: 'Critical & high' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low & info' },
]

const inFilter = (severity: Severity, filter: Filter) =>
  filter === 'all' ||
  (filter === 'urgent' && (severity === 'critical' || severity === 'high')) ||
  (filter === 'medium' && severity === 'medium') ||
  (filter === 'low' && (severity === 'low' || severity === 'info'))

function FindingRow({ finding, open, onToggle }: { finding: Finding; open: boolean; onToggle: () => void }) {
  return (
    <li className="border-b border-line last:border-0">
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        className="flex w-full items-start gap-3 px-4 py-4 text-left transition-colors hover:bg-surface-2"
      >
        <SeverityChip severity={finding.severity} className="mt-0.5" />
        <span className="min-w-0 flex-1">
          <span className="block text-[15px] leading-snug font-medium">{finding.title}</span>
          <span className="mt-1 block font-mono text-[11px] text-muted">
            {finding.category}
            {finding.cwe ? ` · ${finding.cwe}` : ''}
            {finding.evidence?.length ? ` · ${finding.evidence.length} item${finding.evidence.length === 1 ? '' : 's'}` : ''}
          </span>
        </span>
        <ChevronDown className={cn('mt-1 size-4 shrink-0 text-muted transition-transform duration-200', open && 'rotate-180')} aria-hidden />
      </button>
      {open && (
        <div className="border-t border-line px-4 pt-4 pb-5 sm:pl-[72px]">
          <p className="max-w-2xl text-sm leading-relaxed text-muted">{finding.detail}</p>

          {finding.evidence && finding.evidence.length > 0 && (
            <div className="mt-5">
              <p className="font-mono text-[11px] tracking-[0.14em] text-muted uppercase">Evidence</p>
              <ul className="mt-2 flex flex-col gap-1">
                {finding.evidence.map((item, i) => (
                  <li key={`${item}-${i}`} className="border border-line bg-bg px-3 py-2 font-mono text-[12px] leading-relaxed break-all text-fg/85">
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {finding.attacks.length > 0 && (
            <div className="mt-5">
              <p className="font-mono text-[11px] tracking-[0.14em] text-muted uppercase">Attacks this enables</p>
              <div className="mt-2 flex flex-wrap gap-2">
                {finding.attacks.map((id) => {
                  const attack = attackById(id)
                  return (
                    <Link
                      key={id}
                      to={`/attacks#${id}`}
                      className="inline-flex items-center gap-1.5 border border-line px-2 py-1 text-[12.5px] text-muted transition-colors hover:border-line-strong hover:text-fg"
                    >
                      <ShieldAlert className="size-3.5" aria-hidden />
                      {attack?.name ?? id}
                    </Link>
                  )
                })}
              </div>
            </div>
          )}

          <div className="mt-5 border border-line bg-surface-2/60 p-4">
            <p className="flex items-center gap-2 text-[13px] font-medium">
              <Wrench className="size-3.5 text-muted" aria-hidden /> Fix
            </p>
            <p className="mt-2 text-sm leading-relaxed text-muted">{finding.fix}</p>
            {finding.code && (
              <pre className="mt-3 overflow-x-auto border border-line bg-bg p-3 font-mono text-[12px] leading-relaxed text-fg/90">{finding.code}</pre>
            )}
          </div>
        </div>
      )}
    </li>
  )
}

function StatCell({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="px-5 py-4">
      <p className="font-mono text-[10px] tracking-[0.14em] text-muted uppercase">{label}</p>
      <p className="mt-2 text-[24px] leading-none font-semibold tracking-[-0.03em]">{value}</p>
      {sub && <p className="mt-1.5 font-mono text-[11px] text-muted">{sub}</p>}
    </div>
  )
}

export function ScanResults({ result, onRescan }: { result: ScanResult; onRescan?: () => void }) {
  const [filter, setFilter] = useState<Filter>('all')
  const [open, setOpen] = useState<string | null>(result.findings[0]?.id ?? null)

  const counts = countBySeverity(result.findings)
  const visible = result.findings.filter((finding) => inFilter(finding.severity, filter))
  const passing = result.checks.filter((check) => check.status === 'pass').length
  const categories = categoryScores(result.findings, result.kind)
  const attacks = attackMatrix(result.findings)
  const exposedCount = attacks.filter((row) => row.exposed).length

  return (
    <div className="flex flex-col gap-4">
      {/* Summary ------------------------------------------------------ */}
      <section aria-label="Scan summary" className="border border-line bg-surface">
        <div className="flex flex-col gap-6 border-b border-line p-5 sm:flex-row sm:items-center sm:justify-between">
          <div className="min-w-0">
            <p className="font-mono text-[10px] tracking-[0.16em] text-muted uppercase">
              Report · {result.kind === 'site' ? 'Live site' : 'Source upload'}
            </p>
            <h2 className="mt-2 truncate text-[21px] font-medium tracking-[-0.02em]">{result.title || result.target}</h2>
            <p className="mt-1 font-mono text-[11.5px] break-all text-muted">
              {result.finalUrl ?? result.target}
              {result.status ? ` · HTTP ${result.status}` : ''}
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-5">
            <div className="text-right">
              <p className="text-[44px] leading-none font-semibold tracking-[-0.05em]">
                {result.score}
                <span className="ml-1 text-base font-normal text-muted">/100</span>
              </p>
              <p className="mt-1.5 font-mono text-[11px] text-muted">Grade {result.grade}</p>
            </div>
            <div className="flex flex-col gap-2">
              <button
                type="button"
                onClick={() => downloadReport(result)}
                className="inline-flex h-10 items-center gap-2 border border-invert bg-invert px-3 text-sm font-medium text-invert-fg transition-colors hover:bg-invert/88"
              >
                <Download className="size-4" aria-hidden /> Download report
              </button>
              {onRescan && (
                <button
                  type="button"
                  onClick={onRescan}
                  className="inline-flex h-10 items-center gap-2 border border-line-strong px-3 text-sm transition-colors hover:bg-surface-2 hover:border-muted/60"
                >
                  <RefreshCw className="size-4" aria-hidden /> Scan again
                </button>
              )}
            </div>
          </div>
        </div>

        <div className="flex h-1" aria-hidden>
          {(['critical', 'high', 'medium', 'low'] as Severity[]).map((severity) =>
            counts[severity] ? <span key={severity} className={cn('h-full', SEVERITY_META[severity].dot)} style={{ flex: counts[severity] }} /> : null,
          )}
          {result.findings.length === 0 && <span className="h-full flex-1 bg-done" />}
        </div>

        <div className="grid grid-cols-2 divide-x divide-line border-b border-line sm:grid-cols-4">
          <StatCell label="Findings" value={result.findings.length} sub={result.findings.length ? 'to work through' : 'nothing to fix'} />
          <StatCell label="Critical" value={counts.critical} sub={counts.critical ? 'fix first' : 'none'} />
          <StatCell label="High" value={counts.high} sub={counts.high ? 'fix soon' : 'none'} />
          <StatCell label="Checks" value={`${passing}/${result.checks.length}`} sub="passing" />
        </div>

        <div className="flex flex-wrap items-center gap-x-5 gap-y-2 px-5 py-3 font-mono text-[11px] text-muted">
          <span>{result.kind === 'site' ? 'Passive scan' : 'Local pattern scan'}</span>
          <span className="text-line-strong" aria-hidden>
            /
          </span>
          <span>{new Date(result.scannedAt).toLocaleString()}</span>
          <span className="text-line-strong" aria-hidden>
            /
          </span>
          <span>
            {exposedCount} of {attacks.length} attack classes exposed
          </span>
        </div>
      </section>

      {/* Score by area ------------------------------------------------ */}
      <Panel title="Score by area" bodyClassName="p-0">
        <ul className="grid grid-cols-1 sm:grid-cols-2">
          {categories.map((area) => (
            <li key={area.category} className="border-r border-b border-line px-4 py-3">
              <div className="flex items-center justify-between gap-3">
                <span className="flex items-center gap-2 text-[13px]">
                  <span className={cn('size-1.5', area.worst ? SEVERITY_META[area.worst].dot : 'bg-done')} aria-hidden />
                  {area.category}
                </span>
                <span className="font-mono text-[11px] text-muted">{area.score}</span>
              </div>
              <div className="mt-2 h-1 bg-line">
                <span
                  className={cn('block h-full', area.worst ? SEVERITY_META[area.worst].dot : 'bg-done')}
                  style={{ width: `${area.score}%` }}
                />
              </div>
              <p className="mt-1.5 font-mono text-[10.5px] text-muted">
                {area.findings === 0 ? 'clean' : `${area.findings} finding${area.findings === 1 ? '' : 's'}`}
              </p>
            </li>
          ))}
        </ul>
      </Panel>

      {/* Findings ----------------------------------------------------- */}
      <Panel
        title={`Findings${result.findings.length ? ` · ${result.findings.length}` : ''}`}
        actions={
          <SegmentedControl
            label="Filter findings by severity"
            value={filter}
            onChange={setFilter}
            options={FILTERS.map((option) => ({ value: option.value, label: option.label }))}
          />
        }
        bodyClassName="p-0"
      >
        {result.findings.length === 0 ? (
          <div className="px-5 py-12 text-center">
            <p className="text-[15px] font-medium">No issues from these checks</p>
            <p className="mx-auto mt-1.5 max-w-md text-sm text-muted">
              Everything this scan looks at passed. It is a first pass, not a guarantee: a clean report still leaves auth logic, access control and
              business rules untested.
            </p>
          </div>
        ) : visible.length === 0 ? (
          <p className="px-5 py-10 text-center text-sm text-muted">Nothing in this severity band.</p>
        ) : (
          <ul>
            {visible.map((finding) => (
              <FindingRow key={finding.id} finding={finding} open={open === finding.id} onToggle={() => setOpen(open === finding.id ? null : finding.id)} />
            ))}
          </ul>
        )}
      </Panel>

      {/* Attack matrix ------------------------------------------------ */}
      <Panel title={`Attack matrix · ${exposedCount} of ${attacks.length} exposed`} bodyClassName="p-0">
        <ul className="grid grid-cols-1 lg:grid-cols-2">
          {attacks.map((row) => (
            <li key={row.attack.id} className="border-r border-b border-line">
              <Link
                to={`/attacks#${row.attack.id}`}
                className={cn('flex items-start gap-3 p-4 transition-colors hover:bg-surface-2', !row.exposed && 'opacity-65')}
              >
                <span
                  className={cn('mt-1.5 size-1.5 shrink-0', row.exposed ? SEVERITY_META[row.attack.severity].dot : 'bg-line-strong')}
                  aria-hidden
                />
                <span className="min-w-0 flex-1">
                  <span className="flex flex-wrap items-center gap-2">
                    <span className="text-[14px] font-medium">{row.attack.name}</span>
                    {row.exposed ? (
                      <span className="inline-flex h-5 items-center border border-blocked/40 px-1.5 font-mono text-[10px] tracking-[0.06em] text-blocked uppercase">
                        Exposed · {row.findings.length}
                      </span>
                    ) : (
                      <span className="font-mono text-[10px] tracking-[0.06em] text-muted uppercase">No evidence</span>
                    )}
                  </span>
                  <span className="mt-1 block text-[12.5px] leading-relaxed text-muted">{row.attack.tagline}</span>
                </span>
              </Link>
            </li>
          ))}
        </ul>
        <p className="border-t border-line px-4 py-3 text-[12px] leading-relaxed text-muted">
          “No evidence” means nothing in this report maps to that attack class. It is not proof the application is immune.
        </p>
      </Panel>

      {/* Checks ------------------------------------------------------- */}
      <Panel title={`Checks · ${passing}/${result.checks.length} passing`} bodyClassName="p-0">
        <ul className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3">
          {result.checks.map((check) => (
            <li key={check.id} className="flex items-center gap-2.5 border-r border-b border-line px-4 py-3 last:border-b-0">
              {check.status === 'pass' ? (
                <Check className="size-4 shrink-0 text-done" aria-hidden />
              ) : check.status === 'fail' ? (
                <X className="size-4 shrink-0 text-blocked" aria-hidden />
              ) : (
                <AlertTriangle className="size-4 shrink-0 text-progress" aria-hidden />
              )}
              <span className={cn('text-[13px]', check.status === 'pass' ? 'text-muted' : 'text-fg')}>{check.label}</span>
              <span className="sr-only">{check.status === 'pass' ? 'Passed' : check.status === 'fail' ? 'Failed' : 'Warning'}</span>
            </li>
          ))}
        </ul>
      </Panel>

      {/* Response details --------------------------------------------- */}
      {result.kind === 'site' && (
        <Panel title="Response" bodyClassName="p-0">
          {result.redirects && result.redirects.length > 0 && (
            <div className="border-b border-line px-4 py-3">
              <p className="font-mono text-[10px] tracking-[0.14em] text-muted uppercase">Redirect chain</p>
              <ol className="mt-2 flex flex-col gap-1">
                {[result.target, ...result.redirects].map((hop, i) => (
                  <li key={`${hop}-${i}`} className="font-mono text-[11.5px] break-all text-muted">
                    <span className="text-faint">{String(i).padStart(2, '0')}</span> {hop}
                  </li>
                ))}
              </ol>
            </div>
          )}
          <div className="border-b border-line px-4 py-3">
            <p className="font-mono text-[10px] tracking-[0.14em] text-muted uppercase">Response headers</p>
            <dl className="mt-2 grid grid-cols-1 gap-x-6 gap-y-1.5 sm:grid-cols-[minmax(0,200px)_1fr]">
              {(result.headers ?? []).map((header) => (
                <div key={header.name} className="contents">
                  <dt className="font-mono text-[11.5px] break-all text-faint">{header.name}</dt>
                  <dd className="font-mono text-[11.5px] break-all text-fg/85">{header.value}</dd>
                </div>
              ))}
            </dl>
          </div>
          <div className="px-4 py-3">
            <p className="font-mono text-[10px] tracking-[0.14em] text-muted uppercase">Set-Cookie</p>
            {result.cookies && result.cookies.length > 0 ? (
              <ul className="mt-2 flex flex-col gap-1">
                {result.cookies.map((cookie, i) => (
                  <li key={`${cookie}-${i}`} className="font-mono text-[11.5px] break-all text-fg/85">
                    {cookie}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-2 text-[13px] text-muted">No cookies set on this response.</p>
            )}
          </div>
        </Panel>
      )}

      {result.kind === 'files' && result.files && result.files.length > 0 && (
        <Panel title={`Files read · ${result.files.length}`} bodyClassName="p-0">
          <ul className="max-h-72 overflow-y-auto">
            {result.files.map((file) => (
              <li key={file.path} className="flex items-center gap-3 border-b border-line px-4 py-2 last:border-0">
                <span className="min-w-0 flex-1 truncate font-mono text-[11.5px]">{file.path}</span>
                <span className="shrink-0 font-mono text-[11px] text-muted">{(file.bytes / 1024).toFixed(1)} KB</span>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      <Panel title="Scope and limits" bodyClassName="p-0">
        <ul className="flex flex-col">
          {result.notes.map((note) => (
            <li key={note} className="flex gap-3 border-b border-line px-4 py-3 text-[13px] leading-relaxed text-muted last:border-0">
              <span className="mt-[9px] h-px w-3 shrink-0 bg-line-strong" aria-hidden />
              {note}
            </li>
          ))}
        </ul>
      </Panel>
    </div>
  )
}
