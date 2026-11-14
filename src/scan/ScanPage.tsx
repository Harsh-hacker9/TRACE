import { AlertTriangle, Globe, Search, ShieldCheck, Upload } from 'lucide-react'
import { type FormEvent, useEffect, useRef, useState } from 'react'

import { Button } from '@/components/Button'
import { Input } from '@/components/Field'
import { Panel } from '@/components/Section'
import { SegmentedControl } from '@/components/SegmentedControl'
import { Spinner } from '@/components/Spinner'
import { type ScanResult, auditSource, gradeFor, scoreFindings } from '@/lib/audit'
import { cn } from '@/lib/cn'
import { useLocation } from '@/lib/router'
import { readUploads } from '@/lib/zip'
import { SiteFooter, SiteNav } from '@/sections/Landing'
import { ScanResults } from './Results'
import { Uploader } from './Uploader'

type Tab = 'link' | 'upload'

function Scanning({ target }: { target: string }) {
  const steps = ['Requesting the page', 'Reading headers, cookies and CORS', 'Checking content and cross-referencing attacks']
  return (
    <Panel className="mt-4">
      <div className="flex flex-col gap-5 p-6">
        <div className="flex items-center gap-3">
          <Spinner className="size-5 text-fg" />
          <div className="min-w-0">
            <p className="text-sm font-medium">Scanning</p>
            <p className="truncate font-mono text-[11.5px] text-muted">{target}</p>
          </div>
        </div>
        <ol className="flex flex-col gap-2">
          {steps.map((step, i) => (
            <li key={step} className="flex items-center gap-2.5 text-[13px] text-muted">
              <span className={cn('size-1.5', i === 0 ? 'bg-fg' : 'bg-line-strong')} aria-hidden />
              {step}
            </li>
          ))}
        </ol>
        <div className="flex flex-col gap-2" aria-hidden>
          <div className="skel w-2/3" />
          <div className="skel w-1/2" />
          <div className="skel w-3/4" />
        </div>
      </div>
    </Panel>
  )
}

export function ScanPage() {
  const { search } = useLocation()
  const initialUrl = search.get('url') ?? ''
  const initialMode: Tab = search.get('mode') === 'upload' ? 'upload' : 'link'

  const [tab, setTab] = useState<Tab>(initialMode)
  const [url, setUrl] = useState(initialUrl)
  const [files, setFiles] = useState<File[]>([])
  const [result, setResult] = useState<ScanResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const started = useRef(false)

  async function runSite(target: string) {
    const value = target.trim()
    if (!value) {
      setError('Enter a site address, for example example.com.')
      return
    }
    setBusy(true)
    setError(null)
    setResult(null)
    try {
      const response = await fetch('/api/scan-url', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url: value }),
      })
      const payload = (await response.json().catch(() => null)) as (Partial<ScanResult> & { error?: string }) | null
      if (!response.ok) throw new Error(payload?.error ?? 'The scan failed.')
      if (!payload?.findings || !payload.checks) throw new Error('The scan returned no report.')
      setResult(payload as ScanResult)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The scan failed. Try again.')
    } finally {
      setBusy(false)
    }
  }

  async function runFiles(list: File[]) {
    if (!list.length) {
      setError('Choose a file or a zip first.')
      return
    }
    setBusy(true)
    setError(null)
    setResult(null)
    try {
      const { files: parsed, skipped, totalBytes } = await readUploads(list)
      if (!parsed.length) throw new Error('No readable source files in that upload. A zip of the project works best.')
      // Let the busy state paint before the synchronous pattern pass.
      await new Promise((resolve) => setTimeout(resolve, 60))
      const { findings, checks, notes } = auditSource(parsed)
      if (skipped) notes.unshift(`${skipped} file${skipped === 1 ? '' : 's'} skipped (binary, too large, or build output).`)
      notes.unshift(`${(totalBytes / 1024).toFixed(0)} KB of source read locally.`)
      const score = scoreFindings(findings)
      setResult({
        kind: 'files',
        target: list.length === 1 ? list[0].name : `${list.length} uploaded files`,
        scannedAt: Date.now(),
        findings,
        checks,
        score,
        grade: gradeFor(score),
        notes,
        files: parsed.map((file) => ({ path: file.path, bytes: file.bytes })),
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not read those files.')
    } finally {
      setBusy(false)
    }
  }

  useEffect(() => {
    if (started.current || !initialUrl) return
    started.current = true
    void runSite(initialUrl)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const submit = (event: FormEvent) => {
    event.preventDefault()
    void runSite(url)
  }

  return (
    <div className="flex min-h-dvh flex-col bg-bg">
      <SiteNav />
      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-10 sm:px-8">
        <header className="max-w-2xl">
          <p className="font-mono text-[11px] tracking-[0.16em] text-muted uppercase">Scanner</p>
          <h1 className="mt-3 text-[34px] leading-[1.05] font-semibold tracking-[-0.04em] sm:text-[42px]">Scan a site or a codebase</h1>
          <p className="mt-4 text-[16px] leading-relaxed text-muted">
            One report with the bug, the evidence, the attacks it enables and the fix — scored by area and across every attack class. Sites are checked
            passively from the edge; uploaded code is read in this tab. Every report downloads as a standalone file.
          </p>
        </header>

        <Panel className="mt-8">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line p-4">
            <SegmentedControl
              label="Scan type"
              size="md"
              value={tab}
              onChange={setTab}
              options={[
                { value: 'link', label: 'Website link', icon: <Globe className="size-3.5" aria-hidden /> },
                { value: 'upload', label: 'App upload', icon: <Upload className="size-3.5" aria-hidden /> },
              ]}
            />
            <span className="font-mono text-[11px] text-muted">{tab === 'link' ? 'Passive checks from the edge' : 'Read in your browser'}</span>
          </div>

          {tab === 'link' ? (
            <form onSubmit={submit} className="flex flex-col gap-3 p-4 sm:flex-row sm:items-start" noValidate>
              <Input
                className="flex-1"
                aria-label="Website address"
                placeholder="https://your-site.com"
                autoComplete="url"
                spellCheck={false}
                icon={<Globe className="size-4" aria-hidden />}
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                onFocus={() => setError(null)}
              />
              <Button type="submit" variant="primary" loading={busy} icon={<Search className="size-4" aria-hidden />}>
                Scan site
              </Button>
            </form>
          ) : (
            <Uploader files={files} onFiles={setFiles} onScan={() => void runFiles(files)} busy={busy} />
          )}
        </Panel>

        {busy && <Scanning target={tab === 'link' ? url.trim() || 'your site' : `${files.length} file${files.length === 1 ? '' : 's'}`} />}

        {error && !busy && (
          <div role="alert" className="mt-4 flex items-start gap-3 border border-blocked/40 bg-blocked/5 px-4 py-3">
            <AlertTriangle className="mt-0.5 size-4 shrink-0 text-blocked" aria-hidden />
            <div>
              <p className="text-sm font-medium">Scan failed</p>
              <p className="mt-1 text-[13px] text-muted">{error}</p>
            </div>
          </div>
        )}

        {!busy && !error && !result && (
          <div className="mt-6 grid gap-4 sm:grid-cols-3">
            {[
              { icon: ShieldCheck, title: 'What you get', body: 'Severity, evidence, the attacks each issue enables, and a fix you can paste in.' },
              { icon: Globe, title: 'For a link', body: 'The page, its headers, cookies, one CORS probe and robots.txt. No crawling.' },
              { icon: Upload, title: 'For an upload', body: 'A zip of your project, read locally. Secrets are masked in the report.' },
            ].map(({ icon: Icon, title, body }) => (
              <div key={title} className="border border-line p-5">
                <Icon className="size-4 text-muted" aria-hidden />
                <p className="mt-3 text-sm font-medium">{title}</p>
                <p className="mt-1.5 text-[13px] leading-relaxed text-muted">{body}</p>
              </div>
            ))}
          </div>
        )}

        {!busy && result && (
          <div className="mt-6">
            <ScanResults result={result} onRescan={result.kind === 'site' ? () => void runSite(url) : undefined} />
          </div>
        )}

        <p className="mt-8 max-w-2xl border-t border-line pt-5 text-[12.5px] leading-relaxed text-muted">
          Scan only sites and code you own or have written permission to test. Trace sends ordinary GET requests to the address you give it and never
          sends exploit payloads.
        </p>
      </main>
      <SiteFooter />
    </div>
  )
}
