import { Hono } from 'hono'
import { bodyLimit } from 'hono/body-limit'

import { type ScanResult, auditSite, gradeFor, scoreFindings } from '../lib/audit'

// The Worker in front of the app. /api/scan-url is the only server-side scan:
// it fetches the page the user named, reads its response headers, probes CORS
// once, reads robots.txt, and runs the shared rules engine. No payloads, no
// crawling, no path brute-forcing. Uploaded code is analysed in the browser.

type Env = { ASSETS: Fetcher }

const UA = 'TraceScanner/1.0 (passive security review)'
const PROBE_ORIGIN = 'https://probe.trace-scanner.example'
const MAX_HTML = 600_000
const TIMEOUT = 9_000
const WINDOW_MS = 60_000
const LIMIT = 12

const app = new Hono<{ Bindings: Env }>()

app.use('/api/*', bodyLimit({ maxSize: 4 * 1024, onError: (c) => c.json({ error: 'Request is too large.' }, 413) }))

app.get('/api/health', (c) => c.json({ ok: true }))

/* ------------------------------------------------------------------ */
/* Target validation and a small per-isolate rate limit                */
/* ------------------------------------------------------------------ */

function blockedHost(hostname: string) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.home.arpa')) return true
  if (host === 'metadata.google.internal' || host === 'metadata' || host === 'instance-data') return true
  if (host.includes(':')) return true // IPv6 literals are all blocked; none are useful here
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host)
  if (!v4) return false
  const [a, b] = [Number(v4[1]), Number(v4[2])]
  if (a === 0 || a === 10 || a === 127) return true
  if (a === 169 && b === 254) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  if (a >= 224) return true
  return false
}

export function normalizeTarget(raw: unknown): { url: string } | { error: string } {
  if (typeof raw !== 'string') return { error: 'Enter a site address.' }
  const value = raw.trim()
  if (!value) return { error: 'Enter a site address.' }
  if (value.length > 2048) return { error: 'That address is too long.' }
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `https://${value}`
  let url: URL
  try {
    url = new URL(withScheme)
  } catch {
    return { error: 'That does not look like a web address.' }
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return { error: 'Only http:// and https:// addresses can be scanned.' }
  if (url.username || url.password) return { error: 'Remove the username and password from the address.' }
  if (!url.hostname.includes('.') || url.hostname.endsWith('.')) return { error: 'Enter a public hostname, like example.com.' }
  if (blockedHost(url.hostname)) return { error: 'Private, loopback and internal hosts cannot be scanned.' }
  url.hash = ''
  return { url: url.toString() }
}

const hits = new Map<string, number[]>()

function rateLimited(key: string) {
  const now = Date.now()
  const recent = (hits.get(key) ?? []).filter((at) => now - at < WINDOW_MS)
  recent.push(now)
  hits.set(key, recent)
  if (hits.size > 500) hits.clear()
  return recent.length > LIMIT
}

/* ------------------------------------------------------------------ */
/* Fetch helpers                                                       */
/* ------------------------------------------------------------------ */

function splitCookies(headers: Headers) {
  const getSetCookie = (headers as Headers & { getSetCookie?: () => string[] }).getSetCookie
  if (typeof getSetCookie === 'function') {
    const list = getSetCookie.call(headers)
    if (list.length) return list
  }
  const combined = headers.get('set-cookie')
  return combined ? combined.split(/,(?=\s*[^;,]+=)/) : []
}

async function fetchPage(start: string) {
  const chain = [start]
  let url = start
  let response: Response | null = null
  for (let hop = 0; hop < 5; hop++) {
    response = await fetch(url, {
      redirect: 'manual',
      headers: {
        'user-agent': UA,
        accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
        'accept-language': 'en',
      },
      signal: AbortSignal.timeout(TIMEOUT),
    })
    const location = response.headers.get('location')
    if (response.status >= 300 && response.status < 400 && location) {
      let next: string
      try {
        next = new URL(location, url).toString()
      } catch {
        break
      }
      if (chain.includes(next)) break
      chain.push(next)
      url = next
      continue
    }
    break
  }
  if (!response) throw new Error('No response')
  return { response, url, chain }
}

async function readHtml(response: Response) {
  const type = (response.headers.get('content-type') ?? '').toLowerCase()
  const length = Number(response.headers.get('content-length') ?? 0)
  if (type && !/html|xml|text\/plain/.test(type)) return ''
  if (length > 2_000_000) return ''
  const body = await response.text().catch(() => '')
  return body.slice(0, MAX_HTML)
}

async function readText(url: string, limit = 60_000) {
  const response = await fetch(url, {
    redirect: 'follow',
    headers: { 'user-agent': UA, accept: 'text/plain,*/*;q=0.5' },
    signal: AbortSignal.timeout(5_000),
  }).catch(() => null)
  if (!response?.ok) return undefined
  const type = (response.headers.get('content-type') ?? '').toLowerCase()
  if (type && !/text|json|xml/.test(type)) return undefined
  const body = await response.text().catch(() => '')
  return body ? body.slice(0, limit) : undefined
}

/* ------------------------------------------------------------------ */
/* Routes                                                              */
/* ------------------------------------------------------------------ */

app.post('/api/scan-url', async (c) => {
  const body = await c.req.json<{ url?: unknown }>().catch(() => null)
  const target = normalizeTarget(body?.url)
  if ('error' in target) return c.json({ error: target.error }, 400)

  const key = c.req.header('cf-connecting-ip') ?? c.req.header('x-forwarded-for') ?? 'local'
  if (rateLimited(key)) return c.json({ error: 'Too many scans from this address. Wait a minute and try again.' }, 429)

  try {
    const { response, url, chain } = await fetchPage(target.url)
    const headers: Record<string, string> = {}
    const headerList: { name: string; value: string }[] = []
    response.headers.forEach((value, name) => {
      headers[name] = value
      headerList.push({ name, value: value.length > 400 ? `${value.slice(0, 400)}…` : value })
    })

    const html = await readHtml(response)
    const cookies = splitCookies(response.headers)
    const title = /<title[^>]*>([^<]{1,160})/i.exec(html)?.[1]?.trim()

    // One CORS probe: a made-up origin, so a reflected ACAO is unambiguous.
    const probe = await fetch(url, {
      redirect: 'follow',
      headers: { origin: PROBE_ORIGIN, 'user-agent': UA, accept: 'text/html' },
      signal: AbortSignal.timeout(6_000),
    }).catch(() => null)

    let robots: string | undefined
    try {
      robots = await readText(new URL('/robots.txt', url).toString(), 40_000)
    } catch {
      robots = undefined
    }

    const { findings, checks, notes } = auditSite({
      requested: target.url,
      finalUrl: url,
      status: response.status,
      headers,
      cookies,
      html,
      redirects: chain.slice(1),
      cors: {
        probeOrigin: PROBE_ORIGIN,
        allowOrigin: probe?.headers.get('access-control-allow-origin') ?? undefined,
        allowCredentials: probe?.headers.get('access-control-allow-credentials') ?? undefined,
      },
      robots,
    })

    if (response.status >= 400) notes.push(`The page answered ${response.status}, so content checks reflect an error document.`)

    const score = scoreFindings(findings)
    const result: ScanResult = {
      kind: 'site',
      target: target.url,
      finalUrl: url,
      title,
      status: response.status,
      scannedAt: Date.now(),
      findings,
      checks,
      score,
      grade: gradeFor(score),
      notes,
      redirects: chain.slice(1),
      headers: headerList.slice(0, 80),
      cookies,
    }
    return c.json(result)
  } catch {
    return c.json({ error: 'Could not reach that site. It may be offline, block automated requests, or take too long to answer.' }, 502)
  }
})

app.all('/api/*', (c) => c.json({ error: 'Not found' }, 404))

app.all('*', (c) => c.env.ASSETS.fetch(c.req.raw))

export default app
