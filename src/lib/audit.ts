// The rules engine. Two auditors share one vocabulary:
//   auditSite()   — headers, cookies, CORS, TLS-by-URL, HTML content of a reachable page
//   auditSource() — pattern analysis of files the user uploads (read in the browser)
// Both return findings that name the attacks they expose, plus the checks that passed.

import { ATTACKS, type Attack, type AttackId } from './attacks'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

const WEIGHT: Record<Severity, number> = { critical: 26, high: 13, medium: 6, low: 2, info: 0 }

export type Finding = {
  id: string
  title: string
  severity: Severity
  category: string
  detail: string
  evidence?: string[]
  attacks: AttackId[]
  fix: string
  code?: string
  lang?: string
  cwe?: string
}

export type Check = { id: string; label: string; status: 'pass' | 'fail' | 'warn' }

export type ScanResult = {
  kind: 'site' | 'files'
  target: string
  finalUrl?: string
  title?: string
  status?: number
  scannedAt: number
  findings: Finding[]
  checks: Check[]
  score: number
  grade: string
  notes: string[]
  redirects?: string[]
  headers?: { name: string; value: string }[]
  cookies?: string[]
  files?: { path: string; bytes: number }[]
}

export function scoreFindings(findings: Finding[]) {
  let score = 100
  for (const finding of findings) score -= WEIGHT[finding.severity]
  return Math.max(0, Math.min(100, Math.round(score)))
}

export function gradeFor(score: number) {
  if (score >= 92) return 'A'
  if (score >= 82) return 'B'
  if (score >= 70) return 'C'
  if (score >= 56) return 'D'
  if (score >= 40) return 'E'
  return 'F'
}

export function countBySeverity(findings: Finding[]) {
  const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const finding of findings) out[finding.severity] += 1
  return out
}

export const sortFindings = (findings: Finding[]) =>
  [...findings].sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity))

export const SITE_CATEGORIES = ['Transport', 'Headers', 'Cookies', 'CORS', 'Content', 'Forms', 'Disclosure'] as const
export const SOURCE_CATEGORIES = ['Secrets', 'Injection', 'XSS', 'Crypto', 'Session', 'CORS', 'Transport', 'Config', 'Redirects', 'Files', 'Supply chain', 'Disclosure'] as const

export type CategoryScore = { category: string; score: number; findings: number; worst: Severity | null }

/** 100 minus the weight of what was found in that area, so every area has a score. */
export function categoryScores(findings: Finding[], kind: 'site' | 'files'): CategoryScore[] {
  const categories: readonly string[] = kind === 'site' ? SITE_CATEGORIES : SOURCE_CATEGORIES
  return categories.map((category) => {
    const inCategory = findings.filter((finding) => finding.category === category)
    const score = Math.max(0, 100 - inCategory.reduce((total, finding) => total + WEIGHT[finding.severity], 0))
    const worst = SEVERITIES.find((severity) => inCategory.some((finding) => finding.severity === severity)) ?? null
    return { category, score, findings: inCategory.length, worst }
  })
}

export type AttackRow = { attack: Attack; findings: Finding[]; exposed: boolean }

/** Every documented attack class, with the findings from this report that expose it. */
export function attackMatrix(findings: Finding[]): AttackRow[] {
  return ATTACKS.map((attack) => {
    const related = findings.filter((finding) => finding.attacks.includes(attack.id))
    return { attack, findings: related, exposed: related.length > 0 }
  })
}

function buildChecks(catalog: { id: string; label: string }[], findings: Finding[]): Check[] {
  return catalog.map((item) => {
    const hit = findings.find((f) => f.id === item.id)
    if (!hit) return { ...item, status: 'pass' as const }
    return { ...item, status: hit.severity === 'critical' || hit.severity === 'high' ? ('fail' as const) : ('warn' as const) }
  })
}

/* ------------------------------------------------------------------ */
/* Site audit                                                          */
/* ------------------------------------------------------------------ */

export type SiteInput = {
  requested: string
  finalUrl: string
  status: number
  headers: Record<string, string>
  cookies: string[]
  html: string
  redirects: string[]
  cors: { probeOrigin: string; allowOrigin?: string; allowCredentials?: string }
  robots?: string
}

export const SITE_CHECKS = [
  { id: 'https', label: 'Served over HTTPS' },
  { id: 'hsts', label: 'HSTS enabled' },
  { id: 'csp', label: 'Content-Security-Policy' },
  { id: 'xfo', label: 'Clickjacking protection' },
  { id: 'nosniff', label: 'X-Content-Type-Options' },
  { id: 'referrer', label: 'Referrer-Policy' },
  { id: 'permissions', label: 'Permissions-Policy' },
  { id: 'banner', label: 'Server banner hidden' },
  { id: 'generator', label: 'CMS version hidden' },
  { id: 'coop', label: 'Cross-origin opener isolated' },
  { id: 'corp', label: 'Cross-origin resource policy' },
  { id: 'xxp', label: 'Legacy XSS filter off' },
  { id: 'cookies', label: 'Cookie flags' },
  { id: 'cors', label: 'CORS policy' },
  { id: 'mixed', label: 'No mixed content' },
  { id: 'forms', label: 'Forms submit over HTTPS' },
  { id: 'csrf-token', label: 'CSRF token on POST forms' },
  { id: 'iframes', label: 'Third-party frames sandboxed' },
  { id: 'sri', label: 'Third-party script integrity' },
  { id: 'blank', label: 'New-tab links isolated' },
  { id: 'errors', label: 'No stack traces in errors' },
  { id: 'secrets', label: 'No secrets in the page' },
  { id: 'sourcemaps', label: 'Source maps unpublished' },
]

const LOCAL_HOST = /^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(:\d+)?$/i

function isInsecureUrl(url: string) {
  if (!/^http:\/\//i.test(url)) return false
  try {
    return !LOCAL_HOST.test(new URL(url).host)
  } catch {
    return true
  }
}

function directive(csp: string, name: string) {
  const parts = csp.split(';').map((p) => p.trim())
  const own = parts.find((p) => p.toLowerCase().startsWith(name))
  if (own) return own
  return parts.find((p) => p.toLowerCase().startsWith('default-src')) ?? ''
}

function parseCookies(raw: string[]) {
  return raw.map((value) => {
    const [pair, ...rest] = value.split(';')
    const name = pair.split('=')[0]?.trim() ?? ''
    const flags = rest.map((f) => f.trim().toLowerCase())
    return { name, flags, raw: value }
  })
}

export function auditSite(input: SiteInput): { findings: Finding[]; checks: Check[]; notes: string[] } {
  const findings: Finding[] = []
  const notes: string[] = []
  const header = (name: string) => input.headers[name.toLowerCase()]?.trim() ?? ''
  const isHttps = /^https:/i.test(input.finalUrl)
  const host = (() => {
    try {
      return new URL(input.finalUrl).host
    } catch {
      return input.finalUrl
    }
  })()

  /* Transport ------------------------------------------------------- */
  if (!isHttps) {
    findings.push({
      id: 'https',
      title: 'Site is served over plain HTTP',
      severity: 'critical',
      category: 'Transport',
      detail: `${host} answered without TLS. Every request, cookie and password on this page can be read or rewritten by anyone on the network path.`,
      evidence: [`Requested: ${input.requested}`, `Final URL: ${input.finalUrl}`],
      attacks: ['mitm', 'session_hijack', 'secret_leak'],
      fix: 'Serve everything over HTTPS and redirect HTTP with a permanent redirect. Enable HSTS once the redirect is in place.',
      code: 'server {\n  listen 80;\n  server_name example.com;\n  return 301 https://$host$request_uri;\n}',
      lang: 'nginx',
      cwe: 'CWE-319',
    })
  }

  const hsts = header('strict-transport-security')
  if (isHttps) {
    if (!hsts) {
      findings.push({
        id: 'hsts',
        title: 'No HSTS header',
        severity: 'medium',
        category: 'Transport',
        detail: 'Without Strict-Transport-Security the browser will happily follow an http:// link or a stripped redirect to this site, which is exactly what a downgrade attack needs.',
        evidence: ['strict-transport-security: (missing)'],
        attacks: ['mitm', 'session_hijack'],
        fix: 'Send HSTS for at least six months, on the HTTPS response of every host you serve. Add includeSubDomains and preload once you are sure every subdomain supports HTTPS.',
        code: 'Strict-Transport-Security: max-age=31536000; includeSubDomains',
        lang: 'http',
        cwe: 'CWE-319',
      })
    } else {
      const maxAge = Number(/max-age\s*=\s*"?(\d+)/i.exec(hsts)?.[1] ?? 0)
      if (maxAge < 15_552_000) {
        findings.push({
          id: 'hsts',
          title: 'HSTS window is short',
          severity: 'low',
          category: 'Transport',
          detail: `HSTS is enabled but max-age is ${maxAge}s, so the browser forgets the policy quickly and every new visit is downgrade-able for that window.`,
          evidence: [`strict-transport-security: ${hsts}`],
          attacks: ['mitm'],
          fix: 'Raise max-age to 31536000 (one year). Once every subdomain is HTTPS-only, add includeSubDomains and submit to the preload list.',
          code: 'Strict-Transport-Security: max-age=31536000; includeSubDomains',
          lang: 'http',
          cwe: 'CWE-319',
        })
      }
    }
  }

  /* Response headers ------------------------------------------------ */
  const csp = header('content-security-policy')
  if (!csp) {
    findings.push({
      id: 'csp',
      title: 'No Content-Security-Policy',
      severity: 'high',
      category: 'Headers',
      detail: 'Nothing constrains which scripts may run on the page. Any injection that lands in the HTML executes with full access to the DOM and to every non-HttpOnly cookie.',
      evidence: ['content-security-policy: (missing)'],
      attacks: ['xss', 'supply_chain', 'clickjacking'],
      fix: 'Start with a report-only policy, fix what it reports, then enforce. A practical baseline: default-src \'self\', a nonce for your own scripts, and no inline or eval.',
      code: "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-<random>'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
      lang: 'http',
      cwe: 'CWE-693',
    })
  } else {
    const scriptSrc = directive(csp, 'script-src')
    const loose: string[] = []
    if (!scriptSrc) loose.push('no script-src or default-src')
    if (/'unsafe-inline'/i.test(scriptSrc)) loose.push("'unsafe-inline'")
    if (/'unsafe-eval'/i.test(scriptSrc)) loose.push("'unsafe-eval'")
    if (/\s\*\s*$|\s\*\s*;/.test(scriptSrc)) loose.push('a wildcard source')
    if (!/object-src/i.test(csp)) loose.push("object-src not restricted")
    if (loose.length) {
      findings.push({
        id: 'csp',
        title: 'Content-Security-Policy is permissive',
        severity: 'medium',
        category: 'Headers',
        detail: `The policy allows ${loose.join(', ')}, so it will not stop injected or third-party script from running.`,
        evidence: [`content-security-policy: ${csp.slice(0, 220)}`],
        attacks: ['xss', 'supply_chain'],
        fix: "Remove 'unsafe-inline' and 'unsafe-eval' from script-src, use per-response nonces or hashes for your own inline script, and restrict object-src and base-uri.",
        code: "script-src 'self' 'nonce-<random>' https://cdn.example.com",
        lang: 'http',
        cwe: 'CWE-693',
      })
    }
    if (!/frame-ancestors/i.test(csp) && !header('x-frame-options')) {
      findings.push({
        id: 'xfo',
        title: 'Page can be framed by any site',
        severity: 'medium',
        category: 'Headers',
        detail: 'No X-Frame-Options and no frame-ancestors directive, so the page can be loaded in an invisible iframe and clicked through.',
        evidence: ['x-frame-options: (missing)', 'content-security-policy: frame-ancestors (missing)'],
        attacks: ['clickjacking'],
        fix: "Add frame-ancestors 'none' to the CSP (and X-Frame-Options: DENY for old clients).",
        code: "Content-Security-Policy: frame-ancestors 'none'\nX-Frame-Options: DENY",
        lang: 'http',
        cwe: 'CWE-1021',
      })
    } else if (header('x-frame-options').toLowerCase().startsWith('allow-from')) {
      findings.push({
        id: 'xfo',
        title: 'Deprecated X-Frame-Options value',
        severity: 'medium',
        category: 'Headers',
        detail: 'ALLOW-FROM is ignored by every current browser, so this page has no clickjacking protection at all.',
        evidence: [`x-frame-options: ${header('x-frame-options')}`],
        attacks: ['clickjacking'],
        fix: "Replace ALLOW-FROM with CSP frame-ancestors, which every current browser honours.",
        code: "Content-Security-Policy: frame-ancestors 'self'",
        lang: 'http',
        cwe: 'CWE-1021',
      })
    }
  }

  if (!header('x-content-type-options').toLowerCase().includes('nosniff')) {
    findings.push({
      id: 'nosniff',
      title: 'Missing X-Content-Type-Options: nosniff',
      severity: 'low',
      category: 'Headers',
      detail: 'Browsers may sniff a response into a different type than you sent, which turns an uploaded file into executable HTML or script.',
      evidence: ['x-content-type-options: (missing)'],
      attacks: ['xss'],
      fix: 'Send nosniff on every response, not just HTML.',
      code: 'X-Content-Type-Options: nosniff',
      lang: 'http',
      cwe: 'CWE-693',
    })
  }

  const referrer = header('referrer-policy').toLowerCase()
  if (!referrer || /unsafe-url|no-referrer-when-downgrade/.test(referrer)) {
    findings.push({
      id: 'referrer',
      title: referrer ? 'Weak Referrer-Policy' : 'No Referrer-Policy',
      severity: 'low',
      category: 'Headers',
      detail: referrer
        ? `"${referrer}" sends the full URL to other origins, which can leak tokens or internal paths placed in query strings.`
        : 'Without a policy, browsers fall back to behaviour that sends the full URL to other origins, leaking tokens or internal paths in query strings.',
      evidence: [`referrer-policy: ${referrer || '(missing)'}`],
      attacks: ['recon', 'secret_leak'],
      fix: 'Use strict-origin-when-cross-origin, or no-referrer if you do not need referrer data at all.',
      code: 'Referrer-Policy: strict-origin-when-cross-origin',
      lang: 'http',
      cwe: 'CWE-200',
    })
  }

  if (!header('permissions-policy')) {
    findings.push({
      id: 'permissions',
      title: 'No Permissions-Policy',
      severity: 'info',
      category: 'Headers',
      detail: 'Camera, microphone, geolocation and friends are available to every embedded and injected context by default.',
      evidence: ['permissions-policy: (missing)'],
      attacks: ['xss'],
      fix: 'Deny the features you do not use so an injected script or a malicious iframe cannot ask for them.',
      code: 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()',
      lang: 'http',
      cwe: 'CWE-693',
    })
  }

  const banner = [header('server'), header('x-powered-by'), header('x-aspnet-version'), header('x-generator')].filter(Boolean)
  const leaked = banner.filter((value) => /\d/.test(value) || /x-powered-by|aspnet|generator/i.test(value))
  if (leaked.length) {
    findings.push({
      id: 'banner',
      title: 'Stack version disclosed in headers',
      severity: 'low',
      category: 'Headers',
      detail: 'These headers tell an attacker which server and framework version to look up exploits for.',
      evidence: leaked,
      attacks: ['recon'],
      fix: 'Remove version detail: server_tokens off in nginx, remove X-Powered-By in Express, and keep error pages generic.',
      code: "// Express\napp.disable('x-powered-by')\n\n# nginx\nserver_tokens off;",
      lang: 'js',
      cwe: 'CWE-200',
    })
  }

  const coop = header('cross-origin-opener-policy')
  if (!/same-origin/i.test(coop)) {
    findings.push({
      id: 'coop',
      title: 'No Cross-Origin-Opener-Policy',
      severity: 'low',
      category: 'Headers',
      detail: 'A page opened from another window keeps a handle to it through window.opener. COOP cuts that link, so a page from another origin cannot navigate or inspect this one.',
      evidence: [`cross-origin-opener-policy: ${coop || '(missing)'}`],
      attacks: ['xss', 'cors_theft'],
      fix: 'Send Cross-Origin-Opener-Policy: same-origin on documents that carry a session.',
      code: 'Cross-Origin-Opener-Policy: same-origin',
      lang: 'http',
      cwe: 'CWE-1021',
    })
  }

  const corp = header('cross-origin-resource-policy')
  if (!corp) {
    findings.push({
      id: 'corp',
      title: 'No Cross-Origin-Resource-Policy',
      severity: 'info',
      category: 'Headers',
      detail: 'Without CORP, other sites may embed this response as an image, script or frame. That enables hotlinking and some cross-origin leaks.',
      evidence: ['cross-origin-resource-policy: (missing)'],
      attacks: ['recon', 'cors_theft'],
      fix: 'Send Cross-Origin-Resource-Policy: same-origin (or same-site) for private resources.',
      code: 'Cross-Origin-Resource-Policy: same-origin',
      lang: 'http',
      cwe: 'CWE-346',
    })
  }

  const xssFilter = header('x-xss-protection')
  if (/^1/i.test(xssFilter)) {
    findings.push({
      id: 'xxp',
      title: 'Legacy X-XSS-Protection is enabled',
      severity: 'info',
      category: 'Headers',
      detail: 'The old browser XSS filter is deprecated and has itself been used to introduce vulnerabilities. It is not a replacement for CSP.',
      evidence: [`x-xss-protection: ${xssFilter}`],
      attacks: ['xss'],
      fix: 'Remove X-XSS-Protection and rely on a strict Content-Security-Policy instead.',
      code: 'Content-Security-Policy: default-src \'self\'; script-src \'self\'',
      lang: 'http',
      cwe: 'CWE-693',
    })
  }

  /* Cookies --------------------------------------------------------- */
  const cookies = parseCookies(input.cookies)
  if (cookies.length) {
    const issues: string[] = []
    let severe = false
    for (const cookie of cookies) {
      const has = (flag: string) => cookie.flags.some((f) => f === flag || f.startsWith(`${flag}=`))
      if (!has('secure') && isHttps) {
        issues.push(`${cookie.name}: no Secure — sent over plain HTTP if the user ever does`)
        severe = true
      }
      if (!has('httponly')) {
        issues.push(`${cookie.name}: no HttpOnly — readable by any script on the page`)
        severe = true
      }
      const sameSite = cookie.flags.find((f) => f.startsWith('samesite'))
      if (!sameSite) issues.push(`${cookie.name}: no SameSite — attached to cross-site requests`)
      else if (sameSite.includes('none') && !has('secure')) issues.push(`${cookie.name}: SameSite=None without Secure`)
    }
    if (issues.length) {
      findings.push({
        id: 'cookies',
        title: 'Cookie flags are incomplete',
        severity: severe ? 'high' : 'medium',
        category: 'Cookies',
        detail: 'Session cookies without the full flag set can be read by injected script or replayed from another site.',
        evidence: issues.slice(0, 8),
        attacks: severe ? ['session_hijack', 'xss', 'csrf'] : ['csrf'],
        fix: 'Set HttpOnly, Secure and SameSite=Lax (or Strict) on session cookies, and keep their lifetime short.',
        code: 'Set-Cookie: session=<id>; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400',
        lang: 'http',
        cwe: 'CWE-1004',
      })
    }
  }

  /* CORS ------------------------------------------------------------ */
  const allowOrigin = input.cors.allowOrigin?.trim()
  const allowCredentials = input.cors.allowCredentials?.trim().toLowerCase()
  if (allowOrigin === '*' && allowCredentials === 'true') {
    findings.push({
      id: 'cors',
      title: 'CORS allows any origin with credentials',
      severity: 'critical',
      category: 'CORS',
      detail: 'Access-Control-Allow-Origin: * together with credentials means any website can make authenticated requests to this endpoint and read the response.',
      evidence: ['access-control-allow-origin: *', 'access-control-allow-credentials: true'],
      attacks: ['cors_theft', 'session_hijack'],
      fix: 'Reflect only origins from an explicit allowlist, never *. Browsers reject * for credentialed requests, but proxies and older clients will not.',
      code: 'const allowed = new Set(["https://app.example.com"])\nconst origin = req.headers.origin\nif (origin && allowed.has(origin)) {\n  res.setHeader("Access-Control-Allow-Origin", origin)\n  res.setHeader("Vary", "Origin")\n  res.setHeader("Access-Control-Allow-Credentials", "true")\n}',
      lang: 'js',
      cwe: 'CWE-942',
    })
  } else if (allowOrigin && allowOrigin === input.cors.probeOrigin && allowCredentials === 'true') {
    findings.push({
      id: 'cors',
      title: 'CORS reflects any origin with credentials',
      severity: 'critical',
      category: 'CORS',
      detail: `The server echoed back a made-up origin (${input.cors.probeOrigin}) and allowed credentials. Any site can therefore read authenticated responses from this endpoint.`,
      evidence: [`access-control-allow-origin: ${allowOrigin}`, 'access-control-allow-credentials: true'],
      attacks: ['cors_theft', 'session_hijack'],
      fix: 'Compare the Origin header against an allowlist instead of reflecting it, and add Vary: Origin.',
      code: 'const allowed = new Set(["https://app.example.com"])\nif (allowed.has(req.headers.origin)) res.setHeader("Access-Control-Allow-Origin", req.headers.origin)',
      lang: 'js',
      cwe: 'CWE-942',
    })
  } else if (allowOrigin === '*') {
    findings.push({
      id: 'cors',
      title: 'CORS is open to every origin',
      severity: 'low',
      category: 'CORS',
      detail: 'Any site can read this endpoint’s response. That is fine for genuinely public data and a problem the moment private data is added.',
      evidence: ['access-control-allow-origin: *'],
      attacks: ['cors_theft'],
      fix: 'Scope CORS to the origins that need it, and never add credentials while * is in place.',
      code: "Access-Control-Allow-Origin: https://app.example.com\nVary: Origin",
      lang: 'http',
      cwe: 'CWE-942',
    })
  }

  /* Page content ---------------------------------------------------- */
  const html = input.html
  if (!html) {
    notes.push('The response had no HTML body, so page-content checks were skipped.')
  } else {
    const mixed = [...html.matchAll(/(?:src|href|action)\s*=\s*["'](http:\/\/[^"']+)["']/gi)]
      .map((m) => m[1])
      .filter(isInsecureUrl)
    if (mixed.length) {
      findings.push({
        id: 'mixed',
        title: 'Page loads resources over plain HTTP',
        severity: 'high',
        category: 'Content',
        detail: 'Mixed content can be blocked by the browser today, and rewritten by anyone on the network path tomorrow. A script loaded over HTTP can be replaced entirely.',
        evidence: [...new Set(mixed)].slice(0, 6),
        attacks: ['mitm', 'xss', 'supply_chain'],
        fix: 'Load every asset over HTTPS. For https pages the browser also blocks active mixed content, so this usually shows up as broken styles or silent failures.',
        code: '<script src="https://cdn.example.com/app.js"></script>',
        lang: 'html',
        cwe: 'CWE-319',
      })
    }

    const forms = [...html.matchAll(/<form\b[^>]*>/gi)].map((m) => m[0])
    const insecureForm = forms.filter((tag) => /action\s*=\s*["']http:\/\//i.test(tag) && isInsecureUrl(/action\s*=\s*["']([^"']+)/i.exec(tag)?.[1] ?? ''))
    const password = /<input\b[^>]*type\s*=\s*["']?password/i.test(html)
    if (insecureForm.length || (password && !isHttps)) {
      findings.push({
        id: 'forms',
        title: 'Login or form data can travel unencrypted',
        severity: 'critical',
        category: 'Forms',
        detail: 'A password field on a page that is not HTTPS, or a form that posts to an http:// action, sends credentials in clear text.',
        evidence: insecureForm.slice(0, 4),
        attacks: ['mitm', 'session_hijack', 'secret_leak'],
        fix: 'Serve the form over HTTPS and post to a relative or https:// action. Add autocomplete hints and never prefill passwords from a query string.',
        code: '<form method="post" action="/login" autocomplete="on">',
        lang: 'html',
        cwe: 'CWE-319',
      })
    }

    const scriptTags = [...html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi)]
    const thirdParty = scriptTags
      .map((m) => ({ tag: m[0], src: m[1] }))
      .filter(({ tag, src }) => {
        if (!/^https?:\/\//i.test(src) || /integrity\s*=/i.test(tag)) return false
        try {
          return new URL(src, input.finalUrl).host !== host
        } catch {
          return false
        }
      })
    if (thirdParty.length) {
      findings.push({
        id: 'sri',
        title: 'Third-party scripts load without integrity hashes',
        severity: 'medium',
        category: 'Content',
        detail: 'If one of these files changes on the CDN, the browser runs the new code with your origin’s trust, including access to the page and its cookies.',
        evidence: thirdParty.map(({ src }) => src).slice(0, 5),
        attacks: ['supply_chain', 'xss'],
        fix: 'Add integrity and crossorigin to every third-party script and stylesheet, or self-host the file.',
        code: '<script src="https://cdn.example.com/lib.js" integrity="sha384-…" crossorigin="anonymous"></script>',
        lang: 'html',
        cwe: 'CWE-353',
      })
    }

    const blankLinks = [...html.matchAll(/<a\b[^>]*target\s*=\s*["']_blank["'][^>]*>/gi)].map((m) => m[0])
    const unsafeBlank = blankLinks.filter((tag) => !/rel\s*=\s*["'][^"']*(noopener|noreferrer)/i.test(tag))
    if (unsafeBlank.length) {
      findings.push({
        id: 'blank',
        title: 'target="_blank" without rel="noopener"',
        severity: 'low',
        category: 'Content',
        detail: `${unsafeBlank.length} link${unsafeBlank.length === 1 ? '' : 's'} open a new tab without rel="noopener". The opened page can reach back through window.opener.`,
        evidence: unsafeBlank.slice(0, 4),
        attacks: ['xss', 'open_redirect'],
        fix: 'Add rel="noopener noreferrer" to outbound links that open a new tab.',
        code: '<a href="https://example.com" target="_blank" rel="noopener noreferrer">',
        lang: 'html',
        cwe: 'CWE-1022',
      })
    }

    const secretPatterns: { label: string; re: RegExp }[] = [
      { label: 'AWS access key id', re: /\bAKIA[0-9A-Z]{16}\b/ },
      { label: 'Stripe live secret key', re: /\bsk_live_[0-9a-zA-Z]{16,}/ },
      { label: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{30,}/ },
      { label: 'GitHub token', re: /\bgh[pousr]_[0-9A-Za-z]{30,}/ },
      { label: 'Private key block', re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
      { label: 'Slack token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}/ },
    ]
    const secrets = secretPatterns.filter(({ re }) => re.test(html)).map(({ label }) => `${label} found in the HTML or inline script`)
    if (secrets.length) {
      findings.push({
        id: 'secrets',
        title: 'Credentials are present in the page source',
        severity: 'critical',
        category: 'Disclosure',
        detail: 'Anything in the page source is public. A key that ships to the browser can be copied and used directly against the provider.',
        evidence: secrets,
        attacks: ['secret_leak'],
        fix: 'Move the call server-side so the key never reaches the client, then rotate the exposed key and remove it from history.',
        code: '// Browser: call your own API\nawait fetch("/api/weather", { method: "POST", body: JSON.stringify({ city }) })',
        lang: 'js',
        cwe: 'CWE-798',
      })
    }

    const maps = [...html.matchAll(/sourceMappingURL=([^\s*"']+)/gi)].map((m) => m[1])
    if (maps.length) {
      findings.push({
        id: 'sourcemaps',
        title: 'Source maps are referenced in production',
        severity: 'info',
        category: 'Disclosure',
        detail: 'A published .map file gives back your original source, comments, TODOs and sometimes internal endpoints.',
        evidence: [...new Set(maps)].slice(0, 4),
        attacks: ['recon', 'secret_leak'],
        fix: 'Upload source maps to your error tracker instead of serving them publicly, and strip the reference in production builds.',
        code: '// vite.config.ts\nexport default { build: { sourcemap: "hidden" } }',
        lang: 'ts',
        cwe: 'CWE-540',
      })
    }
  }

  if (html) {
    const generator = /<meta[^>]+name\s*=\s*["']generator["'][^>]*>/i.exec(html)?.[0]
    const generatorName = generator ? /content\s*=\s*["']([^"']+)/i.exec(generator)?.[1] : undefined
    if (generatorName) {
      findings.push({
        id: 'generator',
        title: 'CMS or framework version published in the page',
        severity: 'low',
        category: 'Disclosure',
        detail: `A generator meta tag names the exact platform and version, so an attacker can look up exploits that match it.`,
        evidence: [`<meta name="generator" content="${generatorName}">`],
        attacks: ['recon', 'supply_chain'],
        fix: 'Remove the generator tag, or have your CMS stop emitting it, so the page does not advertise its version.',
        code: "remove_action('wp_head', 'wp_generator');",
        lang: 'php',
        cwe: 'CWE-200',
      })
    }

    const unsandboxedFrames = [...html.matchAll(/<iframe\b[^>]*>/gi)].map((match) => match[0]).filter((tag) => !/sandbox\s*=/i.test(tag))
    const externalFrames = unsandboxedFrames.filter((tag) => {
      const src = /src\s*=\s*["']([^"']+)/i.exec(tag)?.[1]
      if (!src) return false
      try {
        return new URL(src, input.finalUrl).host !== host
      } catch {
        return false
      }
    })
    if (externalFrames.length) {
      findings.push({
        id: 'iframes',
        title: 'Third-party iframes are not sandboxed',
        severity: 'low',
        category: 'Content',
        detail: 'An embedded page keeps its own origin, but without a sandbox attribute it can still open popups, navigate the top window and ask for permissions.',
        evidence: externalFrames.slice(0, 4),
        attacks: ['clickjacking', 'xss'],
        fix: 'Add a restrictive sandbox attribute, and list only the capabilities the embed actually needs.',
        code: '<iframe src="https://embed.example.com" sandbox="allow-scripts allow-same-origin"></iframe>',
        lang: 'html',
        cwe: 'CWE-1021',
      })
    }

    const postForms = [...html.matchAll(/<form\b[^>]*>/gi)]
      .map((match) => match[0])
      .filter((tag) => /method\s*=\s*["']?post/i.test(tag))
    const hiddenToken = /<input[^>]+(name|id)\s*=\s*["'][^"']*(csrf|xsrf|_token|authenticity_token|requestverificationtoken)/i.test(html)
    if (postForms.length && cookies.length && !hiddenToken) {
      findings.push({
        id: 'csrf-token',
        title: 'POST form without a visible CSRF token',
        severity: 'medium',
        category: 'Forms',
        detail: 'This page sets cookies and contains a form that posts back, but no hidden anti-CSRF field was found. If the session cookie is not SameSite, another site can submit this form for a signed-in visitor.',
        evidence: postForms.slice(0, 3),
        attacks: ['csrf'],
        fix: 'Add a per-session, per-form token that the server verifies, and keep session cookies SameSite=Lax or Strict.',
        code: '<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">',
        lang: 'html',
        cwe: 'CWE-352',
      })
    }

    if (input.status >= 500 && /traceback \(most recent call last\)|stack trace|sqlstate\[|exception in thread|at [\w.$]+ \(.+:\d+:\d+\)/i.test(html)) {
      findings.push({
        id: 'errors',
        title: 'Server error page exposes internals',
        severity: 'high',
        category: 'Disclosure',
        detail: 'The error response contains a stack trace, framework paths or database detail. That is a full map of the application for anyone who can trigger an error.',
        evidence: [`HTTP ${input.status} with diagnostic output in the body`],
        attacks: ['recon', 'path_traversal', 'sqli'],
        fix: 'Return a generic error page in production and send the detail to your error tracker with a request id.',
        code: 'app.use((err, req, res, next) => {\n  log.error(err, { id: req.id })\n  res.status(500).send("Something went wrong. Reference: " + req.id)\n})',
        lang: 'js',
        cwe: 'CWE-209',
      })
    }
  }

  /* robots.txt ------------------------------------------------------ */
  if (input.robots) {
    const paths = [...input.robots.matchAll(/^\s*Disallow:\s*(\S+)/gim)]
      .map((m) => m[1])
      .filter((path) => path !== '/' && /admin|dashboard|internal|private|backup|staging|\.git|\.env|config|debug|secret|phpmyadmin/i.test(path))
    if (paths.length) {
      findings.push({
        id: 'robots',
        title: 'robots.txt advertises private paths',
        severity: 'info',
        category: 'Disclosure',
        detail: 'robots.txt is public and is the first file scanners read. Listing admin or backup paths saves an attacker the guessing.',
        evidence: [...new Set(paths)].slice(0, 8),
        attacks: ['recon', 'path_traversal'],
        fix: 'Protect those paths with authentication instead of a robots rule, and keep them out of the file.',
        code: 'User-agent: *\nDisallow: /search',
        lang: 'txt',
        cwe: 'CWE-200',
      })
    }
  }

  notes.push('Only this page was requested, plus robots.txt and one CORS probe. No links were crawled and no payloads were sent.')
  notes.push('TLS certificate, DNS and server internals are not visible from the edge, so they are not part of this report.')

  const sorted = sortFindings(findings)
  return { findings: sorted, checks: buildChecks(SITE_CHECKS, sorted), notes }
}

/* ------------------------------------------------------------------ */
/* Source audit                                                        */
/* ------------------------------------------------------------------ */

export type SourceInput = { path: string; text: string }[]

type Hit = { path: string; line: number; text: string }

function scanLines(files: SourceInput, pattern: RegExp, limit = 40): Hit[] {
  const hits: Hit[] = []
  for (const file of files) {
    const lines = file.text.split('\n')
    for (let i = 0; i < lines.length; i++) {
      pattern.lastIndex = 0
      if (!pattern.test(lines[i])) continue
      hits.push({ path: file.path, line: i + 1, text: lines[i].trim().slice(0, 200) })
      if (hits.length >= limit) return hits
    }
  }
  return hits
}

function redact(text: string) {
  return text
    .replace(/^([A-Za-z0-9_.-]+)\s*=\s*(\S.*)$/, (_match, key: string) => `${key}=••••••`)
    .replace(/(['"`])([^'"`\s]{8,})(\1)/g, (match) => (match.length > 20 ? `${match.slice(0, 8)}…${match.slice(-2)}` : match))
    .replace(/\b[A-Za-z0-9_\-]{24,}\b/g, (match) => `${match.slice(0, 4)}…${match.slice(-2)}`)
}

export const SOURCE_CHECKS = [
  { id: 'secrets', label: 'No hardcoded credentials' },
  { id: 'env', label: 'No committed .env files' },
  { id: 'eval', label: 'No eval or dynamic code' },
  { id: 'html-sinks', label: 'No raw HTML sinks' },
  { id: 'sql', label: 'Queries are parameterised' },
  { id: 'insecure-http', label: 'No plain-HTTP endpoints' },
  { id: 'tls-verify', label: 'TLS verification left on' },
  { id: 'weak-hash', label: 'Strong password hashing' },
  { id: 'token-storage', label: 'Tokens kept out of localStorage' },
  { id: 'cors-wildcard', label: 'CORS restricted to allowlist' },
  { id: 'acao-reflect', label: 'Origin header not reflected' },
  { id: 'postmessage', label: 'postMessage verified' },
  { id: 'jwt', label: 'JWTs verified' },
  { id: 'deserialization', label: 'No unsafe deserialising' },
  { id: 'debug', label: 'Debug mode off' },
  { id: 'open-redirect', label: 'Redirects validated' },
  { id: 'path-traversal', label: 'File paths constrained' },
  { id: 'rce', label: 'No shell from user input' },
  { id: 'math-random', label: 'Secrets use a CSPRNG' },
  { id: 'deps', label: 'Dependencies pinned' },
]

export function auditSource(files: SourceInput): { findings: Finding[]; checks: Check[]; notes: string[] } {
  const findings: Finding[] = []
  const notes: string[] = []
  const add = (finding: Finding, hits: Hit[], mask = false) => {
    if (!hits.length) return
    const evidence = hits.slice(0, 6).map((hit) => `${hit.path}:${hit.line}  ${mask ? redact(hit.text) : hit.text}`)
    if (hits.length > 6) evidence.push(`…and ${hits.length - 6} more occurrence${hits.length - 6 === 1 ? '' : 's'}`)
    findings.push({ ...finding, evidence })
  }

  add(
    {
      id: 'secrets',
      title: 'Hardcoded credentials in source',
      severity: 'critical',
      category: 'Secrets',
      detail: 'A key, token or password is written into the code. If this file is bundled for the browser or committed to a repo, the value is already public.',
      attacks: ['secret_leak'],
      fix: 'Move the value into an environment variable or secret manager, rotate the exposed credential, and call the provider from the server.',
      code: 'const key = process.env.STRIPE_SECRET_KEY\nif (!key) throw new Error("STRIPE_SECRET_KEY is not set")',
      lang: 'js',
      cwe: 'CWE-798',
    },
    scanLines(
      files,
      /(\bAKIA[0-9A-Z]{16}\b|\bsk_live_[0-9a-zA-Z]{16,}|\bAIza[0-9A-Za-z_-]{30,}|\bgh[pousr]_[0-9A-Za-z]{30,}|\bxox[baprs]-[0-9A-Za-z-]{10,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|(api[_-]?key|secret|password|access[_-]?token)\s*[:=]\s*['"][^'"\s]{8,}['"])/i,
    ),
    true,
  )

  const envFiles = files.filter((file) => /(^|\/)\.env(\.|$)|(^|\/)(secrets?|credentials?)\.(ya?ml|json|ini|txt)$/i.test(file.path))
  if (envFiles.length) {
    add(
      {
        id: 'env',
        title: 'Environment file included in the upload',
        severity: 'critical',
        category: 'Secrets',
        detail: 'Dotenv files hold the real values for every service the app talks to. They belong in .gitignore, not in a build or a repository.',
        attacks: ['secret_leak'],
        fix: 'Remove the file from the archive, add it to .gitignore, rotate every value it contained, and provide a .env.example with empty values instead.',
        code: '# .gitignore\n.env\n.env.*\n!.env.example',
        lang: 'bash',
        cwe: 'CWE-798',
      },
      envFiles.map((file) => ({ path: file.path, line: 1, text: file.text.split('\n').find((line) => /=/.test(line))?.trim() ?? '' })),
      true,
    )
  }

  add(
    {
      id: 'eval',
      title: 'Dynamic code execution',
      severity: 'high',
      category: 'Injection',
      detail: 'eval() and new Function() run whatever string they are given. One unescaped value on that path becomes remote code execution.',
      attacks: ['rce', 'xss'],
      fix: 'Replace dynamic evaluation with a lookup table, JSON.parse for data, and explicit branches for behaviour.',
      code: 'const handlers = { save, cancel }\nhandlers[action]?.()',
      lang: 'js',
      cwe: 'CWE-95',
    },
    scanLines(files, /\beval\s*\(|new\s+Function\s*\(/),
  )

  add(
    {
      id: 'html-sinks',
      title: 'Raw HTML sinks fed by variables',
      severity: 'high',
      category: 'XSS',
      detail: 'innerHTML, dangerouslySetInnerHTML, document.write and v-html interpret their input as markup. Any user-controlled value on the right-hand side is a cross-site scripting bug.',
      attacks: ['xss'],
      fix: 'Render values as text, or sanitise with a maintained library (DOMPurify) when markup is genuinely required.',
      code: 'element.textContent = value\n// or\n<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />',
      lang: 'jsx',
      cwe: 'CWE-79',
    },
    scanLines(files, /\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(|v-html\s*=|\$sce\.trustAsHtml/),
  )

  add(
    {
      id: 'sql',
      title: 'SQL built by string concatenation',
      severity: 'high',
      category: 'Injection',
      detail: 'A query is assembled from values at runtime. If any part comes from a request, the attacker controls the statement, not just the data.',
      attacks: ['sqli'],
      fix: 'Use parameterised queries (placeholders) and an ORM, including for ORDER BY and identifiers via an allowlist.',
      code: 'await db.query("SELECT * FROM issues WHERE id = $1", [id])',
      lang: 'js',
      cwe: 'CWE-89',
    },
    scanLines(files, /(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)[^;\n]{0,180}(\+\s*[a-zA-Z_$]|\$\{)/i),
  )

  add(
    {
      id: 'insecure-http',
      title: 'Plain-HTTP endpoints in code',
      severity: 'medium',
      category: 'Transport',
      detail: 'Calling an http:// URL sends the request and its response in clear text, even from an HTTPS page.',
      attacks: ['mitm', 'session_hijack'],
      fix: 'Use https:// for every endpoint. Localhost is fine for development; gate it behind an environment check.',
      code: 'const base = import.meta.env.DEV ? "http://localhost:8787" : "https://api.example.com"',
      lang: 'js',
      cwe: 'CWE-319',
    },
    scanLines(files, /["'`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^"'`\s]+/),
  )

  add(
    {
      id: 'tls-verify',
      title: 'TLS verification disabled',
      severity: 'high',
      category: 'Transport',
      detail: 'Certificate checks are turned off, which turns every HTTPS call into an unauthenticated channel that anyone on the path can impersonate.',
      attacks: ['mitm', 'secret_leak'],
      fix: 'Remove the override. If you use a private CA, trust that CA explicitly instead of disabling verification.',
      code: 'https.get(url, { rejectUnauthorized: true }, handler)',
      lang: 'js',
      cwe: 'CWE-295',
    },
    scanLines(files, /rejectUnauthorized\s*:\s*false|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED|InsecureSkipVerify\s*:\s*true/),
  )

  add(
    {
      id: 'weak-hash',
      title: 'Weak hash used for passwords',
      severity: 'high',
      category: 'Crypto',
      detail: 'MD5 and SHA-1 are built for speed, so a leaked hash table is cracked quickly. They are not password hashes.',
      attacks: ['secret_leak'],
      fix: 'Use bcrypt, scrypt or Argon2id with a per-user salt and a sensible cost factor.',
      code: "import { hash } from 'bcryptjs'\nconst digest = await hash(password, 12)",
      lang: 'js',
      cwe: 'CWE-916',
    },
    scanLines(files, /createHash\(\s*['"](md5|sha1)['"]|hashlib\.(md5|sha1)\s*\(|\bmd5\s*\(/i),
  )

  add(
    {
      id: 'token-storage',
      title: 'Auth token saved in localStorage',
      severity: 'medium',
      category: 'Session',
      detail: 'localStorage is readable by any script on the origin, so one XSS turns into a permanent stolen session.',
      attacks: ['xss', 'session_hijack'],
      fix: 'Keep session state in an HttpOnly, Secure cookie, or in memory with a refresh token in a cookie.',
      code: 'Set-Cookie: session=<id>; HttpOnly; Secure; SameSite=Lax',
      lang: 'http',
      cwe: 'CWE-922',
    },
    scanLines(files, /localStorage\.setItem\(\s*[^)]*(token|jwt|auth|session)/i),
  )

  add(
    {
      id: 'cors-wildcard',
      title: 'CORS opened to every origin',
      severity: 'high',
      category: 'CORS',
      detail: 'A wildcard or origin reflection in the CORS layer lets any website read your API responses, including authenticated ones when credentials are allowed.',
      attacks: ['cors_theft'],
      fix: 'Allow only known origins and never reflect the raw Origin header. Add Vary: Origin.',
      code: 'cors({ origin: ["https://app.example.com"], credentials: true })',
      lang: 'js',
      cwe: 'CWE-942',
    },
    scanLines(files, /Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*|origin\s*:\s*['"]\*['"]|cors\(\s*\)/),
  )

  add(
    {
      id: 'debug',
      title: 'Debug mode enabled',
      severity: 'low',
      category: 'Config',
      detail: 'Debug mode ships stack traces, settings and sometimes an interactive console to whoever asks for an error.',
      attacks: ['recon', 'secret_leak'],
      fix: 'Read debug from the environment, default it to false, and make sure the production config never turns it on.',
      code: 'DEBUG = os.environ.get("DEBUG", "false").lower() == "true"',
      lang: 'python',
      cwe: 'CWE-489',
    },
    scanLines(files, /DEBUG\s*=\s*True|debug\s*[:=]\s*true|app\.run\([^)]*debug\s*=\s*True/),
  )

  add(
    {
      id: 'open-redirect',
      title: 'Redirect target taken from the request',
      severity: 'medium',
      category: 'Redirects',
      detail: 'Redirecting to a value straight from the query or form lets an attacker use your domain as a trusted hop to a phishing page.',
      attacks: ['open_redirect'],
      fix: 'Accept only relative paths, or compare against an allowlist of hosts before redirecting.',
      code: 'const next = input.startsWith("/") && !input.startsWith("//") ? input : "/"',
      lang: 'js',
      cwe: 'CWE-601',
    },
    scanLines(files, /redirect\(\s*(req\.(query|body|params)|request\.(args|GET|form))/),
  )

  add(
    {
      id: 'path-traversal',
      title: 'File path built from user input',
      severity: 'high',
      category: 'Files',
      detail: 'Reading a file with a name from the request allows ../ sequences and absolute paths, which escape the intended directory.',
      attacks: ['path_traversal', 'secret_leak'],
      fix: 'Resolve the path and verify it stays inside the base directory; better, map ids to stored files.',
      code: 'const full = path.resolve(base, name)\nif (!full.startsWith(base + path.sep)) throw new Error("invalid path")',
      lang: 'js',
      cwe: 'CWE-22',
    },
    scanLines(files, /readFile(Sync)?\(\s*(req\.|request\.)|\binclude\s*\(\s*\$_(GET|POST|REQUEST)|sendFile\(\s*req\./),
  )

  add(
    {
      id: 'rce',
      title: 'Shell command built from user input',
      severity: 'critical',
      category: 'Injection',
      detail: 'Passing request data into a shell or process call lets an attacker append their own command with ; or &&.',
      attacks: ['rce'],
      fix: 'Use an argument array with a fixed binary, and validate anything that must vary. Never pass a request string to a shell.',
      code: "execFile('convert', [inputPath, outputPath])",
      lang: 'js',
      cwe: 'CWE-78',
    },
    scanLines(files, /(exec|execSync|spawn|system|shell_exec|passthru)\s*\([^)\n]*(req\.|request\.|params|query|body)/),
  )

  add(
    {
      id: 'acao-reflect',
      title: 'Origin header reflected into CORS',
      severity: 'critical',
      category: 'CORS',
      detail: 'The response copies the request’s Origin into Access-Control-Allow-Origin. That trusts every website on the internet, so any page can read authenticated responses.',
      attacks: ['cors_theft', 'session_hijack'],
      fix: 'Compare Origin against an allowlist, then answer with that same value and Vary: Origin.',
      code: 'if (allowed.has(origin)) res.setHeader("Access-Control-Allow-Origin", origin)',
      lang: 'js',
      cwe: 'CWE-942',
    },
    scanLines(files, /Access-Control-Allow-Origin[^\n]{0,40}(req|request)\.(headers|get)/),
  )

  add(
    {
      id: 'postmessage',
      title: 'postMessage listener without an origin check',
      severity: 'medium',
      category: 'XSS',
      detail: 'Any window can send a message to this listener, including a hostile page that embeds or opens yours. Without an origin check, an attacker controls the payload handler.',
      attacks: ['xss', 'cors_theft'],
      fix: 'Reject messages whose event.origin is not on an allowlist, and validate the payload shape before using it.',
      code: 'window.addEventListener("message", (event) => {\n  if (event.origin !== "https://app.example.com") return\n  handle(JSON.parse(event.data))\n})',
      lang: 'js',
      cwe: 'CWE-346',
    },
    scanLines(files, /addEventListener\(\s*["']message["']|\.onmessage\s*=/),
  )

  add(
    {
      id: 'deserialization',
      title: 'Unsafe deserialisation of untrusted data',
      severity: 'high',
      category: 'Injection',
      detail: 'pickle, YAML.load and native object deserialisers can construct arbitrary objects, which is code execution with extra steps.',
      attacks: ['rce'],
      fix: 'Use JSON.parse for data, yaml.safe_load for YAML, and never deserialise a request body into native objects.',
      code: 'const data = JSON.parse(body)\nconst config = yaml.safe_load(text)',
      lang: 'js',
      cwe: 'CWE-502',
    },
    scanLines(files, /pickle\.loads|yaml\.load\(|unserialize\(|Marshal\.load|ObjectInputStream/),
  )

  add(
    {
      id: 'jwt',
      title: 'JWT decoded without verification',
      severity: 'high',
      category: 'Session',
      detail: 'Reading claims with decode() does not check the signature, and accepting the “none” algorithm lets an attacker mint their own token.',
      attacks: ['session_hijack', 'xss'],
      fix: 'Verify with an explicit algorithm list and a secret or public key; never trust unverified claims for authorisation.',
      code: 'jwt.verify(token, publicKey, { algorithms: ["RS256"] })',
      lang: 'js',
      cwe: 'CWE-347',
    },
    scanLines(files, /jwt\.decode\(|algorithms\s*:\s*\[\s*["']none["']/i),
  )

  add(
    {
      id: 'math-random',
      title: 'Math.random used for a security value',
      severity: 'low',
      category: 'Crypto',
      detail: 'Math.random is predictable from a few outputs and is not suitable for tokens, ids or reset codes.',
      attacks: ['session_hijack', 'recon'],
      fix: 'Use crypto.randomUUID() or crypto.getRandomValues() for anything an attacker should not guess.',
      code: 'const token = crypto.randomUUID()',
      lang: 'js',
      cwe: 'CWE-330',
    },
    scanLines(files, /Math\.random\(\)[^\n]{0,60}(token|secret|session|nonce|code|id)/i),
  )

  /* package.json ---------------------------------------------------- */
  for (const file of files) {
    if (!/(^|\/)package\.json$/i.test(file.path)) continue
    try {
      const pkg = JSON.parse(file.text) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string>; scripts?: Record<string, string> }
      const loose: string[] = []
      for (const section of [pkg.dependencies, pkg.devDependencies]) {
        for (const [name, version] of Object.entries(section ?? {})) {
          if (!version || version === '*' || version === 'latest' || /^(git\+|https?:)/i.test(version)) loose.push(`${name}: ${version}`)
        }
      }
      if (loose.length) {
        add(
          {
            id: 'deps',
            title: 'Unpinned dependency versions',
            severity: 'low',
            category: 'Supply chain',
            detail: 'Floating or URL-based versions mean the code you tested is not necessarily the code that installs next time.',
            attacks: ['supply_chain'],
            fix: 'Pin exact versions, commit the lockfile, and let an update bot open reviewed pull requests for changes.',
            code: '"dependencies": {\n  "hono": "4.13.18"\n}',
            lang: 'json',
            cwe: 'CWE-1104',
          },
          loose.map((text) => ({ path: file.path, line: 1, text })),
        )
      }
      if (pkg.scripts?.postinstall && /curl|wget|node -e|bash|sh -c/i.test(pkg.scripts.postinstall)) {
        add(
          {
            id: 'deps',
            title: 'Install script downloads and runs code',
            severity: 'medium',
            category: 'Supply chain',
            detail: 'A postinstall script that pipes a download into a shell runs unreviewed remote code on every install and in CI.',
            attacks: ['supply_chain'],
            fix: 'Remove remote execution from install hooks and vendor the artefact instead.',
            code: '"scripts": { "postbuild": "node scripts/postbuild.mjs" }',
            lang: 'json',
            cwe: 'CWE-829',
          },
          [{ path: file.path, line: 1, text: `postinstall: ${pkg.scripts.postinstall.slice(0, 120)}` }],
        )
      }
    } catch {
      notes.push(`${file.path} is not valid JSON, so dependency checks were skipped for it.`)
    }
  }

  const maps = files.filter((file) => /\.map$/i.test(file.path))
  if (maps.length) {
    add(
      {
        id: 'sourcemaps',
        title: 'Source map files in the upload',
        severity: 'info',
        category: 'Disclosure',
        detail: 'Source maps reconstruct your original source. Fine in a private artefact, risky in anything served publicly.',
        attacks: ['recon', 'secret_leak'],
        fix: 'Build production bundles with hidden source maps and upload them to your error tracker only.',
        code: 'build: { sourcemap: "hidden" }',
        lang: 'ts',
        cwe: 'CWE-540',
      },
      maps.map((file) => ({ path: file.path, line: 1, text: 'source map' })),
    )
  }

  notes.push(`${files.length} file${files.length === 1 ? '' : 's'} read in your browser; nothing was uploaded or stored.`)
  notes.push('This is pattern analysis, not a dependency CVE audit or a running app test. Heuristic rules can miss context and flag sample code.')

  const sorted = sortFindings(findings)
  return { findings: sorted, checks: buildChecks(SOURCE_CHECKS, sorted), notes }
}
