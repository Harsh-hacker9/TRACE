// Every string the marketing site shows. The scanner's own labels live with
// the screens; this file holds copy worth editing in one place.

export const BRAND = {
  name: 'Trace',
  tagline: 'Find the bugs before attackers do',
  prefix: 'TRC',
}

export const NAV = {
  links: [
    { label: 'Scanner', to: '/scan' },
    { label: 'Attacks', to: '/attacks' },
    { label: 'How it works', to: '/#how' },
  ],
  cta: 'Scan a site',
}

export const HERO = {
  eyebrow: 'Security review in 30 seconds',
  title: ['Find the bugs', 'before attackers do'],
  body: 'Paste a link or drop in your app. Trace reads the response, checks the code you ship, and tells you which attacks are possible — and exactly how to close them.',
  placeholder: 'your-site.com',
  cta: 'Scan',
  upload: 'or upload your app',
  points: ['No account', 'Passive checks only', 'Downloadable report'],
}

export const FEATURES_HEAD = {
  eyebrow: 'What we check',
  title: 'The mistakes behind most breaches',
  body: 'Not a vulnerability database and not a fuzzer. A focused review of the settings and code patterns that decide whether an attack works.',
}

export const FEATURES = [
  {
    icon: 'lock',
    title: 'Transport and headers',
    body: 'HTTPS, HSTS, CSP, clickjacking, MIME sniffing, referrer and permissions policy — compared against what a current browser expects.',
  },
  {
    icon: 'cookie',
    title: 'Cookies and sessions',
    body: 'HttpOnly, Secure and SameSite on every Set-Cookie, so a stolen cookie cannot become a stolen login.',
  },
  {
    icon: 'globe',
    title: 'CORS policy',
    body: 'One probe with a made-up origin shows whether any website can read your API — including the wildcard-with-credentials mistake.',
  },
  {
    icon: 'code',
    title: 'Injection sinks',
    body: 'eval, innerHTML, string-built SQL and shell calls, with the line and file where they live.',
  },
  {
    icon: 'key',
    title: 'Secrets in what you ship',
    body: 'Live keys, tokens, committed .env files and production source maps, with the value masked in the report.',
  },
  {
    icon: 'route',
    title: 'Redirects and file paths',
    body: 'Open redirects, path traversal and disabled TLS verification: small bugs that turn into account takeover.',
  },
] as const

export const ATTACKS_HEAD = {
  eyebrow: 'Attack surface',
  title: 'What an attacker actually tries',
  body: 'Each finding maps to one of these classes. Open the library for the steps, the impact and the fix.',
}

export const STEPS_HEAD = {
  eyebrow: 'How it works',
  title: 'Two ways in, one report out',
  body: 'A live site is checked from the edge. Uploaded code is read in your browser and never leaves it.',
}

export const STEPS = [
  {
    step: '01',
    title: 'Point it at your work',
    body: 'Paste a URL, or drop a zip of your project. For uploads, zips and plain source files are read locally.',
  },
  {
    step: '02',
    title: 'Trace reads, it does not attack',
    body: 'For a site: the page, its response headers, its cookies, one CORS probe, robots.txt. For code: the files, line by line.',
  },
  {
    step: '03',
    title: 'Get findings with fixes',
    body: 'Severity, evidence, the attacks each issue enables, and the header or code change that closes it.',
  },
] as const

export const LIMITS = {
  title: 'What this is not',
  body: 'An honest report has edges. Trace is a fast first pass, not a penetration test.',
  items: [
    'It only requests the page you name, plus robots.txt and one CORS probe. It does not crawl your site or guess paths.',
    'It never sends exploit payloads, so a clean report does not prove the app is safe.',
    'TLS certificate details, DNS and server internals are not visible from the edge.',
    'Uploaded code is matched against known risky patterns; there is no dependency CVE database and the app is not run.',
    'Only scan sites and code you own or have written permission to test.',
  ],
}

export const CTA = {
  title: 'Ship the fix, not the incident.',
  body: 'Most of what gets exploited is a missing header or one unescaped value. Find it before someone else does.',
  button: 'Open the scanner',
}

export const FOOTER = {
  blurb: 'A passive security review for the sites and apps you build.',
  columns: [
    {
      title: 'Product',
      links: [
        { label: 'Scanner', to: '/scan' },
        { label: 'Attack library', to: '/attacks' },
        { label: 'How it works', to: '/#how' },
      ],
    },
    {
      title: 'Checks',
      links: [
        { label: 'Response headers', to: '/attacks#xss' },
        { label: 'Session cookies', to: '/attacks#session_hijack' },
        { label: 'CORS', to: '/attacks#cors_theft' },
        { label: 'Secrets', to: '/attacks#secret_leak' },
      ],
    },
    {
      title: 'Resources',
      links: [
        { label: 'API health', to: '/api/health' },
        { label: 'OWASP Top 10', to: 'https://owasp.org/Top10/' },
      ],
    },
  ],
  legal: '© 2026 Trace. Scan only what you are allowed to scan.',
}
