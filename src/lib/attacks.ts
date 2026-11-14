// The attack library. Findings point at these ids, and /attacks renders the
// same entries, so an "attack that applies" card is never out of date.

export type AttackId =
  | 'xss'
  | 'sqli'
  | 'csrf'
  | 'clickjacking'
  | 'mitm'
  | 'session_hijack'
  | 'cors_theft'
  | 'secret_leak'
  | 'recon'
  | 'supply_chain'
  | 'open_redirect'
  | 'path_traversal'
  | 'rce'

export type Attack = {
  id: AttackId
  name: string
  severity: 'critical' | 'high' | 'medium'
  tagline: string
  how: string[]
  impact: string
  defenses: string[]
  owasp: string
  href: string
}

export const ATTACKS: Attack[] = [
  {
    id: 'xss',
    name: 'Cross-site scripting',
    severity: 'critical',
    tagline: 'Attacker code runs inside your page, with your users’ session.',
    how: [
      'Attacker finds a place where input reaches the page without escaping: a comment, a search term, a profile name, a query parameter echoed in HTML.',
      'They send a link or post a value containing a script, for example an image tag with an onerror handler.',
      'The browser treats it as part of your page, so it can read the DOM, cookies that are not HttpOnly, and localStorage tokens.',
      'The script quietly calls the attacker’s server with what it found, or performs actions as the victim.',
    ],
    impact: 'Account takeover, data theft, defacement, and actions performed on behalf of every visitor who opens the page.',
    defenses: [
      'Escape output for the context it lands in (HTML text, attribute, URL, JavaScript) instead of blacklisting characters.',
      'Avoid innerHTML and raw HTML sinks; in React never pass user input to dangerouslySetInnerHTML.',
      'Send a Content-Security-Policy that forbids inline script and eval, and use nonces for the scripts you do need.',
      'Mark session cookies HttpOnly and SameSite so a script cannot read or reuse them.',
    ],
    owasp: 'OWASP A03:2021 · Injection',
    href: 'https://owasp.org/Top10/A03_2021-Injection/',
  },
  {
    id: 'sqli',
    name: 'SQL injection',
    severity: 'critical',
    tagline: 'User input becomes part of your query instead of part of its data.',
    how: [
      'Attacker probes a parameter with a quote or a boolean expression and watches for errors or different responses.',
      'Because the value is concatenated into SQL, they can change the query: add OR 1=1, a UNION SELECT, or a stacked statement.',
      'With the right payload they read other tables, dump password hashes, write files, or delete rows.',
    ],
    impact: 'Full database disclosure, authentication bypass, data loss, and sometimes remote code execution on the database host.',
    defenses: [
      'Use parameterised queries or an ORM for every value, including ORDER BY and table names via an allowlist.',
      'Never build SQL with string concatenation or template literals.',
      'Run the app’s database user with the fewest privileges it needs; no DROP, no file access.',
      'Return generic errors so failed payloads do not describe your schema.',
    ],
    owasp: 'OWASP A03:2021 · Injection',
    href: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
  },
  {
    id: 'csrf',
    name: 'Cross-site request forgery',
    severity: 'high',
    tagline: 'Another site makes your logged-in browser perform an action.',
    how: [
      'Attacker hosts a page with a form or image that points at your endpoint, for example POST /account/email.',
      'The victim visits it while signed in. The browser attaches your cookies automatically.',
      'Your server sees a valid session and applies the change, without the victim ever clicking anything on your site.',
    ],
    impact: 'Silent account changes: email swapped, password reset, funds moved, admin actions triggered.',
    defenses: [
      'Set SameSite=Lax or Strict on session cookies so cross-site requests do not carry them.',
      'Require a per-session CSRF token on state-changing requests, or check the Origin header strictly.',
      'Never make GET requests change state.',
      'For APIs, use a bearer token in an Authorization header rather than a cookie.',
    ],
    owasp: 'OWASP A01:2021 · Broken Access Control',
    href: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
  },
  {
    id: 'clickjacking',
    name: 'Clickjacking',
    severity: 'medium',
    tagline: 'Your site is framed invisibly so clicks land on your buttons.',
    how: [
      'Attacker loads your page in a transparent iframe on top of a decoy page.',
      'The victim thinks they are clicking “play” or “continue”, but the click hits your Delete, Transfer or Authorise button.',
      'Because the request comes from the victim’s own browser and session, it looks completely legitimate.',
    ],
    impact: 'Unauthorised actions performed with the victim’s privileges, from deleting data to approving payments.',
    defenses: [
      'Send Content-Security-Policy: frame-ancestors \'none\' (or your own origins).',
      'Keep X-Frame-Options: DENY as a fallback for old browsers.',
      'Require re-authentication for high-impact actions.',
    ],
    owasp: 'OWASP · Clickjacking Defense',
    href: 'https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html',
  },
  {
    id: 'mitm',
    name: 'Man-in-the-middle',
    severity: 'critical',
    tagline: 'Someone on the network reads and rewrites traffic in transit.',
    how: [
      'Attacker sits on the same Wi-Fi, a hotel network, or an ISP path, and answers DNS or ARP traffic.',
      'Without TLS the page, the login form and the session cookie are readable in clear text.',
      'They can also inject script into the page, or strip a downgrade redirect, and the victim sees nothing unusual.',
    ],
    impact: 'Credential and session theft, injected malware, tampered payments.',
    defenses: [
      'Serve everything over HTTPS and redirect HTTP with a 301.',
      'Enable HSTS with a long max-age and includeSubDomains.',
      'Load every script, style, font and image over HTTPS, and add integrity hashes for third-party scripts.',
      'Set Secure on every cookie.',
    ],
    owasp: 'OWASP A02:2021 · Cryptographic Failures',
    href: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
  },
  {
    id: 'session_hijack',
    name: 'Session hijacking',
    severity: 'high',
    tagline: 'A stolen cookie is a stolen login.',
    how: [
      'Attacker gets the session cookie from a script (XSS), a network sniff, a shared computer, or a URL.',
      'They replay it in their own browser and the server treats them as the victim.',
      'No password is needed, and the victim may not notice until the account is already changed.',
    ],
    impact: 'Account takeover, privilege escalation, and persistent access if the session never expires.',
    defenses: [
      'Set HttpOnly (script cannot read it), Secure (never sent over HTTP) and SameSite on every session cookie.',
      'Rotate the session id on login and privilege change, and expire idle sessions.',
      'Never put tokens in URLs or in localStorage.',
      'Support “sign out everywhere” so a user can end a stolen session.',
    ],
    owasp: 'OWASP A07:2021 · Identification and Authentication Failures',
    href: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
  },
  {
    id: 'cors_theft',
    name: 'Cross-origin data theft',
    severity: 'critical',
    tagline: 'A permissive CORS policy lets any website read your API.',
    how: [
      'Attacker serves a page whose script calls your API from another origin.',
      'If the response allows that origin and credentials, the browser hands the response body to the attacker’s script.',
      'The victim only has to open the page while signed in; nothing else is required.',
    ],
    impact: 'Bulk export of private data and, with write endpoints, actions taken as the victim.',
    defenses: [
      'Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.',
      'Reflect only origins from an explicit allowlist, never the raw Origin header.',
      'Keep authenticated API endpoints same-origin where you can.',
      'Return CORS headers only on the routes that actually need cross-origin access.',
    ],
    owasp: 'OWASP A05:2021 · Security Misconfiguration',
    href: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
  },
  {
    id: 'secret_leak',
    name: 'Credential exposure',
    severity: 'critical',
    tagline: 'An API key in shipped code is a key in public hands.',
    how: [
      'A key, token or password ends up in client code, a public repo, an HTML comment, or a committed .env file.',
      'Attacker finds it by reading the bundle, searching GitHub, or scanning for exposed dotfiles.',
      'They use the key directly against your provider, where it looks like normal traffic from you.',
    ],
    impact: 'Unauthorised spending, data access, message sending, and full account takeover at the provider.',
    defenses: [
      'Keep secrets server-side: environment variables or a secret manager, never in the bundle.',
      'Call third-party APIs through your own backend so the key never reaches the browser.',
      'Add .env and credentials files to .gitignore, and scan commits before pushing.',
      'Rotate any key that has been exposed, then remove it from history.',
    ],
    owasp: 'OWASP A02:2021 · Cryptographic Failures',
    href: 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
  },
  {
    id: 'recon',
    name: 'Reconnaissance',
    severity: 'medium',
    tagline: 'Version banners and path lists make the next attack cheaper.',
    how: [
      'Attacker fingerprints your stack from Server and X-Powered-By headers, error pages and asset names.',
      'They read robots.txt and sitemaps for admin, staging and backup paths your site would rather not advertise.',
      'They map the framework version to known CVEs, then pick the exploit that matches.',
    ],
    impact: 'Faster, more targeted attacks, and easy discovery of forgotten admin or backup endpoints.',
    defenses: [
      'Remove or genericise version banners (server_tokens off, no X-Powered-By).',
      'Do not list private paths in robots.txt; protect them with authentication instead.',
      'Return the same generic 404 for unknown and unauthorised paths.',
      'Put admin surfaces behind a separate host or VPN.',
    ],
    owasp: 'OWASP A05:2021 · Security Misconfiguration',
    href: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
  },
  {
    id: 'supply_chain',
    name: 'Supply chain tampering',
    severity: 'high',
    tagline: 'A third-party script or package changes on someone else’s server.',
    how: [
      'A CDN script you load without an integrity hash is compromised, or a dependency publishes a malicious release.',
      'The browser (or your build) runs the new code with your origin’s full trust, including access to cookies and the DOM.',
      'Nothing in your own code changed, so code review never sees it.',
    ],
    impact: 'Credential skimming, crypto wallet or payment detail theft, backdoors in production builds.',
    defenses: [
      'Add Subresource Integrity (integrity + crossorigin) to third-party scripts and styles.',
      'Self-host critical libraries where practical.',
      'Pin exact versions, commit the lockfile and review dependency updates.',
      'Send CSP script-src with explicit hosts, and monitor for changes.',
    ],
    owasp: 'OWASP A06:2021 · Vulnerable and Outdated Components',
    href: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
  },
  {
    id: 'open_redirect',
    name: 'Open redirect',
    severity: 'medium',
    tagline: 'Your trusted domain forwards users to an attacker’s page.',
    how: [
      'Attacker crafts a link like /login?next=https://evil.example and shares it from your own domain.',
      'The victim trusts the link because the host is real, signs in, and is redirected onward.',
      'The attacker’s page is a pixel-perfect copy that asks for the password again, or delivers malware.',
    ],
    impact: 'Credential phishing under your brand, and OAuth token theft when redirect_uri is not validated.',
    defenses: [
      'Redirect only to relative paths, or to absolute URLs from an allowlist.',
      'Never trust the next/return/redirect parameter as-is.',
      'Exact-match OAuth redirect URIs on the server.',
    ],
    owasp: 'OWASP A01:2021 · Broken Access Control',
    href: 'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html',
  },
  {
    id: 'path_traversal',
    name: 'Path traversal',
    severity: 'high',
    tagline: 'A file path built from user input climbs out of its folder.',
    how: [
      'Attacker sends a filename or key containing ../ sequences, or an absolute path.',
      'The server joins it to a base directory without normalising, and reads outside the intended folder.',
      'Config files, private keys, .env and source code become readable; write access can overwrite templates or code.',
    ],
    impact: 'Disclosure of secrets and source, and sometimes remote code execution through file writes.',
    defenses: [
      'Resolve the path, then verify it is still inside the allowed directory.',
      'Prefer opaque ids mapped to files over user-supplied names.',
      'Allowlist extensions and reject absolute paths and .. segments.',
      'Serve user files from object storage with signed URLs, not from the app filesystem.',
    ],
    owasp: 'OWASP · Path Traversal',
    href: 'https://owasp.org/www-community/attacks/Path_Traversal',
  },
  {
    id: 'rce',
    name: 'Remote code execution',
    severity: 'critical',
    tagline: 'User input reaches an interpreter or a shell.',
    how: [
      'Attacker finds input passed to eval, new Function, a template engine, a deserialiser, or a shell command.',
      'They send code instead of data, and it runs with your server’s permissions.',
      'From there they read secrets, pivot to the database, and persist.',
    ],
    impact: 'Total server compromise: data, credentials, and access to everything the process can reach.',
    defenses: [
      'Never pass user input to eval, new Function, or a shell.',
      'Use an argument-array process API instead of a command string, and validate against an allowlist.',
      'Keep template engines in logic-less mode, and never deserialise untrusted data.',
      'Run the service as an unprivileged user with a narrow filesystem.',
    ],
    owasp: 'OWASP A03:2021 · Injection',
    href: 'https://owasp.org/Top10/A03_2021-Injection/',
  },
]

export const attackById = (id: AttackId) => ATTACKS.find((a) => a.id === id)
