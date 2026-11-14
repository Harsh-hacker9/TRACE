import { ArrowRight, Check, ExternalLink } from 'lucide-react'
import { useEffect } from 'react'

import { ButtonLink } from '@/components/Button'
import { Badge } from '@/components/LabelChip'
import { ATTACKS } from '@/lib/attacks'
import { cn } from '@/lib/cn'
import { Link } from '@/lib/router'
import { SEVERITY_META, SeverityChip } from '@/scan/severity'
import { SiteFooter, SiteNav } from './Landing'

const GUTTER = 'px-4 sm:px-9'

export function AttacksPage() {
  useEffect(() => {
    const id = window.location.hash.slice(1)
    if (!id) return
    const timer = window.setTimeout(() => document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 60)
    return () => window.clearTimeout(timer)
  }, [])

  return (
    <div className="flex min-h-dvh flex-col bg-bg">
      <SiteNav />
      <main className="flex-1">
        <header className={cn('border-b border-line py-16', GUTTER)}>
          <p className="font-mono text-[11px] tracking-[0.16em] text-muted uppercase">Attack library</p>
          <h1 className="mt-4 max-w-3xl text-[38px] leading-[1.04] font-semibold tracking-[-0.04em] sm:text-[50px]">
            What attackers try, and what stops them
          </h1>
          <p className="mt-5 max-w-2xl text-[16.5px] leading-relaxed text-muted">
            Every finding Trace reports names one of these classes. Each entry walks through how the attack actually works, what it costs you, and the
            specific change that closes it.
          </p>
          <div className="mt-8 flex flex-wrap items-center gap-3">
            <ButtonLink to="/scan" variant="primary" iconRight={<ArrowRight className="size-4" aria-hidden />}>
              Scan your site
            </ButtonLink>
            <span className="font-mono text-[11px] text-muted">{ATTACKS.length} classes · mapped to real findings</span>
          </div>
        </header>

        <div className={cn('flex flex-col gap-4 py-12', GUTTER)}>
          {ATTACKS.map((attack) => (
            <article key={attack.id} id={attack.id} className="scroll-mt-24 border border-line bg-surface">
              <header className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-4">
                <SeverityChip severity={attack.severity} />
                <h2 className="text-[19px] font-medium tracking-[-0.015em]">{attack.name}</h2>
                <Badge className="hidden sm:inline-flex">{attack.owasp}</Badge>
                <Link
                  to="/scan"
                  className="ml-auto inline-flex items-center gap-1.5 font-mono text-[11px] text-muted transition-colors hover:text-fg"
                >
                  Scan for it <ArrowRight className="size-3" aria-hidden />
                </Link>
              </header>

              <div className="grid gap-8 p-5 md:grid-cols-2">
                <div>
                  <p className="font-mono text-[10px] tracking-[0.14em] text-muted uppercase">How it works</p>
                  <ol className="mt-3 flex flex-col gap-3">
                    {attack.how.map((step, index) => (
                      <li key={step} className="flex gap-3 text-[14px] leading-relaxed text-muted">
                        <span className="mt-0.5 font-mono text-[11px] text-faint">{String(index + 1).padStart(2, '0')}</span>
                        <span>{step}</span>
                      </li>
                    ))}
                  </ol>
                </div>

                <div>
                  <p className="font-mono text-[10px] tracking-[0.14em] text-muted uppercase">What it costs you</p>
                  <p className="mt-3 text-[14px] leading-relaxed text-muted">{attack.impact}</p>

                  <p className="mt-6 font-mono text-[10px] tracking-[0.14em] text-muted uppercase">How to stop it</p>
                  <ul className="mt-3 flex flex-col gap-2">
                    {attack.defenses.map((defense) => (
                      <li key={defense} className="flex gap-2.5 text-[14px] leading-relaxed text-muted">
                        <Check className="mt-0.5 size-3.5 shrink-0 text-done" aria-hidden />
                        <span>{defense}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              <footer className="flex flex-wrap items-center gap-3 border-t border-line px-5 py-3">
                <span className={cn('size-1.5', SEVERITY_META[attack.severity].dot)} aria-hidden />
                <a
                  href={attack.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 font-mono text-[11px] text-muted transition-colors hover:text-fg"
                >
                  {attack.owasp} <ExternalLink className="size-3" aria-hidden />
                </a>
              </footer>
            </article>
          ))}
        </div>

        <section className={cn('border-t border-line py-16', GUTTER)}>
          <div className="flex flex-col items-start justify-between gap-6 sm:flex-row sm:items-center">
            <div>
              <h2 className="text-[24px] font-semibold tracking-[-0.02em]">See which of these your site is exposed to</h2>
              <p className="mt-2 max-w-xl text-[14.5px] text-muted">A scan takes about ten seconds and needs no account.</p>
            </div>
            <ButtonLink to="/scan" variant="primary" iconRight={<ArrowRight className="size-4" aria-hidden />}>
              Open the scanner
            </ButtonLink>
          </div>
        </section>
      </main>
      <SiteFooter />
    </div>
  )
}
