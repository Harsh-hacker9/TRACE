import { ArrowRight, Bug, Code, Cookie, Globe, Key, Lock, Route, ShieldCheck, Upload } from 'lucide-react'
import { motion } from 'motion/react'
import { type FormEvent, useState } from 'react'

import { Button, ButtonLink } from '@/components/Button'
import { Input } from '@/components/Field'
import { Badge } from '@/components/LabelChip'
import { Logo } from '@/components/Logo'
import { SectionHead } from '@/components/Section'
import { ThemeToggle } from '@/components/ThemeToggle'
import { SITE_CHECKS, SOURCE_CHECKS } from '@/lib/audit'
import { ATTACKS, attackById } from '@/lib/attacks'
import { cn } from '@/lib/cn'
import { EASE } from '@/lib/motion'
import { Link, navigate } from '@/lib/router'
import { ATTACKS_HEAD, BRAND, CTA, FEATURES, FEATURES_HEAD, FOOTER, HERO, LIMITS, NAV, STEPS, STEPS_HEAD } from '@/data'
import { SEVERITY_META } from '@/scan/severity'
import { ScanMock } from './ScanMock'

const GUTTER = 'px-4 sm:px-9'

export function SiteNav() {
  return (
    <header className="sticky top-0 z-40 border-b border-line bg-bg/85 backdrop-blur-md">
      <div className={cn('flex h-16 items-center justify-between gap-4', GUTTER)}>
        <Link to="/" aria-label={`${BRAND.name} home`} className="-ml-1 shrink-0 px-1 py-2">
          <Logo />
        </Link>
        <nav className="flex items-center gap-1 sm:gap-2">
          <div className="mr-1 hidden items-center gap-1 md:flex">
            {NAV.links.map((link) => (
              <Link
                key={link.to}
                to={link.to}
                className="inline-flex h-9 items-center px-3 text-[14px] text-muted transition-colors hover:text-fg"
              >
                {link.label}
              </Link>
            ))}
          </div>
          <ThemeToggle />
          <ButtonLink to="/scan" variant="outline" className="h-10 px-4 text-[14px]">
            {NAV.cta}
          </ButtonLink>
        </nav>
      </div>
    </header>
  )
}

function ScanForm() {
  const [url, setUrl] = useState('')
  const submit = (event: FormEvent) => {
    event.preventDefault()
    const value = url.trim()
    navigate(value ? `/scan?url=${encodeURIComponent(value)}` : '/scan')
  }
  return (
    <form onSubmit={submit} className="mt-9 w-full max-w-lg" noValidate>
      <div className="flex flex-col gap-2 sm:flex-row">
        <Input
          className="flex-1"
          aria-label="Website address"
          placeholder={HERO.placeholder}
          autoComplete="url"
          spellCheck={false}
          icon={<Globe className="size-4" aria-hidden />}
          value={url}
          onChange={(event) => setUrl(event.target.value)}
        />
        <Button type="submit" variant="primary" size="lg" className="h-10 px-5 text-[14px]" iconRight={<ArrowRight className="size-4" aria-hidden />}>
          {HERO.cta}
        </Button>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2">
        <Link to="/scan?mode=upload" className="inline-flex items-center gap-1.5 text-[13px] text-muted transition-colors hover:text-fg">
          <Upload className="size-3.5" aria-hidden /> {HERO.upload}
        </Link>
        <span className="text-line-strong" aria-hidden>
          /
        </span>
        <p className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[11px] text-muted">
          {HERO.points.map((point) => (
            <span key={point} className="inline-flex items-center gap-1.5">
              <span className="size-1 bg-done" aria-hidden /> {point}
            </span>
          ))}
        </p>
      </div>
    </form>
  )
}

function Hero() {
  return (
    <section className="relative overflow-hidden">
      <div className="grid-lines pointer-events-none absolute inset-0 opacity-[0.35] [mask-image:radial-gradient(ellipse_at_top_left,black,transparent_75%)]" aria-hidden />
      <div className={cn('relative grid items-center gap-12 pt-16 pb-20 lg:grid-cols-[1.05fr_0.95fr] lg:pt-24 lg:pb-24', GUTTER)}>
        <div>
          <motion.p
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, ease: EASE.out }}
            className="inline-flex items-center gap-2 border border-line px-2.5 py-1 font-mono text-[10.5px] tracking-[0.14em] text-muted uppercase"
          >
            <Bug className="size-3" aria-hidden /> {HERO.eyebrow}
          </motion.p>
          <motion.h1
            initial="hidden"
            animate="show"
            variants={{ show: { transition: { staggerChildren: 0.08, delayChildren: 0.05 } } }}
            className="mt-6 text-[42px] leading-[1.03] font-semibold tracking-[-0.045em] sm:text-[54px] lg:text-[58px]"
          >
            {HERO.title.map((line) => (
              <motion.span
                key={line}
                className="block"
                variants={{
                  hidden: { opacity: 0, y: 22, filter: 'blur(6px)' },
                  show: { opacity: 1, y: 0, filter: 'blur(0px)', transition: { duration: 0.65, ease: EASE.out } },
                }}
              >
                {line}
              </motion.span>
            ))}
          </motion.h1>
          <motion.p
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.24, ease: EASE.out }}
            className="mt-6 max-w-xl text-[17px] leading-[1.65] text-muted"
          >
            {HERO.body}
          </motion.p>
          <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6, delay: 0.34, ease: EASE.out }}>
            <ScanForm />
          </motion.div>
        </div>

        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.9, delay: 0.3, ease: EASE.out }}
          className="relative lg:pl-4"
        >
          <ScanMock />
          <p className="mt-3 font-mono text-[10.5px] text-muted">Example report. Yours will differ.</p>
        </motion.div>
      </div>
    </section>
  )
}

const ICONS = { lock: Lock, cookie: Cookie, globe: Globe, code: Code, key: Key, route: Route }

function Reveal({ children, className, delay = 0 }: { children: React.ReactNode; className?: string; delay?: number }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 18 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-60px' }}
      transition={{ duration: 0.6, delay, ease: EASE.out }}
      className={className}
    >
      {children}
    </motion.div>
  )
}

function Features() {
  return (
    <section id="checks" className={cn('scroll-mt-16 border-t border-line py-24', GUTTER)}>
      <Reveal>
        <SectionHead eyebrow={FEATURES_HEAD.eyebrow} title={FEATURES_HEAD.title} body={FEATURES_HEAD.body} />
      </Reveal>
      <div className="mt-14 grid grid-cols-1 border-t border-l border-line sm:grid-cols-2 lg:grid-cols-3">
        {FEATURES.map((feature, index) => {
          const Icon = ICONS[feature.icon]
          return (
            <Reveal key={feature.title} delay={(index % 3) * 0.06} className="group relative border-r border-b border-line p-8">
              <div className="hatch pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-300 group-hover:opacity-100" aria-hidden />
              <div className="relative">
                <span className="flex size-10 items-center justify-center border border-line-strong text-fg transition-transform duration-300 ease-out group-hover:-translate-y-0.5">
                  <Icon className="size-[18px]" strokeWidth={1.6} aria-hidden />
                </span>
                <h3 className="mt-7 text-[17px] font-medium tracking-[-0.01em]">{feature.title}</h3>
                <p className="mt-2 text-[15px] leading-relaxed text-muted">{feature.body}</p>
              </div>
            </Reveal>
          )
        })}
      </div>
    </section>
  )
}

const PREVIEW = ['xss', 'cors_theft', 'mitm', 'secret_leak'] as const

function AttackPreview() {
  return (
    <section className="border-t border-line py-24">
      <div className={GUTTER}>
        <Reveal>
          <SectionHead eyebrow={ATTACKS_HEAD.eyebrow} title={ATTACKS_HEAD.title} body={ATTACKS_HEAD.body}>
            <ButtonLink to="/attacks" variant="outline" iconRight={<ArrowRight className="size-4" aria-hidden />}>
              Attack library
            </ButtonLink>
          </SectionHead>
        </Reveal>
      </div>
      <div className="mt-12 flex snap-x snap-mandatory gap-px overflow-x-auto border-y border-line bg-line [scrollbar-width:none] sm:grid sm:grid-cols-2 sm:overflow-visible lg:grid-cols-4">
        {PREVIEW.map((id, index) => {
          const attack = attackById(id)
          if (!attack) return null
          return (
            <motion.article
              key={id}
              initial={{ opacity: 0, y: 16 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-40px' }}
              transition={{ duration: 0.5, delay: index * 0.05, ease: EASE.out }}
              className="min-w-[76vw] snap-start bg-bg p-6 sm:min-w-0"
            >
              <div className="flex items-center gap-2">
                <span className={cn('size-1.5', SEVERITY_META[attack.severity].dot)} aria-hidden />
                <span className="font-mono text-[10px] tracking-[0.12em] text-muted uppercase">{attack.severity}</span>
              </div>
              <h3 className="mt-4 text-[18px] font-medium tracking-[-0.015em]">{attack.name}</h3>
              <p className="mt-2 text-[14px] leading-relaxed text-muted">{attack.tagline}</p>
              <Link to={`/attacks#${attack.id}`} className="mt-5 inline-flex items-center gap-1.5 font-mono text-[11px] text-muted transition-colors hover:text-fg">
                How it works <ArrowRight className="size-3" aria-hidden />
              </Link>
            </motion.article>
          )
        })}
      </div>
      <p className={cn('mt-4 font-mono text-[11px] text-muted', GUTTER)}>{ATTACKS.length} attack classes documented, each mapped to the findings that expose them.</p>
    </section>
  )
}

function HowItWorks() {
  return (
    <section id="how" className={cn('scroll-mt-16 border-t border-line py-24', GUTTER)}>
      <Reveal>
        <SectionHead eyebrow={STEPS_HEAD.eyebrow} title={STEPS_HEAD.title} body={STEPS_HEAD.body} />
      </Reveal>
      <div className="mt-14 grid grid-cols-1 border-t border-l border-line md:grid-cols-3">
        {STEPS.map((step, index) => (
          <Reveal key={step.step} delay={index * 0.06} className="relative border-r border-b border-line p-8">
            <span className="font-mono text-[11px] text-faint">{step.step}</span>
            <h3 className="mt-6 text-[18px] font-medium">{step.title}</h3>
            <p className="mt-2 text-[15px] leading-relaxed text-muted">{step.body}</p>
          </Reveal>
        ))}
      </div>
    </section>
  )
}

function Limits() {
  return (
    <section className={cn('border-t border-line py-24', GUTTER)}>
      <div className="grid gap-10 lg:grid-cols-[1fr_1.2fr]">
        <Reveal>
          <p className="font-mono text-xs tracking-[0.14em] text-muted uppercase">Honest scope</p>
          <h2 className="mt-4 text-[30px] leading-[1.08] font-semibold tracking-[-0.03em] md:text-[36px]">{LIMITS.title}</h2>
          <p className="mt-4 max-w-md text-[16px] leading-relaxed text-muted">{LIMITS.body}</p>
        </Reveal>
        <Reveal delay={0.08}>
          <ul className="border-t border-line">
            {LIMITS.items.map((item) => (
              <li key={item} className="flex gap-3 border-b border-line px-1 py-4 text-[14px] leading-relaxed text-muted">
                <ShieldCheck className="mt-0.5 size-4 shrink-0 text-faint" aria-hidden />
                {item}
              </li>
            ))}
          </ul>
        </Reveal>
      </div>
    </section>
  )
}

function FinalCta() {
  return (
    <section className={cn('relative overflow-hidden border-t border-line py-28', GUTTER)}>
      <div className="grid-lines pointer-events-none absolute inset-0 opacity-40 [mask-image:radial-gradient(ellipse_at_center,black,transparent_70%)]" aria-hidden />
      <Reveal className="relative flex flex-col items-center text-center">
        <h2 className="max-w-3xl text-[38px] leading-[1.03] font-semibold tracking-[-0.045em] text-balance sm:text-[52px]">{CTA.title}</h2>
        <p className="mt-5 max-w-xl text-[17px] text-muted">{CTA.body}</p>
        <Button variant="primary" size="lg" className="mt-10" iconRight={<ArrowRight className="size-[18px]" aria-hidden />} onClick={() => navigate('/scan')}>
          {CTA.button}
        </Button>
      </Reveal>
    </section>
  )
}

export function SiteFooter() {
  return (
    <footer className={cn('border-t border-line pt-16 pb-10', GUTTER)}>
      <div className="grid gap-12 md:grid-cols-[1.5fr_repeat(3,1fr)]">
        <div>
          <Logo />
          <p className="mt-4 max-w-xs text-sm text-muted">{FOOTER.blurb}</p>
        </div>
        {FOOTER.columns.map((column) => (
          <nav key={column.title} aria-label={column.title}>
            <p className="font-mono text-xs tracking-[0.14em] text-muted uppercase">{column.title}</p>
            <ul className="mt-4 flex flex-col">
              {column.links.map((link) => (
                <li key={link.label}>
                  {/^(https?:|mailto:)/.test(link.to) || link.to.startsWith('/api') ? (
                    <a
                      href={link.to}
                      className="inline-flex min-h-10 items-center text-sm text-muted transition-colors hover:text-fg"
                      {...(link.to.startsWith('http') ? { target: '_blank', rel: 'noopener noreferrer' } : {})}
                    >
                      {link.label}
                    </a>
                  ) : (
                    <Link to={link.to} className="inline-flex min-h-10 items-center text-sm text-muted transition-colors hover:text-fg">
                      {link.label}
                    </Link>
                  )}
                </li>
              ))}
            </ul>
          </nav>
        ))}
      </div>
      <div className="mt-16 flex flex-wrap items-center justify-between gap-4 border-t border-line pt-6 font-mono text-xs text-muted">
        <span>{FOOTER.legal}</span>
        <span className="inline-flex items-center gap-2">
          <span className="size-2 bg-done" aria-hidden /> Scanner online
        </span>
      </div>
    </footer>
  )
}

export function Landing() {
  return (
    <div className="min-h-dvh bg-bg">
      <SiteNav />
      <main>
        <Hero />
        <section className={cn('border-t border-line py-5', GUTTER)}>
          <div className="flex flex-wrap items-center gap-x-8 gap-y-3 font-mono text-[11px] tracking-[0.06em] text-muted">
            <span>{SITE_CHECKS.length} site checks</span>
            <span>{SOURCE_CHECKS.length} source checks</span>
            <span>{ATTACKS.length} attack classes</span>
            <span>Evidence + fix for every finding</span>
            <Badge tone="accent" className="ml-auto">
              Passive only
            </Badge>
          </div>
        </section>
        <Features />
        <AttackPreview />
        <HowItWorks />
        <Limits />
        <FinalCta />
      </main>
      <SiteFooter />
    </div>
  )
}
