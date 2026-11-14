import { BRAND } from '@/data'
import { cn } from '@/lib/cn'

/** Crosshair mark: a scan target, not a stack of bars. */
export function LogoMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 20 20" className={className ?? 'size-5'} aria-hidden>
      <path d="M10 1.5v4M10 14.5v4M1.5 10h4M14.5 10h4" stroke="currentColor" strokeWidth="1.4" fill="none" />
      <rect x="4.5" y="4.5" width="11" height="11" fill="none" stroke="currentColor" strokeWidth="1.4" />
      <rect x="8.6" y="8.6" width="2.8" height="2.8" fill="currentColor" />
    </svg>
  )
}

export function Logo({ className, compact }: { className?: string; compact?: boolean }) {
  return (
    <span className={cn('inline-flex items-center gap-2.5 text-fg', className)}>
      <LogoMark />
      {!compact && <span className="text-[17px] font-semibold tracking-[0.07em] uppercase">{BRAND.name}</span>}
    </span>
  )
}
