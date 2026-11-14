import type { Severity } from '@/lib/audit'
import { cn } from '@/lib/cn'

export const SEVERITY_META: Record<Severity, { label: string; chip: string; dot: string }> = {
  critical: { label: 'Critical', chip: 'border-blocked/50 bg-blocked/10 text-blocked', dot: 'bg-blocked' },
  high: { label: 'High', chip: 'border-progress/50 bg-progress/10 text-progress', dot: 'bg-progress' },
  medium: { label: 'Medium', chip: 'border-review/50 bg-review/10 text-review', dot: 'bg-review' },
  low: { label: 'Low', chip: 'border-todo/50 bg-todo/10 text-todo', dot: 'bg-todo' },
  info: { label: 'Info', chip: 'border-line text-muted', dot: 'bg-faint' },
}

export function SeverityChip({ severity, className }: { severity: Severity; className?: string }) {
  const meta = SEVERITY_META[severity]
  return (
    <span className={cn('inline-flex h-5 shrink-0 items-center border px-1.5 font-mono text-[10px] tracking-[0.08em] uppercase', meta.chip, className)}>
      {meta.label}
    </span>
  )
}
