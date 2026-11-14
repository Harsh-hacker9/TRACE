import { motion } from 'motion/react'

import type { Severity } from '@/lib/audit'
import { EASE } from '@/lib/motion'
import { SEVERITY_META, SeverityChip } from '@/scan/severity'

const ROWS: { severity: Severity; title: string; meta: string }[] = [
  { severity: 'critical', title: 'Site is served over plain HTTP', meta: 'Transport' },
  { severity: 'high', title: 'No Content-Security-Policy', meta: 'Headers' },
  { severity: 'high', title: 'Cookie flags are incomplete', meta: 'Cookies' },
  { severity: 'medium', title: 'CORS reflects any origin', meta: 'CORS' },
  { severity: 'low', title: 'Stack version disclosed', meta: 'Headers' },
]

/** The product shot: a finished report at a glance, not a screenshot. */
export function ScanMock({ className }: { className?: string }) {
  return (
    <div className={className}>
      <div className="border border-line bg-surface">
        <div className="flex h-10 items-center gap-2 border-b border-line px-3">
          <span className="size-1.5 bg-line-strong" aria-hidden />
          <span className="size-1.5 bg-line-strong" aria-hidden />
          <span className="size-1.5 bg-line-strong" aria-hidden />
          <span className="ml-2 truncate font-mono text-[11px] text-muted">trace · your-site.com</span>
          <span className="ml-auto inline-flex items-center gap-1.5 font-mono text-[10px] tracking-[0.08em] text-done uppercase">
            <span className="size-1 bg-done" aria-hidden /> done
          </span>
        </div>

        <div className="p-4 sm:p-5">
          <div className="flex items-end justify-between gap-4">
            <div>
              <p className="font-mono text-[10px] tracking-[0.16em] text-muted uppercase">Score</p>
              <p className="mt-1 text-[40px] leading-none font-semibold tracking-[-0.05em]">
                62<span className="ml-1 text-base font-normal text-muted">/100</span>
              </p>
            </div>
            <div className="text-right">
              <p className="font-mono text-[10px] tracking-[0.16em] text-muted uppercase">Grade</p>
              <p className="mt-1 text-[24px] leading-none font-semibold">D</p>
            </div>
          </div>

          <div className="mt-4 flex h-1 gap-px" aria-hidden>
            <span className="flex-[1] bg-blocked" />
            <span className="flex-[2] bg-progress" />
            <span className="flex-[1] bg-review" />
            <span className="flex-[1] bg-todo" />
          </div>

          <ul className="mt-4 flex flex-col">
            {ROWS.map((row, index) => (
              <motion.li
                key={row.title}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.45, delay: 0.35 + index * 0.08, ease: EASE.out }}
                className="flex items-center gap-2.5 border-b border-line py-2.5 last:border-0"
              >
                <span className={`size-1.5 shrink-0 ${SEVERITY_META[row.severity].dot}`} aria-hidden />
                <SeverityChip severity={row.severity} className="hidden sm:inline-flex" />
                <span className="min-w-0 flex-1 truncate text-[12.5px]">{row.title}</span>
                <span className="hidden font-mono text-[10px] text-faint sm:block">{row.meta}</span>
              </motion.li>
            ))}
          </ul>

          <div className="mt-4 flex items-center justify-between border-t border-line pt-3 font-mono text-[10.5px] text-muted">
            <span>5 findings</span>
            <span>4 attacks exposed</span>
            <span>11/16 checks</span>
          </div>
        </div>
      </div>
    </div>
  )
}
