import { ArrowLeft, ArrowRight } from 'lucide-react'
import { motion } from 'motion/react'

import { Button } from '@/components/Button'
import { navigate } from '@/lib/router'
import { SiteFooter, SiteNav } from './Landing'

/** 404 for unknown routes. */
export function NotFound() {
  return (
    <div className="flex min-h-dvh flex-col bg-bg">
      <SiteNav />
      <main className="flex flex-1 items-center px-6 py-24 sm:px-12">
        <motion.div initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }} className="max-w-lg">
          <p className="font-mono text-sm text-muted">TRC-404 · Status: Not found</p>
          <h1 className="mt-5 text-[42px] leading-[1.03] font-semibold tracking-[-0.045em] sm:text-[56px]">This path has nothing to scan.</h1>
          <p className="mt-5 text-[17px] leading-relaxed text-muted">
            <span className="font-mono text-fg/90">{window.location.pathname}</span> does not exist. It may have moved, or the link has a typo.
          </p>
          <div className="mt-10 flex flex-wrap gap-3">
            <Button variant="primary" size="lg" iconRight={<ArrowRight className="size-[18px]" aria-hidden />} onClick={() => navigate('/scan')}>
              Open the scanner
            </Button>
            <Button variant="outline" size="lg" icon={<ArrowLeft className="size-[18px]" aria-hidden />} onClick={() => navigate('/')}>
              Home
            </Button>
          </div>
        </motion.div>
      </main>
      <SiteFooter />
    </div>
  )
}
