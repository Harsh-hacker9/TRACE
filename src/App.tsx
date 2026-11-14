import { lazy, Suspense, useEffect } from 'react'

import { useLocation } from './lib/router'
import { Landing } from './sections/Landing'
import { NotFound } from './sections/NotFound'

const ScanPage = lazy(() => import('./scan/ScanPage').then((m) => ({ default: m.ScanPage })))
const AttacksPage = lazy(() => import('./sections/Attacks').then((m) => ({ default: m.AttacksPage })))

export function App() {
  const { pathname } = useLocation()

  useEffect(() => {
    if (pathname === '/') document.title = 'Trace — Find the bugs before attackers do'
    else if (pathname === '/scan') document.title = 'Scanner · Trace'
    else if (pathname === '/attacks') document.title = 'Attack library · Trace'
    else document.title = 'Not found · Trace'
  }, [pathname])

  if (pathname === '/') return <Landing />
  if (pathname === '/scan')
    return (
      <Suspense fallback={<div className="h-dvh bg-bg" />}>
        <ScanPage />
      </Suspense>
    )
  if (pathname === '/attacks')
    return (
      <Suspense fallback={<div className="min-h-dvh bg-bg" />}>
        <AttacksPage />
      </Suspense>
    )
  return <NotFound />
}
