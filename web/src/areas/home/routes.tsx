// The home area: the start page, loaded with the shell (no extra chunk).
import { createRoute } from '@tanstack/react-router'
import { Gauge } from 'lucide-react'
import type { Area } from '../../app/area'
import { Home } from './Home'

export const homeArea: Area = {
  id: 'home',
  nav: { to: '/', icon: Gauge, label: 'nav.home', order: 10 },
  routes: (shell) => [createRoute({ getParentRoute: () => shell, path: '/', component: Home })],
}
