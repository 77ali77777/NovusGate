import { clsx } from 'clsx'
import {
  Activity,
  ChevronDown,
  ClipboardList,
  Flame,
  GitFork,
  HardDrive,
  LogOut,
  Menu,
  Network,
  Server,
  Settings,
  Shield,
  Users,
  X,
} from 'lucide-react'
import type React from 'react'
import { useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, Outlet, useLocation } from 'react-router-dom'
import { useCan, useNetworks } from '@/api/client'
import { LANGUAGES, setLanguage } from '@/i18n'
import { networkLabel } from '@/lib/networkDisplay'
import { useAppStore, useSidebarOpen } from '@/store'
import { Branding } from './Branding'
import { ErrorBoundary } from './ErrorBoundary'
import { HelpTip } from './HelpTip'
import { Toaster } from './Toaster'
import { UserMenu, useLogout } from './UserMenu'

interface NavItem {
  labelKey: string // layout:nav.*
  href: string
  icon: React.ReactNode
  adminOnly?: boolean // hidden for other roles; the API refuses them anyway
}

const navigation: NavItem[] = [
  { labelKey: 'nav.overview', href: '/dashboard', icon: <Activity className="w-5 h-5" /> },
  { labelKey: 'nav.networks', href: '/networks', icon: <Network className="w-5 h-5" /> },
  { labelKey: 'nav.nodes', href: '/nodes', icon: <Server className="w-5 h-5" /> },
  { labelKey: 'nav.topology', href: '/topology', icon: <GitFork className="w-5 h-5" /> },
  { labelKey: 'nav.groups', href: '/groups', icon: <Users className="w-5 h-5" /> },
  { labelKey: 'nav.firewall', href: '/firewall', icon: <Flame className="w-5 h-5" /> },
  { labelKey: 'nav.fail2ban', href: '/fail2ban', icon: <Shield className="w-5 h-5" /> },
  { labelKey: 'nav.audit', href: '/audit', icon: <ClipboardList className="w-5 h-5" /> },
  {
    labelKey: 'nav.server',
    href: '/server',
    icon: <HardDrive className="w-5 h-5" />,
    adminOnly: true,
  },
  { labelKey: 'nav.settings', href: '/settings', icon: <Settings className="w-5 h-5" /> },
]

export const Layout = () => {
  const { t, i18n } = useTranslation('layout')
  const location = useLocation()
  const sidebarOpen = useSidebarOpen()
  const { toggleSidebar, setSidebarOpen, currentNetworkId, setCurrentNetworkId } = useAppStore()
  const { data: networks } = useNetworks()
  const isAdmin = useCan('admin')
  const logout = useLogout()
  // The mobile drawer closes once a page is chosen; on lg it is always shown.
  const closeDrawer = () => setSidebarOpen(false)

  // Auto-select first network if none selected
  useEffect(() => {
    if (!currentNetworkId && networks && networks.length > 0) {
      setCurrentNetworkId(networks[0].id)
    }
  }, [currentNetworkId, networks, setCurrentNetworkId])

  const currentNetwork = networks?.find((n) => n.id === currentNetworkId)

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Mobile sidebar backdrop */}
      {sidebarOpen && (
        <button
          type="button"
          tabIndex={-1}
          aria-hidden="true"
          className="fixed inset-0 z-40 bg-black/50 lg:hidden"
          onClick={toggleSidebar}
        />
      )}

      {/* Sidebar */}
      <aside
        className={clsx(
          'fixed inset-y-0 left-0 z-50 w-64 bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 transform transition-transform duration-200 ease-in-out lg:translate-x-0 flex flex-col',
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        )}
      >
        {/* Logo */}
        <div className="flex items-center justify-between h-16 px-4 border-b dark:border-gray-700">
          <Link to="/" className="flex items-center gap-2">
            <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
              <Network className="w-5 h-5 text-white" />
            </div>
            <span className="text-lg font-semibold text-gray-900 dark:text-white">NovusGate</span>
          </Link>
          <button
            type="button"
            onClick={toggleSidebar}
            aria-label={t('closeMenu')}
            className="lg:hidden text-gray-500"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Network selector */}
        <div className="p-4 border-b dark:border-gray-700">
          <label
            htmlFor="layout-network-select"
            className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1"
          >
            {t('network')}
            <HelpTip k="helpGeneral:layout.network" />
          </label>
          <div className="relative">
            <select
              data-help="helpGeneral:layout.network"
              id="layout-network-select"
              value={currentNetworkId || ''}
              onChange={(e) => setCurrentNetworkId(e.target.value || null)}
              className="w-full appearance-none bg-gray-100 dark:bg-gray-700 rounded-lg px-3 py-2 pr-8 text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">{t('selectNetwork')}</option>
              {networks?.map((network) => (
                <option key={network.id} value={network.id}>
                  {networkLabel(network, t).name}
                </option>
              ))}
            </select>
            <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500 pointer-events-none" />
          </div>
          {currentNetwork && (
            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
              {t('cidr', { cidr: currentNetwork.cidr })}
            </p>
          )}
        </div>

        {/* Navigation */}
        <nav className="p-4 space-y-1 flex-1 overflow-y-auto">
          {navigation
            .filter((item) => !item.adminOnly || isAdmin)
            .map((item) => {
              const isActive = location.pathname === item.href
              return (
                <Link
                  key={item.href}
                  to={item.href}
                  onClick={closeDrawer}
                  className={clsx(
                    'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                    isActive
                      ? 'bg-blue-50 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400'
                      : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                  )}
                >
                  {item.icon}
                  {t(item.labelKey)}
                </Link>
              )
            })}
        </nav>

        {/* Footer Actions */}
        <div className="p-4 border-t dark:border-gray-700">
          <Branding className="mb-4" />
          <label className="mb-3 flex items-center justify-between gap-2 px-3 text-xs text-gray-500 dark:text-gray-400">
            <span className="inline-flex items-center">
              {t('language')}
              <HelpTip k="helpGeneral:layout.language" />
            </span>
            <select
              data-help="helpGeneral:layout.language"
              value={i18n.language}
              onChange={(e) => setLanguage(e.target.value)}
              className="rounded-md bg-gray-100 px-2 py-1 text-sm text-gray-900 dark:bg-gray-700 dark:text-white"
            >
              {LANGUAGES.map((l) => (
                <option key={l.code} value={l.code}>
                  {l.label}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            onClick={logout}
            className="flex items-center gap-3 px-3 py-2 w-full rounded-lg text-sm font-medium text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-900/20 transition-colors"
          >
            <LogOut className="w-5 h-5" />
            {t('logout')}
          </button>
        </div>

        {/* Version */}
        <div className="px-4 pb-4">
          <p className="text-xs text-gray-500 dark:text-gray-400">NovusGate v0.1.0</p>
        </div>
      </aside>

      {/* Main content: the sidebar is always shown on lg, so the offset is too */}
      <div className="lg:ml-64">
        {/* Top bar */}
        <header className="sticky top-0 z-30 h-16 bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between h-full px-4">
            <button
              type="button"
              onClick={toggleSidebar}
              aria-expanded={sidebarOpen}
              aria-label={t('openMenu')}
              className="lg:hidden text-gray-500 hover:text-gray-700"
            >
              <Menu className="w-6 h-6" />
            </button>

            <div className="ml-auto flex items-center gap-4">
              {/* VPN Status Indicator */}
              {(() => {
                const isVpnSecure = window.location.hostname === '10.99.0.1'
                const isLocalhost =
                  window.location.hostname === 'localhost' ||
                  window.location.hostname === '127.0.0.1'

                if (isVpnSecure) {
                  return (
                    <div className="hidden md:flex items-center gap-2 px-3 py-1 rounded-full bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 text-xs font-medium">
                      <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                      {t('connection.vpn')}
                    </div>
                  )
                } else if (isLocalhost) {
                  return (
                    <div className="hidden md:flex items-center gap-2 px-3 py-1 rounded-full bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400 text-xs font-medium">
                      {t('connection.dev')}
                    </div>
                  )
                } else {
                  return (
                    <div
                      className="hidden md:flex items-center gap-2 px-3 py-1 rounded-full bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 text-xs font-medium"
                      title={t('connection.insecureHint')}
                    >
                      <div className="w-2 h-2 rounded-full bg-red-500" />
                      {t('connection.insecure')}
                    </div>
                  )
                }
              })()}

              <UserMenu />
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="p-6">
          <ErrorBoundary key={location.key}>
            <Outlet />
          </ErrorBoundary>
        </main>
      </div>
      <Toaster />
    </div>
  )
}

// Page header component
interface PageHeaderProps {
  title: string
  description?: string
  actions?: React.ReactNode
}

export const PageHeader: React.FC<PageHeaderProps> = ({ title, description, actions }) => {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">{title}</h1>
        {description && (
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">{description}</p>
        )}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}
