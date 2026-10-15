import { MutationCache, QueryClient, QueryClientProvider } from '@tanstack/react-query'
import React from 'react'
import { useTranslation } from 'react-i18next'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { apiErrorMessage, errorBodyMessage } from './api/errors'
import { Layout } from './components/Layout'
import i18n from './i18n'
import { AuditPage } from './pages/Audit/AuditPage'
import { DashboardPage } from './pages/Dashboard/Dashboard'
import { Fail2BanPage } from './pages/Fail2Ban/Fail2Ban'
import { Firewall } from './pages/Firewall/Firewall'
import { NetworkDetailPage } from './pages/Networks/NetworkDetail'
import { Networks } from './pages/Networks/Networks'
import { NodeDetailPage, NodesPage } from './pages/Nodes/Nodes'
import { SettingsPage } from './pages/Settings/SettingsPage'
import { TopologyPage } from './pages/Topology/TopologyPage'
import { useAppStore } from './store'

// Create React Query client
// Every mutation reports its result as a toast: errors always (with the
// server's message) unless meta.inlineError says the form shows it itself;
// successes when meta.successTitle is set. Titles are i18n keys ('toasts:...').
const queryClient = new QueryClient({
  mutationCache: new MutationCache({
    onError: (error, _vars, _ctx, mutation) => {
      if (mutation.meta?.inlineError) return
      useAppStore.getState().addNotification({
        type: 'error',
        title: i18n.t((mutation.meta?.errorTitle as string) ?? 'toasts:actionFailed'),
        message: apiErrorMessage(error, i18n.t('toasts:serverError')),
      })
    },
    onSuccess: (_data, _vars, _ctx, mutation) => {
      const title = mutation.meta?.successTitle as string | undefined
      if (title) useAppStore.getState().addNotification({ type: 'success', title: i18n.t(title) })
    },
  }),
  defaultOptions: {
    queries: {
      staleTime: 10000,
      refetchOnWindowFocus: false,
    },
  },
})

const LoginPage = () => {
  const { t } = useTranslation('layout')
  const [email, setEmail] = React.useState('admin')
  const [password, setPassword] = React.useState('')
  const [error, setError] = React.useState('')
  const [loading, setLoading] = React.useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')

    try {
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: email, password }),
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(errorBodyMessage(data) ?? t('login.failed'))
      }

      const data = await response.json()
      localStorage.setItem('auth_token', data.token)
      localStorage.setItem('auth_username', data.username)
      window.location.href = '/dashboard'
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t('login.failed'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
      <div className="max-w-md w-full p-8 bg-white dark:bg-gray-800 rounded-xl shadow-lg">
        <div className="text-center mb-8">
          <div className="w-16 h-16 bg-blue-600 rounded-2xl flex items-center justify-center mx-auto mb-4">
            <svg
              className="w-10 h-10 text-white"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
              />
            </svg>
          </div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">NovusGate</h1>
          <p className="text-gray-500 mt-2">{t('login.subtitle')}</p>
        </div>

        {error && (
          <div className="mb-4 p-3 bg-red-100 text-red-700 rounded-lg text-sm">{error}</div>
        )}

        <form className="space-y-4" onSubmit={handleSubmit}>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              {t('login.username')}
            </label>
            <input
              type="text"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:border-gray-600"
              placeholder="admin"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              {t('login.password')}
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:border-gray-600"
              placeholder="••••••••"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full py-2 px-4 bg-blue-600 text-white rounded-lg hover:bg-blue-700 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50"
          >
            {loading ? t('login.signingIn') : t('login.signIn')}
          </button>
        </form>
      </div>
    </div>
  )
}

// Private route wrapper - checks auth before rendering
const PrivateRoute = ({ children }: { children: React.ReactNode }) => {
  const token = localStorage.getItem('auth_token')
  if (!token) {
    return <Navigate to="/login" replace />
  }
  return <>{children}</>
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route
            path="/"
            element={
              <PrivateRoute>
                <Layout />
              </PrivateRoute>
            }
          >
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="dashboard" element={<DashboardPage />} />
            <Route path="networks" element={<Networks />} />
            <Route path="networks/:id" element={<NetworkDetailPage />} />
            <Route path="topology" element={<TopologyPage />} />
            <Route path="nodes" element={<NodesPage />} />
            <Route path="nodes/:id" element={<NodeDetailPage />} />
            <Route path="firewall" element={<Firewall />} />
            <Route path="fail2ban" element={<Fail2BanPage />} />
            <Route path="audit" element={<AuditPage />} />
            <Route path="settings" element={<SettingsPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}

export default App
