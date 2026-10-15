import { AlertTriangle } from 'lucide-react'
import { Component, type ErrorInfo, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'

interface Props {
  children: ReactNode
}

interface State {
  error: Error | null
}

// CrashScreen is the fallback; a function component so it can translate.
const CrashScreen = ({ error, onRetry }: { error: Error; onRetry: () => void }) => {
  const { t } = useTranslation('layout')
  return (
    <div className="rounded-xl border border-red-200 bg-red-50 p-6 dark:border-red-800 dark:bg-red-900/20">
      <div className="flex items-start gap-3">
        <AlertTriangle className="mt-0.5 h-6 w-6 text-red-600" />
        <div className="space-y-2">
          <h2 className="text-lg font-semibold text-red-800 dark:text-red-300">
            {t('crash.title')}
          </h2>
          <p className="font-mono text-sm text-red-700 dark:text-red-400">{error.message}</p>
          <div className="flex gap-2">
            <button
              type="button"
              className="rounded-lg bg-red-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-red-700"
              onClick={onRetry}
            >
              {t('crash.retry')}
            </button>
            <button
              type="button"
              className="rounded-lg border border-red-300 px-3 py-1.5 text-sm font-medium text-red-700 dark:text-red-300"
              onClick={() => window.location.reload()}
            >
              {t('crash.reload')}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ErrorBoundary keeps a crash in one page from blanking the whole panel: the
// sidebar stays, the page shows the error and can be retried. Layout keys it
// by route, so moving to another page starts clean.
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('Page crashed:', error, info.componentStack)
  }

  render() {
    const { error } = this.state
    if (!error) return this.props.children
    return <CrashScreen error={error} onRetry={() => this.setState({ error: null })} />
  }
}
