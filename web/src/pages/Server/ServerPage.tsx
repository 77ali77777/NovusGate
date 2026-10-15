import { Cpu, HardDrive, Network, Wrench } from 'lucide-react'
import { useCallback, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, useCan } from '@/api/client'
import { errorBodyCode } from '@/api/errors'
import { PageHeader } from '@/components/Layout'
import { Button, Input, Modal } from '@/components/ui'
import { type Step, StepUpCancelled, withStepUp } from '@/lib/serverAdmin'
import { KernelTab, NetworkTab, ServicesTab, SystemTab } from './ServerTabs'

type TabId = 'services' | 'network' | 'kernel' | 'system'

// ServerPage: administration of the host the hub runs on (P10a, admin
// only). Reads are open to admins; changes need the password again.
export const ServerPage = () => {
  const { t } = useTranslation('server')
  const isAdmin = useCan('admin')
  const [tab, setTab] = useState<TabId>('services')
  const { ask, prompt } = useStepUpPrompt()
  const step: Step = useCallback((run) => withStepUp(run, ask), [ask])

  if (!isAdmin) {
    return (
      <div className="space-y-6">
        <PageHeader title={t('title')} />
        <p className="text-sm text-gray-500">{t('adminOnly')}</p>
      </div>
    )
  }

  const tabs = [
    { id: 'services' as TabId, label: t('tabs.services'), icon: Wrench },
    { id: 'network' as TabId, label: t('tabs.network'), icon: Network },
    { id: 'kernel' as TabId, label: t('tabs.kernel'), icon: Cpu },
    { id: 'system' as TabId, label: t('tabs.system'), icon: HardDrive },
  ]

  return (
    <div className="space-y-6">
      <PageHeader title={t('title')} description={t('description')} />
      <div
        role="tablist"
        className="flex gap-1 overflow-x-auto border-b border-gray-200 dark:border-gray-700"
      >
        {tabs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={tab === id}
            onClick={() => setTab(id)}
            className={
              tab === id
                ? 'flex items-center gap-2 border-b-2 border-blue-600 px-4 py-2 text-sm font-medium text-blue-600 dark:text-blue-400'
                : 'flex items-center gap-2 border-b-2 border-transparent px-4 py-2 text-sm font-medium text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white'
            }
          >
            <Icon className="h-4 w-4" aria-hidden="true" />
            {label}
          </button>
        ))}
      </div>
      {tab === 'services' && <ServicesTab step={step} />}
      {tab === 'network' && <NetworkTab />}
      {tab === 'kernel' && <KernelTab step={step} />}
      {tab === 'system' && <SystemTab step={step} />}
      {prompt}
    </div>
  )
}

// useStepUpPrompt: ask() opens the password prompt and settles when the
// server has accepted the password (or rejects with StepUpCancelled).
function useStepUpPrompt() {
  const { t } = useTranslation('server')
  const [pending, setPending] = useState<{
    resolve: () => void
    reject: (e: Error) => void
  } | null>(null)
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const ask = useCallback(
    (): Promise<void> =>
      new Promise((resolve, reject) => {
        setPassword('')
        setError('')
        setPending({ resolve, reject })
      }),
    []
  )

  const cancel = () => {
    pending?.reject(new StepUpCancelled())
    setPending(null)
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!pending || !password) return
    setBusy(true)
    try {
      await api.stepUp(password)
      pending.resolve()
      setPending(null)
    } catch (err) {
      const code = errorBodyCode(err)
      setError(
        code === 'invalid_password'
          ? t('stepUp.wrong')
          : code === 'too_many_attempts'
            ? t('stepUp.tooMany')
            : t('stepUp.failed')
      )
    } finally {
      setBusy(false)
      setPassword('')
    }
  }

  const prompt = (
    <Modal isOpen={pending !== null} onClose={cancel} title={t('stepUp.title')} size="sm">
      <form onSubmit={submit} className="space-y-4">
        <p className="text-sm text-gray-600 dark:text-gray-400">{t('stepUp.hint')}</p>
        <Input
          type="password"
          label={t('stepUp.password')}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          error={error || undefined}
          autoComplete="current-password"
          autoFocus
        />
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" onClick={cancel}>
            {t('common:actions.cancel')}
          </Button>
          <Button type="submit" loading={busy} disabled={!password}>
            {t('stepUp.confirm')}
          </Button>
        </div>
      </form>
    </Modal>
  )

  return { ask, prompt }
}
