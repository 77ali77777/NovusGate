import { AlertTriangle, Info } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Card } from '@/components/ui'
import { type EngineState, engineState } from '@/lib/firewallV2'

// Commands and paths, not translated text.
const ENV_LINE = 'FIREWALL_ENGINE=nft'
const RESTART = 'cd /opt/NovusGate/server/deployments/docker && docker compose up -d control-plane'
const RUNBOOK = 'docs/runbooks/p3b2-firewall-cutover.md'

// EngineOff explains why an nftables tab (Advanced, History, System Rules)
// has nothing to show: the server runs the iptables engine (the default after
// an install) or the engine is still starting. Any other error keeps the
// tab's own message (fallback).
export const EngineOff = ({ error, fallback }: { error: unknown; fallback: string }) => {
  const { t } = useTranslation('firewallv2')
  const state: EngineState = engineState(error)
  if (state === 'error') return <p className="text-sm text-gray-500">{fallback}</p>
  if (state === 'not_ready') {
    return (
      <Card>
        <div className="flex gap-3">
          <Info className="h-5 w-5 shrink-0 text-blue-500" aria-hidden="true" />
          <div className="space-y-1">
            <h3 className="font-semibold">{t('engineOff.startingTitle')}</h3>
            <p className="text-sm text-gray-600 dark:text-gray-400">{t('engineOff.starting')}</p>
          </div>
        </div>
      </Card>
    )
  }
  return <EngineDisabled />
}

// EngineDisabled is the iptables-mode explanation. compact (the Limits tab,
// which still lists and edits profiles) shows the title and the given reason
// and folds the steps away.
export const EngineDisabled = ({ compact, why }: { compact?: boolean; why?: string }) => {
  const { t } = useTranslation('firewallv2')
  const steps = (
    <div>
      <p className="font-medium text-gray-900 dark:text-white">{t('engineOff.howTitle')}</p>
      <ol className="ml-5 mt-1 list-decimal space-y-1">
        <li>{t('engineOff.step1')}</li>
        <li>
          {t('engineOff.step2')}{' '}
          <code className="rounded bg-gray-100 px-1 font-mono text-xs dark:bg-gray-700">
            {ENV_LINE}
          </code>
        </li>
        <li>
          <code className="break-all rounded bg-gray-100 px-1 font-mono text-xs dark:bg-gray-700">
            {RESTART}
          </code>
        </li>
        <li>{t('engineOff.step4')}</li>
      </ol>
      <p className="mt-2">
        {t('engineOff.more')}{' '}
        <code className="rounded bg-gray-100 px-1 font-mono text-xs dark:bg-gray-700">
          {RUNBOOK}
        </code>
      </p>
    </div>
  )
  return (
    <Card>
      <div className="flex gap-3">
        <AlertTriangle className="h-5 w-5 shrink-0 text-amber-500" aria-hidden="true" />
        <div className="min-w-0 space-y-3 text-sm text-gray-600 dark:text-gray-400">
          <h3 className="text-base font-semibold text-gray-900 dark:text-white">
            {t('engineOff.title')}
          </h3>
          <p>{why ?? t('engineOff.why')}</p>
          {compact ? (
            <details>
              <summary className="cursor-pointer font-medium text-blue-600 dark:text-blue-400">
                {t('engineOff.howShow')}
              </summary>
              <div className="mt-2 space-y-3">
                <p>{t('engineOff.needs')}</p>
                {steps}
              </div>
            </details>
          ) : (
            <>
              <p>{t('engineOff.needs')}</p>
              {steps}
            </>
          )}
        </div>
      </div>
    </Card>
  )
}
