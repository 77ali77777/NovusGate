import { Lock } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useFirewallV2Preview } from '@/api/client'
import { Badge, Card } from '@/components/ui'
import { systemRules } from '@/lib/systemRules'
import { EngineOff } from './EngineOff'

// SystemRulesTab: the rules NovusGate adds on its own (read-only), taken from
// the compiled nftables ruleset, so the list always matches what is applied.
export const SystemRulesTab = () => {
  const { t } = useTranslation('firewallv2')
  const { data, isLoading, error } = useFirewallV2Preview(true)
  if (isLoading) return <p className="text-sm text-gray-500">{t('common:state.loading')}</p>
  if (error || !data) return <EngineOff error={error} fallback={t('systemRules.unavailable')} />
  const rules = systemRules(data.script)
  const chains = [...new Set(rules.map((r) => r.chain))]
  return (
    <div className="space-y-4">
      <Card>
        <div className="flex items-center gap-2">
          <Lock className="h-5 w-5 text-blue-500" />
          <div>
            <h3 className="text-lg font-semibold">{t('systemRules.title')}</h3>
            <p className="text-sm text-gray-500">{t('systemRules.intro')}</p>
          </div>
        </div>
      </Card>
      {chains.map((chain) => {
        const inChain = rules.filter((r) => r.chain === chain)
        return (
          <Card key={chain}>
            <div className="mb-3 flex items-center gap-2">
              <h4 className="font-mono font-semibold">{chain}</h4>
              {inChain[0].policy && (
                <Badge variant={inChain[0].policy === 'drop' ? 'danger' : 'default'}>
                  {t('systemRules.policy', { policy: inChain[0].policy })}
                </Badge>
              )}
            </div>
            <div className="divide-y divide-gray-100 dark:divide-gray-700">
              {inChain.map((r) => (
                <div key={r.rule} className="py-2">
                  <p className="text-sm">
                    {r.explanation ? t(r.explanation) : t('systemRules.builtIn')}
                  </p>
                  <p className="font-mono text-xs text-gray-500">{r.rule}</p>
                </div>
              ))}
            </div>
          </Card>
        )
      })}
    </div>
  )
}
