import { AlertTriangle, Globe, Info, Network as NetworkIcon } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  useCan,
  useFirewallV2State,
  useNetwork,
  useNodes,
  useSetNetworkTunnel,
  useSetNodeTunnel,
} from '@/api/client'
import { HelpTip } from '@/components/HelpTip'
import { Button, Modal, Select } from '@/components/ui'
import { engineMode } from '@/lib/firewallV2'
import { isAdminInterface, networkLabel } from '@/lib/networkDisplay'
import {
  affectedByNetworkChange,
  effectiveTunnel,
  fullTunnelBlock,
  type TunnelMode,
  type TunnelResult,
  tunnelResultState,
} from '@/lib/tunnelMode'
import { PendingBanner } from '@/pages/Firewall/AdvancedTab'
import type { Network, Node, TunnelChange } from '@/types'

// TunnelBadge: a network's or a node's tunnel mode at a glance.
export const TunnelBadge = ({ mode }: { mode: TunnelMode }) => {
  const { t } = useTranslation('networks')
  const full = mode === 'full'
  const Icon = full ? Globe : NetworkIcon
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${
        full
          ? 'bg-purple-100 text-purple-800 dark:bg-purple-900/40 dark:text-purple-200'
          : 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-200'
      }`}
    >
      <Icon className="h-3 w-3" aria-hidden="true" />
      {t(full ? 'tunnel.full' : 'tunnel.split')}
    </span>
  )
}

// TunnelChoice: the two modes as cards, each saying what it does. fullBlocked
// is the reason full tunnel cannot be chosen, or null.
export const TunnelChoice = ({
  name,
  value,
  onChange,
  fullBlocked,
}: {
  name: string
  value: TunnelMode
  onChange: (mode: TunnelMode) => void
  fullBlocked: string | null
}) => {
  const { t } = useTranslation('networks')
  const options = [
    {
      mode: 'split' as const,
      icon: NetworkIcon,
      title: t('tunnel.split'),
      desc: t('tunnel.splitDesc'),
    },
    { mode: 'full' as const, icon: Globe, title: t('tunnel.full'), desc: t('tunnel.fullDesc') },
  ]
  return (
    <fieldset>
      <legend className="mb-1 flex items-center text-sm font-medium text-gray-700 dark:text-gray-300">
        {t('tunnel.label')}
        <HelpTip k="helpNetworks:tunnelMode" />
      </legend>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {options.map((o) => {
          const disabled = o.mode === 'full' && fullBlocked !== null
          const checked = value === o.mode
          return (
            <label
              key={o.mode}
              className={`flex cursor-pointer gap-2 rounded-lg border p-3 text-sm ${
                checked
                  ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
                  : 'border-gray-200 dark:border-gray-700'
              } ${disabled ? 'cursor-not-allowed opacity-60' : ''}`}
            >
              <input
                data-help="helpNetworks:tunnelMode"
                type="radio"
                name={name}
                value={o.mode}
                checked={checked}
                disabled={disabled}
                aria-describedby={disabled ? `${name}-full-blocked` : undefined}
                onChange={() => onChange(o.mode)}
                className="mt-1"
              />
              <span>
                <span className="flex items-center gap-1 font-medium text-gray-900 dark:text-white">
                  <o.icon className="h-4 w-4" aria-hidden="true" />
                  {o.title}
                </span>
                <span className="mt-0.5 block text-gray-500 dark:text-gray-400">{o.desc}</span>
              </span>
            </label>
          )
        })}
      </div>
      {fullBlocked && (
        <p id={`${name}-full-blocked`} className="mt-1 text-xs text-gray-500">
          {fullBlocked}
        </p>
      )}
    </fieldset>
  )
}

// useEngine is the engine that enforces the firewall. Shadow mode answers the
// v2 state too, but there iptables enforces (the server treats tunnel
// changes as in iptables mode).
export const useEngine = () => {
  const q = useFirewallV2State()
  const mode = engineMode(q)
  return mode === 'nft' && q.data?.mode !== 'nft' ? 'iptables' : mode
}

// useTunnelResult is where an applied tunnel change stands now (see
// tunnelResultState); stored is the saved value, requested the applied one.
const useTunnelResult = (
  change: TunnelChange | null,
  stored: string | null | undefined,
  requested: string
): TunnelResult | null => {
  const { data } = useFirewallV2State()
  if (!change) return null
  const pending = change.pending
  return tunnelResultState({
    hadPending: !!pending,
    stillPending: !!pending && data?.pending?.id === pending.id,
    stored,
    requested,
    deadlinePassed: !!pending && Date.now() > Date.parse(pending.deadline),
  })
}

// FirewallPendingNotice: the confirm bar of a firewall change that waits for
// confirmation, wherever the change was made (e.g. a tunnel mode).
export const FirewallPendingNotice = ({ className }: { className?: string }) => {
  const { data } = useFirewallV2State()
  if (!data?.pending) return null
  return (
    <div className={className}>
      <PendingBanner pending={data.pending} />
    </div>
  )
}

// TunnelModeDialog: change a network's tunnel mode. It says which devices
// switch (they need their configs again), what full tunnel costs and how the
// engine applies it; after Apply it shows the confirm bar or the result.
export const TunnelModeDialog = ({
  network,
  onClose,
}: {
  network: Network
  onClose: () => void
}) => {
  const { t } = useTranslation('networks')
  const isAdmin = useCan('admin')
  const engine = useEngine()
  const { data: nodes = [] } = useNodes(network.id)
  const current = effectiveTunnel('', network.tunnel_mode)
  const [mode, setMode] = useState<TunnelMode>(current)
  const [result, setResult] = useState<TunnelChange | null>(null)
  const setTunnel = useSetNetworkTunnel()
  const block = fullTunnelBlock({
    isAdmin,
    adminNetwork: isAdminInterface(network.interface_name),
    engine,
  })
  const affected = affectedByNetworkChange(nodes, current, mode)
  const state = useTunnelResult(result, network.tunnel_mode, mode)
  // A failure is reported by the mutation's error toast; the dialog stays open.
  const apply = () => setTunnel.mutate({ id: network.id, mode }, { onSuccess: setResult })

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={t('tunnel.dialogTitle', { name: networkLabel(network, t).name })}
    >
      {result ? (
        <div className="space-y-3 text-sm" aria-live="polite">
          {state === 'pending' && (
            <>
              <FirewallPendingNotice />
              <p>{t('tunnel.donePending')}</p>
            </>
          )}
          {state === 'saved' && <p>{t('tunnel.doneNow')}</p>}
          {state === 'confirmed' && <p>{t('tunnel.confirmed')}</p>}
          {state === 'rolledBack' && (
            <p className="flex items-start gap-2 rounded-lg bg-amber-50 p-3 text-amber-800 dark:bg-amber-900/20 dark:text-amber-200">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              {t('tunnel.rolledBack')}
            </p>
          )}
          {state !== 'rolledBack' && result.item.affected_nodes > 0 && (
            <p className="text-gray-600 dark:text-gray-300">
              {t('tunnel.affected', { count: result.item.affected_nodes })} {t('tunnel.redownload')}
            </p>
          )}
          <div className="flex justify-end">
            <Button onClick={onClose}>{t('common:actions.close')}</Button>
          </div>
        </div>
      ) : (
        <div className="space-y-4 text-sm">
          <p className="text-gray-600 dark:text-gray-300">{t('tunnel.choose')}</p>
          <TunnelChoice
            name={`tunnel-${network.id}`}
            value={mode}
            onChange={setMode}
            fullBlocked={
              block === 'role'
                ? t('tunnel.blockRole')
                : block === 'engine'
                  ? t('tunnel.blockEngine')
                  : null
            }
          />
          <p className="flex items-start gap-2 text-gray-600 dark:text-gray-300">
            <Info className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
            {affected > 0 ? t('tunnel.affected', { count: affected }) : t('tunnel.affectedNone')}
          </p>
          {mode === 'full' && mode !== current && (
            <p className="flex items-start gap-2 rounded-lg bg-amber-50 p-3 text-amber-800 dark:bg-amber-900/20 dark:text-amber-200">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              {t('tunnel.fullWarn')}
            </p>
          )}
          {(engine === 'nft' || engine === 'iptables') && (
            <p className="text-xs text-gray-500">
              {t(engine === 'nft' ? 'tunnel.engineNft' : 'tunnel.engineIptables')}
            </p>
          )}
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={onClose}>
              {t('common:actions.cancel')}
            </Button>
            <Button
              onClick={apply}
              loading={setTunnel.isPending}
              disabled={mode === current || !isAdmin}
            >
              {t('tunnel.apply')}
            </Button>
          </div>
        </div>
      )}
    </Modal>
  )
}

// NetworkTunnel: a network's mode and, for admins, the button that changes it.
export const NetworkTunnel = ({ network }: { network: Network }) => {
  const { t } = useTranslation('networks')
  const isAdmin = useCan('admin')
  const [open, setOpen] = useState(false)
  return (
    <div className="flex flex-wrap items-center gap-2">
      <TunnelBadge mode={effectiveTunnel('', network.tunnel_mode)} />
      {isAdmin && (
        <button
          type="button"
          onClick={() => setOpen(true)}
          aria-label={t('tunnel.changeLabel', { name: networkLabel(network, t).name })}
          className="text-xs font-medium text-blue-600 hover:underline dark:text-blue-400"
        >
          {t('tunnel.change')}
        </button>
      )}
      {open && <TunnelModeDialog network={network} onClose={() => setOpen(false)} />}
    </div>
  )
}

// NodeTunnel: a device's tunnel mode (its own, or its network's) and, for
// admins, the choice to follow the network or set its own.
export const NodeTunnel = ({ node }: { node: Node }) => {
  const { t } = useTranslation('nodes')
  const isAdmin = useCan('admin')
  const engine = useEngine()
  const { data: network } = useNetwork(node.network_id)
  const setTunnel = useSetNodeTunnel()
  const [value, setValue] = useState<NodeOverride | null>(null)
  const [result, setResult] = useState<TunnelChange | null>(null)
  const [requested, setRequested] = useState<NodeOverride>('')
  const current = toOverride(node.tunnel_override)
  const shown = value ?? current
  const state = useTunnelResult(result, current, requested)
  const networkMode = effectiveTunnel('', network?.tunnel_mode)
  const block = fullTunnelBlock({
    isAdmin,
    adminNetwork: isAdminInterface(network?.interface_name),
    engine,
  })
  const modeName = (m: TunnelMode) =>
    t(m === 'full' ? 'networks:tunnel.full' : 'networks:tunnel.split')
  const options = [
    { value: '', label: t('nodes:tunnel.follow', { mode: modeName(networkMode) }) },
    { value: 'split', label: modeName('split') },
    // Full is offered only where the server would accept it (or is set already).
    ...(block === null || current === 'full' ? [{ value: 'full', label: modeName('full') }] : []),
  ]
  return (
    <div className="space-y-2 border-b py-2 dark:border-gray-700">
      <div className="flex items-center justify-between gap-3 text-sm">
        <span className="text-gray-500">{t('nodes:tunnel.label')}</span>
        <TunnelBadge mode={effectiveTunnel(current, network?.tunnel_mode)} />
      </div>
      {isAdmin && (
        <div className="flex flex-wrap items-end gap-2">
          <div className="min-w-[12rem] flex-1">
            <Select
              help="helpNodes:tunnel"
              label={t('nodes:tunnel.own')}
              value={shown}
              options={options}
              onChange={(e) => {
                setValue(toOverride(e.target.value))
                setResult(null)
              }}
            />
          </div>
          <Button
            size="sm"
            disabled={shown === current}
            loading={setTunnel.isPending}
            onClick={() =>
              setTunnel.mutate(
                { id: node.id, override: shown },
                {
                  onSuccess: (r) => {
                    setResult(r)
                    setRequested(shown)
                    // While it waits for confirmation the choice stays shown;
                    // the stored value only changes on confirm.
                    if (!r.pending) setValue(null)
                  },
                }
              )
            }
          >
            {t('networks:tunnel.apply')}
          </Button>
        </div>
      )}
      {state && (
        <p className="text-xs text-gray-600 dark:text-gray-300" aria-live="polite">
          {t(
            state === 'pending'
              ? 'nodes:tunnel.pending'
              : state === 'rolledBack'
                ? 'nodes:tunnel.rolledBack'
                : 'nodes:tunnel.saved'
          )}
        </p>
      )}
      {state === 'pending' && <FirewallPendingNotice />}
    </div>
  )
}

type NodeOverride = '' | 'split' | 'full'

const toOverride = (v: string | null | undefined): NodeOverride =>
  v === 'split' || v === 'full' ? v : ''
