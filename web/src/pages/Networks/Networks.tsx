import { format } from 'date-fns'
import { Network, Plus, Search, Shield, Trash2 } from 'lucide-react'
import type React from 'react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import {
  useAllowed,
  useCan,
  useCreateNetwork,
  useDeleteNetwork,
  useMe,
  useNetworks,
  useVPNSettings,
} from '@/api/client'
import { apiErrorMessage } from '@/api/errors'
import { HelpTip } from '@/components/HelpTip'
import { PageHeader } from '@/components/Layout'
import { NetworkInterfaceStatus } from '@/components/NetworkStatus'
import { FirewallPendingNotice, NetworkTunnel, TunnelChoice } from '@/components/Tunnel'
import { dateFnsLocale } from '@/i18n'
import { networkLabel, networkMatches } from '@/lib/networkDisplay'
import type { CreateNetworkForm } from '@/types'

export const Networks = () => {
  const { t } = useTranslation('networks')
  // Networks are changed by operators and admins (P9a).
  const canEdit = useAllowed('networks', 'edit')
  // A role limited to networks cannot create or delete networks.
  const scoped = (useMe().data?.network_ids?.length ?? 0) > 0
  const canManage = canEdit && !scoped
  const isAdmin = useCan('admin') // full tunnel (the hub as internet exit) is admin only
  const { data: networks, isLoading } = useNetworks()
  const createMutation = useCreateNetwork()
  const deleteMutation = useDeleteNetwork()
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false)
  // An empty CIDR: the server takes the next free /24 of the address pool.
  const [formData, setFormData] = useState<CreateNetworkForm>({ name: '', cidr: '' })
  const { data: vpn } = useVPNSettings()
  const [searchQuery, setSearchQuery] = useState('')
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  const filteredNetworks = networks?.filter((n) => networkMatches(n, searchQuery, t))

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    setErrorMessage(null)
    try {
      await createMutation.mutateAsync(formData)
      setIsCreateModalOpen(false)
      setFormData({ name: '', cidr: '' })
    } catch (error) {
      console.error('Failed to create network:', error)
      // Extract error message from response
      const message = apiErrorMessage(error, t('createFailed'))
      setErrorMessage(message)
    }
  }

  const handleDelete = async (id: string, name: string) => {
    if (confirm(t('deleteConfirm', { name }))) {
      try {
        await deleteMutation.mutateAsync(id)
      } catch (error) {
        console.error('Failed to delete network:', error)
      }
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  return (
    <div>
      <PageHeader
        title={t('title')}
        description={t('description')}
        actions={
          canManage && (
            <button
              type="button"
              onClick={() => setIsCreateModalOpen(true)}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
              <Plus className="w-4 h-4" />
              {t('create')}
            </button>
          )
        }
      />

      <FirewallPendingNotice className="mb-4" />

      {/* Search */}
      <div className="mb-6">
        <div className="relative flex max-w-md items-center gap-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            data-help="helpNetworks:search"
            type="text"
            placeholder={t('searchPlaceholder')}
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-900 dark:text-white"
          />
          <HelpTip k="helpNetworks:search" />
        </div>
      </div>

      {/* Networks List */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredNetworks?.map((network) => {
          const label = networkLabel(network, t)
          return (
            <div
              key={network.id}
              className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden hover:shadow-lg transition-shadow"
            >
              <div className="p-6">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-blue-50 dark:bg-blue-900/20 rounded-lg flex items-center justify-center">
                      <Network className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                    </div>
                    <div>
                      <h3 className="font-semibold text-gray-900 dark:text-white">
                        <Link to={`/networks/${network.id}`} className="hover:underline">
                          {label.name}
                        </Link>
                      </h3>
                      {label.note && (
                        <p className="text-xs text-blue-700 dark:text-blue-300">{label.note}</p>
                      )}
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        {t('card.created', {
                          date: format(new Date(network.created_at), 'MMM d, yyyy', {
                            locale: dateFnsLocale(),
                          }),
                        })}
                      </p>
                    </div>
                  </div>
                  {canManage && (
                    <button
                      type="button"
                      onClick={() => handleDelete(network.id, label.name)}
                      className="p-2 text-gray-400 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
                      title={t('card.delete')}
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </div>

                <div className="space-y-4">
                  {/* Network Details */}
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-xs text-gray-500 dark:text-gray-400 block mb-1">
                        {t('card.cidrRange')}
                      </span>
                      <span className="font-medium text-gray-900 dark:text-gray-200">
                        {network.cidr}
                      </span>
                    </div>
                    <div>
                      <span className="text-xs text-gray-500 dark:text-gray-400 block mb-1">
                        {t('common:fields.interface')}
                      </span>
                      <div className="flex items-center gap-1.5 font-medium text-gray-900 dark:text-gray-200">
                        <Shield className="w-3.5 h-3.5 text-green-500" />
                        {network.interface_name || 'wg0'}
                      </div>
                    </div>
                    <div>
                      <span className="text-xs text-gray-500 dark:text-gray-400 block mb-1">
                        {t('card.listenPort')}
                      </span>
                      <span className="font-mono text-gray-900 dark:text-gray-200">
                        {network.listen_port || 51820}
                      </span>
                    </div>
                    <div>
                      <span className="text-xs text-gray-500 dark:text-gray-400 block mb-1">
                        {t('card.serverEndpoint')}
                      </span>
                      <span
                        className="font-mono text-xs text-gray-900 dark:text-gray-200 truncate block"
                        title={network.server_endpoint}
                      >
                        {network.server_endpoint || t('card.autoDetected')}
                      </span>
                    </div>
                    <div className="col-span-2">
                      <span className="text-xs text-gray-500 dark:text-gray-400 block mb-1">
                        {t('tunnel.label')}
                      </span>
                      <NetworkTunnel network={network} />
                    </div>
                  </div>

                  {/* The hub interface as the server reports it */}
                  <div className="pt-4 border-t border-gray-100 dark:border-gray-700">
                    <NetworkInterfaceStatus network={network} />
                  </div>
                </div>
              </div>
            </div>
          )
        })}

        {/* Add New Card (Empty State or Last Item) */}
        {canManage && (
          <button
            type="button"
            onClick={() => setIsCreateModalOpen(true)}
            className="flex flex-col items-center justify-center p-6 border-2 border-dashed border-gray-300 dark:border-gray-700 rounded-xl hover:border-blue-500 dark:hover:border-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/10 transition-all group min-h-[250px]"
          >
            <div className="w-12 h-12 bg-blue-100 dark:bg-blue-900/40 rounded-full flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
              <Plus className="w-6 h-6 text-blue-600 dark:text-blue-400" />
            </div>
            <span className="font-medium text-gray-900 dark:text-white">{t('newCard.title')}</span>
            <p className="text-sm text-gray-500 text-center mt-2 max-w-[200px]">
              {t('newCard.description')}
            </p>
          </button>
        )}
      </div>

      {/* Create Modal */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50">
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-xl max-w-md w-full p-6">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">
              {t('form.title')}
            </h2>
            <form onSubmit={handleCreate}>
              <div className="space-y-4">
                <div>
                  <label
                    htmlFor="net-1"
                    className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1"
                  >
                    {t('form.name')}
                    <HelpTip k="helpNetworks:name" />
                  </label>
                  <input
                    data-help="helpNetworks:name"
                    id="net-1"
                    type="text"
                    required
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    className="w-full rounded-lg border border-gray-300 dark:border-gray-600 px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 outline-none"
                    placeholder={t('form.namePlaceholder')}
                  />
                </div>
                <div>
                  <label
                    htmlFor="net-2"
                    className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1"
                  >
                    {t('card.cidrRange')}
                    <HelpTip k="helpNetworks:cidr" />
                  </label>
                  <input
                    data-help="helpNetworks:cidr"
                    id="net-2"
                    type="text"
                    value={formData.cidr}
                    onChange={(e) => setFormData({ ...formData, cidr: e.target.value.trim() })}
                    className="w-full rounded-lg border border-gray-300 dark:border-gray-600 px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 outline-none"
                    placeholder={
                      vpn?.next_cidr
                        ? t('form.cidrAuto', { next: vpn.next_cidr })
                        : t('form.cidrPlaceholder')
                    }
                  />
                  <p className="mt-1 text-xs text-gray-500">
                    {t('form.cidrHint', { pool: vpn?.pool ?? '10.0.0.0/8' })}
                  </p>
                </div>

                <div>
                  <TunnelChoice
                    name="new-network-tunnel"
                    value={formData.tunnel_mode ?? 'split'}
                    onChange={(mode) => setFormData({ ...formData, tunnel_mode: mode })}
                    fullBlocked={isAdmin ? null : t('tunnel.blockRole')}
                  />
                  <p className="mt-1 text-xs text-gray-500">{t('tunnel.formHint')}</p>
                </div>

                <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg flex gap-3 text-sm text-blue-800 dark:text-blue-200">
                  <Shield className="w-5 h-5 shrink-0" />
                  <p>{t('form.interfaceNote')}</p>
                </div>

                {/* Error Message */}
                {errorMessage && (
                  <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-4 rounded-lg text-sm text-red-700 dark:text-red-300">
                    <strong>{t('error')}</strong> {errorMessage}
                  </div>
                )}
              </div>

              <div className="flex justify-end gap-3 mt-6">
                <button
                  type="button"
                  onClick={() => {
                    setIsCreateModalOpen(false)
                    setErrorMessage(null)
                  }}
                  className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                >
                  {t('common:actions.cancel')}
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending}
                  className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors disabled:opacity-50"
                >
                  {createMutation.isPending ? t('creating') : t('create')}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
