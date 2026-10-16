import { useMutation, useQueryClient } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import {
  Activity,
  CheckCircle,
  Clock,
  Copy,
  Download,
  Laptop,
  Pencil,
  QrCode,
  RefreshCw,
  Server,
  ShieldAlert,
  Terminal,
  Trash2,
} from 'lucide-react'
import type React from 'react'
import { useState } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import { useNavigate, useParams } from 'react-router-dom'
import {
  api,
  useCan,
  useCreateServerWithConfig,
  useDeleteNode,
  useGroups,
  useLimits,
  useNetworks,
  useNode,
  useNodes,
  useResetQuota,
  useUpdateNode,
} from '@/api/client'
import { CreateNodeModal } from '@/components/CreateNodeModal'
import { EditNodeModal } from '@/components/EditNodeModal'
import { HelpTip } from '@/components/HelpTip'
import { PageHeader } from '@/components/Layout'
import { type ConfigTab, ServerConfigModal } from '@/components/ServerConfigModal'
import { TrafficHistoryCard } from '@/components/TrafficHistoryCard'
import { Badge, Button, Card, EmptyState, Modal, StatusIndicator, Table } from '@/components/ui'
import { dateFnsLocale, formatDateTime } from '@/i18n'
import { detailActions, rowActions } from '@/lib/deviceActions'
import { groupsByNode } from '@/lib/groups'
import { formatBytes as formatQuotaBytes, type QuotaUsage, quotaFor } from '@/lib/quota'
import { useCurrentNetworkId } from '@/store'
import type { Node } from '@/types'

const formatBytes = (bytes: number = 0) => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / k ** i).toFixed(2))} ${sizes[i]}`
}

// QuotaBar: a node's use of its monthly traffic quota (P9c).
const QuotaBar = ({ usage, enforcing }: { usage: QuotaUsage; enforcing: boolean }) => {
  const { t } = useTranslation('nodes')
  const color = usage.exceeded
    ? 'bg-red-500'
    : usage.percent >= 80
      ? 'bg-amber-500'
      : 'bg-green-500'
  return (
    <div className="min-w-[8rem]">
      <div className="h-2 w-full rounded bg-gray-200 dark:bg-gray-700">
        <div className={`h-2 rounded ${color}`} style={{ width: `${usage.percent}%` }} />
      </div>
      <p className="mt-1 text-xs text-gray-500">
        {t('quota.used', {
          used: formatQuotaBytes(usage.usedBytes),
          quota: formatQuotaBytes(usage.quotaBytes),
        })}
        {usage.exceeded && (
          <span className="ml-1 text-red-600">
            {t(usage.action === 'throttle' ? 'quota.throttled' : 'quota.blocked')}
            {!enforcing && ` ${t('quota.notEnforced')}`}
          </span>
        )}
      </p>
    </div>
  )
}

export const NodesPage: React.FC = () => {
  const { t } = useTranslation('nodes')
  const navigate = useNavigate()
  const networkId = useCurrentNetworkId()
  const { data: allNodes, isLoading } = useNodes(networkId || '')
  // Config download and changes need an operator (P9a).
  const canEdit = useCan('operator')
  const { data: groupData } = useGroups()
  const nodeGroups = groupsByNode(groupData?.groups)
  const { data: limits } = useLimits()
  const groupOptions = (groupData?.groups ?? []).filter((g) => g !== null)
  const [groupFilter, setGroupFilter] = useState('')
  const nodes = groupFilter
    ? allNodes?.filter((n) => nodeGroups.get(n.id)?.some((g) => g.id === groupFilter))
    : allNodes
  const deleteNode = useDeleteNode()
  const createServer = useCreateServerWithConfig()
  const updateNode = useUpdateNode()
  const { data: networks } = useNetworks()
  const currentNetwork = networks?.find((n) => n.id === networkId)
  const isAdminNetwork =
    currentNetwork?.interface_name === 'wg0' || currentNetwork?.name === 'Admin Management Network'

  const [selectedNode, setSelectedNode] = useState<Node | null>(null)
  const [showDeleteModal, setShowDeleteModal] = useState(false)
  const [showConfigModal, setShowConfigModal] = useState(false)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [showEditModal, setShowEditModal] = useState(false)

  if (!networkId) {
    return (
      <EmptyState
        icon={<Server className="w-12 h-12" />}
        title={t('list.noNetwork.title')}
        description={t('list.noNetwork.description')}
      />
    )
  }

  const handleDelete = async () => {
    if (selectedNode) {
      await deleteNode.mutateAsync(selectedNode.id)
      setShowDeleteModal(false)
      setSelectedNode(null)
    }
  }

  const handleCreatePeer = async (data: {
    name: string
    expires_at?: string
    network_id: string
  }) => {
    createServer.mutate(
      {
        // The network picked in the form (C2), by default the sidebar's one.
        networkId: data.network_id,
        data: {
          name: data.name,
          expires_at: data.expires_at,
          labels: { type: 'client' },
        },
      },
      {
        onSuccess: (response) => {
          setShowCreateModal(false)
          // Show the config download modal for the new node
          if (response.node) {
            setSelectedNode(response.node)
            setShowConfigModal(true)
          }
        },
      }
    )
  }

  const columns = [
    {
      key: 'name',
      header: t('common:fields.name'),
      // Names wrap only between words, never inside one (B6).
      render: (node: Node) => (
        <div className="min-w-[8rem] max-w-[14rem] break-normal">
          <p className="font-medium text-gray-900 dark:text-white">{node.name}</p>
          <p className="text-xs text-gray-500">{node.id.slice(0, 8)}...</p>
          {/* Public IP and labels stay scannable here; the detail page has them in full. */}
          {node.public_ip && (
            <p className="text-xs text-gray-500">
              <span className="sr-only">{t('detail.publicEndpoint')}: </span>
              <code className="font-mono">{node.public_ip}</code>
            </p>
          )}
          {Object.keys(node.labels ?? {}).length > 0 && (
            <div className="mt-1 flex flex-wrap gap-1">
              {Object.entries(node.labels ?? {}).map(([key, value]) => (
                <Badge key={key} size="sm">
                  {key}={value}
                </Badge>
              ))}
            </div>
          )}
        </div>
      ),
    },
    {
      key: 'status',
      header: t('common:fields.status'),
      render: (node: Node) => <StatusIndicator status={node.status} />,
    },
    {
      key: 'virtual_ip',
      header: t('fields.virtualIp'),
      render: (node: Node) => (
        <code className="whitespace-nowrap text-sm bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded">
          {node.virtual_ip}
        </code>
      ),
    },
    {
      key: 'transfer',
      header: t('list.columns.transfer'),
      render: (node: Node) => (
        <div className="whitespace-nowrap text-xs space-y-0.5">
          <p className="text-green-600">↓ {formatBytes(node.transfer_rx)}</p>
          <p className="text-blue-600">↑ {formatBytes(node.transfer_tx)}</p>
        </div>
      ),
    },
    {
      key: 'expires',
      header: t('list.columns.expires'),
      render: (node: Node) => (
        <span
          className={`text-sm ${node.status === 'expired' ? 'text-red-500 font-bold' : 'text-gray-500'}`}
        >
          {node.expires_at && node.expires_at !== '0001-01-01T00:00:00Z'
            ? formatDateTime(node.expires_at)
            : t('fields.forever')}
        </span>
      ),
    },
    {
      key: 'last_seen',
      header: t('fields.lastSeen'),
      render: (node: Node) => (
        <span className="text-gray-500">
          {node.last_seen && node.last_seen !== '0001-01-01T00:00:00Z'
            ? formatDistanceToNow(new Date(node.last_seen), {
                addSuffix: true,
                locale: dateFnsLocale(),
              })
            : t('fields.never')}
        </span>
      ),
    },
    {
      key: 'groups',
      header: t('list.columns.groups'),
      render: (node: Node) => (
        <div className="flex flex-wrap gap-1">
          {(nodeGroups.get(node.id) ?? []).map((g) => (
            <Badge key={g.id} variant="info">
              {g.name}
            </Badge>
          ))}
        </div>
      ),
    },
    {
      key: 'quota',
      header: t('list.columns.quota'),
      render: (node: Node) => {
        const usage = quotaFor(node.id, limits)
        return usage ? (
          <QuotaBar usage={usage} enforcing={limits?.enforcing ?? true} />
        ) : (
          <span className="text-xs text-gray-400">—</span>
        )
      },
    },
    {
      // Row actions in one compact column that stays visible at the right
      // edge, even when the table scrolls sideways (B6).
      key: 'actions',
      header: '',
      className: 'sticky right-0 w-px whitespace-nowrap bg-white dark:bg-gray-800',
      render: (node: Node) => {
        const actions = rowActions(node, canEdit)
        return (
          <div className="flex items-center gap-1">
            {actions.includes('config') && (
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation()
                  setSelectedNode(node)
                  setShowConfigModal(true)
                }}
                className="p-1 text-primary-600 hover:text-primary-700"
                title={t('list.downloadConfig')}
                aria-label={t('list.downloadConfig')}
              >
                <Download className="w-4 h-4" />
              </button>
            )}
            {!node.has_config && (
              <span
                className="p-1 text-xs text-gray-400"
                title={t('list.configUnavailable')}
                role="img"
                aria-label={t('list.configUnavailable')}
              >
                -
              </span>
            )}
            {actions.includes('edit') && (
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation()
                  setSelectedNode(node)
                  setShowEditModal(true)
                }}
                className="p-1 text-gray-400 hover:text-blue-600"
                title={t('common:actions.edit')}
                aria-label={t('common:actions.edit')}
              >
                <Pencil className="w-4 h-4" />
              </button>
            )}
            {actions.includes('delete') && (
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation()
                  setSelectedNode(node)
                  setShowDeleteModal(true)
                }}
                className="p-1 text-gray-400 hover:text-red-600"
                title={t('common:actions.delete')}
                aria-label={t('common:actions.delete')}
              >
                <Trash2 className="w-4 h-4" />
              </button>
            )}
          </div>
        )
      },
    },
  ]

  const visibleColumns = canEdit ? columns : columns.filter((c) => c.key !== 'actions')

  const onlineCount = allNodes?.filter((n) => n.status === 'online').length || 0
  const pendingCount = allNodes?.filter((n) => n.status === 'pending').length || 0
  const offlineCount =
    allNodes?.filter((n) => n.status === 'offline' || n.status === 'expired').length || 0

  return (
    <div>
      <PageHeader
        title={t('list.title')}
        description={t('list.description')}
        actions={
          canEdit && (
            <Button onClick={() => setShowCreateModal(true)}>
              <Server className="w-4 h-4 mr-2" />
              {t('list.createPeer')}
            </Button>
          )
        }
      />

      {/* Admin Network Warning */}
      {isAdminNetwork && (
        <div className="mb-6 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-xl flex items-start gap-3">
          <ShieldAlert className="w-5 h-5 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
          <div>
            <h3 className="text-sm font-semibold text-red-800 dark:text-red-300">
              {t('list.adminWarning.title')}
            </h3>
            <p className="text-sm text-red-700 dark:text-red-400 mt-1">
              <Trans t={t} i18nKey="list.adminWarning.body" components={{ strong: <strong /> }} />
            </p>
          </div>
        </div>
      )}

      {/* Summary cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <Card>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">{t('list.summary.total')}</p>
              <p className="text-2xl font-semibold">{allNodes?.length || 0}</p>
            </div>
            <Server className="w-8 h-8 text-gray-400" />
          </div>
        </Card>
        <Card>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">{t('common:status.online')}</p>
              <p className="text-2xl font-semibold text-green-600">{onlineCount}</p>
            </div>
            <div className="w-3 h-3 bg-green-500 rounded-full" />
          </div>
        </Card>
        <Card>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">{t('common:status.pending')}</p>
              <p className="text-2xl font-semibold text-orange-500">{pendingCount}</p>
            </div>
            <div className="w-3 h-3 bg-orange-500 rounded-full animate-pulse" />
          </div>
        </Card>
        <Card>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">{t('common:status.offline')}</p>
              <p className="text-2xl font-semibold text-gray-400">{offlineCount}</p>
            </div>
            <div className="w-3 h-3 bg-gray-400 rounded-full" />
          </div>
        </Card>
      </div>

      {groupOptions.length > 0 && (
        <div className="mb-4 flex items-center gap-2">
          <label htmlFor="node-group-filter" className="text-sm text-gray-600 dark:text-gray-400">
            {t('list.groupFilter')}
            <HelpTip k="helpNodes:list.groupFilter" />
          </label>
          <select
            data-help="helpNodes:list.groupFilter"
            id="node-group-filter"
            value={groupFilter}
            onChange={(e) => setGroupFilter(e.target.value)}
            className="px-3 py-1.5 text-sm border rounded-lg dark:bg-gray-700 dark:border-gray-600"
          >
            <option value="">{t('list.allGroups')}</option>
            {groupOptions.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </select>
        </div>
      )}

      {/* Nodes table */}
      <Card padding="none">
        <Table
          columns={visibleColumns}
          data={nodes || []}
          loading={isLoading}
          onRowClick={(node) => navigate(`/nodes/${node.id}`)}
          emptyMessage={t('list.empty')}
        />
      </Card>

      {/* Delete confirmation modal */}
      <Modal
        isOpen={showDeleteModal}
        onClose={() => setShowDeleteModal(false)}
        title={t('list.delete.title')}
      >
        <div className="space-y-4">
          <p className="text-gray-600 dark:text-gray-400">
            <Trans
              t={t}
              i18nKey="list.delete.body"
              values={{ name: selectedNode?.name }}
              components={{ strong: <strong /> }}
            />
          </p>
          <div className="flex justify-end gap-3">
            <Button variant="secondary" onClick={() => setShowDeleteModal(false)}>
              {t('common:actions.cancel')}
            </Button>
            <Button variant="danger" onClick={handleDelete} loading={deleteNode.isPending}>
              {t('list.delete.confirm')}
            </Button>
          </div>
        </div>
      </Modal>

      {/* Peer creation modal */}
      <CreateNodeModal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        onSubmit={handleCreatePeer}
        isLoading={createServer.isPending}
      />

      {/* Config Modal */}
      <ServerConfigModal
        isOpen={showConfigModal}
        onClose={() => {
          setShowConfigModal(false)
          setSelectedNode(null)
        }}
        nodeId={selectedNode?.id || ''}
        nodeName={selectedNode?.name || ''}
      />

      {/* Edit Node Modal */}
      <EditNodeModal
        isOpen={showEditModal}
        onClose={() => {
          setShowEditModal(false)
          setSelectedNode(null)
        }}
        node={selectedNode}
        onSubmit={(data) => {
          if (selectedNode) {
            updateNode.mutate(
              {
                id: selectedNode.id,
                data: {
                  name: data.name,
                  expires_at: data.expires_at === undefined ? undefined : data.expires_at || '',
                  status: data.status,
                  node_info: data.node_info,
                },
              },
              {
                onSuccess: () => {
                  setShowEditModal(false)
                  setSelectedNode(null)
                },
              }
            )
          }
        }}
        isLoading={updateNode.isPending}
      />
    </div>
  )
}

// Node detail page
export const NodeDetailPage: React.FC = () => {
  const { t } = useTranslation('nodes')
  const canEdit = useCan('operator')
  const navigate = useNavigate()
  const { id } = useParams<{ id: string }>()
  const [copied, setCopied] = useState(false)
  const { data: node, isLoading, error } = useNode(id || '')
  const [showEditModal, setShowEditModal] = useState(false)
  // The limit profile in force for this node (P9b), and the group it comes from.
  const { data: limits } = useLimits()
  const { data: groupData } = useGroups()
  const nodeLimit = limits?.node_limits?.find((l) => l.node_id === id)
  const limitProfile = limits?.profiles?.find((p) => p.id === nodeLimit?.profile_id)
  const limitGroup = groupData?.groups?.find((g) => g?.id === nodeLimit?.group_id)
  const quotaUsage = quotaFor(id || '', limits)
  const resetQuota = useResetQuota()

  // Update node mutation
  const queryClient = useQueryClient()
  const updateNode = useUpdateNode()
  // Config, QR code and Linux script (C3): the same modal the list opens,
  // started on the tab the button names; null while it is closed.
  const [configTab, setConfigTab] = useState<ConfigTab | null>(null)
  const downloadConfig = useMutation({
    meta: { errorTitle: 'nodes:detail.downloadFailed' },
    mutationFn: async (target: { id: string; name: string }) => ({
      name: target.name,
      text: await api.getNodeConfig(target.id),
    }),
    onSuccess: ({ name, text }) => {
      const element = document.createElement('a')
      element.href = `data:text/plain;base64,${btoa(unescape(encodeURIComponent(text)))}`
      element.download = `${name.replace(/\s+/g, '-').toLowerCase()}.conf`
      document.body.appendChild(element)
      element.click()
      document.body.removeChild(element)
    },
  })
  // "Restore connection": the hub re-adds the WireGuard peers its network
  // lost (POST /networks/{id}/sync); expired and disabled devices stay out.
  const syncPeers = useMutation({
    meta: { errorTitle: 'nodes:detail.syncFailed', successTitle: 'nodes:detail.synced' },
    mutationFn: (networkId: string) => api.syncPeers(networkId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['nodes'] }),
  })

  const handleEditSubmit = (data: {
    name: string
    expires_at?: string | null
    status?: string
    node_info?: { os: string; arch: string; hostname: string }
  }) => {
    if (node) {
      updateNode.mutate(
        {
          id: node.id,
          data: {
            name: data.name,
            expires_at: data.expires_at === undefined ? undefined : data.expires_at || '',
            status: data.status,
            node_info: data.node_info,
          },
        },
        {
          onSuccess: () => {
            setShowEditModal(false)
            queryClient.invalidateQueries({ queryKey: ['node', node.id] })
          },
        }
      )
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  if (error || !node) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] text-center">
        <Server className="w-12 h-12 text-gray-300 mb-4" />
        <h3 className="text-lg font-medium text-gray-900 dark:text-white">
          {t('detail.notFound.title')}
        </h3>
        <p className="text-gray-500 mb-4">{t('detail.notFound.body')}</p>
        <Button variant="secondary" onClick={() => navigate('/nodes')}>
          {t('detail.notFound.back')}
        </Button>
      </div>
    )
  }

  const actions = detailActions(node, canEdit)

  const copyToClipboard = async (text: string) => {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text)
        setCopied(true)
      } else {
        // Fallback for non-secure contexts
        const textArea = document.createElement('textarea')
        textArea.value = text
        textArea.style.position = 'fixed'
        textArea.style.left = '-9999px'
        textArea.style.top = '0'
        document.body.appendChild(textArea)
        textArea.focus()
        textArea.select()
        try {
          document.execCommand('copy')
          setCopied(true)
        } catch (err) {
          console.error('Fallback: Oops, unable to copy', err)
        }
        document.body.removeChild(textArea)
      }
    } catch (err) {
      console.error('Failed to copy!', err)
    }
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header with Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-white dark:bg-gray-800 p-6 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">{node.name}</h1>
            <StatusIndicator status={node.status} />
          </div>
          <p className="mt-1 text-sm text-gray-500 font-mono">ID: {node.id}</p>
        </div>
        <div className="flex flex-wrap gap-3">
          <Button variant="secondary" onClick={() => navigate('/nodes')}>
            {t('common:actions.back')}
          </Button>
          {actions.includes('download') && (
            <Button
              variant="secondary"
              loading={downloadConfig.isPending}
              onClick={() => downloadConfig.mutate({ id: node.id, name: node.name })}
              className="flex items-center gap-2"
            >
              <Download className="w-4 h-4" />
              {t('detail.actions.download')}
            </Button>
          )}
          {actions.includes('qr') && (
            <Button
              variant="secondary"
              onClick={() => setConfigTab('general')}
              className="flex items-center gap-2"
            >
              <QrCode className="w-4 h-4" />
              {t('detail.actions.qr')}
            </Button>
          )}
          {actions.includes('script') && (
            <Button
              variant="secondary"
              onClick={() => setConfigTab('linux')}
              className="flex items-center gap-2"
            >
              <Terminal className="w-4 h-4" />
              {t('detail.actions.script')}
            </Button>
          )}
          {canEdit && (
            <Button onClick={() => setShowEditModal(true)} className="flex items-center gap-2">
              <Pencil className="w-4 h-4" />
              {t('detail.editNode')}
            </Button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Status & Expiration Card */}
        <Card>
          <div className="flex items-center gap-2 mb-4">
            <Clock className="w-5 h-5 text-primary-500" />
            <h3 className="text-lg font-semibold">{t('detail.statusExpiration')}</h3>
          </div>

          <div className="space-y-4">
            <div className="flex justify-between items-center p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
              <span className="text-gray-600 dark:text-gray-300">
                {t('detail.connectionStatus')}
              </span>
              <div className="flex items-center gap-2">
                <div
                  className={`w-3 h-3 rounded-full ${node.status === 'online' ? 'bg-green-500 animate-pulse' : node.status === 'expired' ? 'bg-red-500' : 'bg-gray-400'}`}
                ></div>
                <span className="font-medium capitalize">
                  {t(`common:status.${node.status}`, { defaultValue: node.status })}
                </span>
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 bg-blue-50 dark:bg-blue-900/20 p-3 rounded-lg text-xs text-blue-700 dark:text-blue-300">
              <span className="flex-1 min-w-[12rem]">
                {actions.includes('sync')
                  ? t('detail.reconnectHint')
                  : t('detail.reconnectHintViewer')}
              </span>
              {actions.includes('sync') && (
                <Button
                  variant="secondary"
                  size="sm"
                  loading={syncPeers.isPending}
                  onClick={() => syncPeers.mutate(node.network_id)}
                  className="flex items-center gap-2"
                >
                  <RefreshCw className="w-4 h-4" />
                  {t('detail.actions.sync')}
                </Button>
              )}
              {syncPeers.data && (
                <p className="w-full">
                  {t('detail.syncResult', {
                    added: syncPeers.data.added,
                    skipped: syncPeers.data.skipped,
                  })}
                  {(syncPeers.data.errors ?? []).length > 0 && (
                    <span className="block text-red-600 dark:text-red-400">
                      {(syncPeers.data.errors ?? []).join('; ')}
                    </span>
                  )}
                </p>
              )}
            </div>

            <div className="flex justify-between items-center p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
              <span className="text-gray-600 dark:text-gray-300">{t('fields.expiration')}</span>
              <div className="text-right">
                <div
                  className={`font-bold ${node.status === 'expired' ? 'text-red-500' : 'text-gray-900 dark:text-white'}`}
                >
                  {node.expires_at && node.expires_at !== '0001-01-01T00:00:00Z'
                    ? formatDateTime(node.expires_at)
                    : t('detail.unlimited')}
                </div>
                {node.expires_at &&
                  node.expires_at !== '0001-01-01T00:00:00Z' &&
                  node.status !== 'expired' && (
                    <span className="text-xs text-gray-500">
                      {t('detail.expiresIn', {
                        time: formatDistanceToNow(new Date(node.expires_at), {
                          addSuffix: true,
                          locale: dateFnsLocale(),
                        }),
                      })}
                    </span>
                  )}
              </div>
            </div>

            <div className="flex justify-between items-center p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
              <span className="text-gray-600 dark:text-gray-300">{t('fields.lastSeen')}</span>
              <span className="font-mono">
                {node.last_seen && node.last_seen !== '0001-01-01T00:00:00Z'
                  ? formatDistanceToNow(new Date(node.last_seen), {
                      addSuffix: true,
                      locale: dateFnsLocale(),
                    })
                  : t('fields.never')}
              </span>
            </div>
          </div>
        </Card>

        {/* Network Activity Card */}
        <Card>
          <div className="flex items-center gap-2 mb-4">
            <Activity className="w-5 h-5 text-blue-500" />
            <h3 className="text-lg font-semibold">{t('detail.networkActivity')}</h3>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-xl border border-blue-100 dark:border-blue-900/30 text-center">
              <div className="text-sm text-blue-600 dark:text-blue-400 mb-1">
                {t('fields.downloadRx')}
              </div>
              <div className="text-2xl font-bold text-gray-900 dark:text-white">
                {formatBytes(node.transfer_rx)}
              </div>
            </div>
            <div className="p-4 bg-green-50 dark:bg-green-900/20 rounded-xl border border-green-100 dark:border-green-900/30 text-center">
              <div className="text-sm text-green-600 dark:text-green-400 mb-1">
                {t('fields.uploadTx')}
              </div>
              <div className="text-2xl font-bold text-gray-900 dark:text-white">
                {formatBytes(node.transfer_tx)}
              </div>
            </div>
          </div>

          <div className="mt-4 space-y-2">
            <div className="flex justify-between text-sm py-2 border-b dark:border-gray-700">
              <span className="text-gray-500">{t('fields.virtualIp')}</span>
              <code className="font-mono">{node.virtual_ip}</code>
            </div>
            <div className="flex justify-between text-sm py-2 border-b dark:border-gray-700">
              <span className="text-gray-500">{t('detail.publicEndpoint')}</span>
              <code className="font-mono">{node.public_ip || t('common:status.unknown')}</code>
            </div>
            <div className="flex justify-between gap-3 text-sm py-2 border-b dark:border-gray-700">
              <span className="text-gray-500">{t('list.columns.labels')}</span>
              <span className="flex flex-wrap justify-end gap-1">
                {Object.keys(node.labels ?? {}).length === 0
                  ? '—'
                  : Object.entries(node.labels ?? {}).map(([key, value]) => (
                      <Badge key={key} size="sm">
                        {key}={value}
                      </Badge>
                    ))}
              </span>
            </div>
            <div className="flex justify-between text-sm py-2 border-b dark:border-gray-700">
              <span className="text-gray-500">{t('detail.limitProfile')}</span>
              <span>
                {limitProfile
                  ? limitGroup
                    ? t('detail.limitViaGroup', {
                        profile: limitProfile.name,
                        group: limitGroup.name,
                      })
                    : limitProfile.name
                  : t('detail.noLimit')}
                {limitProfile && limits && !limits.enforcing && (
                  <span className="ml-1 text-amber-600">{t('detail.limitNotEnforced')}</span>
                )}
              </span>
            </div>
            {quotaUsage && (
              <div className="flex items-center justify-between gap-3 py-2 text-sm">
                <span className="text-gray-500">{t('quota.title')}</span>
                <div className="flex items-center gap-2">
                  <QuotaBar usage={quotaUsage} enforcing={limits?.enforcing ?? true} />
                  {canEdit && (
                    <Button
                      variant="secondary"
                      size="sm"
                      loading={resetQuota.isPending}
                      onClick={() => {
                        if (confirm(t('quota.resetConfirm'))) resetQuota.mutate(id || '')
                      }}
                    >
                      {t('quota.reset')}
                    </Button>
                  )}
                </div>
              </div>
            )}
          </div>
        </Card>

        {/* Traffic History Card (P8) */}
        <div className="lg:col-span-2">
          <TrafficHistoryCard nodeId={id || ''} />
        </div>

        {/* System Info Card */}
        <Card className="lg:col-span-2">
          <div className="flex items-center gap-2 mb-4">
            <Laptop className="w-5 h-5 text-purple-500" />
            <h3 className="text-lg font-semibold">{t('detail.deviceSystem')}</h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div>
              <dt className="text-sm text-gray-500">{t('fields.operatingSystem')}</dt>
              <dd className="mt-1 font-medium">
                {node.node_info?.os || t('common:status.unknown')}
              </dd>
            </div>
            <div>
              <dt className="text-sm text-gray-500">{t('fields.hostname')}</dt>
              <dd className="mt-1 font-medium">
                {node.node_info?.hostname || t('common:status.unknown')}
              </dd>
            </div>
            <div>
              <dt className="text-sm text-gray-500">{t('fields.architecture')}</dt>
              <dd className="mt-1 font-medium">
                {node.node_info?.arch || t('common:status.unknown')}
              </dd>
            </div>
            <div className="col-span-full">
              <dt className="text-sm text-gray-500">{t('fields.publicKey')}</dt>
              <dd className="mt-1 flex items-center gap-2">
                <code className="bg-gray-100 dark:bg-gray-700 px-3 py-2 rounded-lg text-sm flex-1 font-mono break-all">
                  {node.public_key}
                </code>
                <button
                  type="button"
                  onClick={() => copyToClipboard(node.public_key)}
                  className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                  title={t('detail.copyPublicKey')}
                >
                  {copied ? (
                    <CheckCircle className="w-5 h-5 text-green-500" />
                  ) : (
                    <Copy className="w-5 h-5 text-gray-500" />
                  )}
                </button>
              </dd>
            </div>
          </div>
        </Card>
      </div>

      <ServerConfigModal
        isOpen={configTab !== null}
        onClose={() => setConfigTab(null)}
        nodeId={node.id}
        nodeName={node.name}
        initialTab={configTab ?? 'general'}
      />

      <EditNodeModal
        isOpen={showEditModal}
        onClose={() => setShowEditModal(false)}
        node={node}
        onSubmit={handleEditSubmit}
        isLoading={updateNode.isPending}
      />
    </div>
  )
}

export default NodesPage
