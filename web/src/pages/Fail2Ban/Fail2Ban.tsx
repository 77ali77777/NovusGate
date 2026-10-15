import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Activity,
  AlertTriangle,
  Ban,
  CheckCircle,
  Clock,
  History,
  List,
  Plus,
  RefreshCw,
  RotateCcw,
  Save,
  Settings,
  Shield,
  ShieldOff,
  Trash2,
  Unlock,
  XCircle,
} from 'lucide-react'
import React, { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, useCan, useFail2BanLogs, useFail2BanStatus, useUnbanIP } from '@/api/client'
import { PageHeader } from '@/components/Layout'
import { Badge, Button, Card } from '@/components/ui'
import { formatBantime } from './formatBantime'

// Hooks
const useManualBan = () => {
  const qc = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'fail2ban:toasts.banFailed', successTitle: 'fail2ban:toasts.banned' },
    mutationFn: (data: { jail: string; ip: string; permanent: boolean }) =>
      api.banIP(data.jail, data.ip, data.permanent),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['fail2ban'] })
      qc.invalidateQueries({ queryKey: ['permanent-bans'] })
    },
  })
}

const useJailSettings = (jail: string) =>
  useQuery({
    queryKey: ['jail-settings', jail],
    queryFn: () => api.getJailSettings(jail),
    enabled: !!jail,
  })

const useUpdateJailSettings = () => {
  const qc = useQueryClient()
  return useMutation({
    meta: {
      errorTitle: 'fail2ban:toasts.settingsFailed',
      successTitle: 'fail2ban:toasts.settingsSaved',
    },
    mutationFn: (data: { jail: string; bantime?: string; maxretry?: string; findtime?: string }) =>
      api.updateJailSettings(data.jail, data),
    onSuccess: (_, v) => {
      qc.invalidateQueries({ queryKey: ['jail-settings', v.jail] })
      qc.invalidateQueries({ queryKey: ['fail2ban'] })
    },
  })
}

const useWhitelist = (jail: string) =>
  useQuery({
    queryKey: ['whitelist', jail],
    queryFn: () => api.getWhitelist(jail),
    enabled: !!jail,
  })

const useUpdateWhitelist = () => {
  const qc = useQueryClient()
  return useMutation({
    meta: {
      errorTitle: 'fail2ban:toasts.whitelistFailed',
      successTitle: 'fail2ban:toasts.whitelistUpdated',
    },
    mutationFn: (data: { jail: string; action: 'add' | 'remove'; ip: string }) =>
      api.updateWhitelist(data.jail, data.action, data.ip),
    onSuccess: (_, v) => qc.invalidateQueries({ queryKey: ['whitelist', v.jail] }),
  })
}

const usePermanentBans = () =>
  useQuery({ queryKey: ['permanent-bans'], queryFn: () => api.getPermanentBans() })

const useRemovePermanentBan = () => {
  const qc = useQueryClient()
  return useMutation({
    meta: {
      errorTitle: 'fail2ban:toasts.permanentRemoveFailed',
      successTitle: 'fail2ban:toasts.permanentRemoved',
    },
    mutationFn: (ip: string) => api.removePermanentBan(ip),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['permanent-bans'] }),
  })
}

const useReloadFail2Ban = () => {
  const qc = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'fail2ban:toasts.reloadFailed', successTitle: 'fail2ban:toasts.reloaded' },
    mutationFn: (jail?: string) => api.reloadFail2Ban(jail),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['fail2ban'] }),
  })
}

const useFail2BanPing = () =>
  useQuery({
    queryKey: ['fail2ban-ping'],
    queryFn: () => api.pingFail2Ban(),
    refetchInterval: 30000,
  })
const useBanHistory = () =>
  useQuery({ queryKey: ['ban-history'], queryFn: () => api.getBanHistory(undefined, 100) })

interface JailData {
  name: string
  banned_count?: number
  total_banned?: number
  failed_count?: number
  total_failed?: number
  banned_ips?: string[]
}
interface LogEntry {
  timestamp?: string
  action?: string
  raw: string
}
interface HistoryEntry {
  timestamp?: string
  action?: string
  jail?: string
  ip?: string
  raw: string
}

type ActiveTabProps =
  | 'overview'
  | 'banned'
  | 'whitelist'
  | 'settings'
  | 'permanent'
  | 'history'
  | 'logs'

export const Fail2BanPage = () => {
  const { t } = useTranslation('fail2ban')
  const [activeTab, setActiveTab] = useState<ActiveTabProps>('overview')
  const [selectedJail, setSelectedJail] = useState<string>('sshd')
  const [showBanModal, setShowBanModal] = useState(false)
  const [banForm, setBanForm] = useState({ ip: '', permanent: false })
  const [settingsForm, setSettingsForm] = useState({ bantime: '', maxretry: '', findtime: '' })
  const [newWhitelistIP, setNewWhitelistIP] = useState('')

  const { data: status, isLoading: statusLoading, refetch: refetchStatus } = useFail2BanStatus()
  const { data: logs, refetch: refetchLogs } = useFail2BanLogs(100)
  const { data: jailSettings, refetch: refetchSettings } = useJailSettings(selectedJail)
  const { data: whitelist, refetch: refetchWhitelist } = useWhitelist(selectedJail)
  const { data: permanentBans, refetch: refetchPermanentBans } = usePermanentBans()
  const { data: pingStatus } = useFail2BanPing()
  const { data: banHistory, refetch: refetchHistory } = useBanHistory()

  // Fail2Ban changes are admin-only (P9a).
  const isAdmin = useCan('admin')
  const unbanMutation = useUnbanIP()
  const banMutation = useManualBan()
  const updateSettingsMutation = useUpdateJailSettings()
  const updateWhitelistMutation = useUpdateWhitelist()
  const removePermanentBanMutation = useRemovePermanentBan()
  const reloadMutation = useReloadFail2Ban()

  const handleRefresh = () => {
    refetchStatus()
    refetchLogs()
    refetchSettings()
    refetchWhitelist()
    refetchPermanentBans()
    refetchHistory()
  }

  // Set default jail when status loads
  React.useEffect(() => {
    if (status?.jails?.length > 0 && !status.jails.find((j: JailData) => j.name === selectedJail)) {
      setSelectedJail(status.jails[0].name)
    }
  }, [status, selectedJail])

  // Load settings when jail changes
  React.useEffect(() => {
    if (jailSettings) {
      setSettingsForm({
        bantime: jailSettings.bantime || '',
        maxretry: jailSettings.maxretry || '',
        findtime: jailSettings.findtime || '',
      })
    }
  }, [jailSettings])

  const currentJail = status?.jails?.find((j: JailData) => j.name === selectedJail)

  // Duration in the panel's language, e.g. "10 min" or "Permanent".
  const duration = (s: string) => {
    const { unit, count } = formatBantime(s)
    return t(`duration.${unit}`, { count })
  }

  if (statusLoading)
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    )

  if (!status?.installed)
    return (
      <div className="space-y-6">
        <PageHeader title="Fail2Ban" description={t('notInstalled.description')} />
        <Card className="text-center py-12">
          <ShieldOff className="w-16 h-16 mx-auto text-gray-400 mb-4" />
          <h2 className="text-xl font-semibold mb-2">{t('notInstalled.title')}</h2>
          <p className="text-gray-500">{t('notInstalled.hint')}</p>
        </Card>
      </div>
    )

  const tabs = [
    { id: 'overview', label: t('tabs.overview'), icon: Shield, count: undefined },
    { id: 'banned', label: t('tabs.banned'), icon: Ban, count: currentJail?.banned_count },
    { id: 'whitelist', label: t('tabs.whitelist'), icon: CheckCircle, count: undefined },
    { id: 'settings', label: t('tabs.settings'), icon: Settings, count: undefined },
    { id: 'permanent', label: t('tabs.permanent'), icon: Ban, count: permanentBans?.count },
    { id: 'history', label: t('tabs.history'), icon: History, count: undefined },
    { id: 'logs', label: t('tabs.logs'), icon: List, count: undefined },
  ] as const

  return (
    <div className="space-y-6">
      <PageHeader title={t('title')} description={t('description')} />

      {/* Status Bar */}
      <Card className="p-4">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-4">
            <Badge variant={status.running ? 'success' : 'danger'} size="md">
              {status.running ? (
                <>
                  <CheckCircle className="w-4 h-4 mr-1" /> {t('common:status.running')}
                </>
              ) : (
                <>
                  <XCircle className="w-4 h-4 mr-1" /> {t('common:status.stopped')}
                </>
              )}
            </Badge>
            {pingStatus?.alive && (
              <Badge variant="default" size="md">
                <Activity className="w-4 h-4 mr-1" /> {t('responsive')}
              </Badge>
            )}

            {/* Jail Selector */}
            <div className="flex items-center gap-2">
              <span className="text-sm text-gray-500">{t('jailLabel')}</span>
              <select
                value={selectedJail}
                onChange={(e) => setSelectedJail(e.target.value)}
                className="px-3 py-1.5 text-sm border rounded-lg dark:bg-gray-700 dark:border-gray-600 font-medium"
              >
                {status.jails?.map((jail: JailData) => (
                  <option key={jail.name} value={jail.name}>
                    {jail.name}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {isAdmin && (
              <Button variant="danger" size="sm" onClick={() => setShowBanModal(true)}>
                <Ban className="w-4 h-4 mr-1" /> {t('actions.banIp')}
              </Button>
            )}
            {isAdmin && (
              <Button
                variant="secondary"
                size="sm"
                onClick={() => reloadMutation.mutate(undefined)}
                loading={reloadMutation.isPending}
              >
                <RotateCcw className="w-4 h-4 mr-1" /> {t('actions.reload')}
              </Button>
            )}
            <Button variant="secondary" size="sm" onClick={handleRefresh}>
              <RefreshCw className="w-4 h-4 mr-1" /> {t('common:actions.refresh')}
            </Button>
          </div>
        </div>
      </Card>

      {/* Tab Navigation */}
      <div className="flex gap-1 p-1 bg-gray-100 dark:bg-gray-800 rounded-lg overflow-x-auto">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-md whitespace-nowrap transition-colors ${
              activeTab === tab.id
                ? 'bg-white dark:bg-gray-700 text-blue-600 dark:text-blue-400 shadow-sm'
                : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            <tab.icon className="w-4 h-4" />
            {tab.label}
            {tab.count !== undefined && tab.count > 0 && (
              <span className="px-1.5 py-0.5 text-xs bg-red-100 dark:bg-red-900/50 text-red-600 dark:text-red-400 rounded-full">
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-lg bg-red-100 dark:bg-red-900/30 flex items-center justify-center">
                <Ban className="w-6 h-6 text-red-600 dark:text-red-400" />
              </div>
              <div>
                <p className="text-sm text-gray-500">{t('stats.currentlyBanned')}</p>
                <p className="text-2xl font-bold text-red-600">{currentJail?.banned_count || 0}</p>
              </div>
            </div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-lg bg-orange-100 dark:bg-orange-900/30 flex items-center justify-center">
                <AlertTriangle className="w-6 h-6 text-orange-600 dark:text-orange-400" />
              </div>
              <div>
                <p className="text-sm text-gray-500">{t('stats.failedAttempts')}</p>
                <p className="text-2xl font-bold text-orange-600">
                  {currentJail?.failed_count || 0}
                </p>
              </div>
            </div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-lg bg-blue-100 dark:bg-blue-900/30 flex items-center justify-center">
                <Shield className="w-6 h-6 text-blue-600 dark:text-blue-400" />
              </div>
              <div>
                <p className="text-sm text-gray-500">{t('stats.totalBanned')}</p>
                <p className="text-2xl font-bold text-blue-600">{currentJail?.total_banned || 0}</p>
              </div>
            </div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-lg bg-purple-100 dark:bg-purple-900/30 flex items-center justify-center">
                <Ban className="w-6 h-6 text-purple-600 dark:text-purple-400" />
              </div>
              <div>
                <p className="text-sm text-gray-500">{t('stats.permanentBans')}</p>
                <p className="text-2xl font-bold text-purple-600">{permanentBans?.count || 0}</p>
              </div>
            </div>
          </Card>

          {/* Quick Info */}
          <Card className="p-4 md:col-span-2">
            <h3 className="font-semibold mb-3">
              {t('overview.currentSettings', { jail: selectedJail })}
            </h3>
            <div className="grid grid-cols-3 gap-4">
              <div className="text-center p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                <p className="text-xs text-gray-500 mb-1">{t('settings.bantime')}</p>
                <p className="font-bold">{duration(jailSettings?.bantime || '0')}</p>
              </div>
              <div className="text-center p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                <p className="text-xs text-gray-500 mb-1">{t('settings.maxretry')}</p>
                <p className="font-bold">{jailSettings?.maxretry || '0'}</p>
              </div>
              <div className="text-center p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                <p className="text-xs text-gray-500 mb-1">{t('settings.findtime')}</p>
                <p className="font-bold">{duration(jailSettings?.findtime || '0')}</p>
              </div>
            </div>
          </Card>

          <Card className="p-4 md:col-span-2">
            <h3 className="font-semibold mb-3">{t('overview.allJails')}</h3>
            <div className="space-y-2">
              {status.jails?.map((jail: JailData) => (
                <div
                  key={jail.name}
                  className="flex items-center justify-between p-2 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
                >
                  <div className="flex items-center gap-2">
                    <Shield className="w-4 h-4 text-blue-500" />
                    <span className="font-medium">{jail.name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {(jail.banned_count || 0) > 0 && (
                      <Badge variant="danger">
                        {t('overview.bannedCount', { count: jail.banned_count })}
                      </Badge>
                    )}
                    <Badge variant="default">
                      {t('overview.failedCount', { count: jail.failed_count || 0 })}
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}

      {/* Banned IPs Tab */}
      {activeTab === 'banned' && (
        <Card>
          <div className="p-4 border-b border-gray-200 dark:border-gray-700">
            <h3 className="font-semibold">{t('banned.title', { jail: selectedJail })}</h3>
            <p className="text-sm text-gray-500">{t('banned.subtitle')}</p>
          </div>
          <div className="p-4">
            {currentJail?.banned_ips && currentJail.banned_ips.length > 0 ? (
              <div className="space-y-2">
                {currentJail.banned_ips.map((ip: string) => (
                  <div
                    key={ip}
                    className="flex items-center justify-between p-3 bg-red-50 dark:bg-red-900/20 rounded-lg"
                  >
                    <div className="flex items-center gap-3">
                      <Ban className="w-5 h-5 text-red-500" />
                      <span className="font-mono font-medium">{ip}</span>
                    </div>
                    {isAdmin && (
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => {
                          if (confirm(t('banned.confirmUnban', { ip })))
                            unbanMutation.mutate({ jail: selectedJail, ip })
                        }}
                        loading={unbanMutation.isPending}
                      >
                        <Unlock className="w-4 h-4 mr-1" /> {t('actions.unban')}
                      </Button>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-12 text-gray-500">
                <CheckCircle className="w-12 h-12 mx-auto mb-3 text-green-500" />
                <p className="font-medium">{t('banned.emptyTitle')}</p>
                <p className="text-sm">{t('banned.emptyHint', { jail: selectedJail })}</p>
              </div>
            )}
          </div>
        </Card>
      )}

      {/* Whitelist Tab */}
      {activeTab === 'whitelist' && (
        <Card>
          <div className="p-4 border-b border-gray-200 dark:border-gray-700">
            <h3 className="font-semibold">{t('whitelist.title', { jail: selectedJail })}</h3>
            <p className="text-sm text-gray-500">{t('whitelist.subtitle')}</p>
          </div>
          <div className="p-4 space-y-4">
            <div className="flex gap-2">
              <input
                type="text"
                placeholder={t('whitelist.placeholder')}
                value={newWhitelistIP}
                onChange={(e) => setNewWhitelistIP(e.target.value)}
                className="flex-1 px-4 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
              />
              {isAdmin && (
                <Button
                  variant="primary"
                  onClick={() => {
                    if (newWhitelistIP) {
                      updateWhitelistMutation.mutate({
                        jail: selectedJail,
                        action: 'add',
                        ip: newWhitelistIP,
                      })
                      setNewWhitelistIP('')
                    }
                  }}
                  loading={updateWhitelistMutation.isPending}
                >
                  <Plus className="w-4 h-4 mr-1" /> {t('common:actions.add')}
                </Button>
              )}
            </div>

            {whitelist?.whitelist && whitelist.whitelist.length > 0 ? (
              <div className="space-y-2">
                {whitelist.whitelist.map((ip: string) => (
                  <div
                    key={ip}
                    className="flex items-center justify-between p-3 bg-green-50 dark:bg-green-900/20 rounded-lg"
                  >
                    <div className="flex items-center gap-3">
                      <CheckCircle className="w-5 h-5 text-green-500" />
                      <span className="font-mono font-medium">{ip}</span>
                    </div>
                    {isAdmin && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          if (confirm(t('whitelist.confirmRemove', { ip })))
                            updateWhitelistMutation.mutate({
                              jail: selectedJail,
                              action: 'remove',
                              ip,
                            })
                        }}
                      >
                        <Trash2 className="w-4 h-4 text-red-500" />
                      </Button>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-gray-500">
                <p>{t('whitelist.empty')}</p>
              </div>
            )}
          </div>
        </Card>
      )}

      {/* Settings Tab */}
      {activeTab === 'settings' && (
        <Card>
          <div className="p-4 border-b border-gray-200 dark:border-gray-700">
            <h3 className="font-semibold">{t('settings.title', { jail: selectedJail })}</h3>
            <p className="text-sm text-gray-500">{t('settings.subtitle')}</p>
          </div>
          <div className="p-4 space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div>
                <label className="block text-sm font-medium mb-2">{t('settings.bantime')}</label>
                <input
                  type="text"
                  placeholder="3600"
                  value={settingsForm.bantime}
                  onChange={(e) => setSettingsForm({ ...settingsForm, bantime: e.target.value })}
                  className="w-full px-4 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                />
                <p className="text-xs text-gray-500 mt-1">{t('settings.bantimeHint')}</p>
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">{t('settings.maxretry')}</label>
                <input
                  type="text"
                  placeholder="3"
                  value={settingsForm.maxretry}
                  onChange={(e) => setSettingsForm({ ...settingsForm, maxretry: e.target.value })}
                  className="w-full px-4 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                />
                <p className="text-xs text-gray-500 mt-1">{t('settings.maxretryHint')}</p>
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">{t('settings.findtime')}</label>
                <input
                  type="text"
                  placeholder="600"
                  value={settingsForm.findtime}
                  onChange={(e) => setSettingsForm({ ...settingsForm, findtime: e.target.value })}
                  className="w-full px-4 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                />
                <p className="text-xs text-gray-500 mt-1">{t('settings.findtimeHint')}</p>
              </div>
            </div>
            <div className="flex justify-end">
              {isAdmin && (
                <Button
                  variant="primary"
                  onClick={() =>
                    updateSettingsMutation.mutate({ jail: selectedJail, ...settingsForm })
                  }
                  loading={updateSettingsMutation.isPending}
                >
                  <Save className="w-4 h-4 mr-1" /> {t('settings.save')}
                </Button>
              )}
            </div>
          </div>
        </Card>
      )}

      {/* Permanent Bans Tab */}
      {activeTab === 'permanent' && (
        <Card>
          <div className="p-4 border-b border-gray-200 dark:border-gray-700">
            <h3 className="font-semibold">{t('permanent.title')}</h3>
            <p className="text-sm text-gray-500">{t('permanent.subtitle')}</p>
          </div>
          <div className="p-4">
            {permanentBans?.permanent_bans && permanentBans.permanent_bans.length > 0 ? (
              <div className="space-y-2">
                {permanentBans.permanent_bans.map(
                  (ban: { ip: string; line_number: string; protocol: string }) => (
                    <div
                      key={ban.ip}
                      className="flex items-center justify-between p-3 bg-red-50 dark:bg-red-900/20 rounded-lg border border-red-200 dark:border-red-800"
                    >
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-full bg-red-100 dark:bg-red-900/50 flex items-center justify-center">
                          <Ban className="w-5 h-5 text-red-600" />
                        </div>
                        <div>
                          <span className="font-mono font-medium">{ban.ip}</span>
                          <p className="text-xs text-gray-500">
                            {t('permanent.ruleInfo', {
                              line: ban.line_number,
                              protocol: ban.protocol,
                            })}
                          </p>
                        </div>
                      </div>
                      {isAdmin && (
                        <Button
                          variant="danger"
                          size="sm"
                          onClick={() => {
                            if (confirm(t('permanent.confirmRemove', { ip: ban.ip })))
                              removePermanentBanMutation.mutate(ban.ip)
                          }}
                          loading={removePermanentBanMutation.isPending}
                        >
                          <Unlock className="w-4 h-4 mr-1" /> {t('actions.unblock')}
                        </Button>
                      )}
                    </div>
                  )
                )}
              </div>
            ) : (
              <div className="text-center py-12 text-gray-500">
                <CheckCircle className="w-12 h-12 mx-auto mb-3 text-green-500" />
                <p className="font-medium">{t('permanent.emptyTitle')}</p>
                <p className="text-sm">{t('permanent.emptyHint')}</p>
              </div>
            )}
          </div>
        </Card>
      )}

      {/* History Tab */}
      {activeTab === 'history' && (
        <Card>
          <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <div>
              <h3 className="font-semibold">{t('history.title')}</h3>
              <p className="text-sm text-gray-500">{t('history.subtitle')}</p>
            </div>
            <Button variant="ghost" size="sm" onClick={() => refetchHistory()}>
              <RefreshCw className="w-4 h-4" />
            </Button>
          </div>
          <div className="p-4">
            {banHistory?.history && banHistory.history.length > 0 ? (
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {banHistory.history.map((entry: HistoryEntry, i: number) => (
                  <div
                    key={i}
                    className={`flex items-center justify-between p-3 rounded-lg ${entry.action === 'ban' ? 'bg-red-50 dark:bg-red-900/20' : 'bg-green-50 dark:bg-green-900/20'}`}
                  >
                    <div className="flex items-center gap-3">
                      <Badge variant={entry.action === 'ban' ? 'danger' : 'success'}>
                        {entry.action?.toUpperCase()}
                      </Badge>
                      <span className="font-mono">{entry.ip}</span>
                      {entry.jail && <Badge variant="default">{entry.jail}</Badge>}
                    </div>
                    {entry.timestamp && (
                      <span className="text-xs text-gray-500">
                        <Clock className="w-3 h-3 inline mr-1" />
                        {entry.timestamp}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-12 text-gray-500">
                <History className="w-12 h-12 mx-auto mb-3" />
                <p>{t('history.empty')}</p>
              </div>
            )}
          </div>
        </Card>
      )}

      {/* Logs Tab */}
      {activeTab === 'logs' && (
        <Card>
          <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <div>
              <h3 className="font-semibold">{t('logs.title')}</h3>
              <p className="text-sm text-gray-500">{t('logs.subtitle')}</p>
            </div>
            <Button variant="ghost" size="sm" onClick={() => refetchLogs()}>
              <RefreshCw className="w-4 h-4" />
            </Button>
          </div>
          <div className="p-4">
            {logs?.logs && logs.logs.length > 0 ? (
              <div className="space-y-1 max-h-96 overflow-y-auto font-mono text-xs">
                {logs.logs.map((log: LogEntry, i: number) => (
                  <div
                    key={i}
                    className={`p-2 rounded ${log.action === 'ban' ? 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300' : log.action === 'unban' ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300' : 'bg-gray-50 dark:bg-gray-700/50 text-gray-600 dark:text-gray-400'}`}
                  >
                    {log.timestamp && <span className="text-gray-500 mr-2">{log.timestamp}</span>}
                    {log.action && (
                      <Badge variant={log.action === 'ban' ? 'danger' : 'success'} size="sm">
                        {log.action.toUpperCase()}
                      </Badge>
                    )}
                    <span className="ml-2 break-all">{log.raw}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-12 text-gray-500">
                <List className="w-12 h-12 mx-auto mb-3" />
                <p>{t('logs.empty')}</p>
              </div>
            )}
          </div>
        </Card>
      )}

      {/* Ban Modal */}
      {showBanModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-full max-w-md shadow-xl">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Ban className="w-5 h-5 text-red-500" /> {t('banModal.title')}
            </h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-2">
                  {t('common:fields.ipAddress')}
                </label>
                <input
                  type="text"
                  placeholder={t('banModal.ipPlaceholder')}
                  value={banForm.ip}
                  onChange={(e) => setBanForm({ ...banForm, ip: e.target.value })}
                  className="w-full px-4 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">{t('banModal.jail')}</label>
                <select
                  value={selectedJail}
                  onChange={(e) => setSelectedJail(e.target.value)}
                  className="w-full px-4 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                >
                  {status.jails?.map((jail: JailData) => (
                    <option key={jail.name} value={jail.name}>
                      {jail.name}
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="permanent"
                  checked={banForm.permanent}
                  onChange={(e) => setBanForm({ ...banForm, permanent: e.target.checked })}
                  className="rounded"
                />
                <label htmlFor="permanent" className="text-sm">
                  {t('banModal.permanent')}
                </label>
              </div>
              {banForm.permanent && (
                <div className="p-3 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg text-sm text-yellow-700 dark:text-yellow-300 flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                  <span>{t('banModal.permanentWarning')}</span>
                </div>
              )}
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <Button variant="secondary" onClick={() => setShowBanModal(false)}>
                {t('common:actions.cancel')}
              </Button>
              <Button
                variant="danger"
                onClick={() => {
                  if (banForm.ip) {
                    banMutation.mutate({
                      jail: selectedJail,
                      ip: banForm.ip,
                      permanent: banForm.permanent,
                    })
                    setBanForm({ ip: '', permanent: false })
                    setShowBanModal(false)
                  }
                }}
                loading={banMutation.isPending}
              >
                <Ban className="w-4 h-4 mr-1" /> {t('actions.banIp')}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default Fail2BanPage
