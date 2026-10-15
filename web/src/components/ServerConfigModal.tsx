import { Box, Check, Copy, Download, Monitor, QrCode as QrIcon, Terminal } from 'lucide-react'
import type React from 'react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import { api } from '@/api/client'
import { apiErrorMessage } from '@/api/errors'
import { HelpTip } from '@/components/HelpTip'
import { Button, Modal } from '@/components/ui'

interface ServerConfigModalProps {
  isOpen: boolean
  onClose: () => void
  nodeId: string
  nodeName: string
}

const InstallTab: React.FC<{
  icon: React.ReactNode
  label: string
  active: boolean
  onClick: () => void
}> = ({ icon, label, active, onClick }) => (
  <button
    type="button"
    onClick={onClick}
    className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
      active
        ? 'border-primary-600 text-primary-600 dark:text-primary-400'
        : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200'
    }`}
  >
    {icon}
    {label}
  </button>
)

export const ServerConfigModal: React.FC<ServerConfigModalProps> = ({
  isOpen,
  onClose,
  nodeId,
  nodeName,
}) => {
  const { t } = useTranslation('nodes')
  const [activeTab, setActiveTab] = useState<'general' | 'windows' | 'mac' | 'linux' | 'docker'>(
    'general'
  )
  const [config, setConfig] = useState<string>('')
  const [qrCodeUrl, setQrCodeUrl] = useState<string>('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)
  const [installScript, setInstallScript] = useState('')
  const [scriptLoading, setScriptLoading] = useState(false)
  const [scriptError, setScriptError] = useState('')
  const [scriptCopied, setScriptCopied] = useState(false)
  // The node the modal shows now; a script fetched for another node is dropped.
  const nodeIdRef = useRef(nodeId)
  nodeIdRef.current = nodeId

  // Each fetch issues a new one-time enrollment token, so the script is
  // generated on request rather than when the modal opens.
  const loadInstallScript = async () => {
    const forNode = nodeId
    setScriptLoading(true)
    setScriptError('')
    try {
      const script = await api.getNodeInstallScript(forNode)
      if (nodeIdRef.current === forNode) setInstallScript(script)
    } catch (err) {
      if (nodeIdRef.current === forNode) {
        setScriptError(apiErrorMessage(err, t('connect.linux.scriptError')))
      }
    } finally {
      setScriptLoading(false)
    }
  }

  const handleScriptDownload = () => {
    const element = document.createElement('a')
    element.href = `data:text/x-shellscript;base64,${btoa(unescape(encodeURIComponent(installScript)))}`
    element.download = `install-${nodeName.replace(/\s+/g, '-').toLowerCase()}.sh`
    document.body.appendChild(element)
    element.click()
    document.body.removeChild(element)
  }

  const loadConfig = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      // Fetch Config Text
      const text = await api.getNodeConfig(nodeId)
      setConfig(text)

      // Fetch QR Code as base64 data URL (avoids blob URL security warning)
      const blob = await api.getNodeQrCode(nodeId)
      const reader = new FileReader()
      reader.onloadend = () => {
        setQrCodeUrl(reader.result as string)
      }
      reader.readAsDataURL(blob)
    } catch (err) {
      setError((err instanceof Error && err.message) || t('connect.loadError'))
    } finally {
      setLoading(false)
    }
  }, [nodeId, t])

  useEffect(() => {
    if (isOpen && nodeId) {
      loadConfig()
      setActiveTab('general')
      setInstallScript('') // a script belongs to one node and expires
      setScriptError('')
    }
  }, [isOpen, nodeId, loadConfig])

  const handleDownload = () => {
    const element = document.createElement('a')
    // Use data URL instead of blob URL to avoid security warning
    const base64 = btoa(unescape(encodeURIComponent(config)))
    element.href = `data:text/plain;base64,${base64}`
    element.download = `${nodeName.replace(/\s+/g, '-').toLowerCase()}.conf`
    document.body.appendChild(element)
    element.click()
    document.body.removeChild(element)
  }

  const copyToClipboard = async (text: string, markCopied: (v: boolean) => void = setCopied) => {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text)
        markCopied(true)
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
          markCopied(true)
        } catch (err) {
          console.error('Fallback: Oops, unable to copy', err)
        }
        document.body.removeChild(textArea)
      }
    } catch (err) {
      console.error('Failed to copy!', err)
    }
    setTimeout(() => markCopied(false), 2000)
  }

  const renderContent = () => {
    switch (activeTab) {
      case 'general':
        return (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <label
                  htmlFor="server-config-text"
                  className="text-sm font-medium text-gray-700 dark:text-gray-300"
                >
                  {t('connect.general.wgConfig')}
                  <HelpTip k="helpNodes:config.text" />
                </label>
                <button
                  type="button"
                  onClick={() => copyToClipboard(config)}
                  className="text-xs flex items-center gap-1 text-primary-600 hover:text-primary-700"
                >
                  {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                  {copied ? t('common:actions.copied') : t('common:actions.copy')}
                </button>
              </div>
              <textarea
                data-help="helpNodes:config.text"
                id="server-config-text"
                className="w-full h-64 p-3 text-xs font-mono bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg resize-none focus:ring-2 focus:ring-primary-500 outline-none"
                readOnly
                value={config}
              />
              <Button
                onClick={handleDownload}
                className="w-full flex items-center justify-center gap-2"
              >
                <Download className="w-4 h-4" /> {t('connect.general.downloadConf')}
              </Button>
            </div>
            <div className="flex flex-col items-center justify-center space-y-3 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
              <h3 className="text-sm font-medium text-gray-900 dark:text-white">
                {t('connect.general.mobileScan')}
              </h3>
              {qrCodeUrl ? (
                <div className="bg-white p-3 rounded-lg shadow-sm">
                  <img src={qrCodeUrl} alt={t('connect.general.qrAlt')} className="w-48 h-48" />
                </div>
              ) : (
                <div className="w-48 h-48 bg-gray-100 dark:bg-gray-700 flex items-center justify-center text-gray-400 rounded-lg">
                  <QrIcon className="w-10 h-10 opacity-50" />
                </div>
              )}
              <p className="text-xs text-center text-gray-500 dark:text-gray-400">
                {t('connect.general.scanHint')}
              </p>
            </div>
          </div>
        )

      case 'windows':
        return (
          <div className="space-y-4">
            <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
              <h4 className="font-semibold text-blue-900 dark:text-blue-100 mb-2">
                {t('connect.installWireGuard')}
              </h4>
              <p className="text-sm text-blue-800 dark:text-blue-200 mb-3">
                {t('connect.windows.intro')}
              </p>
              <a
                href="https://download.wireguard.com/windows-client/wireguard-installer.exe"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md text-sm font-medium transition-colors"
              >
                <Download className="w-4 h-4" /> {t('connect.windows.downloadInstaller')}
              </a>
            </div>
            <div className="space-y-2">
              <h4 className="font-semibold text-gray-900 dark:text-white">
                {t('connect.importConfig')}
              </h4>
              <ol className="list-decimal list-inside text-sm text-gray-600 dark:text-gray-300 space-y-1">
                <li>{t('connect.windows.open')}</li>
                <li>
                  <Trans
                    t={t}
                    i18nKey="connect.windows.import"
                    components={{ strong: <strong /> }}
                  />
                </li>
                <li>
                  <Trans t={t} i18nKey="connect.selectFile" components={{ code: <code /> }} />
                </li>
                <li>
                  <Trans t={t} i18nKey="connect.activate" components={{ strong: <strong /> }} />
                </li>
              </ol>
            </div>
          </div>
        )

      case 'mac':
        return (
          <div className="space-y-4">
            <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
              <h4 className="font-semibold text-gray-900 dark:text-white mb-2">
                {t('connect.installWireGuard')}
              </h4>
              <p className="text-sm text-gray-600 dark:text-gray-300 mb-3">
                {t('connect.mac.intro')}
              </p>
              <a
                href="https://apps.apple.com/us/app/wireguard/id1451685025?mt=12"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-2 px-4 py-2 bg-gray-900 hover:bg-black text-white rounded-md text-sm font-medium transition-colors"
              >
                <Download className="w-4 h-4" /> {t('connect.mac.store')}
              </a>
            </div>
            <div className="space-y-2">
              <h4 className="font-semibold text-gray-900 dark:text-white">
                {t('connect.importConfig')}
              </h4>
              <ol className="list-decimal list-inside text-sm text-gray-600 dark:text-gray-300 space-y-1">
                <li>{t('connect.mac.open')}</li>
                <li>
                  <Trans t={t} i18nKey="connect.mac.import" components={{ strong: <strong /> }} />
                </li>
                <li>
                  <Trans t={t} i18nKey="connect.selectFile" components={{ code: <code /> }} />
                </li>
                <li>
                  <Trans t={t} i18nKey="connect.activate" components={{ strong: <strong /> }} />
                </li>
              </ol>
            </div>
          </div>
        )

      case 'linux': {
        return (
          <div className="space-y-4">
            <div className="p-4 bg-gray-900 border border-gray-800 rounded-lg">
              <div className="flex justify-between items-center mb-2">
                <h4 className="text-sm font-semibold text-gray-400">
                  {t('connect.linux.installScript')}
                </h4>
                {installScript && (
                  <div className="flex items-center gap-3">
                    <button
                      type="button"
                      onClick={() => copyToClipboard(installScript, setScriptCopied)}
                      className="text-xs flex items-center gap-1 text-primary-400 hover:text-primary-300"
                    >
                      {scriptCopied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                      {scriptCopied ? t('common:actions.copied') : t('common:actions.copy')}
                    </button>
                    <button
                      type="button"
                      onClick={handleScriptDownload}
                      className="text-xs flex items-center gap-1 text-primary-400 hover:text-primary-300"
                    >
                      <Download className="w-3 h-3" />
                      {t('common:actions.download')}
                    </button>
                    <button
                      type="button"
                      onClick={loadInstallScript}
                      disabled={scriptLoading}
                      className="text-xs flex items-center gap-1 text-primary-400 hover:text-primary-300 disabled:opacity-50"
                    >
                      {scriptLoading
                        ? t('connect.linux.generating')
                        : t('connect.linux.regenerate')}
                    </button>
                  </div>
                )}
              </div>
              {installScript ? (
                <pre className="text-xs text-green-400 max-h-64 overflow-auto whitespace-pre">
                  {installScript}
                </pre>
              ) : (
                <button
                  type="button"
                  onClick={loadInstallScript}
                  disabled={scriptLoading}
                  className="px-3 py-1.5 text-sm rounded-lg bg-primary-600 text-white hover:bg-primary-700 disabled:opacity-50"
                >
                  {scriptLoading ? t('connect.linux.generating') : t('connect.linux.generate')}
                </button>
              )}
              {scriptError && <p className="text-xs text-red-400 mt-2">{scriptError}</p>}
              <p className="text-xs text-yellow-500 mt-2">{t('connect.linux.scriptHint')}</p>
            </div>

            <div className="space-y-4">
              <div className="p-4 bg-gray-900 text-gray-300 rounded-lg font-mono text-sm overflow-x-auto">
                <p className="text-gray-500 mb-2"># {t('connect.linux.manualInstall')}</p>
                <p className="mb-4 text-green-400">
                  sudo apt update && sudo apt install -y wireguard
                </p>

                <p className="text-gray-500 mb-2"># {t('connect.linux.saveConfig')}</p>
                <p className="mb-4 text-green-400">sudo nano /etc/wireguard/wg0.conf</p>
                <p className="text-gray-500 italic mb-4 text-xs">{t('connect.linux.pasteHint')}</p>

                <p className="text-gray-500 mb-2"># {t('connect.linux.startVpn')}</p>
                <p className="text-green-400">sudo wg-quick up wg0</p>
              </div>
            </div>
          </div>
        )
      }

      case 'docker':
        return (
          <div className="space-y-4">
            <p className="text-sm text-gray-600 dark:text-gray-300">
              <Trans t={t} i18nKey="connect.docker.intro" components={{ code: <code /> }} />
            </p>
            <div className="p-4 bg-gray-900 text-gray-300 rounded-lg font-mono text-sm overflow-x-auto relative group">
              <button
                type="button"
                onClick={() =>
                  copyToClipboard(`docker run -d \\
  --name=wireguard-client \\
  --cap-add=NET_ADMIN \\
  --cap-add=SYS_MODULE \\
  -v /path/to/wg0.conf:/config/wg0.conf \\
  linuxserver/wireguard`)
                }
                className="absolute top-2 right-2 p-1 text-gray-500 hover:text-white opacity-0 group-hover:opacity-100 transition-opacity"
              >
                <Copy className="w-4 h-4" />
              </button>
              <pre>
                {`docker run -d \\
  --name=wireguard-client \\
  --cap-add=NET_ADMIN \\
  --cap-add=SYS_MODULE \\
  -v /path/to/wg0.conf:/config/wg0.conf \\
  linuxserver/wireguard`}
              </pre>
            </div>
          </div>
        )
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={t('connect.title', { name: nodeName })}>
      <div className="space-y-6">
        {loading ? (
          <div className="flex justify-center p-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
          </div>
        ) : error ? (
          <div className="text-red-500 p-4 bg-red-50 rounded-lg">{error}</div>
        ) : (
          <>
            {/* Tabs */}
            <div className="flex overflow-x-auto border-b border-gray-200 dark:border-gray-700">
              <InstallTab
                active={activeTab === 'general'}
                label={t('connect.tabs.general')}
                icon={<QrIcon className="w-4 h-4" />}
                onClick={() => setActiveTab('general')}
              />
              <InstallTab
                active={activeTab === 'windows'}
                label="Windows"
                icon={<Monitor className="w-4 h-4" />}
                onClick={() => setActiveTab('windows')}
              />
              <InstallTab
                active={activeTab === 'mac'}
                label="macOS"
                icon={<Monitor className="w-4 h-4" />}
                onClick={() => setActiveTab('mac')}
              />
              <InstallTab
                active={activeTab === 'linux'}
                label="Linux"
                icon={<Terminal className="w-4 h-4" />}
                onClick={() => setActiveTab('linux')}
              />
              <InstallTab
                active={activeTab === 'docker'}
                label="Docker"
                icon={<Box className="w-4 h-4" />}
                onClick={() => setActiveTab('docker')}
              />
            </div>

            {/* Tab Content */}
            <div className="mt-4">{renderContent()}</div>
          </>
        )}

        <div className="flex justify-end pt-4 border-t border-gray-100 dark:border-gray-800">
          <Button variant="secondary" onClick={onClose}>
            {t('common:actions.close')}
          </Button>
        </div>
      </div>
    </Modal>
  )
}
