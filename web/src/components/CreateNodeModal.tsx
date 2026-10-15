import { Clock } from 'lucide-react'
import type React from 'react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button, Input, Modal, Select } from '@/components/ui'

interface CreateNodeModalProps {
  isOpen: boolean
  onClose: () => void
  onSubmit: (data: { name: string; expires_at?: string }) => void
  isLoading?: boolean
}

// Expiry choices; their labels are nodes:create.expiry.<value>.
const EXPIRY_VALUES = ['forever', '1h', '1d', '1w', 'custom']

type ExpiryValueProp = (typeof EXPIRY_VALUES)[number]

export const CreateNodeModal = ({ isOpen, onClose, onSubmit, isLoading }: CreateNodeModalProps) => {
  const { t } = useTranslation('nodes')
  const expiryOptions = EXPIRY_VALUES.map((value) => ({
    value,
    label: t(`create.expiry.${value}`),
  }))
  const [name, setName] = useState('')
  const [expiryType, setExpiryType] = useState<ExpiryValueProp>('forever')
  const [customDate, setCustomDate] = useState('')

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    let expiresAt: string | undefined
    const now = new Date()

    if (expiryType === '1h') {
      expiresAt = new Date(now.getTime() + 60 * 60 * 1000).toISOString()
    } else if (expiryType === '1d') {
      expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString()
    } else if (expiryType === '1w') {
      expiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString()
    } else if (expiryType === 'custom' && customDate) {
      expiresAt = new Date(customDate).toISOString()
    }

    onSubmit({ name, expires_at: expiresAt })
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={t('create.title')}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <Input
          help="helpNodes:create.name"
          label={t('fields.peerName')}
          placeholder={t('fields.peerNamePlaceholder')}
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />

        <Select
          id="expiry-type"
          label={t('create.expiryLabel')}
          help="helpNodes:create.expiry"
          options={expiryOptions}
          value={expiryType}
          onChange={(e) => setExpiryType(e.target.value)}
        />

        {expiryType === 'custom' && (
          <Input
            help="helpNodes:create.customDate"
            label={t('create.customDate')}
            type="datetime-local"
            value={customDate}
            min={new Date().toISOString().slice(0, 16)}
            onChange={(e) => setCustomDate(e.target.value)}
            required
          />
        )}

        {expiryType !== 'forever' && expiryType !== 'custom' && (
          <div className="flex items-center gap-2 text-xs text-blue-600 bg-blue-50 dark:bg-blue-900/20 p-2 rounded-lg">
            <Clock className="w-4 h-4" />
            <span>{t('create.autoDisableHint')}</span>
          </div>
        )}

        <div className="flex justify-end gap-3 mt-6">
          <Button variant="secondary" type="button" onClick={onClose}>
            {t('common:actions.cancel')}
          </Button>
          <Button type="submit" loading={isLoading} disabled={!name}>
            {t('create.submit')}
          </Button>
        </div>
      </form>
    </Modal>
  )
}
