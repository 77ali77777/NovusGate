import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button, Input, Modal } from '@/components/ui'

// ConfirmWordModal: a dangerous action runs only after its word is typed.
export const ConfirmWordModal = ({
  isOpen,
  title,
  description,
  word,
  actionLabel,
  onClose,
  onConfirm,
}: {
  isOpen: boolean
  title: string
  description: string
  word: string
  actionLabel: string
  onClose: () => void
  onConfirm: () => void
}) => {
  const { t } = useTranslation('server')
  const [typed, setTyped] = useState('')
  const close = () => {
    setTyped('')
    onClose()
  }
  return (
    <Modal isOpen={isOpen} onClose={close} title={title} size="sm">
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault()
          if (typed !== word) return
          setTyped('')
          onConfirm()
        }}
      >
        <p className="text-sm text-gray-600 dark:text-gray-400">{description}</p>
        <Input
          label={t('confirmWord', { word })}
          help="helpServer:confirmWord"
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          autoComplete="off"
          autoFocus
        />
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" onClick={close}>
            {t('common:actions.cancel')}
          </Button>
          <Button type="submit" variant="danger" disabled={typed !== word}>
            {actionLabel}
          </Button>
        </div>
      </form>
    </Modal>
  )
}
