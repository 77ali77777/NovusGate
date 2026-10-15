import { HelpCircle } from 'lucide-react'
import { useEffect, useId, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

// HelpTip: the "?" next to a field. k is "namespace:path"; the texts are
// <path>.what (what the field is), <path>.who (who needs it and why) and
// <path>.effect (what setting or changing it does). It opens on hover, on
// focus and on click (touch screens have no hover); Escape or a click
// elsewhere closes it. tests/helpTips.test.mjs checks every input has one.
export const HelpTip = ({ k }: { k: string }) => {
  const { t } = useTranslation()
  const id = useId()
  const [open, setOpen] = useState(false)
  const [pinned, setPinned] = useState(false)
  const box = useRef<HTMLSpanElement>(null)

  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setOpen(false)
        setPinned(false)
      }
    }
    const onDown = (e: PointerEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) {
        setOpen(false)
        setPinned(false)
      }
    }
    window.addEventListener('keydown', onKey)
    window.addEventListener('pointerdown', onDown)
    return () => {
      window.removeEventListener('keydown', onKey)
      window.removeEventListener('pointerdown', onDown)
    }
  }, [open])

  const part = (name: 'what' | 'who' | 'effect') => (
    <span className="block">
      <span className="font-semibold">{t(`common:help.${name}`)}</span> {t(`${k}.${name}`)}
    </span>
  )

  return (
    <span ref={box} className="relative inline-flex align-middle">
      <button
        type="button"
        className="ml-1 rounded-full text-gray-400 hover:text-blue-600 focus:text-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500 dark:text-gray-500 dark:hover:text-blue-400"
        aria-label={t('common:help.button')}
        aria-expanded={open}
        aria-describedby={open ? id : undefined}
        onMouseEnter={() => setOpen(true)}
        onMouseLeave={() => !pinned && setOpen(false)}
        onFocus={() => setOpen(true)}
        onBlur={() => !pinned && setOpen(false)}
        onClick={(e) => {
          e.preventDefault() // inside a <label> the click would focus the input
          // A click pins the tip open; a second click closes it.
          setOpen(!pinned)
          setPinned(!pinned)
        }}
      >
        <HelpCircle className="h-4 w-4" aria-hidden="true" />
      </button>
      {open && (
        <span
          id={id}
          role="tooltip"
          className="absolute left-0 top-full z-50 mt-1 block w-72 max-w-[calc(100vw-2rem)] space-y-1.5 rounded-lg border border-gray-200 bg-white p-3 text-left text-xs font-normal normal-case leading-relaxed text-gray-700 shadow-lg dark:border-gray-600 dark:bg-gray-800 dark:text-gray-200"
        >
          {part('what')}
          {part('who')}
          {part('effect')}
        </span>
      )}
    </span>
  )
}
