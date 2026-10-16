import { Lock, type LucideIcon } from 'lucide-react'
import { useRef } from 'react'

export interface TabItem<T extends string> {
  id: T
  label: string
  icon?: LucideIcon
  count?: number
  // locked shows a lock badge with this text (title and screen readers).
  locked?: string
}

interface TabBarProps<T extends string> {
  tabs: TabItem<T>[]
  active: T
  onChange: (id: T) => void
  label: string
  idPrefix: string
  size?: 'md' | 'sm'
}

// TabBar: an accessible tab strip (role tablist/tab, aria-selected, arrow
// keys) that scrolls sideways on narrow screens instead of overflowing.
export function TabBar<T extends string>({
  tabs,
  active,
  onChange,
  label,
  idPrefix,
  size = 'md',
}: TabBarProps<T>) {
  const refs = useRef<(HTMLButtonElement | null)[]>([])
  const onKeyDown = (e: React.KeyboardEvent, i: number) => {
    let next = -1
    if (e.key === 'ArrowRight') next = (i + 1) % tabs.length
    else if (e.key === 'ArrowLeft') next = (i - 1 + tabs.length) % tabs.length
    else if (e.key === 'Home') next = 0
    else if (e.key === 'End') next = tabs.length - 1
    if (next < 0) return
    e.preventDefault()
    onChange(tabs[next].id)
    refs.current[next]?.focus()
  }
  const pad = size === 'sm' ? 'px-3 py-1.5 text-xs' : 'px-4 py-2 text-sm'
  return (
    <div
      role="tablist"
      aria-label={label}
      // relative: absolutely placed children (the lock badge's sr-only text) stay
      // inside the scroll area instead of widening the page on phones
      className="relative flex max-w-full gap-1 overflow-x-auto rounded-lg bg-gray-100 p-1 dark:bg-gray-800"
    >
      {tabs.map((tab, i) => {
        const selected = tab.id === active
        const Icon = tab.icon
        return (
          <button
            key={tab.id}
            ref={(el) => {
              refs.current[i] = el
            }}
            type="button"
            role="tab"
            id={`${idPrefix}-tab-${tab.id}`}
            aria-selected={selected}
            aria-controls={`${idPrefix}-panel-${tab.id}`}
            tabIndex={selected ? 0 : -1}
            onClick={() => onChange(tab.id)}
            onKeyDown={(e) => onKeyDown(e, i)}
            className={`flex shrink-0 items-center gap-2 whitespace-nowrap rounded-md font-medium transition-colors ${pad} ${
              selected
                ? 'bg-white text-blue-600 shadow-sm dark:bg-gray-700 dark:text-blue-400'
                : 'text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white'
            }`}
          >
            {Icon && <Icon className="h-4 w-4" />}
            {tab.label}
            {tab.count !== undefined && tab.count > 0 && (
              <span className="rounded-full bg-gray-200 px-1.5 py-0.5 text-xs text-gray-700 dark:bg-gray-600 dark:text-gray-200">
                {tab.count}
              </span>
            )}
            {tab.locked && (
              <span title={tab.locked} className="inline-flex items-center text-amber-600">
                <Lock className="h-3.5 w-3.5" aria-hidden="true" />
                <span className="sr-only">{tab.locked}</span>
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}

// TabPanel is the region a TabBar tab controls.
export const TabPanel = ({
  idPrefix,
  id,
  children,
}: {
  idPrefix: string
  id: string
  children: React.ReactNode
}) => (
  <div
    role="tabpanel"
    id={`${idPrefix}-panel-${id}`}
    aria-labelledby={`${idPrefix}-tab-${id}`}
    className="space-y-4"
  >
    {children}
  </div>
)
