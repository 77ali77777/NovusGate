import { ChevronDown, KeyRound, LogOut, User } from 'lucide-react'
import { useCallback, useEffect, useId, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { api, useMe } from '@/api/client'
import { roleLabelKey } from '@/lib/userMenu'

// useLogout asks for confirmation, revokes the session on the server and
// leaves locally even if that fails.
export const useLogout = () => {
  const { t } = useTranslation('layout')
  return useCallback(() => {
    if (!confirm(t('logoutConfirm'))) return
    api
      .logout()
      .catch(() => undefined)
      .finally(() => {
        localStorage.removeItem('auth_token')
        localStorage.removeItem('auth_username')
        window.location.href = '/login'
      })
  }, [t])
}

// UserMenu: the signed-in user's name and role in the top bar, with
// "change password" and "log out". Escape or a click outside closes it.
export const UserMenu = () => {
  const { t } = useTranslation('layout')
  const navigate = useNavigate()
  const logout = useLogout()
  const { data: me } = useMe()
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)
  const buttonRef = useRef<HTMLButtonElement>(null)
  const firstItemRef = useRef<HTMLButtonElement>(null)
  const menuId = useId()

  useEffect(() => {
    if (!open) return
    firstItemRef.current?.focus()
    const onPointerDown = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false)
    }
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setOpen(false)
        buttonRef.current?.focus()
      }
    }
    document.addEventListener('mousedown', onPointerDown)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('mousedown', onPointerDown)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [open])

  const username = me?.username ?? ''
  const roleKey = roleLabelKey(me?.role)
  const role = roleKey ? t(roleKey) : (me?.role ?? '')

  return (
    <div ref={rootRef} className="relative">
      <button
        ref={buttonRef}
        type="button"
        aria-haspopup="true"
        aria-expanded={open}
        aria-controls={menuId}
        aria-label={t('userMenu.open')}
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 rounded-lg px-2 py-1 text-left hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 dark:hover:bg-gray-700"
      >
        <span className="flex h-8 w-8 items-center justify-center rounded-full bg-blue-100 text-blue-700 dark:bg-blue-900/50 dark:text-blue-300">
          <User className="h-4 w-4" />
        </span>
        <span className="hidden sm:block leading-tight">
          <span className="block text-sm font-medium text-gray-900 dark:text-white">
            {username}
          </span>
          <span className="block text-xs text-gray-500 dark:text-gray-400">{role}</span>
        </span>
        <ChevronDown className="h-4 w-4 text-gray-500" />
      </button>

      {open && (
        <div
          id={menuId}
          className="absolute right-0 z-50 mt-2 w-56 rounded-lg border border-gray-200 bg-white py-1 shadow-lg dark:border-gray-700 dark:bg-gray-800"
        >
          <div className="border-b px-4 py-2 sm:hidden dark:border-gray-700">
            <p className="text-sm font-medium text-gray-900 dark:text-white">{username}</p>
            <p className="text-xs text-gray-500 dark:text-gray-400">{role}</p>
          </div>
          <button
            ref={firstItemRef}
            type="button"
            onClick={() => {
              setOpen(false)
              navigate('/settings')
            }}
            className="flex w-full items-center gap-2 px-4 py-2 text-left text-sm text-gray-700 hover:bg-gray-100 focus:bg-gray-100 focus:outline-none dark:text-gray-200 dark:hover:bg-gray-700 dark:focus:bg-gray-700"
          >
            <KeyRound className="h-4 w-4" />
            {t('userMenu.changePassword')}
          </button>
          <button
            type="button"
            onClick={() => {
              setOpen(false)
              logout()
            }}
            className="flex w-full items-center gap-2 px-4 py-2 text-left text-sm text-red-600 hover:bg-red-50 focus:bg-red-50 focus:outline-none dark:text-red-400 dark:hover:bg-red-900/20 dark:focus:bg-red-900/20"
          >
            <LogOut className="h-4 w-4" />
            {t('logout')}
          </button>
        </div>
      )}
    </div>
  )
}
