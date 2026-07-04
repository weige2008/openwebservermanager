import { create } from 'zustand'
import { persist } from 'zustand/middleware'

import type { Theme, ThemeAppearance } from '@/types'

export const defaultAppearance: ThemeAppearance = {
  preset: 'default',
  font: 'default',
  radius: 'default',
  scale: 'default',
  contentLayout: 'full',
  sidebarStyle: 'default',
}

interface PreferencesState {
  theme: Theme
  appearance: ThemeAppearance
  setTheme: (theme: Theme) => void
  setAppearance: (appearance: Partial<ThemeAppearance>) => void
  resetAppearance: () => void
}

function migrateAppearance(value: unknown): ThemeAppearance {
  if (!value || typeof value !== 'object') return defaultAppearance
  const parsed = value as Partial<ThemeAppearance>
  return {
    preset: parsed.preset || defaultAppearance.preset,
    font: parsed.font || defaultAppearance.font,
    radius: parsed.radius || defaultAppearance.radius,
    scale: parsed.scale || defaultAppearance.scale,
    contentLayout: parsed.contentLayout || defaultAppearance.contentLayout,
    sidebarStyle: parsed.sidebarStyle || defaultAppearance.sidebarStyle,
  }
}

function readLegacyTheme(): Theme {
  const stored = localStorage.getItem('openwebservermanager:theme') || localStorage.getItem('servermanager:theme')
  return stored === 'light' || stored === 'dark' || stored === 'system' ? stored : 'system'
}

function readLegacyAppearance(): ThemeAppearance {
  const stored = localStorage.getItem('openwebservermanager:appearance') || localStorage.getItem('servermanager:appearance')
  if (!stored) return defaultAppearance
  try {
    return migrateAppearance(JSON.parse(stored))
  } catch {
    return defaultAppearance
  }
}

export const usePreferencesStore = create<PreferencesState>()(
  persist(
    (set) => ({
      theme: readLegacyTheme(),
      appearance: readLegacyAppearance(),
      setTheme: (theme) => set({ theme }),
      setAppearance: (appearance) =>
        set((state) => ({
          appearance: { ...state.appearance, ...appearance },
        })),
      resetAppearance: () => set({ appearance: defaultAppearance }),
    }),
    {
      name: 'openwebservermanager:preferences',
      partialize: (state) => ({
        theme: state.theme,
        appearance: state.appearance,
      }),
      merge: (persisted, current) => {
        const stored = persisted as Partial<PreferencesState> | undefined
        return {
          ...current,
          theme: stored?.theme || current.theme,
          appearance: migrateAppearance(stored?.appearance),
        }
      },
    }
  )
)
