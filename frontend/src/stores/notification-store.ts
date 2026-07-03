import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface NotificationState {
  readKeys: string[]
  markRead: (keys: string[]) => void
  isRead: (key: string) => boolean
  resetReadState: () => void
}

export const useNotificationStore = create<NotificationState>()(
  persist(
    (set, get) => ({
      readKeys: [],
      markRead: (keys) =>
        set((state) => ({
          readKeys: [...new Set([...state.readKeys, ...keys])],
        })),
      isRead: (key) => get().readKeys.includes(key),
      resetReadState: () => set({ readKeys: [] }),
    }),
    {
      name: 'servermanager:notifications',
      partialize: (state) => ({
        readKeys: state.readKeys,
      }),
    }
  )
)
