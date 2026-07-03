import '@fontsource-variable/public-sans'
import '@fontsource-variable/lora'
import '@xterm/xterm/css/xterm.css'
import './i18n/config'
import { QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider } from '@tanstack/react-router'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import { AppProvider } from './app/app-provider'
import { queryClient } from './app/query-client'
import { router } from './routes/router'
import './styles.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <AppProvider>
        <RouterProvider router={router} />
      </AppProvider>
    </QueryClientProvider>
  </StrictMode>
)
