import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'
import { LiveFeed } from '@/components/incidents/LiveFeed'

interface LayoutProps {
  title: string
  children: React.ReactNode
}

export function Layout({ title, children }: LayoutProps) {
  return (
    <div className="h-screen flex overflow-hidden bg-mace-bg">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar title={title} />
        <main className="flex-1 overflow-auto p-6">
          {children}
        </main>
      </div>
      <LiveFeed />
    </div>
  )
}
