import { Sidebar } from './Sidebar'
interface LayoutProps { title: string; children: React.ReactNode }
export function Layout({ title, children }: LayoutProps) {
  return (
    <div className="h-screen flex overflow-hidden adm-bg">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="h-14 bg-adm-surface border-b border-adm-border flex items-center px-6 flex-shrink-0">
          <h1 className="font-semibold text-white">{title}</h1>
          <div className="ml-auto flex items-center gap-3">
            <span className="text-xs text-adm-muted font-mono">MACE v2 Admin Console</span>
            <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" title="System healthy" />
          </div>
        </header>
        <main className="flex-1 overflow-auto p-6">{children}</main>
      </div>
    </div>
  )
}
