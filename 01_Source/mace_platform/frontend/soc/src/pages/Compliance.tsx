import { Layout } from '@/components/layout/Layout'
import { RegulatoryCalendar } from '@/components/compliance/RegulatoryCalendar'

export default function Compliance() {
  return (
    <Layout title="Regulatory Compliance">
      <div className="mb-4">
        <p className="text-sm text-slate-500">
          UREA auto-generates evidence and notification drafts for 22 frameworks across 5 jurisdictions.
          Deadlines shown are calculated from incident detection time per framework SLA.
        </p>
      </div>
      <RegulatoryCalendar />
    </Layout>
  )
}
