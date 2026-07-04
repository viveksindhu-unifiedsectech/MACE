import { useState } from 'react'
import { Layout } from '@/components/layout/Layout'
import { IncidentTable } from '@/components/incidents/IncidentTable'
import { IncidentDetail } from '@/components/incidents/IncidentDetail'
import type { Incident } from '@/types'

export default function Incidents() {
  const [selected, setSelected] = useState<Incident | null>(null)

  return (
    <Layout title="Incidents">
      <IncidentTable onSelect={setSelected} />
      {selected && <IncidentDetail incident={selected} onClose={() => setSelected(null)} />}
    </Layout>
  )
}
