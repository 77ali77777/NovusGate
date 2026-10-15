import { useQueries } from '@tanstack/react-query'
import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import ReactFlow, { Background, Controls, type Edge, MarkerType, type Node } from 'reactflow'
import 'reactflow/dist/style.css'
import { api, useFirewallPolicyMatrix, useNetworks } from '@/api/client'
import { PageHeader } from '@/components/Layout'
import { Card } from '@/components/ui'
import { buildTopology, type TopoPeer } from '@/lib/topology'

const nodeStyle = (kind: string, status?: string): React.CSSProperties => {
  if (kind === 'hub')
    return { background: '#2563eb', color: '#fff', fontWeight: 600, border: 'none' }
  if (kind === 'network')
    return { background: '#e0e7ff', border: '1px solid #6366f1', fontWeight: 600 }
  const online = status === 'online'
  return {
    background: online ? '#dcfce7' : '#f3f4f6',
    border: `1px solid ${online ? '#16a34a' : '#9ca3af'}`,
    fontSize: 11,
  }
}

// TopologyPage: the hub, the VPN networks, their peers and which networks
// may reach each other (green: allowed, amber: partly). Click a network or a
// peer to open it.
export const TopologyPage = () => {
  const { t } = useTranslation('topology')
  const navigate = useNavigate()
  const { data: networks = [], isLoading } = useNetworks()
  const { data: matrix } = useFirewallPolicyMatrix(true)
  const peerQueries = useQueries({
    queries: networks.map((n) => ({
      queryKey: ['nodes', n.id],
      queryFn: () => api.getNodes(n.id),
      refetchInterval: 30000,
    })),
  })
  const peersKey = peerQueries.map((q) => q.dataUpdatedAt).join(',')

  // biome-ignore lint/correctness/useExhaustiveDependencies: peersKey changes whenever a peer list does
  const { nodes, edges } = useMemo(() => {
    const peersByNetwork: Record<string, TopoPeer[]> = {}
    networks.forEach((n, i) => {
      peersByNetwork[n.id] = (peerQueries[i]?.data ?? []).map((p) => ({
        id: p.id,
        name: p.name,
        status: p.status,
      }))
    })
    const topo = buildTopology(networks, peersByNetwork, matrix?.cells)
    const flowNodes: Node[] = topo.nodes.map((n) => ({
      id: n.id,
      position: n.position,
      data: { label: n.label },
      style: nodeStyle(n.kind, n.status),
      draggable: true,
    }))
    const flowEdges: Edge[] = topo.edges.map((e) =>
      e.kind === 'policy'
        ? {
            id: e.id,
            source: e.source,
            target: e.target,
            animated: true,
            style: { stroke: e.verdict === 'allow' ? '#16a34a' : '#d97706', strokeWidth: 2 },
            markerEnd: {
              type: MarkerType.ArrowClosed,
              color: e.verdict === 'allow' ? '#16a34a' : '#d97706',
            },
          }
        : { id: e.id, source: e.source, target: e.target, style: { stroke: '#9ca3af' } }
    )
    return { nodes: flowNodes, edges: flowEdges }
  }, [networks, matrix, peersKey])

  return (
    <div className="space-y-6">
      <PageHeader title={t('title')} description={t('description')} />
      <Card padding="none">
        {isLoading ? (
          <p className="p-6 text-sm text-gray-500">{t('common:state.loading')}</p>
        ) : (
          <div style={{ height: '70vh' }}>
            <ReactFlow
              nodes={nodes}
              edges={edges}
              fitView
              onNodeClick={(_, n) => {
                if (n.id.startsWith('net:')) navigate(`/networks/${n.id.slice(4)}`)
                if (n.id.startsWith('peer:')) navigate(`/nodes/${n.id.slice(5)}`)
              }}
            >
              <Background />
              <Controls />
            </ReactFlow>
          </div>
        )}
      </Card>
    </div>
  )
}
