import { useQueries } from '@tanstack/react-query'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import ReactFlow, {
  Background,
  Controls,
  type Edge,
  MarkerType,
  type Node,
  type NodeChange,
  useNodesInitialized,
  useNodesState,
  useReactFlow,
} from 'reactflow'
import 'reactflow/dist/style.css'
import { api, useFirewallPolicyMatrix, useNetworks } from '@/api/client'
import { PageHeader } from '@/components/Layout'
import { Card } from '@/components/ui'
import { networkLabel } from '@/lib/networkDisplay'
import { buildTopology, type TopoPeer } from '@/lib/topology'
import { nodeSetKey, shouldFitView } from '@/lib/topologyFit'

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

// FitOnNodeSetChange fits the map to the screen once its nodes are measured,
// and again when nodes appear or go (the peer lists load after the
// networks), unless the user has dragged nodes into their own layout.
const FitOnNodeSetChange = ({ setKey, userMoved }: { setKey: string; userMoved: boolean }) => {
  const { fitView } = useReactFlow()
  const initialized = useNodesInitialized()
  const fittedKey = useRef('')
  useEffect(() => {
    if (!shouldFitView({ initialized, key: setKey, fittedKey: fittedKey.current, userMoved }))
      return
    // React Flow takes the new measurements into its store after this render:
    // a fit now would still see the old node set (it stayed at the hub alone,
    // zoomed to the maximum). Fit in the next frame, and only count the set
    // as fitted when that fit ran.
    const frame = requestAnimationFrame(() => {
      fittedKey.current = setKey
      fitView({ padding: 0.15 })
    })
    return () => cancelAnimationFrame(frame)
  }, [initialized, setKey, userMoved, fitView])
  return null
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
    // Shown names: wg0 is "Admin VPN" (lib/networkDisplay).
    const shown = networks.map((n) => ({ ...n, name: networkLabel(n, t).name }))
    const topo = buildTopology(shown, peersByNetwork, matrix?.cells ?? undefined)
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
  }, [networks, matrix, peersKey, t])

  // Dragged positions are kept across the 30 s refetches.
  const [shownNodes, setShownNodes, onNodesChange] = useNodesState([])
  useEffect(() => {
    setShownNodes((prev) => {
      const moved = new Map(prev.map((n) => [n.id, n.position]))
      return nodes.map((n) => ({ ...n, position: moved.get(n.id) ?? n.position }))
    })
  }, [nodes, setShownNodes])

  // Once a node is dragged, the automatic fit stops so the layout stays.
  const [userMoved, setUserMoved] = useState(false)
  const handleNodesChange = (changes: NodeChange[]) => {
    if (changes.some((c) => c.type === 'position' && c.dragging)) setUserMoved(true)
    onNodesChange(changes)
  }
  const setKey = nodeSetKey(shownNodes.map((n) => n.id))

  return (
    <div className="space-y-6">
      <PageHeader title={t('title')} description={t('description')} />
      <Card padding="none">
        {isLoading ? (
          <p className="p-6 text-sm text-gray-500">{t('common:state.loading')}</p>
        ) : (
          <div style={{ height: '70vh' }}>
            <ReactFlow
              nodes={shownNodes}
              onNodesChange={handleNodesChange}
              edges={edges}
              onNodeClick={(_, n) => {
                if (n.id.startsWith('net:')) navigate(`/networks/${n.id.slice(4)}`)
                if (n.id.startsWith('peer:')) navigate(`/nodes/${n.id.slice(5)}`)
              }}
            >
              <Background />
              <Controls />
              <FitOnNodeSetChange setKey={setKey} userMoved={userMoved} />
            </ReactFlow>
          </div>
        )}
      </Card>
    </div>
  )
}
