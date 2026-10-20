import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import ReactFlow, { Background, Controls, type Edge, MarkerType, type Node } from 'reactflow'
import 'reactflow/dist/style.css'
import { buildTopology, type TopoCells } from '@/lib/topology'

interface Props {
  network: { id: string; name: string }
  others: { id: string; name: string }[]
  devices: { id: string; name: string; status: string }[]
  cells?: TopoCells
}

const style = (kind: string, status?: string, self?: boolean): React.CSSProperties => {
  if (kind === 'hub')
    return { background: '#2563eb', color: '#fff', fontWeight: 600, border: 'none' }
  if (kind === 'network')
    return self
      ? { background: '#c7d2fe', border: '2px solid #4f46e5', fontWeight: 700 }
      : { background: '#eef2ff', border: '1px dashed #6366f1', fontWeight: 600 }
  const online = status === 'online'
  return {
    background: online ? '#dcfce7' : '#f3f4f6',
    border: `1px solid ${online ? '#16a34a' : '#9ca3af'}`,
    fontSize: 11,
  }
}

// NetworkTopology: this network around the hub with its devices, the other
// networks without theirs, and an arrow where the policy lets traffic go to
// or from this network (green: allowed, amber: partly). Click to open.
export const NetworkTopology = ({ network, others, devices, cells }: Props) => {
  const navigate = useNavigate()
  const { nodes, edges } = useMemo(() => {
    const topo = buildTopology([network, ...others], { [network.id]: devices }, cells)
    const self = `net:${network.id}`
    const flowNodes: Node[] = topo.nodes.map((n) => ({
      id: n.id,
      position: n.position,
      data: { label: n.label },
      style: style(n.kind, n.status, n.id === self),
    }))
    const flowEdges: Edge[] = topo.edges
      .filter((e) => e.kind === 'link' || e.source === self || e.target === self)
      .map((e) =>
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
  }, [network, others, devices, cells])
  return (
    <div style={{ height: '60vh' }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        fitViewOptions={{ padding: 0.15 }}
        nodesDraggable={false}
        onNodeClick={(_, n) => {
          if (n.id.startsWith('peer:')) navigate(`/nodes/${n.id.slice(5)}`)
          else if (n.id.startsWith('net:') && n.id !== `net:${network.id}`)
            navigate(`/networks/${n.id.slice(4)}`)
        }}
        proOptions={{ hideAttribution: true }}
      >
        <Background />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  )
}
