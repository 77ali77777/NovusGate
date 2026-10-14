import { BarChart3 } from 'lucide-react'
import { useState } from 'react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { useNodeTraffic } from '@/api/client'
import { Card } from '@/components/ui'
import { bucketLabel, type TrafficRange, totals } from '@/lib/traffic'

const RANGES: TrafficRange[] = ['24h', '7d', '30d']

const formatBytes = (bytes = 0) => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)))
  return `${Number.parseFloat((bytes / k ** i).toFixed(2))} ${sizes[i]}`
}

// TrafficHistoryCard charts a node's traffic per interval (P8). The server
// samples every 5 minutes and keeps 30 days.
export const TrafficHistoryCard = ({ nodeId }: { nodeId: string }) => {
  const [range, setRange] = useState<TrafficRange>('24h')
  const { data, isLoading, isError } = useNodeTraffic(nodeId, range)
  const points = (data?.points ?? []).map((p) => ({ ...p, label: bucketLabel(p.t, range) }))
  const sum = totals(data?.points ?? [])
  return (
    <Card>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <BarChart3 className="h-5 w-5 text-blue-500" />
          <h3 className="text-lg font-semibold">Traffic History</h3>
        </div>
        <div
          className="flex gap-1 rounded-lg bg-gray-100 p-1 dark:bg-gray-800"
          role="tablist"
          aria-label="Range"
        >
          {RANGES.map((r) => (
            <button
              key={r}
              type="button"
              role="tab"
              aria-selected={range === r}
              onClick={() => setRange(r)}
              className={`rounded-md px-3 py-1 text-sm font-medium ${
                range === r ? 'bg-white shadow-sm dark:bg-gray-700' : 'text-gray-500'
              }`}
            >
              {r}
            </button>
          ))}
        </div>
      </div>
      <div className="mb-3 flex gap-6 text-sm text-gray-600 dark:text-gray-400">
        <span>
          Download (Rx): <strong className="text-blue-600">{formatBytes(sum.rx)}</strong>
        </span>
        <span>
          Upload (Tx): <strong className="text-green-600">{formatBytes(sum.tx)}</strong>
        </span>
      </div>
      {isLoading ? (
        <p className="py-16 text-center text-sm text-gray-500">Loading…</p>
      ) : isError ? (
        <p className="py-16 text-center text-sm text-red-600">
          Traffic history could not be loaded.
        </p>
      ) : sum.rx + sum.tx === 0 ? (
        <p className="py-16 text-center text-sm text-gray-500">
          No traffic recorded in this range yet. Samples are taken every 5 minutes.
        </p>
      ) : (
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={points} margin={{ top: 4, right: 8, left: 8, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="label" minTickGap={24} tick={{ fontSize: 11 }} />
              <YAxis
                tickFormatter={(v: number) => formatBytes(v)}
                width={70}
                tick={{ fontSize: 11 }}
              />
              <Tooltip formatter={(v: number) => formatBytes(v)} />
              <Legend />
              <Bar dataKey="rx" name="Download (Rx)" fill="#3b82f6" stackId="t" />
              <Bar dataKey="tx" name="Upload (Tx)" fill="#22c55e" stackId="t" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </Card>
  )
}
