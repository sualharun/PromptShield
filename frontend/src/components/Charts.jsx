import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  Radar,
  RadarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

const SEVERITY_COLORS = {
  critical: '#da1e28',
  high: '#ff832b',
  medium: '#f1c21b',
  low: '#0f62fe',
}

const SEV_WEIGHTS = { critical: 40, high: 20, medium: 8, low: 3 }

const TOOLTIP_STYLE = {
  border: '1px solid #e0e0e0',
  background: '#ffffff',
  fontSize: 12,
  fontFamily: 'IBM Plex Sans, sans-serif',
  borderRadius: 0,
  padding: '8px 10px',
}

export function SeverityBar({ findings = [] }) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 }
  findings.forEach((f) => {
    const s = (f.severity || 'low').toLowerCase()
    if (counts[s] !== undefined) counts[s] += 1
  })
  const data = ['critical', 'high', 'medium', 'low'].map((k) => ({
    name: k[0].toUpperCase() + k.slice(1),
    key: k,
    value: counts[k],
  }))
  return (
    <div className="h-56 w-full">
      <ResponsiveContainer>
        <BarChart data={data} margin={{ top: 12, right: 8, left: -16, bottom: 0 }}>
          <CartesianGrid stroke="#e0e0e0" vertical={false} />
          <XAxis
            dataKey="name"
            stroke="#6f6f6f"
            tickLine={false}
            axisLine={{ stroke: '#c6c6c6' }}
            tick={{ fontSize: 11, fontFamily: 'IBM Plex Sans' }}
          />
          <YAxis
            allowDecimals={false}
            stroke="#6f6f6f"
            tickLine={false}
            axisLine={false}
            tick={{ fontSize: 11, fontFamily: 'IBM Plex Sans' }}
          />
          <Tooltip
            contentStyle={TOOLTIP_STYLE}
            cursor={{ fill: 'rgba(15,98,254,0.06)' }}
          />
          <Bar dataKey="value" animationDuration={700}>
            {data.map((entry) => (
              <Cell key={entry.key} fill={SEVERITY_COLORS[entry.key]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

export function CategoryRadar({ findings = [] }) {
  const buckets = {}
  findings.forEach((f) => {
    const t = f.type || 'OTHER'
    const w = SEV_WEIGHTS[(f.severity || 'low').toLowerCase()] || 1
    buckets[t] = (buckets[t] || 0) + w
  })
  const keys = Object.keys(buckets)
  const data = (keys.length > 0
    ? keys
    : ['DIRECT_INJECTION', 'SECRET_IN_PROMPT', 'ROLE_CONFUSION', 'DATA_LEAKAGE']
  ).map((k) => ({
    category: k.replaceAll('_', ' ').toLowerCase(),
    score: buckets[k] || 0,
  }))
  return (
    <div className="h-56 w-full">
      <ResponsiveContainer>
        <RadarChart data={data} outerRadius="72%">
          <PolarGrid stroke="#e0e0e0" />
          <PolarAngleAxis
            dataKey="category"
            tick={{ fill: '#525252', fontSize: 10, fontFamily: 'IBM Plex Sans' }}
          />
          <PolarRadiusAxis
            tick={{ fill: '#8d8d8d', fontSize: 9, fontFamily: 'IBM Plex Sans' }}
          />
          <Radar
            dataKey="score"
            stroke="#0f62fe"
            fill="#0f62fe"
            fillOpacity={0.18}
            animationDuration={800}
          />
          <Tooltip contentStyle={TOOLTIP_STYLE} />
        </RadarChart>
      </ResponsiveContainer>
    </div>
  )
}

export function TrendLine({ scans = [] }) {
  const data = [...scans]
    .reverse()
    .map((s, i) => ({ name: `#${s.id ?? i + 1}`, score: s.risk_score }))
  return (
    <div className="h-56 w-full">
      <ResponsiveContainer>
        <LineChart data={data} margin={{ top: 12, right: 8, left: -16, bottom: 0 }}>
          <CartesianGrid stroke="#e0e0e0" vertical={false} />
          <XAxis
            dataKey="name"
            stroke="#6f6f6f"
            tickLine={false}
            axisLine={{ stroke: '#c6c6c6' }}
            tick={{ fontSize: 11, fontFamily: 'IBM Plex Sans' }}
          />
          <YAxis
            domain={[0, 100]}
            stroke="#6f6f6f"
            tickLine={false}
            axisLine={false}
            tick={{ fontSize: 11, fontFamily: 'IBM Plex Sans' }}
          />
          <Tooltip contentStyle={TOOLTIP_STYLE} />
          <Line
            type="monotone"
            dataKey="score"
            stroke="#0f62fe"
            strokeWidth={2}
            dot={{ r: 3, fill: '#0f62fe', stroke: '#0f62fe' }}
            animationDuration={800}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}
