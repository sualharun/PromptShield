import { useEffect, useMemo, useRef, useState } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import { fetchWithTimeout, asNetworkErrorMessage } from '../lib/fetchWithTimeout.js'

/* ── Node-type color palette (IBM Carbon tokens) ─────────────────────── */
function typeColor(type) {
  if (type === 'agent') return '#a56eff'        // purple-50 — central agent
  if (type === 'tool') return '#4589ff'         // blue-50 — tool functions
  if (type === 'data_source') return '#08bdba'  // teal-40 — input sources
  if (type === 'dangerous_sink') return '#de715d' // coral accent — dangerous sinks
  if (type === 'resource') return '#ff832b'     // orange-40 — threatened resources
  return '#6fdc8c'
}

function typeShape(type) {
  if (type === 'agent') return 'diamond'
  if (type === 'tool') return 'hexagon'
  if (type === 'data_source') return 'triangle'
  if (type === 'dangerous_sink') return 'square'
  if (type === 'resource') return 'circle'
  return 'circle'
}

function prettyType(type) {
  const labels = {
    agent: 'AI Agent',
    tool: 'Tool',
    data_source: 'Data Source',
    dangerous_sink: 'Dangerous Sink',
    resource: 'Resource',
  }
  return labels[type] || (type || 'unknown').replace(/_/g, ' ')
}

function scoreTone(score) {
  if (score >= 70) return 'critical'
  if (score >= 50) return 'high'
  if (score >= 30) return 'medium'
  return 'low'
}

function toneClasses(tone) {
  switch (tone) {
    case 'critical':
      return 'border-[#de715d] bg-[#ffe7e1] text-[#b84d39] dark:bg-[#2d1215] dark:text-[#ffd7d9] dark:border-ibm-red-60'
    case 'high':
      return 'border-[#de715d]/60 bg-[#fff1ec] text-[#b84d39] dark:bg-[#2a1b0f] dark:text-[#ffd9b8] dark:border-ibm-orange-40'
    case 'medium':
      return 'border-[#58532a]/40 bg-[#f9f6ec] text-[#58532a] dark:bg-[#2a250f] dark:text-[#ffefb1] dark:border-[#8a6f00]'
    default:
      return 'border-[#58532a]/30 bg-[#f0f5ec] text-[#2a4d1e] dark:bg-[#10231a] dark:text-[#b8f5cb] dark:border-ibm-green-60'
  }
}

function compactLabel(text, max = 28) {
  if (!text) return ''
  const clean = String(text).replace(/\s+/g, ' ').trim()
  if (clean.length <= max) return clean
  return `${clean.slice(0, max - 3)}...`
}

function riskPass(score, filter) {
  if (filter === 'all') return true
  if (filter === 'critical') return score >= 75
  if (filter === 'high') return score >= 55
  if (filter === 'medium') return score >= 35
  if (filter === 'low') return score < 35
  return true
}

/* ── Shape painters ───────────────────────────────────────────────────── */
function drawDiamond(ctx, x, y, r) {
  ctx.beginPath()
  ctx.moveTo(x, y - r)
  ctx.lineTo(x + r, y)
  ctx.lineTo(x, y + r)
  ctx.lineTo(x - r, y)
  ctx.closePath()
}

function drawHexagon(ctx, x, y, r) {
  ctx.beginPath()
  for (let i = 0; i < 6; i++) {
    const angle = (Math.PI / 3) * i - Math.PI / 6
    const px = x + r * Math.cos(angle)
    const py = y + r * Math.sin(angle)
    if (i === 0) ctx.moveTo(px, py)
    else ctx.lineTo(px, py)
  }
  ctx.closePath()
}

function drawTriangle(ctx, x, y, r) {
  ctx.beginPath()
  ctx.moveTo(x, y - r)
  ctx.lineTo(x + r * 0.87, y + r * 0.5)
  ctx.lineTo(x - r * 0.87, y + r * 0.5)
  ctx.closePath()
}

function drawSquare(ctx, x, y, r) {
  const half = r * 0.75
  ctx.beginPath()
  ctx.rect(x - half, y - half, half * 2, half * 2)
}

/* ── Lane layout ──────────────────────────────────────────────────────── */
const TYPE_LANE_ORDER = ['data_source', 'agent', 'tool', 'dangerous_sink', 'resource']

function laneForType(type) {
  const idx = TYPE_LANE_ORDER.indexOf(type || 'tool')
  return idx >= 0 ? idx : 2
}


export default function AgentGraph({ scanId }) {
  const graphShellRef = useRef(null)
  const graphRef = useRef(null)
  const [graphSize, setGraphSize] = useState({ width: 920, height: 420 })
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [riskFilter, setRiskFilter] = useState('all')
  const [typeFilter, setTypeFilter] = useState('all')
  const [showLabels, setShowLabels] = useState(true)
  const [viewMode, setViewMode] = useState('clean')
  const [selectedNodeId, setSelectedNodeId] = useState('')
  const [hoveredNodeId, setHoveredNodeId] = useState('')
  const [selectedChainIdx, setSelectedChainIdx] = useState(0)
  const [playChain, setPlayChain] = useState(false)
  const [playStep, setPlayStep] = useState(0)

  /* ── Data fetch ─────────────────────────────────────────────────────── */
  useEffect(() => {
    let active = true

    const run = async () => {
      setLoading(true)
      setError('')

      try {
        let response = await fetchWithTimeout(`/api/agent-graph/${scanId}`)

        if (response.status === 404) {
          const analyze = await fetchWithTimeout(`/api/agent-graph/analyze/${scanId}`, {
            method: 'POST',
          })
          if (analyze.ok) {
            response = await fetchWithTimeout(`/api/agent-graph/${scanId}`)
          } else {
            // Analyze failed — show empty state instead of error
            if (active) setData({ nodes: [], edges: [], overall_risk_score: 0, threat_level: 'LOW', blast_radius: { affected_count: 0, affected_packages: [], description: '' }, risk_chains: [], insights: {} })
            return
          }
        }

        if (!response.ok) {
          throw new Error(`Agent graph request failed (${response.status})`)
        }

        const payload = await response.json()
        if (active) setData(payload)
      } catch (err) {
        if (active) setError(asNetworkErrorMessage(err, 'Unable to load agent attack surface graph.'))
      } finally {
        if (active) setLoading(false)
      }
    }

    run()
    return () => { active = false }
  }, [scanId])

  /* ── Graph data ─────────────────────────────────────────────────────── */
  const filteredNodeIds = useMemo(() => {
    const ids = new Set()
    for (const n of data?.nodes || []) {
      const score = Number(n.risk_score || 0)
      if (!riskPass(score, riskFilter)) continue
      if (typeFilter !== 'all' && (n.type || 'unknown') !== typeFilter) continue
      ids.add(n.id)
    }
    return ids
  }, [data, riskFilter, typeFilter])

  const nodeTypeOptions = useMemo(() => {
    const types = [...new Set((data?.nodes || []).map((n) => n.type || 'unknown'))]
    return ['all', ...types]
  }, [data])

  const graphData = useMemo(() => {
    if (!data?.nodes?.length) return { nodes: [], links: [] }
    const perTypeCount = new Map()
    const nodes = data.nodes
      .filter((node) => filteredNodeIds.has(node.id))
      .map((node, idx) => {
        const t = node.type || 'tool'
        const lane = laneForType(t)
        const lanePos = perTypeCount.get(t) || 0
        perTypeCount.set(t, lanePos + 1)

        const xLaneGap = 200
        const laneCenter = (TYPE_LANE_ORDER.length - 1) / 2
        const baseX = (lane - laneCenter) * xLaneGap
        const yStride = 80
        const yOffset = (lanePos - 2) * yStride + ((idx % 2 === 0 ? -1 : 1) * 12)

        return {
          ...node,
          x: node.x ?? baseX,
          y: node.y ?? yOffset,
        }
      })
    const nodeIdSet = new Set(nodes.map((n) => n.id))
    const links = (data.edges || []).filter(
      (edge) => nodeIdSet.has(edge.source) && nodeIdSet.has(edge.target)
    )
    return { nodes, links }
  }, [data, filteredNodeIds])

  const selectedNode = useMemo(
    () => (data?.nodes || []).find((n) => n.id === selectedNodeId) || null,
    [data, selectedNodeId]
  )

  const selectedChain = useMemo(() => {
    const chains = data?.risk_chains || []
    if (chains.length === 0) return null
    return chains[Math.min(selectedChainIdx, chains.length - 1)]
  }, [data, selectedChainIdx])

  const selectedChainNodeIds = useMemo(() => {
    if (!selectedChain) return []
    if (Array.isArray(selectedChain.node_ids) && selectedChain.node_ids.length) {
      return selectedChain.node_ids
    }
    if (!Array.isArray(selectedChain.path) || selectedChain.path.length === 0) return []
    const byName = new Map((data?.nodes || []).map((n) => [n.name, n.id]))
    return selectedChain.path.map((name) => byName.get(name)).filter(Boolean)
  }, [selectedChain, data])

  const chainFrameCount = useMemo(
    () => Math.max(3, selectedChainNodeIds.length),
    [selectedChainNodeIds.length]
  )

  const activeChainNodeIds = useMemo(() => {
    if (!selectedChainNodeIds.length || !playChain) return []
    const progress = Math.min(1, (playStep + 1) / chainFrameCount)
    const visibleCount = Math.max(
      2,
      Math.min(selectedChainNodeIds.length, Math.ceil(progress * selectedChainNodeIds.length))
    )
    return selectedChainNodeIds.slice(0, visibleCount)
  }, [playChain, playStep, chainFrameCount, selectedChainNodeIds])

  const chainNodeSet = useMemo(() => new Set(selectedChainNodeIds), [selectedChainNodeIds])

  /* ── Neighbor highlight ─────────────────────────────────────────────── */
  const idOf = (value) => (value && typeof value === 'object') ? value.id : value

  const selectedNeighborIds = useMemo(() => {
    if (!selectedNodeId) return new Set()
    const set = new Set([selectedNodeId])
    for (const e of graphData.links) {
      const src = idOf(e.source)
      const dst = idOf(e.target)
      if (src === selectedNodeId) set.add(dst)
      if (dst === selectedNodeId) set.add(src)
    }
    return set
  }, [graphData.links, selectedNodeId])
  const cleanMode = viewMode === 'clean'

  /* ── Attack path animation ──────────────────────────────────────────── */
  useEffect(() => {
    if (!playChain || !selectedChainNodeIds.length) return
    setPlayStep(0)
    const id = setInterval(() => {
      setPlayStep((curr) => {
        const next = curr + 1
        if (next >= chainFrameCount) {
          setPlayChain(false)
          return chainFrameCount - 1
        }
        return next
      })
    }, 700)
    return () => clearInterval(id)
  }, [playChain, selectedChainNodeIds, chainFrameCount])

  useEffect(() => {
    if (!graphRef.current || !playChain || !activeChainNodeIds.length) return
    const currentId = activeChainNodeIds[activeChainNodeIds.length - 1]
    const node = graphData.nodes.find((n) => n.id === currentId)
    if (!node || node.x === undefined || node.y === undefined) return
    graphRef.current.centerAt(node.x, node.y, 700)
    const currentZoom = graphRef.current.zoom()
    graphRef.current.zoom(Math.max(1.8, currentZoom), 650)
  }, [playChain, activeChainNodeIds, graphData.nodes])

  /* ── Force config ───────────────────────────────────────────────────── */
  useEffect(() => {
    if (!graphRef.current || !graphData.nodes.length) return
    const t = setTimeout(() => {
      if (graphRef.current) graphRef.current.zoomToFit(500, 80)
    }, 450)
    return () => clearTimeout(t)
  }, [graphData])

  useEffect(() => {
    if (!graphRef.current) return
    const charge = cleanMode ? -620 : -500
    const linkDistance = cleanMode ? 180 : 160
    const chargeForce = graphRef.current.d3Force('charge')
    if (chargeForce && typeof chargeForce.strength === 'function') {
      chargeForce.strength(charge)
    }
    const linkForce = graphRef.current.d3Force('link')
    if (linkForce && typeof linkForce.distance === 'function') {
      linkForce.distance(() => linkDistance)
      if (typeof linkForce.strength === 'function') {
        linkForce.strength(cleanMode ? 0.45 : 0.35)
      }
    }
    if (typeof graphRef.current.d3ReheatSimulation === 'function') {
      graphRef.current.d3ReheatSimulation()
    }
  }, [graphData, cleanMode])

  /* ── Resize observer ────────────────────────────────────────────────── */
  useEffect(() => {
    const el = graphShellRef.current
    if (!el) return
    const updateSize = () => {
      const width = Math.max(300, Math.floor(el.clientWidth))
      const height = width < 640 ? 340 : 420
      setGraphSize({ width, height })
    }
    updateSize()
    const observer = new ResizeObserver(updateSize)
    observer.observe(el)
    return () => observer.disconnect()
  }, [])

  /* ── Edge helpers ───────────────────────────────────────────────────── */
  const isPathEdge = (edge, pathNodeIds) => {
    if (!pathNodeIds.length) return false
    const src = idOf(edge.source)
    const dst = idOf(edge.target)
    const ai = pathNodeIds.indexOf(src)
    const bi = pathNodeIds.indexOf(dst)
    return ai >= 0 && bi >= 0 && Math.abs(ai - bi) === 1
  }

  const isChainEdge = (edge) => isPathEdge(edge, selectedChainNodeIds)
  const isActivePlayEdge = (edge) => isPathEdge(edge, activeChainNodeIds)

  const linkColor = (edge) => {
    const src = idOf(edge.source)
    const dst = idOf(edge.target)
    const edgeFocus = !selectedNodeId || selectedNeighborIds.has(src) || selectedNeighborIds.has(dst)
    if (!edgeFocus) return 'rgba(110, 118, 129, 0.12)'
    if (isActivePlayEdge(edge)) return '#ffe66d'
    if (isChainEdge(edge)) return '#2de2ff'
    if (edge.risk === 'critical') return '#ff595e'
    if (edge.risk === 'high') return '#ffd166'
    return '#8fd3ff'
  }

  const linkParticles = (edge) => {
    if (cleanMode && !isActivePlayEdge(edge) && !isChainEdge(edge)) return 0
    if (isActivePlayEdge(edge)) return 10
    if (isChainEdge(edge)) return cleanMode ? 2 : 4
    if (edge.risk === 'critical') return cleanMode ? 1 : 2
    return cleanMode ? 0 : 1
  }

  /* ── Node rendering ─────────────────────────────────────────────────── */
  const nodeVal = (node) => {
    if (node.type === 'agent') return 14
    if (node.type === 'dangerous_sink') return 11
    if (node.type === 'tool') return 10
    return 9
  }

  const nodeColor = (node) => {
    const base = typeColor(node.type)
    const active = selectedNodeId === node.id || hoveredNodeId === node.id
    const dimmed = selectedNodeId && !selectedNeighborIds.has(node.id)
    if (dimmed) return 'rgba(140, 140, 140, 0.2)'
    if (active) return '#16213e'
    if (chainNodeSet.has(node.id)) return '#be95ff'
    return base
  }

  const nodePaint = (node, ctx, globalScale) => {
    const r = nodeVal(node)
    const x = node.x || 0
    const y = node.y || 0
    const active = selectedNodeId === node.id || hoveredNodeId === node.id
    const inChain = chainNodeSet.has(node.id)
    const shape = typeShape(node.type)
    const color = nodeColor(node)

    // Halo for chain nodes
    if (inChain) {
      ctx.beginPath()
      ctx.arc(x, y, r + 5, 0, 2 * Math.PI, false)
      ctx.fillStyle = 'rgba(190, 149, 255, 0.25)'
      ctx.fill()
    }

    // Risk glow for dangerous sinks
    if (node.type === 'dangerous_sink' && node.risk_score >= 70) {
      ctx.beginPath()
      ctx.arc(x, y, r + 4, 0, 2 * Math.PI, false)
      ctx.fillStyle = 'rgba(218, 30, 40, 0.2)'
      ctx.fill()
    }

    // Draw shape
    switch (shape) {
      case 'diamond':
        drawDiamond(ctx, x, y, r)
        break
      case 'hexagon':
        drawHexagon(ctx, x, y, r)
        break
      case 'triangle':
        drawTriangle(ctx, x, y, r)
        break
      case 'square':
        drawSquare(ctx, x, y, r)
        break
      default:
        ctx.beginPath()
        ctx.arc(x, y, r, 0, 2 * Math.PI, false)
    }

    ctx.fillStyle = color
    ctx.fill()
    ctx.lineWidth = active ? 2 : 1
    ctx.strokeStyle = active ? 'rgba(255,255,255,0.9)' : 'rgba(255,255,255,0.25)'
    ctx.stroke()

    // Labels
    if (!showLabels && !active && !inChain) return

    const label = compactLabel(node.name, 28)
    const typeName = prettyType(node.type)
    const fontSize = (active ? 11 : 9) / globalScale
    const typeSize = (active ? 9 : 7.5) / globalScale
    const y1 = y + r + 12 / globalScale
    const y2 = y + r + 23 / globalScale

    ctx.font = `600 ${fontSize}px "IBM Plex Sans", ui-sans-serif, -apple-system, sans-serif`
    ctx.fillStyle = active ? '#16213e' : '#d0d0d0'
    ctx.textAlign = 'center'
    ctx.textBaseline = 'alphabetic'
    ctx.fillText(label, x, y1)

    ctx.font = `500 ${typeSize}px "IBM Plex Sans", ui-sans-serif, -apple-system, sans-serif`
    ctx.fillStyle = 'rgba(160,170,185,0.95)'
    ctx.fillText(typeName, x, y2)

    // Risk score badge above node
    if (node.risk_score > 0) {
      const riskLabel = `${node.risk_score}`
      const y3 = y - r - 8 / globalScale
      const badgeSize = (active ? 9 : 7.5) / globalScale
      ctx.font = `700 ${badgeSize}px "IBM Plex Mono", monospace`
      ctx.fillStyle = node.risk_score >= 70 ? '#ff8fa3' : node.risk_score >= 45 ? '#ffb784' : '#6fdc8c'
      ctx.fillText(riskLabel, x, y3)
    }
  }

  const resetGraphView = (full = false) => {
    setSelectedNodeId('')
    setHoveredNodeId('')
    setPlayChain(false)
    setPlayStep(0)
    if (full) {
      setRiskFilter('all')
      setTypeFilter('all')
    }
    setTimeout(() => {
      if (graphRef.current) {
        graphRef.current.zoomToFit(600, 120)
      }
    }, 40)
  }

  /* ── Loading / error states ─────────────────────────────────────────── */
  if (loading) {
    return (
      <div className="mt-3 border border-carbon-border bg-carbon-layer px-5 py-6 text-sm text-carbon-text-secondary dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-30">
        Loading agent attack surface graph...
      </div>
    )
  }

  if (error) {
    return (
      <div className="mt-3 border border-ibm-red-60 bg-[#2d1215] px-5 py-6 text-sm text-[#ffd7d9]">
        {error}
      </div>
    )
  }

  if (!data) {
    return (
      <div className="mt-3 border border-carbon-border bg-carbon-layer px-5 py-6 text-sm text-carbon-text-secondary dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-30">
        No agent attack surface data available.
      </div>
    )
  }

  if (!data.nodes || data.nodes.length <= 1) {
    return (
      <div className="mt-3 border border-carbon-border bg-white px-6 py-8 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
        <p className="text-[15px] font-medium text-carbon-text dark:text-ibm-gray-10">No agent attack surface detected</p>
        <p className="mt-3 max-w-[62ch] text-[14px] leading-7 text-carbon-text-secondary dark:text-ibm-gray-30">
          This scan does not contain AI agent patterns. The attack surface graph visualizes tool definitions,
          LLM output execution paths, and RAG pipelines found in the scanned code.
        </p>
        <div className="mt-5 space-y-2 text-[13px] text-carbon-text-tertiary dark:text-ibm-gray-40">
          <p>To see this graph, scan code that contains:</p>
          <div className="mt-2 flex flex-wrap gap-2">
            {['@tool decorators', 'eval() / exec() on LLM output', 'subprocess with LLM response', 'RAG similarity_search'].map((item) => (
              <span key={item} className="border border-carbon-border bg-carbon-layer px-3 py-1.5 font-mono text-[11px] dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
                {item}
              </span>
            ))}
          </div>
        </div>
      </div>
    )
  }

  const score = Number(data.overall_risk_score || 0)
  const scoreBand = scoreTone(score)
  const insights = data.insights || {}
  const chains = data.risk_chains || []

  return (
    <div className="mt-3 space-y-4">
      {/* ── Risk header ───────────────────────────────────────────────── */}
      <div className={`border px-4 py-3 ${toneClasses(scoreBand)}`}>
        <div className="text-[11px] uppercase tracking-[0.08em] opacity-80">Agent attack surface risk</div>
        <div className="mt-1 text-2xl font-light">{score}/100 · {data.threat_level || 'LOW'}</div>
        <p className="mt-2 text-sm leading-relaxed">
          {insights.dangerous_tools > 0
            ? `${insights.dangerous_tools} of ${insights.total_tools} tool(s) have dangerous capabilities. `
            : `${insights.total_tools || 0} tool(s) analyzed. `}
          {insights.dangerous_sinks > 0 && `${insights.dangerous_sinks} dangerous sink(s) reachable. `}
          {insights.attack_paths > 0 && `${insights.attack_paths} proven attack chain(s).`}
        </p>
      </div>

      {/* ── Blast radius + insights ───────────────────────────────────── */}
      <div className="grid gap-px border border-carbon-border bg-carbon-border md:grid-cols-2 dark:border-ibm-gray-80 dark:bg-ibm-gray-80">
        <div className="bg-white p-4 dark:bg-ibm-gray-90">
          <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
            Blast radius
          </div>
          <div className="mt-1 text-lg font-light text-carbon-text dark:text-ibm-gray-10">
            {data.blast_radius?.affected_count || 0} system resource(s) reachable
          </div>
          <p className="mt-2 text-sm text-carbon-text-secondary dark:text-ibm-gray-30">
            {data.blast_radius?.description || 'No dangerous resources reachable.'}
          </p>
        </div>
        <div className="bg-white p-4 dark:bg-ibm-gray-90">
          <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
            Threatened resources
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            {(data.blast_radius?.affected_packages || []).map((name) => (
              <span
                key={name}
                className="border border-[#de715d]/40 bg-[#ffe7e1] px-2 py-1 font-mono text-[11px] text-[#b84d39] dark:border-ibm-red-60 dark:bg-[#2d1215] dark:text-[#ffd7d9]"
              >
                {name}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* ── Filters ───────────────────────────────────────────────────── */}
      <div className="border border-carbon-border bg-carbon-layer p-3 dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
        <div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
          Graph controls
        </div>
        <div className="grid gap-2 md:grid-cols-6">
        <label className="flex flex-col gap-1 text-[11px] uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
          Risk filter
          <select
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value)}
            className="border border-carbon-border bg-white px-2 py-1 text-[12px] text-carbon-text dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-10"
          >
            <option value="all">All</option>
            <option value="critical">Critical</option>
            <option value="high">High+</option>
            <option value="medium">Medium+</option>
            <option value="low">Low</option>
          </select>
        </label>
        <label className="flex flex-col gap-1 text-[11px] uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
          Node type
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="border border-carbon-border bg-white px-2 py-1 text-[12px] text-carbon-text dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-10"
          >
            {nodeTypeOptions.map((t) => (
              <option key={t} value={t}>{prettyType(t)}</option>
            ))}
          </select>
        </label>
        <div className="flex items-end">
          <button
            type="button"
            onClick={() => setShowLabels((v) => !v)}
            className="w-full border border-carbon-border bg-white px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.08em] text-carbon-text hover:bg-carbon-layer dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-10 dark:hover:bg-ibm-gray-80"
          >
            {showLabels ? 'Hide labels' : 'Show labels'}
          </button>
        </div>
        <div className="flex items-end">
          <div className="w-full border border-carbon-border dark:border-ibm-gray-80">
            <div className="grid grid-cols-2">
              <button
                type="button"
                onClick={() => setViewMode('clean')}
                className={`px-2 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] ${viewMode === 'clean' ? 'bg-carbon-text text-white dark:bg-ibm-blue-60' : 'bg-white text-carbon-text hover:bg-carbon-layer dark:bg-ibm-gray-90 dark:text-ibm-gray-10 dark:hover:bg-ibm-gray-80'}`}
              >
                Clean
              </button>
              <button
                type="button"
                onClick={() => setViewMode('detailed')}
                className={`px-2 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] ${viewMode === 'detailed' ? 'bg-carbon-text text-white dark:bg-ibm-blue-60' : 'bg-white text-carbon-text hover:bg-carbon-layer dark:bg-ibm-gray-90 dark:text-ibm-gray-10 dark:hover:bg-ibm-gray-80'}`}
              >
                Detailed
              </button>
            </div>
          </div>
        </div>
        <div className="flex items-end">
          <button
            type="button"
            onClick={() => resetGraphView(true)}
            className="w-full border border-carbon-border bg-white px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.08em] text-carbon-text hover:bg-carbon-layer dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-10 dark:hover:bg-ibm-gray-80"
          >
            Reset view
          </button>
        </div>
        <div className="flex items-end">
          <button
            type="button"
            onClick={() => {
              if (!selectedChainNodeIds.length) return
              setPlayChain(true)
              setPlayStep(0)
            }}
            disabled={!selectedChainNodeIds.length}
            className="w-full border border-[#de715d] bg-[#de715d] px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.08em] text-white hover:bg-[#c96351] disabled:opacity-40"
          >
            Play attack path
          </button>
        </div>
        </div>
      </div>

      {/* ── Legend ─────────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-4 px-1 text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
        {TYPE_LANE_ORDER.map((t) => (
          <span key={t} className="flex items-center gap-1.5">
            <span
              className="inline-block h-2.5 w-2.5"
              style={{ backgroundColor: typeColor(t), borderRadius: t === 'resource' ? '50%' : '2px' }}
            />
            {prettyType(t)}
          </span>
        ))}
      </div>

      {/* ── Graph canvas ──────────────────────────────────────────────── */}
      <div
        ref={graphShellRef}
        className="relative h-[340px] w-full overflow-hidden border border-carbon-border dark:border-ibm-gray-80 md:h-[420px]"
        onMouseLeave={() => setHoveredNodeId('')}
      >
        <div className="pointer-events-none absolute inset-0 z-0 bg-[radial-gradient(circle_at_18%_18%,rgba(120,169,255,0.17),transparent_38%),radial-gradient(circle_at_82%_28%,rgba(190,149,255,0.16),transparent_42%),linear-gradient(180deg,#171c24_0%,#0f131a_100%)]" />
        <div className="pointer-events-none absolute inset-0 z-0 opacity-20 [background-image:linear-gradient(rgba(141,141,141,0.15)_1px,transparent_1px),linear-gradient(90deg,rgba(141,141,141,0.15)_1px,transparent_1px)] [background-size:30px_30px]" />
        <div className="absolute inset-0 z-10">
          <ForceGraph2D
            ref={graphRef}
            graphData={graphData}
            width={graphSize.width}
            height={graphSize.height}
            backgroundColor="transparent"
            nodeCanvasObject={nodePaint}
            nodeVal={nodeVal}
            linkColor={linkColor}
            linkWidth={(edge) => (isActivePlayEdge(edge) ? 3.4 : isChainEdge(edge) ? 2.2 : cleanMode ? 0.9 : 1.2)}
            linkDirectionalParticles={linkParticles}
            linkDirectionalParticleWidth={(edge) => (isActivePlayEdge(edge) ? 3.8 : isChainEdge(edge) ? 2.6 : 2.0)}
            linkDirectionalParticleSpeed={(edge) => {
              if (isActivePlayEdge(edge)) return 0.032
              if (isChainEdge(edge)) return 0.02
              return cleanMode ? 0.006 : 0.011
            }}
            linkDirectionalArrowLength={6}
            linkDirectionalArrowRelPos={0.85}
            linkDirectionalArrowColor={linkColor}
            onNodeClick={(node) => setSelectedNodeId(node.id === selectedNodeId ? '' : node.id)}
            onNodeHover={(node) => setHoveredNodeId(node?.id || '')}
            onBackgroundClick={() => setSelectedNodeId('')}
            warmupTicks={80}
            cooldownTicks={cleanMode ? 140 : 220}
            enableZoomInteraction
            enablePanInteraction
          />
        </div>
      </div>

      {/* ── Attack chains ─────────────────────────────────────────────── */}
      {chains.length > 0 && (
        <div className="border border-carbon-border bg-white p-4 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
          <div className="mb-3 flex items-baseline justify-between">
            <h3 className="text-[11px] font-semibold uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
              Attack chains ({chains.length})
            </h3>
            {chains.length > 1 && (
              <div className="flex gap-1">
                {chains.map((_, i) => (
                  <button
                    key={i}
                    onClick={() => setSelectedChainIdx(i)}
                    className={`h-5 w-5 border text-[10px] font-bold ${
                      i === selectedChainIdx
                        ? 'border-[#de715d] bg-[#de715d] text-white'
                        : 'border-carbon-border bg-carbon-layer text-carbon-text-tertiary dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-40'
                    }`}
                  >
                    {i + 1}
                  </button>
                ))}
              </div>
            )}
          </div>
          {selectedChain && (
            <div>
              <div className="flex flex-wrap items-center gap-2 font-mono text-[12px]">
                {selectedChain.path.map((step, i) => (
                  <span key={i} className="flex items-center gap-2">
                    <span className="border border-carbon-border bg-carbon-layer px-2 py-1 text-carbon-text dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-10">
                      {step}
                    </span>
                    {i < selectedChain.path.length - 1 && (
                      <span className="text-[#de715d]">&#8594;</span>
                    )}
                  </span>
                ))}
              </div>
              {selectedChain.description && (
                <p className="mt-2 text-[12px] text-carbon-text-secondary dark:text-ibm-gray-30">
                  {selectedChain.description}
                </p>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── Node inspector ────────────────────────────────────────────── */}
      {selectedNode && (
        <div className="border border-carbon-border bg-white p-4 dark:border-ibm-gray-80 dark:bg-ibm-gray-90">
          <div className="flex items-baseline justify-between">
            <h3 className="text-[13px] font-semibold text-carbon-text dark:text-ibm-gray-10">
              {selectedNode.name}
            </h3>
            <span
              className="text-[10px] font-bold uppercase tracking-[0.08em] px-2 py-0.5"
              style={{ backgroundColor: typeColor(selectedNode.type), color: '#fff' }}
            >
              {prettyType(selectedNode.type)}
            </span>
          </div>
          <div className="mt-2 space-y-1 text-[12px] text-carbon-text-secondary dark:text-ibm-gray-30">
            <div>Risk score: <strong>{selectedNode.risk_score}</strong></div>
            {selectedNode.line_number && <div>Line: {selectedNode.line_number}</div>}
            {selectedNode.cwe && <div>CWE: {selectedNode.cwe}</div>}
            {selectedNode.owasp && <div>OWASP: {selectedNode.owasp}</div>}
            {selectedNode.params && <div>Params: {selectedNode.params.join(', ')}</div>}
            {selectedNode.docstring && <div className="italic opacity-80">{selectedNode.docstring}</div>}
            {selectedNode.description && <div>{selectedNode.description}</div>}
          </div>
        </div>
      )}
    </div>
  )
}
