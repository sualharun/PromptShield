import { useEffect, useMemo, useRef, useState } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import { fetchWithTimeout, asNetworkErrorMessage } from '../lib/fetchWithTimeout.js'

function scoreTone(score) {
  if (score >= 70) return 'critical'
  if (score >= 50) return 'high'
  if (score >= 30) return 'medium'
  return 'low'
}

function toneClasses(tone) {
  switch (tone) {
    case 'critical':
      return 'border-ibm-red-60 bg-[#2d1215] text-[#ffd7d9]'
    case 'high':
      return 'border-ibm-orange-40 bg-[#2a1b0f] text-[#ffd9b8]'
    case 'medium':
      return 'border-[#8a6f00] bg-[#2a250f] text-[#ffefb1]'
    default:
      return 'border-ibm-green-60 bg-[#10231a] text-[#b8f5cb]'
  }
}

function typeColor(type) {
  if (type === 'pull_request') return '#a56eff'
  if (type === 'contributor') return '#78a9ff'
  if (type === 'commit') return '#33b1ff'
  if (type === 'repository') return '#08bdba'
  if (type === 'maintainer') return '#be95ff'
  if (type === 'vulnerable_repo') return '#da1e28'
  return '#24a148'
}

function prettyType(type) {
  return (type || 'unknown').replace(/_/g, ' ')
}

function compactLabel(text, max = 34) {
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

function hasDirectedCycle(nodes, links) {
  const ids = new Set((nodes || []).map((n) => n.id))
  const adj = new Map()
  const state = new Map() // 0=unseen, 1=visiting, 2=done

  for (const id of ids) {
    adj.set(id, [])
    state.set(id, 0)
  }
  for (const e of links || []) {
    const s = typeof e.source === 'object' ? e.source?.id : e.source
    const t = typeof e.target === 'object' ? e.target?.id : e.target
    if (!ids.has(s) || !ids.has(t)) continue
    adj.get(s).push(t)
  }

  const dfs = (u) => {
    state.set(u, 1)
    for (const v of adj.get(u) || []) {
      const st = state.get(v)
      if (st === 1) return true
      if (st === 0 && dfs(v)) return true
    }
    state.set(u, 2)
    return false
  }

  for (const id of ids) {
    if (state.get(id) === 0 && dfs(id)) return true
  }
  return false
}

const TYPE_LANE_ORDER = [
  'pull_request',
  'contributor',
  'commit',
  'repository',
  'dependency',
  'maintainer',
  'vulnerable_repo',
]

function laneForType(type) {
  const idx = TYPE_LANE_ORDER.indexOf(type || 'dependency')
  return idx >= 0 ? idx : TYPE_LANE_ORDER.indexOf('dependency')
}

export default function DependencyGraph({ scanId }) {
  const graphShellRef = useRef(null)
  const graphRef = useRef(null)
  const [graphSize, setGraphSize] = useState({ width: 920, height: 420 })
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [riskFilter, setRiskFilter] = useState('all')
  const [typeFilter, setTypeFilter] = useState('all')
  const [showLabels, setShowLabels] = useState(false)
  const [viewMode, setViewMode] = useState('clean')
  const [selectedNodeId, setSelectedNodeId] = useState('')
  const [hoveredNodeId, setHoveredNodeId] = useState('')
  const [selectedChainIdx, setSelectedChainIdx] = useState(0)
  const [playChain, setPlayChain] = useState(false)
  const [playStep, setPlayStep] = useState(0)

  useEffect(() => {
    let active = true

    const run = async () => {
      setLoading(true)
      setError('')

      try {
        let response = await fetchWithTimeout(`/api/graph/${scanId}`)

        if (response.status === 404) {
          const analyze = await fetchWithTimeout(`/api/graph/analyze/${scanId}`, {
            method: 'POST',
          })
          if (!analyze.ok) {
            throw new Error('Unable to run dependency graph analysis for this scan.')
          }
          response = await fetchWithTimeout(`/api/graph/${scanId}`)
        }

        if (!response.ok) {
          throw new Error(`Graph request failed (${response.status})`)
        }

        const payload = await response.json()
        if (active) setData(payload)
      } catch (err) {
        if (active) setError(asNetworkErrorMessage(err, 'Unable to load dependency graph.'))
      } finally {
        if (active) setLoading(false)
      }
    }

    run()

    return () => {
      active = false
    }
  }, [scanId])

  const depNodes = useMemo(() => {
    if (!data?.nodes) return []
    return data.nodes.filter((n) => n.type === 'dependency')
  }, [data])

  const nodeTypeOptions = useMemo(() => {
    const types = [...new Set((data?.nodes || []).map((n) => n.type || 'unknown'))]
    return ['all', ...types]
  }, [data])

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

  const selectedNode = useMemo(
    () => (data?.nodes || []).find((n) => n.id === selectedNodeId) || null,
    [data, selectedNodeId]
  )

  const selectedChain = useMemo(() => {
    const chains = data?.risk_chains || []
    if (chains.length === 0) return null
    return chains[Math.min(selectedChainIdx, chains.length - 1)]
  }, [data, selectedChainIdx])

  const selectedChainNodeNames = useMemo(() => {
    if (!selectedChain?.path?.length) return []
    return selectedChain.path
  }, [selectedChain])

  const activeChainNodeNames = useMemo(() => {
    if (!selectedChainNodeNames.length) return []
    if (!playChain) return []
    return selectedChainNodeNames.slice(0, Math.max(2, playStep + 1))
  }, [playChain, playStep, selectedChainNodeNames])

  useEffect(() => {
    if (!playChain || !selectedChainNodeNames.length) return
    setPlayStep(1)
    const id = setInterval(() => {
      setPlayStep((curr) => {
        const next = curr + 1
        if (next >= selectedChainNodeNames.length) {
          setPlayChain(false)
          return selectedChainNodeNames.length - 1
        }
        return next
      })
    }, 850)
    return () => clearInterval(id)
  }, [playChain, selectedChainNodeNames])

  const graphData = useMemo(() => {
    if (!data?.nodes?.length) return { nodes: [], links: [] }
    const perTypeCount = new Map()
    const nodes = data.nodes
      .filter((node) => filteredNodeIds.has(node.id))
      .map((node, idx, arr) => {
        const t = node.type || 'dependency'
        const lane = laneForType(t)
        const lanePos = perTypeCount.get(t) || 0
        perTypeCount.set(t, lanePos + 1)

        const xLaneGap = 170
        const laneCenter = (TYPE_LANE_ORDER.length - 1) / 2
        const baseX = (lane - laneCenter) * xLaneGap
        const yStride = 72
        const yOffset = (lanePos - 3) * yStride + ((idx % 2 === 0 ? -1 : 1) * 16)

        // Keep deterministic fallback in case existing x/y are undefined and type lanes are sparse.
        const angle = (idx / Math.max(1, arr.length)) * Math.PI * 2
        const fallbackRadius = 150 + (idx % 5) * 18
        return {
          ...node,
          x: node.x ?? baseX + Math.cos(angle) * 16,
          y: node.y ?? (yOffset || Math.sin(angle) * fallbackRadius),
        }
      })
    const nodeIdSet = new Set(nodes.map((n) => n.id))
    const links = (data.edges || []).filter(
      (edge) => nodeIdSet.has(edge.source) && nodeIdSet.has(edge.target)
    )
    return { nodes, links }
  }, [data, filteredNodeIds])

  const graphIsDense = useMemo(() => {
    return graphData.nodes.length >= 16 || graphData.links.length >= 22
  }, [graphData.nodes.length, graphData.links.length])

  const canUseDag = useMemo(() => {
    if (!graphData.nodes.length || !graphData.links.length) return false
    return !hasDirectedCycle(graphData.nodes, graphData.links)
  }, [graphData])

  const cleanMode = viewMode === 'clean'

  const prioritizedLabelIds = useMemo(() => {
    const sorted = [...graphData.nodes]
      .sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0))
      .slice(0, cleanMode ? 9 : 20)
    return new Set(sorted.map((n) => n.id))
  }, [graphData.nodes, cleanMode])

  const idOf = (value) => {
    if (value && typeof value === 'object') return value.id
    return value
  }

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

  useEffect(() => {
    if (!graphRef.current || !graphData.nodes.length) return
    const t = setTimeout(() => {
      if (graphRef.current) graphRef.current.zoomToFit(500, 80)
    }, 450)
    return () => clearTimeout(t)
  }, [graphData])

  useEffect(() => {
    if (!graphRef.current) return
    const charge = cleanMode ? -560 : -420
    const linkDistance = cleanMode ? 165 : 138
    const chargeForce = graphRef.current.d3Force('charge')
    if (chargeForce && typeof chargeForce.strength === 'function') {
      chargeForce.strength(charge)
    }

    const linkForce = graphRef.current.d3Force('link')
    if (linkForce && typeof linkForce.distance === 'function') {
      linkForce.distance(() => linkDistance)
      if (typeof linkForce.strength === 'function') {
        linkForce.strength(cleanMode ? 0.42 : 0.34)
      }
    }

    if (typeof graphRef.current.d3ReheatSimulation === 'function') {
      graphRef.current.d3ReheatSimulation()
    }
  }, [graphData, cleanMode])

  useEffect(() => {
    if (!graphRef.current || !playChain || !activeChainNodeNames.length) return
    const currentName = activeChainNodeNames[activeChainNodeNames.length - 1]
    const node = graphData.nodes.find((n) => n.name === currentName)
    if (!node || node.x === undefined || node.y === undefined) return
    graphRef.current.centerAt(node.x, node.y, 700)
    const currentZoom = graphRef.current.zoom()
    graphRef.current.zoom(Math.max(1.8, currentZoom), 650)
  }, [playChain, activeChainNodeNames, graphData.nodes])

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

  const chainNameSet = useMemo(() => new Set(selectedChainNodeNames), [selectedChainNodeNames])

  const isPathEdge = (edge, pathNodes) => {
    if (!pathNodes.length) return false
    const sourceName = typeof edge.source === 'object'
      ? edge.source.name
      : data?.nodes?.find((n) => n.id === edge.source)?.name
    const targetName = typeof edge.target === 'object'
      ? edge.target.name
      : data?.nodes?.find((n) => n.id === edge.target)?.name
    const a = sourceName || ''
    const b = targetName || ''
    const ai = pathNodes.indexOf(a)
    const bi = pathNodes.indexOf(b)
    return ai >= 0 && bi >= 0 && Math.abs(ai - bi) === 1
  }

  const isChainEdge = (edge) => {
    return isPathEdge(edge, selectedChainNodeNames)
  }

  const isActivePlayEdge = (edge) => {
    return isPathEdge(edge, activeChainNodeNames)
  }

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
    if (cleanMode && !isActivePlayEdge(edge)) return 0
    if (isActivePlayEdge(edge)) return 10
    if (isChainEdge(edge)) return cleanMode ? 2 : 4
    if (edge.risk === 'critical') return cleanMode ? 2 : 5
    if (edge.risk === 'high') return cleanMode ? 1 : 3
    return cleanMode ? 0 : 2
  }

  const nodeVal = (node) => {
    if (cleanMode) {
      if (node.type === 'pull_request') return 12
      if (node.type === 'contributor') return 10
      return 8
    }
    if (node.type === 'pull_request') return 18
    if (node.type === 'contributor') return 14
    return 10
  }

  const nodeColor = (node) => {
    const tone = scoreTone(Number(node.risk_score || 0))
    const base = typeColor(node.type || 'dependency')
    const inChain = chainNameSet.has(node.name)
    const active = selectedNodeId === node.id || hoveredNodeId === node.id
    const dimmed = selectedNodeId && !selectedNeighborIds.has(node.id)
    if (dimmed) return 'rgba(140, 140, 140, 0.2)'
    if (tone === 'critical' && (node.type === 'dependency' || node.type === 'vulnerable_repo')) return '#da1e28'
    if (active) return '#ffffff'
    if (inChain) return '#be95ff'
    return base
  }

  const nodeThreeObject = (node) => {
    const active = selectedNodeId === node.id || hoveredNodeId === node.id
    const inChain = chainNameSet.has(node.name)
    const canShowDenseLabel = !cleanMode || prioritizedLabelIds.has(node.id)
    return active || inChain || (showLabels && canShowDenseLabel)
  }

  const nodePaint = (node, ctx, globalScale) => {
    const r = nodeVal(node)
    const x = node.x || 0
    const y = node.y || 0
    const active = selectedNodeId === node.id || hoveredNodeId === node.id
    const inChain = chainNameSet.has(node.name)

    // halo for focused path nodes
    if (inChain) {
      ctx.beginPath()
      ctx.arc(x, y, r + 4, 0, 2 * Math.PI, false)
      ctx.fillStyle = 'rgba(190, 149, 255, 0.25)'
      ctx.fill()
    }

    ctx.beginPath()
    ctx.arc(x, y, r, 0, 2 * Math.PI, false)
    ctx.fillStyle = nodeColor(node)
    ctx.fill()

    ctx.lineWidth = active ? 2 : 1
    ctx.strokeStyle = active ? 'rgba(255,255,255,0.9)' : 'rgba(255,255,255,0.25)'
    ctx.stroke()

    if (!nodeThreeObject(node)) return

    const label = compactLabel(node.name, cleanMode ? 24 : 34)
    const type = prettyType(node.type)
    const fontSize = (active ? 11 : 9) / globalScale
    const typeSize = (active ? 9 : 8) / globalScale
    const y1 = y + r + 12 / globalScale
    const y2 = y + r + 24 / globalScale

    ctx.font = `600 ${fontSize}px ui-sans-serif, -apple-system, Segoe UI, Roboto, Helvetica, Arial`
    const pad = 4 / globalScale
    const w = ctx.measureText(label).width + pad * 2
    const h = 12 / globalScale
    ctx.fillStyle = active ? 'rgba(22,29,41,0.82)' : 'rgba(20,20,24,0.56)'
    ctx.fillRect(x - w / 2, y1 - h + 1 / globalScale, w, h)
    ctx.fillStyle = active ? '#ffffff' : '#d0d0d0'
    ctx.textAlign = 'center'
    ctx.textBaseline = 'alphabetic'
    ctx.fillText(label, x, y1)

    ctx.font = `500 ${typeSize}px ui-sans-serif, -apple-system, Segoe UI, Roboto, Helvetica, Arial`
    ctx.fillStyle = 'rgba(160,170,185,0.95)'
    ctx.fillText(type, x, y2)
  }

  if (loading) {
    return (
      <div className="mt-3 border border-carbon-border bg-carbon-layer px-5 py-6 text-sm text-carbon-text-secondary dark:border-ibm-gray-80 dark:bg-ibm-gray-100 dark:text-ibm-gray-30">
        Loading dependency graph analysis...
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
        No dependency graph data available.
      </div>
    )
  }

  const score = Number(data.overall_risk_score || 0)
  const scoreBand = scoreTone(score)

  return (
    <div className="mt-3 space-y-4">
      <div className={`border px-4 py-3 ${toneClasses(scoreBand)}`}>
        <div className="text-[11px] uppercase tracking-[0.08em] opacity-80">Dependency risk score</div>
        <div className="mt-1 text-2xl font-light">{score}/100 · {data.threat_level || 'LOW'}</div>
        {data.narrative && <p className="mt-2 text-sm leading-relaxed">{data.narrative}</p>}
      </div>

      <div className="grid gap-px border border-carbon-border bg-carbon-border md:grid-cols-2 dark:border-ibm-gray-80 dark:bg-ibm-gray-80">
        <div className="bg-white p-4 dark:bg-ibm-gray-90">
          <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
            Blast radius
          </div>
          <div className="mt-1 text-lg font-light text-carbon-text dark:text-ibm-gray-10">
            {data.blast_radius?.affected_count || 0} packages affected
          </div>
          <p className="mt-2 text-sm text-carbon-text-secondary dark:text-ibm-gray-30">
            {data.blast_radius?.description || 'No propagation details available.'}
          </p>
        </div>
        <div className="bg-white p-4 dark:bg-ibm-gray-90">
          <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
            Connected dependencies
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            {(data.blast_radius?.affected_packages || []).slice(0, 8).map((name) => (
              <span
                key={name}
                className="border border-carbon-border bg-carbon-layer px-2 py-1 font-mono text-[11px] dark:border-ibm-gray-80 dark:bg-ibm-gray-100"
              >
                {name}
              </span>
            ))}
            {(data.blast_radius?.affected_packages || []).length > 8 && (
              <span className="px-2 py-1 text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
                +{data.blast_radius.affected_packages.length - 8} more
              </span>
            )}
          </div>
        </div>
      </div>

      <div className="grid gap-2 border border-carbon-border bg-carbon-layer p-3 md:grid-cols-6 dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
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
            onClick={() => {
              setRiskFilter('all')
              setTypeFilter('all')
              setSelectedNodeId('')
              setHoveredNodeId('')
            }}
            className="w-full border border-carbon-border bg-white px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.08em] text-carbon-text hover:bg-carbon-layer dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-10 dark:hover:bg-ibm-gray-80"
          >
            Reset view
          </button>
        </div>
        <div className="flex items-end">
          <button
            type="button"
            onClick={() => {
              if (!selectedChainNodeNames.length) return
              setPlayStep(1)
              setPlayChain(true)
            }}
            disabled={!selectedChainNodeNames.length || playChain}
            className="w-full border border-ibm-blue-60 bg-ibm-blue-60 px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.08em] text-white hover:bg-ibm-blue-70 disabled:cursor-not-allowed disabled:border-ibm-gray-60 disabled:bg-ibm-gray-60"
          >
            {playChain ? 'Playing...' : 'Play attack path'}
          </button>
        </div>
      </div>

      <div className="grid gap-px border border-carbon-border bg-carbon-border md:grid-cols-[2fr,1fr] dark:border-ibm-gray-80 dark:bg-ibm-gray-80">
        <div className="bg-white p-3 dark:bg-ibm-gray-90">
          <div className="px-2 pb-2 text-[11px] font-semibold uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
            Risk propagation graph
          </div>
          {graphIsDense && cleanMode && (
            <div className="px-2 pb-2 text-[11px] text-carbon-text-secondary dark:text-ibm-gray-30">
              Dense graph mode: spacing boosted, non-essential labels/particles reduced for clarity.
            </div>
          )}
          <div className="px-2 pb-2 text-[11px] text-carbon-text-secondary dark:text-ibm-gray-30">
            Flow legend: <span className="text-[#ffe66d]">yellow = active path</span>, <span className="text-[#2de2ff]">cyan = focused chain</span>
          </div>
          <div className="px-2 pb-2 text-[11px] text-carbon-text-tertiary dark:text-ibm-gray-40">
            2D map: drag nodes to reposition, wheel to zoom, drag canvas to pan.
          </div>
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
                backgroundColor="rgba(0,0,0,0)"
                width={graphSize.width}
                height={graphSize.height}
                nodeId="id"
                nodeVal={nodeVal}
                nodeCanvasObject={nodePaint}
                nodePointerAreaPaint={(node, color, ctx) => {
                  ctx.fillStyle = color
                  ctx.beginPath()
                  ctx.arc(node.x || 0, node.y || 0, nodeVal(node) + 6, 0, 2 * Math.PI, false)
                  ctx.fill()
                }}
                nodeLabel={(node) => `${compactLabel(node.name, 80)} (${prettyType(node.type)})\nRisk: ${Math.round(Number(node.risk_score || 0))}`}
                linkSource="source"
                linkTarget="target"
                dagMode={cleanMode && canUseDag ? 'lr' : undefined}
                dagLevelDistance={cleanMode && canUseDag ? 140 : undefined}
                linkDirectionalArrowLength={3.8}
                linkDirectionalArrowRelPos={1}
                linkCurvature={cleanMode ? 0.12 : 0.08}
                linkDirectionalParticles={linkParticles}
                linkDirectionalParticleWidth={(edge) => {
                  if (isActivePlayEdge(edge)) return 3.8
                  if (isChainEdge(edge)) return 2.8
                  return cleanMode ? 1.5 : 2.2
                }}
                linkDirectionalParticleSpeed={(edge) => {
                  if (isActivePlayEdge(edge)) return 0.032
                  if (isChainEdge(edge)) return 0.02
                  if (edge.risk === 'critical') return cleanMode ? 0.012 : 0.02
                  if (edge.risk === 'high') return cleanMode ? 0.009 : 0.015
                  return cleanMode ? 0.006 : 0.011
                }}
                linkDirectionalParticleColor={(edge) => {
                  if (isActivePlayEdge(edge)) return '#ffe66d'
                  if (isChainEdge(edge)) return '#2de2ff'
                  if (edge.risk === 'critical') return '#ff8fa3'
                  if (edge.risk === 'high') return '#ffd166'
                  return '#7bc8ff'
                }}
                linkColor={linkColor}
                linkWidth={(edge) => {
                  if (isActivePlayEdge(edge)) return 3.4
                  if (isChainEdge(edge)) return 2.2
                  if (edge.risk === 'critical') return 2.4
                  if (edge.risk === 'high') return 1.8
                  return cleanMode ? 0.9 : 1.2
                }}
                warmupTicks={80}
                cooldownTicks={cleanMode ? 180 : 240}
                d3AlphaDecay={cleanMode ? 0.018 : 0.014}
                d3VelocityDecay={cleanMode ? 0.2 : 0.18}
                enableNodeDrag
                enablePanInteraction
                enableZoomInteraction
                onEngineStop={() => {
                  if (graphRef.current) graphRef.current.zoomToFit(700, cleanMode ? 140 : 120)
                }}
                onNodeHover={(node) => setHoveredNodeId(node?.id || '')}
                onNodeClick={(node) => setSelectedNodeId(node?.id || '')}
              />
            </div>
          </div>
        </div>
        <div className="bg-white p-3 dark:bg-ibm-gray-90">
          <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
            Node inspector
          </div>
          {selectedNode ? (
            <div className="mt-2 space-y-2">
              <div className={`border px-2 py-2 ${toneClasses(scoreTone(Number(selectedNode.risk_score || 0)))}`}>
                <p className="font-mono text-xs">{selectedNode.name}</p>
                <p className="text-[10px] uppercase tracking-[0.08em] opacity-90">{prettyType(selectedNode.type)}</p>
                <p className="mt-1 text-xs">Risk {Math.round(Number(selectedNode.risk_score || 0))}/100</p>
              </div>
              {selectedNode.version && (
                <p className="text-xs text-carbon-text-secondary dark:text-ibm-gray-30">
                  Version: <span className="font-mono">{selectedNode.version}</span>
                </p>
              )}
              {selectedNode.exploit_history && (
                <p className="text-xs text-carbon-text-secondary dark:text-ibm-gray-30">{selectedNode.exploit_history}</p>
              )}
              {!!selectedNode.vulnerabilities?.length && (
                <div className="space-y-1">
                  <p className="text-[10px] uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">Vulnerabilities</p>
                  {selectedNode.vulnerabilities.slice(0, 4).map((v) => (
                    <p key={`${selectedNode.id}-${v.cve_id}`} className="font-mono text-[10px] text-ibm-red-50">{v.cve_id} · {v.severity}</p>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <p className="mt-2 text-xs text-carbon-text-secondary dark:text-ibm-gray-30">
              Click a node to inspect details and focus related edges.
            </p>
          )}
        </div>
      </div>

      {!!(data.insights || data.risk_chains?.length) && (
        <div className="grid gap-px border border-carbon-border bg-carbon-border md:grid-cols-2 dark:border-ibm-gray-80 dark:bg-ibm-gray-80">
          <div className="bg-white p-4 dark:bg-ibm-gray-90">
            <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
              Correlation insights
            </div>
            <div className="mt-2 space-y-1 text-sm text-carbon-text-secondary dark:text-ibm-gray-30">
              <p>Risky dependencies: {data.insights?.risky_dependency_count || 0}</p>
              <p>Flagged maintainers: {data.insights?.maintainer_flags || 0}</p>
              <p>Connected vulnerable repos: {data.insights?.connected_vulnerable_repos || 0}</p>
            </div>
          </div>
          <div className="bg-white p-4 dark:bg-ibm-gray-90">
            <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
              Top risk chains
            </div>
            {(data.risk_chains || []).length === 0 ? (
              <p className="mt-2 text-sm text-carbon-text-secondary dark:text-ibm-gray-30">No high-risk path found.</p>
            ) : (
              <div className="mt-2 space-y-2">
                {(data.risk_chains || []).slice(0, 3).map((c, idx) => (
                  <div
                    key={`${idx}-${c.terminal_type}`}
                    className={`border px-2 py-1 text-xs dark:border-ibm-gray-80 ${selectedChainIdx === idx ? 'border-ibm-blue-60 bg-[#1a2a4a] text-[#cde1ff]' : 'border-carbon-border bg-carbon-layer dark:bg-ibm-gray-100'}`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <p className="font-semibold">{Math.round(Number(c.risk_score || 0))} risk · {c.terminal_type}</p>
                      <button
                        type="button"
                        onClick={() => {
                          setSelectedChainIdx(idx)
                          setPlayChain(false)
                          setPlayStep(0)
                        }}
                        className="border border-carbon-border bg-white px-1.5 py-0.5 text-[10px] uppercase tracking-[0.08em] text-carbon-text dark:border-ibm-gray-80 dark:bg-ibm-gray-90 dark:text-ibm-gray-10"
                      >
                        Focus
                      </button>
                    </div>
                    <p className="font-mono opacity-90">{(c.path || []).join(' -> ')}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      <div className="border border-carbon-border bg-carbon-layer p-2 dark:border-ibm-gray-80 dark:bg-ibm-gray-100">
        <div className="px-2 py-1 text-[11px] font-semibold uppercase tracking-[0.08em] text-carbon-text-tertiary dark:text-ibm-gray-40">
          Dependency nodes
        </div>
        {depNodes.length === 0 ? (
          <div className="px-3 py-4 text-sm text-carbon-text-secondary dark:text-ibm-gray-30">
            No dependency nodes found for this scan.
          </div>
        ) : (
          <div className="space-y-2 p-2">
            {depNodes.map((node) => {
              const tone = scoreTone(Number(node.risk_score || 0))
              return (
                <div
                  key={node.id}
                  className={`border px-3 py-2 ${toneClasses(tone)}`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="font-mono text-[12px]">
                      {node.name}@{node.version || 'unknown'}
                    </div>
                    <div className="text-[11px] font-semibold uppercase tracking-[0.06em]">
                      {Math.round(Number(node.risk_score || 0))} risk
                    </div>
                  </div>
                  <p className="mt-1 text-xs opacity-90">
                    {(node.vulnerabilities || []).length} known vulnerabilities
                  </p>
                  {(node.vulnerabilities || []).length > 0 && (
                    <div className="mt-1 flex flex-wrap gap-1">
                      {node.vulnerabilities.slice(0, 4).map((v) => (
                        <span
                          key={`${node.id}-${v.cve_id}`}
                          className="border border-current/40 px-1.5 py-0.5 font-mono text-[10px]"
                        >
                          {v.cve_id}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
