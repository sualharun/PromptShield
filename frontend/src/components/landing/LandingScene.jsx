import { useRef } from 'react'
import { motion, useReducedMotion, useScroll, useTransform } from 'framer-motion'
import { SCROLL_HEIGHT } from '../../lib/motion/sceneTimeline.js'
import SceneFrame from './SceneFrame.jsx'
import SceneNav from './SceneNav.jsx'
import RibbonWave from './RibbonWave.jsx'
import MetalPlane from './MetalPlane.jsx'
import FloatingBoard from './FloatingBoard.jsx'
import CTACluster from './CTACluster.jsx'
import SceneProgressLabel from './SceneProgressLabel.jsx'

export default function LandingScene({ onDashboard, onScan }) {
  const containerRef = useRef(null)
  const reduceMotion = useReducedMotion()
  const { scrollYProgress } = useScroll({
    target: containerRef,
    offset: ['start start', 'end end'],
  })

  // Phase 1: Intro headline
  const headlineOpacity = useTransform(scrollYProgress, [0.0, 0.16, 0.22], [1, 1, 0])
  const headlineY = useTransform(scrollYProgress, [0, 0.16, 0.22], [0, 0, -24])

  // Phase 2 subtitle
  const subtitleOpacity = useTransform(scrollYProgress, [0.0, 0.16, 0.22], [0.9, 0.9, 0])

  // Phase 6: Final lockup
  const lockupOpacity = useTransform(scrollYProgress, [0.84, 0.92, 1.0], [0, 1, 1])
  const lockupX = useTransform(scrollYProgress, [0.84, 0.92], [-30, 0])

  // Scene canvas background shifts
  const canvasBg = useTransform(
    scrollYProgress,
    [0, 0.34, 0.50, 0.84, 1],
    [
      'rgba(250,250,252,1)',
      'rgba(248,248,252,1)',
      'rgba(245,245,250,1)',
      'rgba(248,248,252,1)',
      'rgba(250,250,252,1)',
    ]
  )
  const prefersReducedMotion = !!reduceMotion

  return (
    <section
      ref={containerRef}
      className="relative"
      style={{ height: prefersReducedMotion ? 'auto' : SCROLL_HEIGHT }}
    >
      <div className={`${prefersReducedMotion ? 'relative' : 'sticky top-0'} flex h-screen items-center justify-center px-4 md:px-8`}>
        {/* Ambient blobs */}
        <div className="pointer-events-none absolute -left-32 top-1/4 h-[30rem] w-[30rem] rounded-full bg-gradient-to-br from-pink-200/30 to-purple-200/20 blur-3xl dark:from-pink-800/10 dark:to-purple-800/10" />
        <div className="pointer-events-none absolute -right-32 bottom-1/4 h-[30rem] w-[30rem] rounded-full bg-gradient-to-br from-blue-200/30 to-cyan-200/20 blur-3xl dark:from-blue-800/10 dark:to-cyan-800/10" />

        <SceneFrame className="relative h-[74vh] max-h-[680px] min-h-[460px] w-full">
          <SceneNav />

          <motion.div className="absolute inset-0 top-12 rounded-b-2xl" style={{ backgroundColor: canvasBg }} />
          <div className="pointer-events-none absolute inset-0 top-12 rounded-b-2xl bg-[radial-gradient(circle_at_20%_15%,rgba(236,227,255,0.45),transparent_40%),radial-gradient(circle_at_82%_85%,rgba(206,232,255,0.5),transparent_45%)]" />

          {/* Content layers */}
          <div className="relative flex h-[calc(100%-48px)] w-full flex-col overflow-hidden">

            {/* Phase 1: Intro headline + ribbon */}
            <div className="relative z-10 grid grid-cols-1 gap-4 px-6 pt-8 md:grid-cols-[1.2fr,0.8fr] md:px-10 md:pt-10">
              <motion.div
                className="max-w-md flex-1 md:max-w-lg"
                style={{ opacity: headlineOpacity, y: headlineY }}
              >
                <p className="inline-flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.2em] text-ibm-purple-60 dark:text-ibm-purple-40">
                  <span className="h-1.5 w-1.5 rounded-full bg-ibm-purple-60 dark:bg-ibm-purple-50" />
                  PromptShield
                </p>
                <h1 className="mt-4 text-3xl font-light leading-[1.05] text-carbon-text md:text-5xl lg:text-[62px]">
                  Prompt security
                  <br />
                  <span className="bg-gradient-to-r from-ibm-blue-60 via-ibm-blue-50 to-ibm-purple-50 bg-clip-text text-transparent">
                    for AI systems.
                  </span>
                </h1>
              </motion.div>

              <motion.div
                className="mt-2 max-w-sm justify-self-start text-sm leading-relaxed text-carbon-text-secondary md:mt-8 md:justify-self-end md:text-right"
                style={{ opacity: subtitleOpacity }}
              >
                <p>
                  AST-powered dataflow analysis, 12 attack payload simulations, and CI gating before merge.
                </p>
              </motion.div>
            </div>

            {/* Phase 1-2: Ribbon */}
            <div className="relative z-10 mt-4 px-6 pb-6 md:mt-3 md:px-10">
              <RibbonWave scrollProgress={scrollYProgress} />
              <div className="mt-4 md:mt-5">
                <CTACluster
                  scrollProgress={scrollYProgress}
                  onDashboard={onDashboard}
                  onScan={onScan}
                />
              </div>
            </div>

            {/* Phase 3: Metal plane */}
            <MetalPlane scrollProgress={scrollYProgress} />

            {/* Phase 4-5: Floating board */}
            <FloatingBoard scrollProgress={scrollYProgress} />

            {/* Phase 6: Final lockup */}
            <motion.div
              className="absolute inset-0 z-20 flex items-center px-6 md:px-10"
              style={{ opacity: lockupOpacity, x: lockupX }}
            >
              <div className="grid w-full gap-8 md:grid-cols-2">
                <div className="flex flex-col justify-center">
                  <h2 className="text-2xl font-light leading-tight text-carbon-text dark:text-ibm-gray-10 md:text-4xl">
                    Ship AI code
                    <br />
                    <span className="font-medium">with confidence.</span>
                  </h2>
                  <p className="mt-4 max-w-sm text-sm leading-relaxed text-carbon-text-secondary dark:text-ibm-gray-30">
                    96% F1 on our 100-sample benchmark. Dataflow-proven injection paths,
                    not regex guesses. Every PR scanned, every risk scored.
                  </p>
                  <div className="mt-6 flex flex-wrap gap-3">
                    <button
                      onClick={onDashboard}
                      className="rounded-full bg-carbon-text px-6 py-2.5 text-sm font-semibold text-white shadow-md transition-all hover:scale-[1.02] hover:shadow-lg dark:bg-white dark:text-ibm-gray-100"
                    >
                      Open dashboard
                    </button>
                    <button
                      onClick={onScan}
                      className="rounded-full border border-carbon-border px-6 py-2.5 text-sm font-medium text-carbon-text transition-all hover:bg-carbon-layer dark:border-ibm-gray-70 dark:text-ibm-gray-10"
                    >
                      Try a scan
                    </button>
                  </div>
                </div>
                {/* Right side spacer — board is visible behind */}
                <div className="hidden md:block" />
              </div>
            </motion.div>
          </div>

          <SceneProgressLabel scrollProgress={scrollYProgress} />
        </SceneFrame>
      </div>
    </section>
  )
}
