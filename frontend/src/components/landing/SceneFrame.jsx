import { forwardRef } from 'react'

const SceneFrame = forwardRef(function SceneFrame({ children, className = '' }, ref) {
  return (
    <div
      ref={ref}
      className={`relative mx-auto w-full max-w-6xl overflow-hidden rounded-[26px] border border-black/[0.06] bg-[#fdfdff]/92 shadow-[0_22px_90px_-28px_rgba(39,46,73,0.45)] backdrop-blur-xl ${className}`}
    >
      {children}
    </div>
  )
})

export default SceneFrame
