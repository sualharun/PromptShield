import React from 'react'

export default class PanelErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, message: '' }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, message: error?.message || 'Unknown error' }
  }

  componentDidCatch(error) {
    // Keep diagnostics in console while preventing full-screen crash.
    console.error('PanelErrorBoundary caught:', error)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="mt-3 border border-ibm-red-60 bg-[#2d1215] px-5 py-6 text-sm text-[#ffd7d9]">
          <p className="font-semibold">Graph panel failed to render.</p>
          <p className="mt-1 opacity-90">{this.state.message}</p>
        </div>
      )
    }
    return this.props.children
  }
}
