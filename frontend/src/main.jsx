import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './styles.css'

function renderFatal(message) {
  const root = document.getElementById('root')
  if (!root) return
  root.innerHTML = `
    <div style="
      min-height:100vh;
      display:flex;
      align-items:flex-start;
      justify-content:center;
      padding:32px;
      background:#111315;
      color:#f4f4f4;
      font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;
    ">
      <div style="max-width:920px;width:100%;border:1px solid #da1e28;background:#2d1215;padding:16px 20px;">
        <div style="font-weight:700;margin-bottom:8px;">PromptShield failed to start</div>
        <div style="opacity:.95;white-space:pre-wrap;line-height:1.45;">${String(message || 'Unknown runtime error')}</div>
      </div>
    </div>
  `
}

window.addEventListener('error', (event) => {
  if (event?.error) {
    renderFatal(event.error.message || event.message)
  }
})

window.addEventListener('unhandledrejection', (event) => {
  const reason = event?.reason
  const msg = reason?.message || String(reason || 'Unhandled promise rejection')
  renderFatal(msg)
})

try {
  ReactDOM.createRoot(document.getElementById('root')).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>
  )
} catch (err) {
  renderFatal(err?.message || err)
}
