# v0 Prompts for PromptShield UI Enhancement

> Copy each prompt to v0.dev → click "Create new" → paste → generate

---

## 🎯 PRIORITY 1: Landing Page (Eye-Catching Hero) — $5 credits

```
Create a professional, eye-catching landing page for PromptShield (LLM security scanner).

Hero Section:
- Headline: "PromptShield: Enterprise LLM Security Scanning"
- Subheading: "Detect prompt injection, jailbreaks, and data exfiltration in real-time"
- CTA buttons:
  - Primary: "Start Free Scan" (blue)
  - Secondary: "View Demo" (outline)
- Hero image: Abstract cybersecurity theme with circuit patterns, AI concepts

Navigation:
- Logo + Home, Features, Dashboard, Docs, GitHub
- Sign up / Login buttons

Featured Sections Below Hero:

1. Three Key Features (3 cards):
   - "Dependency Risk Graph" with icon
   - "Real-time PR Scanning" with icon
   - "Executive Risk Briefs" with icon
   - Each card has description + icon from Carbon Design System

2. Statistics Row:
   - "500+ LLM Attack Patterns Detected"
   - "89% F1 Score on Benchmark"
   - "10K+ PRs Scanned"
   - "Fortune 500 Companies Trust Us"

3. Use Cases (4 cards with icons):
   - "Secure Your AI Pipelines"
   - "Compliance & Governance"
   - "Red Team Simulations"
   - "Supply Chain Risk"

4. Integration Logos Row:
   - GitHub, Jira, Slack, IBM Watson icons

5. Security Badges:
   - "SOC 2 Compliant" "OWASP Aligned" "Open Source"

6. CTA Section:
   - "Join 1000+ security teams"
   - Email signup form
   - "Start Free Trial"

Design:
- Dark theme (IBM Carbon dark gray bg #161616)
- Accent colors: Blue (#0F62FE), Red for alerts (#DA1E28), Green for safe (#24A148)
- Font: Modern sans-serif (Inter or similar)
- Animations: Subtle fade-ins, hover effects on cards
- Responsive: Stack on mobile
- High contrast, readable text
- Professional but approachable tone

Use Tailwind CSS with custom dark theme.
```

---

## 🎯 PRIORITY 2: Scan Page Redesign (Better UX) — $4 credits

```
Redesign the PromptShield Scan Page to be more professional and user-friendly.

Current Flow: User pastes prompt → Click Scan → See results

Improved Layout:

Header Section:
- Large input area for prompt text
- Placeholder: "Paste your prompt here to scan for vulnerabilities..."
- Character counter (show 0/2000)
- Dropdown: "Select Model" (GPT-4, Claude, etc.)
- Scan Options section (collapsible):
  - Checkbox: "Include Dependency Analysis"
  - Checkbox: "Run Threat Intelligence Check"
  - Checkbox: "Cross-repo Comparison"

Primary CTA:
- Large blue "Scan Prompt" button
- Shows seconds to complete: "Typical scan: <5 seconds"

Results Section (when scanning complete):

1. Risk Summary Card (top):
   - Overall risk score (0-100) with large number
   - Threat level badge: CRITICAL / HIGH / MEDIUM / LOW with color coding
   - Status: "✅ Safe" or "⚠️ Requires Review"
   - Timestamp + scan ID

2. Finding Cards (tabbed section):
   - Tab 1: "Vulnerabilities Found" (X items)
     - For each finding:
       - Icon + Finding type (Injection, Exfil, etc.)
       - Severity badge (color-coded)
       - Description (1 line)
       - OWASP category link
       - "View Details" → expand to show full info + remediation
   
   - Tab 2: "Dependency Risks" 
     - List of risky dependencies
     - CVE count, severity, patch available?
   
   - Tab 3: "Attack Paths"
     - Show top 3 attack chains
     - Visualize as connected nodes
     - Click to expand full path

3. Recommendations Section:
   - Card: "How to Fix"
   - List of actionable remediation steps
   - Priority-sorted (Critical first)
   - Code snippets where applicable

4. Data Visualization:
   - Severity distribution pie chart (top right)
   - Timeline of findings if multiple scans

Design Guidelines:
- Clean, scannable layout with good whitespace
- Icons from Carbon Design System
- Color-coded severity: Red (#DA1E28), Orange (#F1C21B), Yellow (#FDD835), Green (#24A148)
- Dark Tailwind theme to match DependencyGraph.jsx
- Smooth transitions between tabs
- Loading states with skeleton screens
- Empty state: "No vulnerabilities found! 🎉"

Make it look professional, NOT scary – use design to guide users toward action, not overwhelm them.
```

---

## 🎯 PRIORITY 3: Enterprise Dashboard (Professional Executive View) — $4 credits

```
Create a professional Enterprise Dashboard for PromptShield showing security metrics and compliance.

Layout: Sidebar navigation + Main content area

Sidebar:
- Company logo
- Menu items:
  - Dashboard (active, highlighted)
  - Security Scorecard
  - Compliance (OWASP)
  - Red Team Lab
  - Threat Intelligence
  - Audit Logs
  - Settings

Main Dashboard:

1. Header Bar:
   - "Enterprise Dashboard"
   - Date range filter: "Last 30 days"
   - Org selector dropdown
   - Refresh button

2. Top KPI Cards (4 cards in a row):
   - "Total Scans": 1,234 (large number)
   - "Average Risk Score": 42 / 100 (gauge visualization)
   - "Critical Findings": 12 (with trend arrow ↑↓)
   - "Compliance Score": 78% (progress bar)

3. Charts Section (2 columns):
   Left:
   - "Risk Trend (Last 30 Days)": Line chart showing risk score trend over time
   - Y-axis: Risk score (0-100)
   - X-axis: Time (dates)
   - Color: Blue line with shaded area

   Right:
   - "Finding Distribution": Stacked bar chart
   - Categories: Injection, Exfil, Jailbreak, etc.
   - Stacked by severity: Critical, High, Medium, Low

4. Bottom Section (3 columns):
   
   Left Card: "Riskiest Repositories"
   - Table: Repo name | Risk Score | Status
   - Sortable, clickable rows
   - Top 5 repos

   Middle Card: "Recent Vulnerabilities"
   - List of latest findings
   - Time + Type + Severity
   - 5 most recent

   Right Card: "Recommendations"
   - Priority list of actions
   - "Enable threat intel" 
   - "Setup red team tests"
   - "Configure Slack alerts"

5. Bottom Action Row:
   - "Export Report" button
   - "Schedule Scan" button
   - "Invite Team" button

Design:
- Professional corporate dashboard style
- Dark Tailwind theme
- Use Recharts for all visualizations
- Color-coded severity (Carbon colors)
- Hover effects on cards
- Icons from Carbon Design System
- Grid layout, well-organized
- Numbers are large and readable

Make it look like a professional security dashboard (think Datadog, New Relic style).
```

---

## 🎯 PRIORITY 4: Report Page (Professional PDF-Ready) — $3 credits

```
Design a professional Security Report Page for PromptShield that's PDF-export ready.

Header Section:
- Company logo (left)
- Report title: "Security Scan Report"
- Report date + time
- Scan ID / Reference number
- Organization name

Executive Summary Section:
- Overall Risk Score: large number with gauge
- Threat Level: CRITICAL / HIGH / MEDIUM / LOW badge
- Key metrics in 3 boxes:
  - Total findings: X
  - Critical findings: Y
  - Time to remediate (estimated): Z days

Detailed Findings Section:
- For each finding category (Injections, Exfiltration, etc.):
  - Category title
  - List of findings as collapsible cards:
    - Finding name
    - Severity badge (color-coded)
    - Description
    - Impact statement
    - Remediation steps
    - Reference (OWASP link, CVE, etc.)

Compliance Section:
- OWASP LLM Top 10 Coverage (checklist)
  - ✓ LLM01: Prompt Injection
  - ✗ LLM02: Insecure Output Handling
  etc.
- Compliance score: X%

Dependency Risk Section:
- Table: Package | Version | CVEs | Severity | Status
- Download / Export options

Recommendations Section:
- Priority-ranked list of actions
- Each item with:
  - Priority (1-5)
  - Description
  - Estimated fix time
  - Owner assignment option

Footer:
- "Confidential"
- "Generated on [date]"
- Page numbers
- Company branding

Design:
- Professional, clean layout (look like real security reports)
- White/dark background with clear hierarchy
- Serif font for headers, sans-serif for body
- Plenty of whitespace
- Good for both digital viewing and PDF export
- No unnecessary colors – use them strategically
- Easy to scan and read
- Include page breaks for PDF

Make it look like a professional security audit report.
```

---

## 📝 BONUS: Bug Reports / Improvements Page — $2 credits

```
Create a "Found an Issue?" page for users to report bugs and suggest improvements.

Header:
- "Help Us Improve PromptShield"
- Subheading: "Found a bug? Have an idea? We'd love to hear it."

Two Sections:

Section 1: Report a Bug
- Heading: "🐛 Report a Bug"
- Form fields:
  - Bug title (required)
  - Description (textarea, multiline)
  - Steps to reproduce (numbered list helper)
  - Expected behavior
  - Actual behavior
  - Browser/OS info (auto-detect option)
  - Severity selector: Critical / High / Medium / Low
  - Attachments: Drop zone for screenshots
  - Priority: "I'll fix this myself" checkbox
  - Submit button: "Report Bug"

Section 2: Suggest a Feature
- Heading: "💡 Suggest a Feature"
- Form fields:
  - Feature title (required)
  - Description
  - Use case (why do you need this?)
  - Priority: High / Medium / Low
  - Upvote system: "👍 I want this too" count
  - Submit button: "Submit Idea"

Additional:
- "Recent Bug Reports" section showing status
- "Trending Ideas" showing most-wanted features
- Links to GitHub Issues
- Feedback: "Thank you! We'll review your submission"

Design:
- Encouraging, friendly tone (make users feel heard)
- Clear visual separation between Bug and Feature
- Icons assist each section
- Dark Tailwind theme
- Forms are easy to fill out
- Success states after submission
```

---

## 🚀 IMPLEMENTATION ORDER (By Priority)

| Priority | Component | Credits | Time | Action |
|----------|-----------|---------|------|--------|
| 1 | Landing Page | $5 | 10 min | v0 → copy → `frontend/src/pages/LandingPage.jsx` |
| 2 | Scan Page Redesign | $4 | 10 min | v0 → copy → update `frontend/src/pages/ScanPage.jsx` |
| 3 | Enterprise Dashboard | $4 | 10 min | v0 → copy → `frontend/src/pages/EnterprisePage.jsx` |
| **TOTAL** | **3 Components** | **$13** | **30 min** | **Ship to production** |
| 4 | Report Page | $3 | 10 min | v0 → copy → `frontend/src/pages/ReportPage.jsx` |

---

## 💡 USAGE TIPS

**Copy a prompt:**
1. Select entire text block (tripple-click or cmd+A)
2. Copy (cmd+C)
3. Go to v0.dev → "Create new"
4. Paste prompt into text input
5. Click generate
6. Review 2-3 variants (v0 gives you options)
7. Click "Copy Code" on best variant
8. Paste into your `.jsx` file

**Iterating:**
- If you don't like the output, regenerate
- Tell v0 what to change: "Make the buttons bigger" "Use more white space" "Add more icons"
- Each regeneration costs ~1 credit

**Integration:**
- Copy v0 component → paste into your React file
- Update imports for Recharts, React components
- Wire up to your backend APIs
- Test with `npm run dev`

---

## 🎯 TALKING POINTS FOR JUDGES

> "Our UI uses IBM Carbon Design System, Tailwind CSS dark theme for accessibility, and professional dashboard patterns. Every page is optimized for both readability and action – from the eye-catching landing page that explains our value, to the executive dashboard showing real security metrics."

---

## 🔥 QUICK START (Next 5 minutes)

1. Go to **v0.dev**
2. Redeem code: **HOOKEM-V0**
3. Paste the **Landing Page** prompt
4. Generate & review
5. Copy best variant
6. Create `frontend/src/pages/LandingPage.jsx`
7. Paste output
8. Update navigation in `frontend/src/App.jsx` to show landing page

**Result in 30 minutes:** A professional, eye-catching landing page + improved scan/enterprise UIs
