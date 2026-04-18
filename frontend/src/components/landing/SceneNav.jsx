const ITEMS = ['Product', 'Solutions', 'Learn']

export default function SceneNav() {
  return (
    <div className="flex h-12 items-center border-b border-black/[0.05] px-5 dark:border-white/[0.06] md:px-7">
      <div className="flex min-w-0 items-center gap-3">
        <span className="text-xl font-semibold tracking-tight text-carbon-text dark:text-ibm-gray-10">
          PromptShield
        </span>
        <span className="hidden text-[9px] font-medium uppercase tracking-[0.11em] text-carbon-text-tertiary dark:text-ibm-gray-40 md:block">
          Security for AI code
        </span>
      </div>

      <nav className="ml-10 hidden items-center gap-7 md:flex">
        {ITEMS.map((item) => (
          <button
            key={item}
            className="text-[10px] font-semibold uppercase tracking-[0.14em] text-carbon-text-secondary transition-colors hover:text-carbon-text dark:text-ibm-gray-40 dark:hover:text-ibm-gray-10"
          >
            {item}
          </button>
        ))}
      </nav>

      <div className="ml-auto flex items-center gap-4">
        <button className="hidden text-[10px] font-semibold uppercase tracking-[0.13em] text-carbon-text-secondary dark:text-ibm-gray-40 md:inline-flex">
          Sign in
        </button>
        <button className="inline-flex rounded-full border border-black/[0.08] px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-carbon-text transition-colors hover:bg-black/[0.03] dark:border-white/[0.14] dark:text-ibm-gray-20 dark:hover:bg-white/[0.06]">
          Get in touch
        </button>
      </div>
    </div>
  )
}
