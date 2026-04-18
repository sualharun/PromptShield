import matplotlib.pyplot as plt
import numpy as np

IBM_DARK = "#161616"
IBM_BLUE = "#0043CE"
IBM_GREEN = "#24A148"
IBM_WHITE = "#FFFFFF"
IBM_LIGHT = "#F4F4F4"
IBM_GRAY = "#393939"

iterations = [1, 2, 3]
prompts = [50, 80, 151]
f1_scores = [0.919, 0.951, 0.972]
labels = ["Iteration 1\n50 prompts", "Iteration 2\n80 prompts", "Iteration 3\n151 prompts"]

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6), facecolor=IBM_DARK)

# ── F1 Improvement Chart ──────────────────────────────────────────────────────
ax1.set_facecolor(IBM_DARK)
bars = ax1.bar(labels, f1_scores, color=[IBM_BLUE, IBM_BLUE, IBM_GREEN],
               width=0.5, edgecolor=IBM_GRAY, linewidth=1)

for bar, score in zip(bars, f1_scores):
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.003,
             f"{score:.3f}", ha="center", va="bottom",
             color=IBM_WHITE, fontsize=13, fontweight="bold",
             fontfamily="monospace")

ax1.set_ylim(0.85, 1.0)
ax1.set_facecolor(IBM_DARK)
ax1.tick_params(colors=IBM_LIGHT, labelsize=10)
ax1.set_title("F1 SCORE BY ITERATION", color=IBM_WHITE,
              fontfamily="monospace", fontsize=12, fontweight="bold", pad=15)
ax1.set_ylabel("Cross-Validation F1", color=IBM_LIGHT,
               fontfamily="monospace", fontsize=10)
for label in ax1.get_xticklabels():
    label.set_fontfamily("monospace")
    label.set_color(IBM_LIGHT)
for spine in ax1.spines.values():
    spine.set_edgecolor(IBM_GRAY)

ax1.axhline(y=0.919, color="#FF832B", linestyle="--", alpha=0.4, linewidth=1)
ax1.text(2.35, 0.921, "baseline", color="#FF832B",
         fontsize=8, fontfamily="monospace", alpha=0.7)

# ── Layer Comparison Chart ────────────────────────────────────────────────────
ax2.set_facecolor(IBM_DARK)
layers = ["Static Rules", "Claude API", "ML Classifier\n(ours)"]
scores = [0.90, 0.50, 1.00]
colors = [IBM_BLUE, IBM_BLUE, IBM_GREEN]

bars2 = ax2.bar(layers, scores, color=colors, width=0.5,
                edgecolor=IBM_GRAY, linewidth=1)

for bar, score in zip(bars2, scores):
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
             f"{score:.0%}", ha="center", va="bottom",
             color=IBM_WHITE, fontsize=13, fontweight="bold",
             fontfamily="monospace")

ax2.set_ylim(0, 1.15)
ax2.set_facecolor(IBM_DARK)
ax2.tick_params(colors=IBM_LIGHT, labelsize=10)
ax2.set_title("LAYER ACCURACY ON 20 ATTACK PROMPTS", color=IBM_WHITE,
              fontfamily="monospace", fontsize=12, fontweight="bold", pad=15)
ax2.set_ylabel("Accuracy", color=IBM_LIGHT,
               fontfamily="monospace", fontsize=10)
for label in ax2.get_xticklabels():
    label.set_fontfamily("monospace")
    label.set_color(IBM_LIGHT)
for spine in ax2.spines.values():
    spine.set_edgecolor(IBM_GRAY)

fig.suptitle("PROMPTSHIELD · ML MODEL PERFORMANCE", color=IBM_WHITE,
             fontfamily="monospace", fontsize=14, fontweight="bold", y=0.98)

plt.tight_layout(rect=[0, 0, 1, 0.95])
plt.savefig("iteration_chart.png", dpi=150, bbox_inches="tight",
            facecolor=IBM_DARK)
print("Saved to iteration_chart.png")
plt.show()