import json

import matplotlib.pyplot as plt
import numpy as np

with open("benchmark_results.json", "r") as f:
    data = json.load(f)

cm = data["confusion_matrix"]
tp, fp, fn, tn = cm["tp"], cm["fp"], cm["fn"], cm["tn"]
precision = data["precision"]
recall = data["recall"]
f1 = data["f1"]
accuracy = data["accuracy"]

# IBM Carbon colors
IBM_BLUE = "#0043CE"
IBM_DARK = "#161616"
IBM_GRAY = "#393939"
IBM_GREEN = "#24A148"
IBM_RED = "#DA1E28"
IBM_WHITE = "#FFFFFF"
IBM_LIGHT = "#F4F4F4"

fig = plt.figure(figsize=(14, 8), facecolor=IBM_DARK)

# ── Confusion Matrix ──────────────────────────────────────────────────────────
ax1 = fig.add_subplot(1, 2, 1)
ax1.set_facecolor(IBM_DARK)

matrix = np.array([[tp, fn], [fp, tn]])
colors = [[IBM_GREEN, IBM_RED], [IBM_RED, IBM_GREEN]]
labels = [["TP", "FN"], ["FP", "TN"]]
values = [[tp, fn], [fp, tn]]
sublabels = [["Caught attacks", "Missed attacks"], ["False alarms", "Correct clears"]]

for i in range(2):
    for j in range(2):
        ax1.add_patch(plt.Rectangle((j, 1-i), 1, 1, color=colors[i][j], alpha=0.85))
        ax1.text(j+0.5, 1-i+0.65, labels[i][j], ha="center", va="center",
                fontsize=18, fontweight="bold", color=IBM_WHITE,
                fontfamily="monospace")
        ax1.text(j+0.5, 1-i+0.42, str(values[i][j]), ha="center", va="center",
                fontsize=36, fontweight="bold", color=IBM_WHITE,
                fontfamily="monospace")
        ax1.text(j+0.5, 1-i+0.18, sublabels[i][j], ha="center", va="center",
                fontsize=9, color=IBM_LIGHT, fontfamily="monospace")

ax1.set_xlim(0, 2)
ax1.set_ylim(0, 2)
ax1.set_xticks([0.5, 1.5])
ax1.set_xticklabels(["Predicted\nVulnerable", "Predicted\nSafe"],
                     color=IBM_LIGHT, fontfamily="monospace", fontsize=10)
ax1.set_yticks([0.5, 1.5])
ax1.set_yticklabels(["Actually\nSafe", "Actually\nVulnerable"],
                     color=IBM_LIGHT, fontfamily="monospace", fontsize=10)
ax1.tick_params(colors=IBM_LIGHT)
for spine in ax1.spines.values():
    spine.set_edgecolor(IBM_GRAY)
ax1.set_title("CONFUSION MATRIX", color=IBM_WHITE, fontfamily="monospace",
              fontsize=13, fontweight="bold", pad=15)

# ── Metrics Bar Chart ─────────────────────────────────────────────────────────
ax2 = fig.add_subplot(1, 2, 2)
ax2.set_facecolor(IBM_DARK)

metrics = ["Precision", "Recall", "F1 Score", "Accuracy"]
values_m = [precision, recall, f1, accuracy]
bar_colors = [IBM_BLUE, IBM_BLUE, IBM_GREEN, IBM_BLUE]

bars = ax2.barh(metrics, values_m, color=bar_colors, height=0.5, edgecolor=IBM_GRAY)

for bar, val in zip(bars, values_m):
    ax2.text(val - 0.02, bar.get_y() + bar.get_height()/2,
             f"{val:.2f}", ha="right", va="center",
             color=IBM_WHITE, fontsize=14, fontweight="bold",
             fontfamily="monospace")

ax2.set_xlim(0, 1.1)
ax2.set_facecolor(IBM_DARK)
ax2.tick_params(colors=IBM_LIGHT, labelsize=11)
ax2.set_xticklabels([])
for spine in ax2.spines.values():
    spine.set_edgecolor(IBM_GRAY)
ax2.set_title("BENCHMARK METRICS", color=IBM_WHITE, fontfamily="monospace",
              fontsize=13, fontweight="bold", pad=15)
for label in ax2.get_yticklabels():
    label.set_fontfamily("monospace")
    label.set_color(IBM_LIGHT)

# ── Title ─────────────────────────────────────────────────────────────────────
fig.suptitle("PROMPTSHIELD · BENCHMARK VALIDATION · 20 PROMPTS",
             color=IBM_WHITE, fontfamily="monospace", fontsize=14,
             fontweight="bold", y=0.98)

plt.tight_layout(rect=[0, 0, 1, 0.95])
plt.savefig("benchmark_chart.png", dpi=150, bbox_inches="tight",
            facecolor=IBM_DARK)
print("Saved to benchmark_chart.png")
plt.show()