#!/usr/bin/env python3
"""Tổng hợp raw.csv -> summary.csv và vẽ biểu đồ (data-model.md §2.3, FR-023).

    python3 bench/plot.py                 # đợt đo mới nhất trong results/
    python3 bench/plot.py results/<run_id>

Đầu ra trong cùng thư mục:
  summary.csv        mean/std/n theo (experiment, config, rules, load_mode)
  drop_cost.png      Đo 1: pps tối đa 1 luồng + CPU ở tải cố định
  rule_scaling.png   Đo 2: pps tối đa / CPU / ns mỗi gói của XDP theo số rule (trục log)
  legit_impact.png   Đo 3: throughput và RTT p99 của client, không flood vs có flood
"""
import sys
import textwrap
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

# Thứ tự cố định + màu cố định theo cấu hình (màu đi theo cấu hình, không theo thứ hạng).
CONFIGS = ["baseline", "xdp-native", "xdp-generic", "ipt-legacy-raw",
           "ipt-legacy-filter", "ipt-nft-raw", "ipt-nft-filter", "nft-set"]
PALETTE = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100",
           "#e87ba4", "#008300", "#6250d6", "#e34948"]
COLOR = dict(zip(CONFIGS, PALETTE))
BASELINE_GRAY = "#8a8985"  # baseline là mốc tham chiếu, không phải một bộ lọc
COLOR["baseline"] = BASELINE_GRAY
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e6e5e1"

METRICS = ["sent_pps", "dropped_pps", "cpu_busy_pct", "xdp_ns_per_pkt",
           "rtt_avg_ms", "rtt_p99_ms", "legit_mbps"]
KEYS = ["experiment", "config", "rules", "load_mode"]

plt.rcParams.update({
    "font.size": 10, "axes.edgecolor": INK2, "axes.labelcolor": INK2,
    "xtick.color": INK2, "ytick.color": INK2, "axes.titleweight": "bold",
    "axes.titlesize": 11, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8,
    "axes.axisbelow": True, "legend.frameon": False, "figure.dpi": 150,
})


def latest_run() -> Path:
    runs = sorted(p for p in Path("results").glob("2*") if (p / "raw.csv").exists())
    if not runs:
        sys.exit("không có results/<run_id>/raw.csv — chạy make bench trước")
    return runs[-1]


def summarize(raw: pd.DataFrame) -> pd.DataFrame:
    g = raw.groupby(KEYS, sort=False)[METRICS]
    s = g.agg(["mean", "std", "count"])
    s.columns = [f"{m}_{a if a != 'count' else 'n'}" for m, a in s.columns]
    # n chung = số lần đo của nhóm
    s.insert(0, "n", raw.groupby(KEYS, sort=False).size())
    s = s.drop(columns=[c for c in s.columns if c.endswith("_n")])
    return s.reset_index()


def ordered(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["config"] = pd.Categorical(df["config"], CONFIGS, ordered=True)
    return df.sort_values(["config", "rules"])


def bars(ax, d: pd.DataFrame, metric: str, scale: float, fmt: str, ylabel: str, title: str):
    d = ordered(d)
    x = range(len(d))
    names = [str(c) for c in d["config"]]
    ax.bar(x, d[f"{metric}_mean"] / scale, yerr=d[f"{metric}_std"].fillna(0) / scale,
           color=[COLOR[c] for c in names], width=0.7, edgecolor="white", linewidth=2,
           error_kw={"ecolor": INK2, "elinewidth": 1, "capsize": 3})
    for i, v in zip(x, d[f"{metric}_mean"] / scale):
        ax.annotate(fmt.format(v), (i, v), xytext=(0, 3), textcoords="offset points",
                    ha="center", va="bottom", fontsize=8, color=INK)
    ax.set_xticks(list(x), names, rotation=30, ha="right")
    ax.set_ylabel(ylabel)
    ax.set_title(title, loc="left")
    ax.grid(axis="x", visible=False)


def plot_drop_cost(s: pd.DataFrame, out: Path, note: str):
    d = s[s.experiment == "drop_cost"]
    if d.empty:
        return
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(12, 4.6))
    bars(a1, d[d.load_mode == "max"], "sent_pps", 1e3, "{:.0f}k",
         "nghìn gói/s", "pps tối đa với 1 luồng gửi (cao hơn = lọc rẻ hơn)")
    bars(a2, d[d.load_mode == "fixed"], "cpu_busy_pct", 1, "{:.1f}",
         "%sys+%irq+%soft cộng 8 CPU (0–800)", "CPU ở tải cố định (thấp hơn = tốt hơn)")
    fig.suptitle("Đo 1 — chi phí drop flood UDP 64 B (1 rule khớp)", x=0.01, ha="left",
                 fontweight="bold")
    fig.text(0.01, 0.005, note, fontsize=7.5, color=INK2)
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.savefig(out / "drop_cost.png")
    plt.close(fig)


def lines(ax, d: pd.DataFrame, metric: str, scale: float, ylabel: str, title: str):
    for cfg in CONFIGS:
        c = d[d.config == cfg].sort_values("rules")
        if c.empty or c[f"{metric}_mean"].isna().all():
            continue
        ax.errorbar(c["rules"], c[f"{metric}_mean"] / scale, yerr=c[f"{metric}_std"].fillna(0) / scale,
                    color=COLOR[cfg], lw=2, marker="o", ms=5, capsize=3, elinewidth=1,
                    markeredgecolor="white", markeredgewidth=1.5, label=cfg)
    ax.set_xscale("log")
    ax.set_xticks([10, 100, 1000, 10000], ["10", "100", "1 000", "10 000"])
    ax.set_xlabel("số rule (rule khớp đặt cuối)")
    ax.set_ylabel(ylabel)
    ax.set_title(title, loc="left")
    ax.set_ylim(bottom=0)


def plot_rule_scaling(s: pd.DataFrame, out: Path, note: str):
    d = s[s.experiment == "rule_scaling"]
    if d.empty:
        return
    fig, (a1, a2, a3) = plt.subplots(1, 3, figsize=(15, 4.8))
    lines(a1, d[d.load_mode == "max"], "sent_pps", 1e3, "nghìn gói/s", "pps tối đa, 1 luồng")
    lines(a2, d[d.load_mode == "fixed"], "cpu_busy_pct", 1, "CPU (0–800)", "CPU ở tải cố định")
    lines(a3, d[(d.load_mode == "fixed") & d.config.str.startswith("xdp")], "xdp_ns_per_pkt", 1,
          "ns / gói (bpf_stats)", "Chi phí thuần chương trình XDP")
    h, lab = a1.get_legend_handles_labels()
    fig.legend(h, lab, loc="upper right", ncol=len(lab), fontsize=8.5)
    fig.suptitle("Đo 2 — mở rộng theo số rule", x=0.01, ha="left", fontweight="bold")
    fig.text(0.01, 0.005, note, fontsize=7.5, color=INK2)
    fig.tight_layout(rect=(0, 0.05, 1, 0.93))
    fig.savefig(out / "rule_scaling.png")
    plt.close(fig)


def plot_legit(s: pd.DataFrame, out: Path, note: str):
    d = s[s.experiment == "legit_impact"]
    if d.empty:
        return
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(12, 4.6))
    cfgs = [c for c in CONFIGS if c in set(d.config)]
    w = 0.38
    for ax, metric, scale, ylabel, title in (
        (a1, "legit_mbps", 1e3, "Gbit/s", "Throughput TCP của client (iperf3)"),
        (a2, "rtt_p99_ms", 1, "ms", "RTT p99 của client (ping)"),
    ):
        for k, (mode, alpha, lab) in enumerate((("none", 0.45, "không flood"), ("fixed", 1.0, "có flood"))):
            m = d[d.load_mode == mode].set_index("config").reindex(cfgs)
            xs = [i + (k - 0.5) * w for i in range(len(cfgs))]
            ax.bar(xs, m[f"{metric}_mean"] / scale, yerr=m[f"{metric}_std"].fillna(0) / scale, width=w,
                   color=[COLOR[c] for c in cfgs], alpha=alpha, edgecolor="white", linewidth=2,
                   error_kw={"ecolor": INK2, "elinewidth": 1, "capsize": 2}, label=lab)
        ax.set_xticks(range(len(cfgs)), cfgs, rotation=30, ha="right")
        ax.set_ylabel(ylabel)
        ax.set_title(title, loc="left")
        ax.grid(axis="x", visible=False)
    # chú giải độ đậm: nhạt = không flood, đậm = có flood
    from matplotlib.patches import Patch
    fig.legend(handles=[Patch(color=INK2, alpha=0.45, label="không flood"),
                        Patch(color=INK2, label="có flood (tải cố định)")],
               loc="upper right", ncol=2, fontsize=8.5)
    fig.suptitle("Đo 3 — ảnh hưởng tới traffic hợp lệ", x=0.01, ha="left", fontweight="bold")
    fig.text(0.01, 0.005, note, fontsize=7.5, color=INK2)
    fig.tight_layout(rect=(0, 0.05, 1, 0.95))
    fig.savefig(out / "legit_impact.png")
    plt.close(fig)


def env_note(run: Path) -> str:
    env = {}
    f = run / "env.txt"
    if f.exists():
        for line in f.read_text(encoding="utf-8").splitlines():
            if ":" in line and not line.startswith(("#", " ")):
                k, v = line.split(":", 1)
                env[k.strip()] = v.strip()
    return textwrap.fill(f"run {run.name} · kernel {env.get('kernel', '?')} · {env.get('cpu_model', '?')} · "
            f"{env.get('nproc', '?')} vCPU (WSL2, veth) · {env.get('params', '')} · thanh lỗi = ±1 std", width=170)


def main():
    run = Path(sys.argv[1]) if len(sys.argv) > 1 else latest_run()
    raw = pd.read_csv(run / "raw.csv")
    s = summarize(raw)
    s.to_csv(run / "summary.csv", index=False, float_format="%.3f")
    note = env_note(run)
    plot_drop_cost(s, run, note)
    plot_rule_scaling(s, run, note)
    plot_legit(s, run, note)
    print(f"{run}: {len(raw)} lần đo -> summary.csv ({len(s)} nhóm), "
          + ", ".join(p.name for p in sorted(run.glob("*.png"))))


if __name__ == "__main__":
    main()
