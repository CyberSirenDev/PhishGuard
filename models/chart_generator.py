import os
import io
import math
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend — safe for server use
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np


# ── Colour palette (matches the UI dark theme) ────────────────────────────────
BG      = '#111111'
ACCENT  = '#6366f1'
GREEN   = '#22c55e'
RED     = '#ef4444'
YELLOW  = '#eab308'
MUTED   = '#888888'
TEXT    = '#f0f0f0'


def _score_color(score):
    if score >= 70: return RED
    if score >= 40: return YELLOW
    return GREEN


# ── 1. Risk Score Gauge ───────────────────────────────────────────────────────
def generate_gauge_chart(risk_score: float) -> bytes:
    """Returns a PNG (bytes) of a half-donut risk-score gauge."""
    fig, ax = plt.subplots(figsize=(4, 2.2), facecolor=BG)
    ax.set_aspect('equal')
    ax.axis('off')

    # Background arc
    theta = np.linspace(0, np.pi, 200)
    ax.plot(np.cos(theta), np.sin(theta), lw=18, color='#2a2a2a', solid_capstyle='round')

    # Filled arc proportional to score
    end_angle = np.pi * (1 - risk_score / 100)
    theta_filled = np.linspace(end_angle, np.pi, 200)
    col = _score_color(risk_score)
    ax.plot(np.cos(theta_filled), np.sin(theta_filled), lw=18, color=col, solid_capstyle='round')

    # Score text
    ax.text(0, 0.1, f"{int(risk_score)}", ha='center', va='center',
            fontsize=38, fontweight='bold', color=col)
    ax.text(0, -0.22, 'Risk Score', ha='center', va='center',
            fontsize=9, color=MUTED)

    verdict = 'PHISHING' if risk_score >= 70 else 'SUSPICIOUS' if risk_score >= 40 else 'SAFE'
    ax.text(0, -0.48, verdict, ha='center', va='center',
            fontsize=10, fontweight='bold', color=col)

    ax.set_xlim(-1.2, 1.2)
    ax.set_ylim(-0.7, 1.15)

    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=130, bbox_inches='tight',
                facecolor=BG, transparent=False)
    plt.close(fig)
    buf.seek(0)
    return buf.read()


# ── 2. Radar Chart ────────────────────────────────────────────────────────────
def generate_radar_chart(features: dict) -> bytes:
    """
    Returns a PNG (bytes) of a radar/spider chart summarising 6 key risk
    dimensions, each normalised to 0-1.
    """
    labels = ['URL Length', 'Entropy', 'Subdomains', 'Keywords', 'Hyphens', 'No HTTPS']

    url_len  = min(features.get('url_length', 0) / 200, 1.0)
    entropy  = min(features.get('url_entropy', 0) / 6.0, 1.0)
    subs     = min(features.get('num_subdomains', 0) / 5.0, 1.0)
    keywords = min(features.get('suspicious_keyword_count', 0) / 5.0, 1.0)
    hyphens  = min(features.get('num_hyphens', 0) / 8.0, 1.0)
    no_https = 1.0 if features.get('is_https', 1) == 0 else 0.0

    values = [url_len, entropy, subs, keywords, hyphens, no_https]

    N = len(labels)
    angles = [n / float(N) * 2 * math.pi for n in range(N)]
    angles += angles[:1]
    values += values[:1]

    fig, ax = plt.subplots(figsize=(3.8, 3.8), facecolor=BG,
                           subplot_kw=dict(polar=True))
    ax.set_facecolor(BG)

    # Grid
    ax.set_theta_offset(math.pi / 2)
    ax.set_theta_direction(-1)
    ax.set_rlim(0, 1)
    ax.set_yticklabels([])
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(labels, fontsize=7.5, color=MUTED)
    ax.tick_params(colors=MUTED)
    ax.spines['polar'].set_color('#2e2e2e')
    ax.grid(color='#2e2e2e', linewidth=0.8)

    # Fill
    ax.fill(angles, values, color=ACCENT, alpha=0.25)
    ax.plot(angles, values, color=ACCENT, linewidth=1.8)

    # Dots at each vertex
    ax.scatter(angles[:-1], values[:-1], s=40, color=ACCENT, zorder=5)

    fig.patch.set_facecolor(BG)

    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=130, bbox_inches='tight',
                facecolor=BG, transparent=False)
    plt.close(fig)
    buf.seek(0)
    return buf.read()


# ── 3. Feature Bar Chart ──────────────────────────────────────────────────────
def generate_bar_chart(features: dict) -> bytes:
    """
    Returns a PNG (bytes) of a horizontal bar chart of the most important
    raw feature values.
    """
    items = [
        ('URL Length',      features.get('url_length', 0)),
        ('Domain Length',   features.get('domain_length', 0)),
        ('URL Entropy',     round(features.get('url_entropy', 0), 2)),
        ('Domain Entropy',  round(features.get('domain_entropy', 0), 2)),
        ('Subdomains',      features.get('num_subdomains', 0)),
        ('Keywords',        features.get('suspicious_keyword_count', 0)),
        ('Hyphens',         features.get('num_hyphens', 0)),
        ('Domain Age (d)',  features.get('domain_age_days', -1)),
    ]
    labels = [i[0] for i in items]
    vals   = [max(i[1], 0) for i in items]   # clamp negative to 0 for display

    fig, ax = plt.subplots(figsize=(5, 3.2), facecolor=BG)
    ax.set_facecolor('#1a1a1a')

    bar_colors = [ACCENT] * len(vals)
    # Highlight suspicious values
    kw_idx = labels.index('Keywords')
    if vals[kw_idx] > 0: bar_colors[kw_idx] = RED
    s_idx = labels.index('Subdomains')
    if vals[s_idx] > 2:  bar_colors[s_idx]  = YELLOW

    bars = ax.barh(labels, vals, color=bar_colors, height=0.55, zorder=3)

    # Value labels
    for bar, val in zip(bars, [i[1] for i in items]):
        ax.text(bar.get_width() + max(max(vals)*0.01, 0.2), bar.get_y() + bar.get_height()/2,
                str(val), va='center', fontsize=7.5, color=TEXT)

    ax.tick_params(axis='y', colors=MUTED, labelsize=8)
    ax.tick_params(axis='x', colors='#444', labelsize=7)
    ax.spines[['top', 'right', 'left']].set_visible(False)
    ax.spines['bottom'].set_color('#2e2e2e')
    ax.set_xlabel('Value', fontsize=7.5, color=MUTED)
    ax.grid(axis='x', color='#2e2e2e', linewidth=0.7, zorder=0)
    ax.set_xlim(0, max(vals) * 1.2 + 1)

    fig.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=130, bbox_inches='tight',
                facecolor=BG, transparent=False)
    plt.close(fig)
    buf.seek(0)
    return buf.read()


if __name__ == '__main__':
    # Quick smoke test
    test_feats = {
        'url_length': 85, 'domain_length': 32, 'url_entropy': 4.5,
        'domain_entropy': 3.8, 'num_subdomains': 3, 'suspicious_keyword_count': 4,
        'num_hyphens': 5, 'domain_age_days': 12, 'is_https': 0
    }
    os.makedirs('tmp', exist_ok=True)
    with open('tmp/gauge.png',  'wb') as f: f.write(generate_gauge_chart(85))
    with open('tmp/radar.png',  'wb') as f: f.write(generate_radar_chart(test_feats))
    with open('tmp/bars.png',   'wb') as f: f.write(generate_bar_chart(test_feats))
    print("Charts written to tmp/")
