from backend.models.verdict import VerdictLabel

PALETTE = {
    VerdictLabel.SAFE: {
        "sky": "#D6E9F2",
        "water": "#BBDDEC",
        "sun": "#F4C95D",
        "sand": "#E8C691",
        "accent": "#6BAF7D",
    },
    VerdictLabel.SUSPICIOUS: {
        "sky": "#F4D9B5",
        "water": "#7EB8D9",
        "sun": "#F4C95D",
        "sand": "#E8C691",
        "accent": "#F0A04B",
    },
    VerdictLabel.MALICIOUS: {
        "sky": "#F4B5A5",
        "water": "#4A8FC7",
        "sun": "#E54F4F",
        "sand": "#E8C691",
        "accent": "#E54F4F",
    },
    VerdictLabel.UNKNOWN: {
        "sky": "#E0E0E0",
        "water": "#A0A0A0",
        "sun": "#C0C0C0",
        "sand": "#D0D0D0",
        "accent": "#808080",
    },
}

# Wave path per state - `M x,y ... Z` defines the water silhouette.
# SAFE: gentle rolling wave. SUSPICIOUS: choppier alternating peaks/troughs.
# MALICIOUS: a single large breaking wave (cubic curves).
WAVE_PATHS = {
    VerdictLabel.SAFE: (
        "M 0 100 Q 40 97 80 100 T 160 100 T 240 100 T 320 100 "
        "L 320 130 L 0 130 Z"
    ),
    VerdictLabel.SUSPICIOUS: (
        "M 0 96 Q 15 80 30 96 Q 45 110 60 96 Q 75 80 90 96 Q 105 112 120 96 "
        "Q 135 80 150 96 Q 165 112 180 96 Q 195 80 210 96 Q 225 112 240 96 "
        "Q 255 80 270 96 Q 285 112 300 96 Q 312 84 320 96 L 320 128 L 0 128 Z"
    ),
    VerdictLabel.MALICIOUS: (
        "M 0 70 C 40 38 80 28 120 54 C 160 80 200 28 230 36 "
        "C 260 44 290 76 320 60 L 320 128 L 0 128 Z"
    ),
    VerdictLabel.UNKNOWN: "M 0 100 L 320 100 L 320 130 L 0 130 Z",
}


def render_wave_svg(label: VerdictLabel, score: int) -> str:
    p = PALETTE[label]
    wave = WAVE_PATHS[label]
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 320 150" preserveAspectRatio="xMidYMid slice">
  <rect x="0" y="0" width="320" height="100" fill="{p['sky']}"/>
  <circle cx="248" cy="48" r="13" fill="{p['sun']}" opacity="0.9"/>
  <path d="{wave}" fill="{p['water']}"/>
  <path d="M 0 128 Q 160 124 320 128 L 320 150 L 0 150 Z" fill="{p['sand']}"/>
  <text x="160" y="142" font-family="DM Sans, sans-serif" font-size="11" font-weight="600"
        text-anchor="middle" fill="{p['accent']}">{label.value} · {score}/100</text>
</svg>"""
