"""AES-128-GCM on Windows on ARM: what four implementations do, and whether
they hold it.

  windows-perf-arm64-cipher-libs   one core, and the decay over two minutes

The ARM64 counterpart of ciphercharts.py's first chart, minus its middle
panel: there is no Thunderbolt link on this machine to push the packets into,
so these are cipher numbers rather than transfer numbers.

  ciphercharts_arm64.py <datadir> <outdir>
"""
import csv
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import MultipleLocator

DATA, OUT = sys.argv[1], sys.argv[2]

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 11,
    "axes.spines.top": False, "axes.spines.right": False,
    "svg.fonttype": "none",
})

FOOT = ("QEMU virtual machine, 4 vCPU, Windows 11 Pro 26200 ARM64  ·  the host processor is not visible "
        "from inside the guest, so read the rates against each other, not against a laptop\n"
        "AES-128-GCM as SSH uses it: one complete GCM message per 32 KB packet, fresh IV, "
        "4 bytes of AAD, 16-byte tag, one thread, no network\n"
        "rsync 3.5.0 Windows port, github.com/nuket/rsync-windows  ·  © 2026 Max Vilimpoc")

# ISA-L is x86-64 assembly with no MSVC-buildable ARM64 equivalent, so its
# slot -- and its colour -- go to a hand-written NEON implementation, which
# asks the same question: what does doing the cipher ourselves buy here?
LIBS = [
    ("CNG",        "cng",      "#e08b4a"),
    ("NEON",       "neon",     "#1f6fb4"),
    ("OpenSSL 3",  "openssl3", "#2ca02c"),
    ("LibreSSL",   "libressl", "#d62728"),
]


def save(fig, name):
    for ext in ("svg", "png"):
        fig.savefig(os.path.join(OUT, "%s.%s" % (name, ext)), dpi=200,
                    bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote", name)


def footer(fig, extra=None, y=-0.02):
    fig.text(0.01, y, (extra + "\n" + FOOT) if extra else FOOT,
             fontsize=8, color="#666666", ha="left", va="top")


def read_peak():
    rows = csv.DictReader(open(os.path.join(DATA, "gcm-peak_arm64.csv")))
    return {r["lib"]: float(r["mbps"]) for r in rows}


def read_thr(tag):
    rows = csv.DictReader(open(os.path.join(DATA, "gcm-%s-thr_arm64.csv" % tag)))
    return [(float(r["t"]), float(r["mbps"])) for r in rows]


def stats(tag):
    v = [x[1] for x in read_thr(tag)]
    n = max(1, len(v) // 4)          # a 120 s run: the first and last 30 s
    first = sum(v[:n]) / n
    last = sum(v[-n:]) / n
    return {"mean": sum(v) / len(v), "first": first, "last": last,
            "decay": 100 * (1 - last / first)}


def libs_chart():
    fig, ax = plt.subplots(1, 2, figsize=(11, 5.2),
                           gridspec_kw={"width_ratios": [1.25, 1]})

    names = [l[0] for l in LIBS]
    cols = [l[2] for l in LIBS]
    x = range(len(LIBS))

    # --- what each one can do -------------------------------------------
    # Linear, as the x64 chart is: the two EVP builds come out as slivers a
    # fiftieth the height of CNG, which is the finding rather than a drawing
    # problem.  Every bar carries its number for the ratio.
    peak = read_peak()
    vals = [peak[l[1]] for l in LIBS]
    b = ax[0].bar(x, vals, 0.62, color=cols)
    for r in b:
        ax[0].annotate("%d" % r.get_height(),
                       xy=(r.get_x() + r.get_width() / 2, r.get_height()),
                       xytext=(0, 4), textcoords="offset points", ha="center",
                       fontsize=10, fontweight="bold")
    ax[0].set_ylim(0, 10000)
    ax[0].yaxis.set_major_locator(MultipleLocator(2000))
    ax[0].set_ylabel("MB/s, one core")
    ax[0].set_title("what the cipher can do\n(best of three interleaved rounds)",
                    fontsize=12, fontweight="bold", loc="left")
    ax[0].annotate("the two EVP builds carry no ARM64\n"
                   "assembly: this is table-driven AES\n"
                   "and a software GHASH",
                   xy=(0.49, 0.10), xycoords="axes fraction", fontsize=9,
                   color="#55555c")

    # --- and whether it holds it ----------------------------------------
    st = {l[1]: stats(l[1]) for l in LIBS}
    dec = [-st[l[1]]["decay"] for l in LIBS]
    b = ax[1].bar(x, dec, 0.62, color=cols)
    for r, d in zip(b, dec):
        ax[1].annotate("%+.1f%%" % d, xy=(r.get_x() + r.get_width() / 2, r.get_height()),
                       xytext=(0, 5 if d >= 0 else -15), textcoords="offset points",
                       ha="center", fontsize=10, fontweight="bold")
    ax[1].axhline(0, color="#9a9aa2", lw=0.9)
    span = max(3.0, max(abs(d) for d in dec) * 1.6)
    ax[1].set_ylim(-span, span)
    ax[1].set_ylabel("throughput change over 2 min, %")
    ax[1].set_title("how much it throttles away\n(last 30 s vs first 30 s)",
                    fontsize=12, fontweight="bold", loc="left")

    for a in ax:
        a.set_xticks(list(x))
        a.set_xticklabels(names, fontsize=10)
        a.grid(True, axis="y", color="#e2e2e8", lw=0.8)
        a.set_axisbelow(True)

    fig.suptitle("The same cipher, four implementations on Windows on ARM: here the platform's own is the fast one",
                 x=0.008, ha="left", fontsize=14, fontweight="bold", y=1.045)
    fig.subplots_adjust(wspace=0.30)
    footer(fig,
           "ISA-L is x86-64 assembly and has no ARM64 build, so its slot goes to a hand-written NEON "
           "implementation -- AESE/AESMC and PMULL through MSVC intrinsics, four blocks in flight, one "
           "reduction per four --\nwhich answers the same question: what is there to win by doing the cipher "
           "ourselves?  On x64 that was worth 55% over CNG; here it costs half.  It is checked against CNG, "
           "OpenSSL and LibreSSL over a whole\n32 KB packet, ciphertext and tag, before it is allowed to "
           "report a number.  Nothing here throttles much: a virtual machine's clock is the host's business.",
           y=-0.05)
    save(fig, "windows-perf-arm64-cipher-libs")


libs_chart()
