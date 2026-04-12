#!/usr/bin/env python3
"""
Comparative QUIC implementation benchmark.

Measures throughput, handshake latency, and performance under network
impairment for zquic and other QUIC stacks.  Each implementation runs in
its own Docker container; `tc netem` simulates loss/delay on the loopback
bridge.

Usage:
    python3 bench/compare.py
    python3 bench/compare.py --impl zquic,quiche --sizes 1,10,100 --loss 0,1,5
    python3 bench/compare.py --delay 0,50,100 --runs 3

Requirements:
    - Docker (with buildx)
    - Python 3.8+
    - Root/sudo for tc netem (or Docker with NET_ADMIN)
"""

import argparse
import csv
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
DOCKER_DIR = SCRIPT_DIR / "dockerfiles"

# ── Implementation registry ──────────────────────────────────────────────────

@dataclass
class Implementation:
    """Describes how to build and run one QUIC implementation."""
    name: str
    dockerfile: str
    image_tag: str
    # Server command template.  Placeholders: {port}, {cert}, {key}, {www}
    server_cmd: str
    # Client command template.  Placeholders: {host}, {port}, {url}, {output}
    client_cmd: str
    # True if the implementation supports HTTP/3 file serving.
    # If False, we use HTTP/0.9 (raw file path on stream).
    h3: bool = False
    built: bool = False

IMPLEMENTATIONS = {
    "zquic": Implementation(
        name="zquic",
        dockerfile="Dockerfile.zquic",
        image_tag="bench-zquic",
        server_cmd=(
            "zquic-server --port {port} --cert {cert} --key {key}"
            " --www {www} --http09"
        ),
        client_cmd=(
            "zquic-client --host {host} --port {port}"
            " --url https://{host}:{port}/{filename}"
            " --output {output} --http09"
        ),
    ),
    "quiche": Implementation(
        name="quiche",
        dockerfile="Dockerfile.quiche",
        image_tag="bench-quiche",
        server_cmd=(
            "quiche-server --listen 0.0.0.0:{port}"
            " --cert {cert} --key {key} --root {www}"
            " --no-retry"
        ),
        client_cmd=(
            "quiche-client --no-verify"
            " https://{host}:{port}/{filename}"
            " --dump-response-body {output}/{filename}"
        ),
    ),
    "ngtcp2": Implementation(
        name="ngtcp2",
        dockerfile="Dockerfile.ngtcp2",
        image_tag="bench-ngtcp2",
        server_cmd=(
            "ngtcp2-server 0.0.0.0 {port}"
            " {key} {cert} -d {www}"
        ),
        client_cmd=(
            "ngtcp2-client {host} {port}"
            " https://{host}:{port}/{filename}"
            " -d {output}"
        ),
    ),
    "msquic": Implementation(
        name="msquic",
        dockerfile="Dockerfile.msquic",
        image_tag="bench-msquic",
        server_cmd=(
            "quicperf -listen:* -port:{port}"
            " -cert_file:{cert} -key_file:{key}"
            " -target:0 -upload:0 -download:{size_bytes}"
        ),
        client_cmd=(
            "quicperf -target:{host} -port:{port}"
            " -download:{size_bytes}"
        ),
    ),
}

# ── Docker helpers ───────────────────────────────────────────────────────────

DOCKER_NET = "bench-quic-net"
BENCH_PORT = 14433

def docker(*args, capture=False, check=True, timeout=None):
    """Run a docker command."""
    cmd = ["docker"] + list(args)
    if capture:
        return subprocess.run(cmd, capture_output=True, text=True,
                              check=check, timeout=timeout)
    return subprocess.run(cmd, check=check, timeout=timeout)

def build_image(impl: Implementation):
    """Build the Docker image for an implementation."""
    if impl.built:
        return
    df = DOCKER_DIR / impl.dockerfile
    if not df.exists():
        print(f"  ⚠ Dockerfile not found for {impl.name}: {df}")
        return
    print(f"  Building {impl.name} image ({impl.image_tag})...")
    ctx = PROJECT_ROOT if impl.name == "zquic" else DOCKER_DIR
    docker("build", "-t", impl.image_tag, "-f", str(df), str(ctx),
           timeout=600)
    impl.built = True

def ensure_network():
    """Create the benchmark Docker bridge network if it doesn't exist."""
    r = docker("network", "ls", "--format", "{{.Name}}", capture=True)
    if DOCKER_NET not in r.stdout.splitlines():
        docker("network", "create", DOCKER_NET)

def cleanup_containers():
    """Remove any leftover benchmark containers."""
    for suffix in ("server", "client"):
        docker("rm", "-f", f"bench-{suffix}", check=False,
               capture=True)

def generate_certs(cert_dir: Path):
    """Generate a self-signed ECDSA cert + key."""
    cert = cert_dir / "cert.pem"
    key = cert_dir / "priv.key"
    if cert.exists() and key.exists():
        return
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "ec",
        "-pkeyopt", "ec_paramgen_curve:P-256",
        "-keyout", str(key), "-out", str(cert),
        "-days", "1", "-nodes", "-subj", "/CN=bench",
    ], check=True, capture_output=True)

def create_test_file(www_dir: Path, size_mb: int) -> str:
    """Create a test file of the given size.  Returns the filename."""
    fname = f"bench_{size_mb}mb.bin"
    fpath = www_dir / fname
    if fpath.exists() and fpath.stat().st_size == size_mb * 1024 * 1024:
        return fname
    print(f"  Creating {size_mb} MB test file...")
    with open(fpath, "wb") as f:
        remaining = size_mb * 1024 * 1024
        chunk = 65536
        while remaining > 0:
            n = min(chunk, remaining)
            f.write(os.urandom(n))
            remaining -= n
    return fname

# ── Network impairment ───────────────────────────────────────────────────────

def apply_netem(container: str, delay_ms: int = 0, loss_pct: float = 0):
    """Apply tc netem impairment to a container's eth0."""
    parts = ["tc", "qdisc", "add", "dev", "eth0", "root", "netem"]
    if delay_ms > 0:
        parts += ["delay", f"{delay_ms}ms"]
    if loss_pct > 0:
        parts += ["loss", f"{loss_pct}%"]
    if delay_ms == 0 and loss_pct == 0:
        return  # nothing to apply
    docker("exec", container, *parts, check=False, capture=True)

def clear_netem(container: str):
    """Remove any netem qdisc."""
    docker("exec", container, "tc", "qdisc", "del", "dev", "eth0", "root",
           check=False, capture=True)

# ── Single benchmark run ─────────────────────────────────────────────────────

@dataclass
class BenchResult:
    impl: str
    size_mb: int
    delay_ms: int
    loss_pct: float
    run_idx: int
    elapsed_s: float = 0.0
    throughput_mbps: float = 0.0
    success: bool = False
    error: str = ""

def run_one(impl: Implementation, size_mb: int, delay_ms: int,
            loss_pct: float, run_idx: int, cert_dir: Path,
            www_dir: Path, dl_dir: Path) -> BenchResult:
    """Run a single benchmark: start server, transfer file, measure time."""
    result = BenchResult(
        impl=impl.name, size_mb=size_mb, delay_ms=delay_ms,
        loss_pct=loss_pct, run_idx=run_idx,
    )
    filename = create_test_file(www_dir, size_mb)
    size_bytes = size_mb * 1024 * 1024

    # Clean up any previous containers.
    cleanup_containers()

    # Prepare download directory (clean for this run).
    if dl_dir.exists():
        shutil.rmtree(dl_dir)
    dl_dir.mkdir(parents=True)

    # Format server command.
    srv_cmd = impl.server_cmd.format(
        port=BENCH_PORT, cert="/certs/cert.pem", key="/certs/priv.key",
        www="/www", size_bytes=size_bytes,
    )

    try:
        # Start server container.
        docker(
            "run", "-d", "--name", "bench-server",
            "--network", DOCKER_NET,
            "--cap-add", "NET_ADMIN",
            "-v", f"{cert_dir}:/certs:ro",
            "-v", f"{www_dir}:/www:ro",
            impl.image_tag,
            "sh", "-c", srv_cmd,
        )

        # Wait for server to be ready.
        time.sleep(0.5)

        # Apply network impairment to server container.
        if delay_ms > 0 or loss_pct > 0:
            apply_netem("bench-server", delay_ms=delay_ms // 2,
                        loss_pct=loss_pct)

        # Format client command.
        cli_cmd = impl.client_cmd.format(
            host="bench-server", port=BENCH_PORT, filename=filename,
            output="/downloads", size_bytes=size_bytes,
        )

        # Run client and time it.
        t0 = time.monotonic()
        r = docker(
            "run", "--name", "bench-client",
            "--network", DOCKER_NET,
            "--cap-add", "NET_ADMIN",
            "-v", f"{dl_dir}:/downloads",
            "-v", f"{cert_dir}:/certs:ro",
            impl.image_tag,
            "sh", "-c", cli_cmd,
            capture=True, check=False, timeout=120,
        )
        elapsed = time.monotonic() - t0

        if r.returncode == 0:
            # For msquic (perf tool), parse output; for file-based, check size.
            if impl.name == "msquic":
                result.elapsed_s = elapsed
                result.throughput_mbps = (size_bytes * 8) / (elapsed * 1e6)
                result.success = True
            else:
                dl_file = dl_dir / filename
                if dl_file.exists():
                    recv = dl_file.stat().st_size
                    result.elapsed_s = elapsed
                    result.throughput_mbps = (recv * 8) / (elapsed * 1e6)
                    result.success = recv == size_bytes
                    if not result.success:
                        result.error = f"incomplete: {recv}/{size_bytes}"
                else:
                    result.error = "download file not found"
        else:
            result.error = (r.stderr or r.stdout or "unknown error")[:200]

    except subprocess.TimeoutExpired:
        result.error = "timeout (120s)"
    except Exception as e:
        result.error = str(e)[:200]
    finally:
        cleanup_containers()

    return result

# ── Main benchmark driver ────────────────────────────────────────────────────

def print_table(results: list[BenchResult]):
    """Pretty-print results as an ASCII table."""
    if not results:
        print("No results.")
        return

    # Group by scenario.
    scenarios: dict[tuple, list[BenchResult]] = {}
    for r in results:
        key = (r.size_mb, r.delay_ms, r.loss_pct)
        scenarios.setdefault(key, []).append(r)

    print()
    print("=" * 90)
    print(f"{'Scenario':<30} {'Implementation':<15} {'Throughput':>12} "
          f"{'Time':>10} {'Status':>8}")
    print("=" * 90)

    for (size_mb, delay_ms, loss_pct), group in sorted(scenarios.items()):
        label = f"{size_mb}MB"
        if delay_ms > 0:
            label += f" +{delay_ms}ms"
        if loss_pct > 0:
            label += f" +{loss_pct}%loss"

        # Average across runs per implementation.
        by_impl: dict[str, list[BenchResult]] = {}
        for r in group:
            by_impl.setdefault(r.impl, []).append(r)

        first = True
        for impl_name, runs in sorted(by_impl.items()):
            ok_runs = [r for r in runs if r.success]
            if ok_runs:
                avg_tp = sum(r.throughput_mbps for r in ok_runs) / len(ok_runs)
                avg_t = sum(r.elapsed_s for r in ok_runs) / len(ok_runs)
                status = "OK"
                tp_str = f"{avg_tp:.1f} Mbps"
                t_str = f"{avg_t:.2f}s"
            else:
                status = "FAIL"
                tp_str = "-"
                t_str = "-"
                if runs:
                    status = runs[0].error[:8]

            scenario_col = label if first else ""
            first = False
            print(f"  {scenario_col:<28} {impl_name:<15} {tp_str:>12} "
                  f"{t_str:>10} {status:>8}")

        print("-" * 90)

    print()

def export_csv(results: list[BenchResult], path: Path):
    """Export results to CSV."""
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["implementation", "size_mb", "delay_ms", "loss_pct",
                     "run", "elapsed_s", "throughput_mbps", "success", "error"])
        for r in results:
            w.writerow([r.impl, r.size_mb, r.delay_ms, r.loss_pct,
                        r.run_idx, f"{r.elapsed_s:.3f}",
                        f"{r.throughput_mbps:.1f}", r.success, r.error])
    print(f"Results exported to {path}")

def export_json(results: list[BenchResult], path: Path):
    """Export results to JSON."""
    data = []
    for r in results:
        data.append({
            "implementation": r.impl,
            "size_mb": r.size_mb,
            "delay_ms": r.delay_ms,
            "loss_pct": r.loss_pct,
            "run": r.run_idx,
            "elapsed_s": round(r.elapsed_s, 3),
            "throughput_mbps": round(r.throughput_mbps, 1),
            "success": r.success,
            "error": r.error,
        })
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Results exported to {path}")

def main():
    parser = argparse.ArgumentParser(
        description="Comparative QUIC implementation benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 bench/compare.py
  python3 bench/compare.py --impl zquic,quiche --sizes 1,10,100
  python3 bench/compare.py --impl zquic,quiche,ngtcp2 --loss 0,1,5 --delay 0,50
  python3 bench/compare.py --runs 5 --export results.csv
        """,
    )
    parser.add_argument(
        "--impl", default="zquic,quiche",
        help="Comma-separated list of implementations to benchmark "
             f"(available: {','.join(IMPLEMENTATIONS.keys())})",
    )
    parser.add_argument(
        "--sizes", default="1,10",
        help="Comma-separated file sizes in MB (default: 1,10)",
    )
    parser.add_argument(
        "--delay", default="0",
        help="Comma-separated one-way delays in ms (default: 0)",
    )
    parser.add_argument(
        "--loss", default="0",
        help="Comma-separated loss percentages (default: 0)",
    )
    parser.add_argument(
        "--runs", type=int, default=3,
        help="Number of runs per scenario (default: 3)",
    )
    parser.add_argument(
        "--export", default=None,
        help="Export results to file (supports .csv and .json)",
    )
    parser.add_argument(
        "--skip-build", action="store_true",
        help="Skip Docker image build (use existing images)",
    )
    args = parser.parse_args()

    impl_names = [s.strip() for s in args.impl.split(",")]
    sizes = [int(s) for s in args.sizes.split(",")]
    delays = [int(s) for s in args.delay.split(",")]
    losses = [float(s) for s in args.loss.split(",")]

    # Validate implementations.
    impls = []
    for name in impl_names:
        if name not in IMPLEMENTATIONS:
            print(f"Unknown implementation: {name}")
            print(f"Available: {', '.join(IMPLEMENTATIONS.keys())}")
            sys.exit(1)
        impls.append(IMPLEMENTATIONS[name])

    print(f"\n{'='*60}")
    print(f"  zquic comparative benchmark")
    print(f"{'='*60}")
    print(f"  implementations : {', '.join(impl_names)}")
    print(f"  file sizes      : {', '.join(str(s) for s in sizes)} MB")
    print(f"  delays          : {', '.join(str(d) for d in delays)} ms")
    print(f"  loss rates      : {', '.join(str(l) for l in losses)} %")
    print(f"  runs per combo  : {args.runs}")
    print()

    # Set up temporary directories.
    tmpbase = Path(tempfile.mkdtemp(prefix="zquic_bench_"))
    cert_dir = tmpbase / "certs"
    www_dir = tmpbase / "www"
    dl_dir = tmpbase / "downloads"
    cert_dir.mkdir()
    www_dir.mkdir()
    dl_dir.mkdir()

    print(f"  temp directory  : {tmpbase}")
    print()

    try:
        # Generate certs.
        print("Generating TLS certificates...")
        generate_certs(cert_dir)

        # Build images.
        if not args.skip_build:
            print("Building Docker images...")
            for impl in impls:
                build_image(impl)
        print()

        # Ensure network.
        ensure_network()

        # Run benchmarks.
        results: list[BenchResult] = []
        total = len(impls) * len(sizes) * len(delays) * len(losses) * args.runs
        done = 0

        for size_mb in sizes:
            for delay_ms in delays:
                for loss_pct in losses:
                    for impl in impls:
                        for run_idx in range(args.runs):
                            done += 1
                            label = f"{impl.name} {size_mb}MB"
                            if delay_ms > 0:
                                label += f" +{delay_ms}ms"
                            if loss_pct > 0:
                                label += f" +{loss_pct}%"
                            print(f"  [{done}/{total}] {label} "
                                  f"(run {run_idx+1}/{args.runs})...",
                                  end="", flush=True)

                            r = run_one(
                                impl, size_mb, delay_ms, loss_pct, run_idx,
                                cert_dir, www_dir, dl_dir,
                            )
                            results.append(r)

                            if r.success:
                                print(f" {r.throughput_mbps:.1f} Mbps "
                                      f"({r.elapsed_s:.2f}s)")
                            else:
                                print(f" FAILED: {r.error[:60]}")

        # Print summary table.
        print_table(results)

        # Export if requested.
        if args.export:
            export_path = Path(args.export)
            if export_path.suffix == ".csv":
                export_csv(results, export_path)
            elif export_path.suffix == ".json":
                export_json(results, export_path)
            else:
                export_csv(results, export_path)

    finally:
        # Cleanup.
        cleanup_containers()
        docker("network", "rm", DOCKER_NET, check=False, capture=True)
        shutil.rmtree(tmpbase, ignore_errors=True)

if __name__ == "__main__":
    main()
