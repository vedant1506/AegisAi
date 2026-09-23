#!/usr/bin/env python3
"""
AegisAI — Master Orchestrator (start_all.py)
=============================================
One-click launcher for the entire AegisAI platform:
  1. FastAPI Backend (http://127.0.0.1:8000)
  2. Next.js Frontend Dashboard (http://localhost:3000)

Features:
  - Auto-locates project virtual environment (venv)
  - Auto-locates compatible Node.js LTS (v24+)
  - Live log streaming with colour-coded service tags
  - Health checks: waits for both services to be ready
  - Clean shutdown: press Ctrl+C to cleanly terminate all processes
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

# Ensure UTF-8 output and unbuffered streams
os.environ["PYTHONUNBUFFERED"] = "1"
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

def print_flush(msg: str = "") -> None:
    print(msg, flush=True)

# ── Color codes for console output ───────────────────────────
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[32m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
RED = "\033[31m"

def print_banner() -> None:
    banner = f"""{CYAN}{BOLD}
    ===============================================================
       _    ____ ____ ___ ____     _    ___
      / \\  | ____/ ___|_ _/ ___|   / \\  |_ _|
     / _ \\ |  _|| |  _ | |\\___ \\  / _ \\  | |
    / ___ \\| |__| |_| || | ___) |/ ___ \\ | |
   /_/   \\_\\_____\\____|___|____//_/   \\_\\___|
   
   Autonomous Multi-Agent Application Security & VAPT Platform
    ==============================================================={RESET}
    """
    print_flush(banner)

def find_project_root() -> Path:
    """Find the AegisAi root folder whether run from PDS or PDS/AegisAi."""
    current = Path(__file__).resolve().parent
    if (current / "backend").exists() and (current / "frontend").exists():
        return current
    if (current / "AegisAi").exists():
        return current / "AegisAi"
    return current

PROJECT_ROOT = find_project_root()
BACKEND_DIR = PROJECT_ROOT / "backend"
FRONTEND_DIR = PROJECT_ROOT / "frontend"

def find_python_executable() -> str:
    """Locate the virtualenv Python or fallback to current sys.executable."""
    candidates = [
        PROJECT_ROOT / "venv" / "Scripts" / "python.exe",
        PROJECT_ROOT.parent / "venv" / "Scripts" / "python.exe",
        Path(sys.executable),
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    return sys.executable

def resolve_node_and_npm() -> tuple[str, dict[str, str]]:
    """Ensure Node.js 18.18+ or 24+ is used for npm execution."""
    env = os.environ.copy()
    winget_node_dirs = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WinGet" / "Packages" / "OpenJS.NodeJS.LTS_Microsoft.Winget.Source_8wekyb3d8bbwe" / "node-v24.19.0-win-x64",
    ]
    for n_dir in winget_node_dirs:
        node_exe = n_dir / "node.exe"
        npm_cmd = n_dir / "npm.cmd"
        if node_exe.exists() and npm_cmd.exists():
            current_path = env.get("PATH", "")
            env["PATH"] = f"{str(n_dir)};{current_path}"
            return str(npm_cmd), env

    # Fallback to standard npm
    npm_name = "npm.cmd" if sys.platform == "win32" else "npm"
    return npm_name, env

class ProcessManager:
    def __init__(self) -> None:
        self.processes: list[subprocess.Popen] = []
        self._shutting_down = False

    def stream_output(self, pipe, prefix: str, color: str) -> None:
        """Stream subprocess stdout/stderr line by line with tagged prefix."""
        try:
            for line in iter(pipe.readline, ""):
                if not line:
                    break
                stripped = line.rstrip()
                if stripped:
                    print(f"{color}[{prefix}]{RESET} {stripped}")
        except Exception:
            pass

    def start_process(self, cmd: list[str], cwd: Path, name: str, color: str, env: dict[str, str] | None = None) -> subprocess.Popen:
        """Spawn a managed subprocess with output streaming."""
        use_shell = sys.platform == "win32" and cmd[0].endswith(".cmd")
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            env=env or os.environ.copy(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            shell=use_shell,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
        )
        self.processes.append(proc)
        t = threading.Thread(target=self.stream_output, args=(proc.stdout, name, color), daemon=True)
        t.start()
        return proc

    def stop_all(self) -> None:
        """Gracefully terminate all running subprocesses."""
        if self._shutting_down:
            return
        self._shutting_down = True
        print(f"\n{YELLOW}[AegisAI] Stopping all services...{RESET}")
        for proc in self.processes:
            try:
                if sys.platform == "win32":
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                else:
                    proc.terminate()
            except Exception:
                pass
        print(f"{GREEN}[AegisAI] All services stopped cleanly.{RESET}")

def wait_for_url(url: str, timeout: int = 40, service_name: str = "Service") -> bool:
    """Poll an HTTP URL until it returns 200 or timeout expires."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "AegisAI-Launcher"})
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(1)
    return False

def main() -> None:
    parser = argparse.ArgumentParser(description="Start all AegisAI services.")
    parser.add_argument("--no-frontend", action="store_true", help="Do not start frontend dev server")
    parser.add_argument("--no-backend", action="store_true", help="Do not start backend API server")
    parser.add_argument("--with-testbed", action="store_true", help="Also start vulnerable target testbed on port 8081")
    parser.add_argument("--browser", action="store_true", default=True, help="Auto-open browser when ready")
    parser.add_argument("--no-browser", dest="browser", action="store_false", help="Do not open browser")
    args = parser.parse_args()

    print_banner()

    python_exe = find_python_executable()
    npm_path, node_env = resolve_node_and_npm()

    print_flush(f"{CYAN}* Project Root:{RESET} {PROJECT_ROOT}")
    print_flush(f"{CYAN}* Python:{RESET}       {python_exe}")
    print_flush(f"{CYAN}* NPM / Node:{RESET}   {npm_path}")
    print_flush(f"{CYAN}* Working Dir:{RESET}  {os.getcwd()}")
    print_flush("-" * 65)

    pm = ProcessManager()

    # Register signal handler
    def handle_sigint(sig, frame):
        pm.stop_all()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigint)

    # ── 1. Start Backend ──────────────────────────────────────
    if not args.no_backend:
        print_flush(f"{GREEN}{BOLD}[1/2] Starting FastAPI Backend on http://127.0.0.1:8000 ...{RESET}")
        backend_cmd = [
            python_exe,
            "-m",
            "uvicorn",
            "main:app",
            "--host",
            "127.0.0.1",
            "--port",
            "8000",
            "--reload",
        ]
        pm.start_process(backend_cmd, BACKEND_DIR, "BACKEND", CYAN)
    else:
        print_flush(f"{YELLOW}[1/2] Backend skipped (--no-backend){RESET}")

    # ── 2. Start Frontend ─────────────────────────────────────
    if not args.no_frontend:
        print_flush(f"{MAGENTA}{BOLD}[2/2] Starting Next.js Frontend on http://localhost:3000 ...{RESET}")
        frontend_cmd = [npm_path, "run", "dev"]
        pm.start_process(frontend_cmd, FRONTEND_DIR, "FRONTEND", MAGENTA, env=node_env)
    else:
        print_flush(f"{YELLOW}[2/2] Frontend skipped (--no-frontend){RESET}")

    # ── 3. Start Target Testbed (Optional) ────────────────────
    if args.with_testbed:
        testbed_script = PROJECT_ROOT / "crawler_dast" / "target_docker" / "custom_auth_testbed" / "app.py"
        if testbed_script.exists():
            print_flush(f"{YELLOW}{BOLD}[+] Starting Vulnerable Testbed on http://127.0.0.1:8081 ...{RESET}")
            testbed_cmd = [python_exe, str(testbed_script)]
            pm.start_process(testbed_cmd, testbed_script.parent, "TESTBED", YELLOW)

    # ── 4. Health Checks ──────────────────────────────────────
    print_flush(f"\n{YELLOW}[AegisAI] Waiting for services to initialize...{RESET}")

    backend_ok = True
    if not args.no_backend:
        backend_ok = wait_for_url("http://127.0.0.1:8000/health", timeout=25, service_name="Backend")
        if backend_ok:
            print_flush(f"{GREEN}[OK] Backend is ready and healthy! (http://127.0.0.1:8000){RESET}")
        else:
            print_flush(f"{RED}[!] Backend took longer than expected to report healthy.{RESET}")

    frontend_ok = True
    if not args.no_frontend:
        frontend_ok = wait_for_url("http://localhost:3000", timeout=35, service_name="Frontend")
        if frontend_ok:
            print_flush(f"{GREEN}[OK] Frontend is ready! (http://localhost:3000){RESET}")
        else:
            print_flush(f"{RED}[!] Frontend took longer than expected to respond.{RESET}")

    # ── 4. Ready Status Summary ───────────────────────────────
    print_flush("\n" + "=" * 65)
    print_flush(f"{GREEN}{BOLD}    AegisAI is up and running!{RESET}")
    print_flush("=" * 65)
    print_flush(f"  * {BOLD}Dashboard UI:{RESET}     {CYAN}http://localhost:3000{RESET}")
    print_flush(f"  * {BOLD}Backend API:{RESET}      {CYAN}http://127.0.0.1:8000{RESET}")
    print_flush(f"  * {BOLD}API Docs (Swagger):{RESET} {CYAN}http://127.0.0.1:8000/docs{RESET}")
    print_flush("=" * 65)
    print_flush(f"{YELLOW}Press Ctrl+C at any time to gracefully stop all services.{RESET}\n")

    if args.browser and frontend_ok:
        try:
            webbrowser.open("http://localhost:3000")
        except Exception:
            pass

    # Keep main thread alive monitoring children
    try:
        while True:
            time.sleep(1)
            for p in pm.processes:
                ret = p.poll()
                if ret is not None and not pm._shutting_down:
                    print(f"{RED}[AegisAI] A managed service exited unexpectedly (code {ret}). Shutting down.{RESET}")
                    pm.stop_all()
                    sys.exit(ret)
    except KeyboardInterrupt:
        pm.stop_all()
        sys.exit(0)

if __name__ == "__main__":
    main()
