#!/usr/bin/env python3
"""devhub: tracks the dev servers you run under your project folders and serves a
dashboard + reverse proxy for them, reachable from any device over Tailscale.

    python3 devhub.py serve     run the hub (launchd does this for you, see install.sh)
    python3 devhub.py list      print known servers

Routing (all on one port):
    http://<hub>/                    dashboard
    http://<hub>/<name>/...          proxied to that server (prefix stripped)
    http://<name>.<domain>/...       proxied to that server (needs wildcard DNS, see README)

Standard library only.
"""
import asyncio
import ctypes
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit, unquote

HOME = Path.home()
DATA_DIR = Path(os.environ.get("DEVHUB_HOME", HOME / ".devhub")).expanduser()
CONFIG_PATH = DATA_DIR / "config.json"
STATE_PATH = DATA_DIR / "servers.json"
LOG_DIR = DATA_DIR / "logs"
UI_PATH = Path(__file__).resolve().with_name("dashboard.html")
SELF_DIR = str(Path(__file__).resolve().parent)

DEFAULT_CONFIG = {
    "roots": ["~/Documents", "~/Developer"],
    "port": 80,
    "domain": "",
    "listen_tailscale": True,
    # Tailscale logins allowed in; empty = only the account this Mac is signed into. "*" = whole tailnet.
    "allowed_users": [],
    "poll_seconds": 3,
    "discover_minutes": 15,
    # After launching an always-on project, wait this long for it to come up before trying again.
    "start_grace_seconds": 300,
    "https_port": 443,
    "tls_cert": str(DATA_DIR / "certs" / "fullchain.pem"),
    "tls_key": str(DATA_DIR / "certs" / "privkey.pem"),
    "ignore_ports": [],
    "ignore_paths": [],
    # Infrastructure that listens on ports but isn't a dev server you'd open.
    "ignore_commands": ["limactl", "colima", "com.docker.backend", "vpnkit", "ssh", "ollama"],
}

SHELLS = {"zsh", "bash", "sh", "fish", "dash", "ksh", "tcsh", "csh", "login", "tmux", "screen", "sudo"}
# Never dev servers, even when started from a project folder (matched as name prefixes).
ALWAYS_IGNORE = ("Google Chrome", "Chromium", "chrome", "Microsoft Edge", "Brave Browser", "firefox",
                 "Code Helper", "Cursor Helper", "Electron")
# Files that mark the top of a project: one card per folder holding one of these.
PROJECT_MARKERS = ("package.json", "pyproject.toml", "requirements.txt", "manage.py", "Cargo.toml",
                   "go.mod", "Gemfile", "composer.json", "deno.json", ".git")
TEMP_DIRS = ("/tmp/", "/private/tmp/", "/var/folders/", "/private/var/folders/")
# Ports that aren't web pages: the dashboard shows an address to connect to instead of "Open".
NON_WEB_PORTS = {25565: "Minecraft", 19132: "Minecraft Bedrock", 5432: "PostgreSQL", 3306: "MySQL",
                 6379: "Redis", 27017: "MongoDB", 11434: "Ollama API"}
# Folder names too generic to be a useful URL on their own; prefixed with their parent.
GENERIC_NAMES = {"app", "apps", "web", "www", "site", "frontend", "backend", "client", "server",
                 "api", "src", "ui", "admin", "dashboard", "service", "services"}
# Environment captured from a running server so it can be restarted from the dashboard.
ENV_KEYS = {"PATH", "LANG", "LC_ALL", "VIRTUAL_ENV", "PYTHONPATH", "CONDA_PREFIX",
            "CONDA_DEFAULT_ENV", "PNPM_HOME", "BUN_INSTALL", "PORT", "HOST",
            "DJANGO_SETTINGS_MODULE", "__PYVENV_LAUNCHER__"}
ENV_PREFIXES = ("NODE_", "NVM_", "PYENV_", "FLASK_", "UV_")
TRUSTED_NETS = [ipaddress.ip_network(n) for n in
                ("127.0.0.0/8", "::1/128", "100.64.0.0/10", "fd7a:115c:a1e0::/48")]
HOP_HEADERS = {"connection", "keep-alive", "proxy-connection", "te", "trailer",
               "transfer-encoding", "upgrade", "expect", "host"}
TAILSCALE_BINS = ["/usr/local/bin/tailscale", "/opt/homebrew/bin/tailscale",
                  "/Applications/Tailscale.app/Contents/MacOS/Tailscale"]


def log(*args):
    print(time.strftime("%H:%M:%S"), *args, flush=True)


def load_config():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(exist_ok=True)
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        cfg.update(json.loads(CONFIG_PATH.read_text()))
    else:
        CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2) + "\n")
    if os.environ.get("DEVHUB_PORT"):
        cfg["port"] = int(os.environ["DEVHUB_PORT"])
    cfg["roots"] = [os.path.realpath(os.path.expanduser(r)) for r in cfg["roots"]]
    cfg["ignore_paths"] = [os.path.realpath(os.path.expanduser(p)) for p in cfg["ignore_paths"]]
    cfg["tls_cert"] = os.path.expanduser(cfg["tls_cert"])
    cfg["tls_key"] = os.path.expanduser(cfg["tls_key"])
    cfg["domain"] = (cfg.get("domain") or "").strip(".").lower()
    return cfg


# ---------------------------------------------------------------- process scanning

def run(args, timeout=15):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def under(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


def listening_sockets():
    """{pid: {port: [hosts to connect to]}} for every TCP listener we can see."""
    socks, pid = {}, None
    for line in run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpn"]).splitlines():
        if line.startswith("p"):
            pid = int(line[1:])
        elif line.startswith("n") and pid:
            addr, _, port = line[1:].rpartition(":")
            if not port.isdigit():
                continue
            addr = addr.strip("[]")
            if addr in ("*", "0.0.0.0"):
                hosts = ["127.0.0.1", "::1"]
            elif addr == "::":
                hosts = ["::1", "127.0.0.1"]
            else:
                hosts = [addr]
            known = socks.setdefault(pid, {}).setdefault(int(port), [])
            known.extend(h for h in hosts if h not in known)
    return socks


def process_table():
    """{pid: (ppid, pgid, executable name)}"""
    table = {}
    for line in run(["ps", "-axo", "pid=,ppid=,pgid=,comm="]).splitlines():
        parts = line.split(None, 3)
        if len(parts) == 4:
            table[int(parts[0])] = (int(parts[1]), int(parts[2]),
                                    os.path.basename(parts[3].strip()).lstrip("-"))
    return table


def group_usage():
    """{pgid: (cpu %, resident MB)} summed over every process in each process group."""
    usage = {}
    for line in run(["ps", "-axo", "pgid=,%cpu=,rss="]).splitlines():
        parts = line.split()
        if len(parts) == 3:
            cpu, mb = usage.get(int(parts[0]), (0.0, 0.0))
            usage[int(parts[0])] = (cpu + float(parts[1]), mb + int(parts[2]) / 1024)
    return usage


def cwds(pids):
    out, pid = {}, None
    if not pids:
        return out
    for line in run(["lsof", "-a", "-d", "cwd", "-p", ",".join(map(str, pids)), "-Fn"]).splitlines():
        if line.startswith("p"):
            pid = int(line[1:])
        elif line.startswith("n") and pid:
            out[pid] = line[1:]
    return out


def find_root(pid, table):
    """Topmost non-shell ancestor in the same process group: the thing you typed
    (`npm run dev`), not the worker that actually holds the socket."""
    pgid = table[pid][1]
    chain, cur = [pid], pid
    while True:
        parent = table[cur][0]
        if parent <= 1 or parent not in table or table[parent][1] != pgid:
            break
        chain.append(parent)
        cur = parent
    for p in reversed(chain):
        if table[p][2] not in SHELLS:
            return p
    return pid


_libc = ctypes.CDLL(None, use_errno=True)


def procargs(pid):
    """(argv, env) of a process via sysctl KERN_PROCARGS2, or None."""
    size = ctypes.c_size_t(1 << 20)
    buf = ctypes.create_string_buffer(size.value)
    mib = (ctypes.c_int * 3)(1, 49, pid)  # CTL_KERN, KERN_PROCARGS2
    if _libc.sysctl(mib, 3, buf, ctypes.byref(size), None, ctypes.c_size_t(0)) != 0:
        return None
    data = buf.raw[:size.value]
    argc = int.from_bytes(data[:4], sys.byteorder)
    rest = data[4:]
    rest = rest[rest.find(b"\0"):].lstrip(b"\0")  # skip exec path + padding
    parts = [p.decode("utf-8", "replace") for p in rest.split(b"\0")]
    argv, env = parts[:argc], {}
    for item in parts[argc:]:
        if not item or "=" not in item:
            break
        k, _, v = item.partition("=")
        env[k] = v
    return argv, env


def describe(pid):
    """(command string, captured env) used to restart a server later."""
    info = procargs(pid)
    if not info:
        return "", {}
    argv, env = info
    args = [a for a in argv if a]
    keep = {k: v for k, v in env.items() if k in ENV_KEYS or k.startswith(ENV_PREFIXES)}
    if not args:
        return "", keep
    # Node rewrites its title ("npm run dev" as a single argv[0]); use it verbatim.
    if len(args) == 1 and " " in args[0]:
        return args[0], keep
    launcher = env.get("__PYVENV_LAUNCHER__")
    if launcher and "python" in os.path.basename(args[0]).lower():
        args[0] = launcher  # framework Python hides the venv interpreter behind Python.app
    return shlex.join(args), keep


def project_root(cwd, roots):
    """Nearest folder at or above `cwd` (but inside a watched root) that looks like a project."""
    d = cwd
    while True:
        if any(os.path.exists(os.path.join(d, m)) for m in PROJECT_MARKERS):
            return d
        parent = os.path.dirname(d)
        if parent == d or any(d == r for r in roots) or not any(under(parent, r) for r in roots):
            return cwd
        d = parent


def is_temp_command(cmd):
    """A script run from a temp folder (a test harness, a screenshot tool) isn't the project's server."""
    return any(t in cmd for t in TEMP_DIRS)


def scan(cfg, exclude_pids, exclude_ports, extra_roots=()):
    """Group listening sockets under the project roots into processes, each tagged with its project.
    `extra_roots` are projects added by hand outside the watched folders."""
    roots = list(cfg["roots"]) + [r for r in extra_roots if r not in cfg["roots"]]
    socks = listening_sockets()
    table = process_table()
    prefixes = ALWAYS_IGNORE + tuple(cfg["ignore_commands"])
    root_of = {pid: find_root(pid, table) for pid in socks
               if pid in table and pid not in exclude_pids and not table[pid][2].startswith(prefixes)}
    root_of = {pid: root for pid, root in root_of.items() if not table[root][2].startswith(prefixes)}
    dirs = cwds(set(root_of) | set(root_of.values()))
    groups = {}
    for pid, root in root_of.items():
        cwd = next((d for d in (dirs.get(root), dirs.get(pid))
                    if d and any(under(d, r) for r in roots)), None)
        if not cwd or any(under(cwd, p) for p in cfg["ignore_paths"]) or under(cwd, SELF_DIR):
            continue  # ignored folders, and other devhub instances (e.g. a dev copy of this hub)
        ports = {p: h for p, h in socks[pid].items()
                 if p not in exclude_ports and p not in cfg["ignore_ports"]}
        if not ports:
            continue
        g = groups.setdefault(root, {"cwd": cwd, "project": project_root(cwd, roots),
                                     "pgid": table[root][1], "pids": set(), "ports": {}})
        g["pids"].add(pid)
        for p, hosts in ports.items():
            g["ports"].setdefault(p, [])
            g["ports"][p].extend(h for h in hosts if h not in g["ports"][p])
    if groups:
        usage = group_usage()
        for g in groups.values():
            g["cpu"], g["mem"] = usage.get(g["pgid"], (0.0, 0.0))
    return groups


def slug(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:50] or "app"


# ---------------------------------------------------------------- project discovery

SKIP_DIRS = {"node_modules", "venv", "env", "dist", "build", "out", "cdk.out", "__pycache__",
             "site-packages", "coverage", "target", "vendor", "Pods", "ios", "android", "Library", "tmp"}
# First match wins, so frontend frameworks come before the servers they might also depend on.
NODE_FRAMEWORKS = {"next": "Next.js", "nuxt": "Nuxt", "astro": "Astro", "@sveltejs/kit": "SvelteKit",
                   "@remix-run/dev": "Remix", "gatsby": "Gatsby", "@angular/cli": "Angular", "expo": "Expo",
                   "react-scripts": "CRA", "vite": "Vite", "@nestjs/core": "NestJS", "express": "Express",
                   "fastify": "Fastify", "koa": "Koa", "hono": "Hono", "webpack-dev-server": "webpack",
                   "parcel": "Parcel"}
PY_FRAMEWORKS = {"django": "Django", "fastapi": "FastAPI", "flask": "Flask", "streamlit": "Streamlit",
                 "gradio": "Gradio"}
PY_ENTRY_ORDER = ("main", "app", "server", "web", "api", "run", "wsgi", "asgi")


def read_text(path, limit=300_000):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""


def detect_node(d):
    try:
        pkg = json.loads((d / "package.json").read_text())
    except (OSError, ValueError):
        return None
    deps = {**(pkg.get("dependencies") or {}), **(pkg.get("devDependencies") or {})}
    fw = next((label for dep, label in NODE_FRAMEWORKS.items() if dep in deps), None)
    scripts = pkg.get("scripts") or {}
    order = ("web", "dev", "start") if fw == "Expo" else ("dev", "start", "serve")
    script = next((s for s in order if s in scripts), None)
    if not fw or not script:
        return None
    lock = {"pnpm-lock.yaml": "pnpm", "yarn.lock": "yarn", "bun.lockb": "bun", "bun.lock": "bun"}
    pm = next((tool for f, tool in lock.items() if (d / f).exists() or (d.parent / f).exists()), "npm")
    return fw, f"{pm} run {script}"


def python_for(d):
    for base, prefix in ((d, ""), (d.parent, "../"), (d.parent.parent, "../../")):
        for venv in (".venv", "venv", "env"):
            if (base / venv / "bin" / "python").exists():
                return f"{prefix}{venv}/bin/python"
    return "uv run python" if (d / "uv.lock").exists() else "python3"


def detect_python(d):
    py = python_for(d)
    if (d / "manage.py").exists():
        return "Django", f"{py} manage.py runserver"
    deps = (read_text(d / "pyproject.toml") + read_text(d / "requirements.txt")).lower()
    fw = next((label for name, label in PY_FRAMEWORKS.items()
               if re.search(rf'(^|["\'\s]){name}\b', deps, re.M)), None)
    if not fw:
        return None
    for script in ("run.sh", "start.sh", "dev.sh"):
        if re.search(r"uvicorn|flask|gunicorn|streamlit|python", read_text(d / script)):
            return fw, f"bash {script}"
    files = [f for f in [*d.glob("*.py"), *d.glob("*/*.py"), *d.glob("src/*/*.py"), *d.glob("src/*/*/*.py")]
             if not ({p for p in f.relative_to(d).parts} & (SKIP_DIRS | {"tests", "test", "scripts"}))
             and not f.relative_to(d).parts[0].startswith(".")]
    files.sort(key=lambda f: (len(f.relative_to(d).parts),
                              PY_ENTRY_ORDER.index(f.stem) if f.stem in PY_ENTRY_ORDER else 99, str(f)))

    def module(f):
        parts = f.relative_to(d).with_suffix("").parts
        if parts[0] == "src":  # src layout: import the package from src/
            return ".".join(parts[1:]) + " --app-dir src"
        return ".".join(parts)

    sources = [(f, read_text(f)) for f in files[:200]]
    for f, src in sources:  # an entrypoint that starts the server itself
        rel = str(f.relative_to(d))
        if f.relative_to(d).parts[0] == "src" and len(f.relative_to(d).parts) > 2:
            continue  # packaged src layouts: their CLIs need arguments; use the app object below
        if fw == "Streamlit" and "import streamlit" in src:
            return fw, f"{py} -m streamlit run {rel}"
        if re.search(r"__name__\s*==\s*['\"]__main__['\"]", src) and \
                re.search(r"uvicorn\.run\(|socketio\.run\(|\bapp\.run\(|\.launch\(", src):
            in_pkg = (f.parent / "__init__.py").exists() and f.parent != d
            return fw, f"{py} -m {module(f)}" if in_pkg else f"{py} {rel}"
    for f, src in sources:  # otherwise a module that defines the app object
        m = re.search(r"^(\w+)\s*(?::\s*\w+\s*)?=\s*(FastAPI|Flask)\(", src, re.M)
        if m and m[2] == "FastAPI":
            mod, _, app_dir = module(f).partition(" ")
            return fw, f"{py} -m uvicorn {mod}:{m[1]} {app_dir} --reload".replace("  ", " ")
        if m:
            return fw, f"{py} -m flask --app {module(f).split(' ')[0]}:{m[1]} run --debug"
    for f, src in sources:  # or an app factory
        if re.search(r"^def create_app\(", src, re.M) and re.search(r"FastAPI\(|Flask\(", src):
            mod, _, app_dir = module(f).partition(" ")
            if fw == "Flask":
                return fw, f"{py} -m flask --app '{mod}:create_app()' run --debug"
            return fw, f"{py} -m uvicorn {mod}:create_app --factory {app_dir} --reload".replace("  ", " ")
    return None


def discover(cfg):
    """[{cwd, framework, command}] for runnable-looking projects under the roots."""
    found = []
    for root in cfg["roots"]:
        for dirpath, dirnames, filenames in os.walk(root):
            depth = dirpath[len(root):].count(os.sep)
            if depth >= 5 or any(under(dirpath, p) for p in cfg["ignore_paths"]):
                dirnames[:] = []
                continue
            dirnames[:] = [n for n in dirnames if not n.startswith(".") and n not in SKIP_DIRS]
            d, names = Path(dirpath), set(filenames)
            hit = detect_node(d) if "package.json" in names else None
            if not hit and names & {"manage.py", "pyproject.toml", "requirements.txt"}:
                hit = detect_python(d)
            if hit:
                found.append({"cwd": dirpath, "framework": hit[0], "command": hit[1]})
    return found


def login_path():
    """PATH from your interactive shell, so dashboard starts find node/npm/uv like a terminal would."""
    out = run(["/bin/zsh", "-lic", "printf '\\n__PATH__%s' \"$PATH\""], timeout=15)
    m = re.search(r"__PATH__(.+)", out)
    return m[1].strip() if m else ""


# ---------------------------------------------------------------- state

class Store:
    def __init__(self, cfg):
        self.cfg = cfg
        self.servers = {}
        self.events = []
        self.dismissed = []  # project folders you forgot, so discovery doesn't re-add them
        self.children = {}  # pid -> Popen for servers we launched (so we can reap them)
        self.base_path = "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        if STATE_PATH.exists():
            try:
                data = json.loads(STATE_PATH.read_text())
                self.servers, self.events = data.get("servers", {}), data.get("events", [])
                self.dismissed = data.get("dismissed", [])
            except (OSError, ValueError):
                log("could not read", STATE_PATH, "- starting fresh")
        self.migrate()

    def migrate(self):
        """Older versions made one entry per folder + command; fold those into one per project."""
        groups = {}
        for s in self.servers.values():
            groups.setdefault(project_root(s["cwd"], self.cfg["roots"]), []).append(s)
        merged = 0
        for root, entries in groups.items():
            entries.sort(key=lambda s: (bool(s.get("discovered")), s.get("first_seen") or 0))
            base = entries[0]
            base["cwd"] = root
            for k in ("root_pid", "pgid", "pids"):
                base.pop(k, None)
            base.setdefault("procs", [])
            for other in entries[1:]:
                self.remember(base, other.get("command", ""), other.get("env") or {}, other.get("last_seen") or 0)
                for k in ("last_seen", "last_started", "last_stopped"):
                    base[k] = max(base.get(k) or 0, other.get(k) or 0) or None
                base["first_seen"] = min(base.get("first_seen") or 9e12, other.get("first_seen") or 9e12)
                for k in ("framework", "log"):
                    base[k] = base.get(k) or other.get(k)
                del self.servers[other["id"]]
                merged += 1
            base["alternatives"] = [a for a in base.get("alternatives", []) if not is_temp_command(a["command"])]
        self.dismissed = [d.split("\n")[0] for d in self.dismissed]
        if merged:
            log(f"merged {merged} duplicate entries into one card per project")
            self.save()

    def remember(self, s, cmd, env, when):
        """Record a command seen running in this project: the first real one becomes the Start command,
        others are kept as alternatives you can switch to."""
        if not cmd or is_temp_command(cmd):
            return
        if s.get("discovered") or not s.get("command"):  # a guess gives way to what you actually ran
            s["command"], s["env"] = cmd, env
            s.pop("discovered", None)
        elif cmd == s["command"]:
            s["env"] = env or s.get("env", {})
        else:
            alts = s.setdefault("alternatives", [])
            alt = next((a for a in alts if a["command"] == cmd), None)
            if alt:
                alt.update(env=env or alt.get("env", {}), last_used=max(when, alt.get("last_used") or 0))
            else:
                alts.append({"command": cmd, "env": env, "last_used": when})
            alts.sort(key=lambda a: -(a.get("last_used") or 0))
            del alts[8:]

    def save(self):
        tmp = STATE_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps({"servers": self.servers, "events": self.events[-300:],
                                   "dismissed": self.dismissed}, indent=1))
        os.chmod(tmp, 0o600)
        os.replace(tmp, STATE_PATH)

    def event(self, s, kind, detail=""):
        self.events.append({"t": time.time(), "id": s["id"], "name": s["name"], "kind": kind, "detail": detail})
        del self.events[:-300]
        log(kind, s["name"], detail)

    def unique_name(self, cwd, sid=None):
        p = Path(cwd)
        base = slug(p.name)
        if base in GENERIC_NAMES:
            base = slug(f"{p.parent.name}-{p.name}")
        taken = {s["name"] for s in self.servers.values() if s["id"] != sid}
        if base in taken and not any(s["cwd"] == cwd for s in self.servers.values() if s["name"] == base):
            base = slug(f"{p.parent.name}-{p.name}")
        name, i = base, 2
        while name in taken:
            name, i = f"{base}-{i}", i + 1
        return name

    def by_name(self, name):
        return next((s for s in self.servers.values() if s["name"] == name), None)

    def reconcile(self, groups):
        """One card per project folder: every process running in it is attached to that card."""
        now, changed = time.time(), False
        by_project = {s["cwd"]: s for s in self.servers.values()}
        seen = {p["root"]: p for s in self.servers.values() for p in s.get("procs") or []}
        live = {}
        for root, g in groups.items():
            prev = seen.get(root)
            if prev and prev["pgid"] == g["pgid"]:
                cmd, env = prev["command"], None  # same process as last scan
            else:
                cmd, env = describe(root)
            s = by_project.get(g["project"])
            if not s:
                sid = uuid.uuid4().hex[:10]
                s = by_project[g["project"]] = self.servers[sid] = {
                    "id": sid, "name": self.unique_name(g["project"]), "cwd": g["project"], "command": "",
                    "env": {}, "first_seen": now, "running": False, "ports": [], "hosts": {}, "procs": [],
                }
            if env is not None:
                self.remember(s, cmd, env, now)
            live.setdefault(s["id"], []).append({
                "root": root, "pgid": g["pgid"], "pids": sorted(g["pids"]), "command": cmd,
                "ports": sorted(g["ports"]), "hosts": {str(p): h for p, h in g["ports"].items()},
                "cpu": round(g.get("cpu", 0), 1), "mem": round(g.get("mem", 0)),
            })
        for s in self.servers.values():
            procs = live.get(s["id"], [])
            if procs:
                procs.sort(key=lambda p: (p["command"] != s["command"], p["ports"]))
                ports = sorted({port for p in procs for port in p["ports"]})
                if ports != s.get("ports") or len(procs) != len(s.get("procs") or []):
                    changed = True
                s.update(procs=procs, ports=ports, last_seen=now,
                         hosts={k: v for p in procs for k, v in p["hosts"].items()})
                if s.get("primary_port") not in ports:
                    s["primary_port"] = procs[0]["ports"][0]
                if not s.get("running"):
                    s["running"], s["last_started"], changed = True, now, True
                    s.pop("discovered", None)
                    self.event(s, "started", f"port {', '.join(map(str, ports))}")
            elif s.get("running"):
                s.update(running=False, last_stopped=now, procs=[])
                s.pop("managed_pgid", None)
                changed = True
                self.event(s, "stopped")
        for pid, proc in list(self.children.items()):
            if proc.poll() is not None:
                del self.children[pid]
        if changed:
            self.save()

    def merge_discovered(self, found):
        now, added = time.time(), []
        known = {s["cwd"] for s in self.servers.values()}
        frameworks = {f["cwd"]: f["framework"] for f in found}
        for f in found:
            if f["cwd"] in known or f["cwd"] in self.dismissed:
                continue
            sid = uuid.uuid4().hex[:10]
            self.servers[sid] = {
                "id": sid, "name": self.unique_name(f["cwd"]), "cwd": f["cwd"], "command": f["command"],
                "framework": f["framework"], "env": {}, "first_seen": now, "running": False,
                "ports": [], "hosts": {}, "discovered": True,
            }
            known.add(f["cwd"])
            added.append(self.servers[sid]["name"])
        for s in list(self.servers.values()):
            if s["cwd"] in frameworks:
                s["framework"] = frameworks[s["cwd"]]
            if s.get("discovered") and not s.get("running") and not os.path.isdir(s["cwd"]):
                del self.servers[s["id"]]
        if added:
            log(f"discovered {len(added)} projects: {', '.join(added)}")
        self.save()
        return added

    def place(self, cwd):
        """(root label, parent-folder group, path relative to the root)"""
        for r in self.cfg["roots"]:
            if under(cwd, r):
                parts = os.path.relpath(cwd, r).split(os.sep)
                return os.path.basename(r), parts[0] if len(parts) > 1 else "", "/".join(parts)
        return "Other", "", cwd.replace(str(HOME), "~", 1)

    def start(self, s, reason="from dashboard"):
        if s.get("running"):
            raise ValueError("already running")
        if not s.get("command"):
            raise ValueError("no command recorded; edit it first")
        if not os.path.isdir(s["cwd"]):
            raise ValueError(f"folder no longer exists: {s['cwd']}")
        logfile = LOG_DIR / f"{s['name']}.log"
        out = open(logfile, "ab")
        out.write(f"\n=== {time.strftime('%Y-%m-%d %H:%M:%S')}  {s['command']}\n".encode())
        out.flush()
        env = {k: os.environ[k] for k in ("HOME", "USER", "LOGNAME", "SHELL", "TMPDIR") if k in os.environ}
        env.update(PATH=self.base_path, TERM="dumb", BROWSER="none")
        env.update(s.get("env") or {})
        env.pop("__PYVENV_LAUNCHER__", None)
        proc = subprocess.Popen(["/bin/zsh", "-c", s["command"]], cwd=s["cwd"], env=env,
                                stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                start_new_session=True)
        out.close()
        self.children[proc.pid] = proc
        s.update(managed_pgid=proc.pid, log=str(logfile), launched_at=time.time(), paused=False)
        s.pop("gave_up", None)
        self.event(s, "launched", reason)
        self.save()

    def keep_alive(self):
        """Start every always-on project that isn't running, with a grace period while it boots and a
        limit on retries so a broken server doesn't loop forever."""
        now, grace = time.time(), self.cfg["start_grace_seconds"]
        for s in list(self.servers.values()):
            if not s.get("always_on"):
                continue
            if s.get("running"):
                if now - (s.get("last_started") or now) > 600:  # healthy for 10 minutes: forget old failures
                    s.pop("auto_starts", None)
                continue
            if s.get("paused") or s.get("gave_up") or now - (s.get("launched_at") or 0) < grace:
                continue
            recent = [t for t in s.get("auto_starts", []) if now - t < 1800]
            if len(recent) >= 3:
                s["gave_up"] = True
                self.event(s, "gave up", "3 automatic starts in 30 minutes; press Start to try again")
                self.save()
                continue
            s["auto_starts"] = recent + [now]
            try:
                self.start(s, "always on: was not running")
            except (ValueError, OSError) as e:
                self.event(s, "auto-start failed", str(e))
                s["launched_at"] = now
                self.save()

    async def stop(self, s, pause=True):
        """Stop every process running in this project. If the project has its own stop command (one that
        saves state first, like a game server's), run that and only fall back to signals if needed."""
        if not s.get("running") or not s.get("procs"):
            raise ValueError("not running")
        if pause and s.get("always_on"):
            s["paused"] = True  # a deliberate stop holds until you press Start
        if s.get("stop_command"):
            self.event(s, "stop requested", s["stop_command"])
            proc = await asyncio.create_subprocess_exec(
                "/bin/zsh", "-c", s["stop_command"], cwd=s["cwd"], stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env={**os.environ, "PATH": self.base_path, **(s.get("env") or {})})
            try:
                await asyncio.wait_for(proc.wait(), 120)
            except asyncio.TimeoutError:
                proc.kill()
            roots = [p["root"] for p in s["procs"]]
            for _ in range(20):
                if not any(alive(r) for r in roots):
                    self.save()
                    return
                await asyncio.sleep(0.5)
        table = await asyncio.to_thread(process_table)
        targets = []
        for proc in s["procs"]:
            root, pgid = proc["root"], proc["pgid"]
            if root not in table or table[root][1] != pgid:
                continue  # already gone
            members = [p for p, (_, g, _) in table.items() if g == pgid]
            whole_group = (pgid > 1 and pgid != os.getpgrp() and
                           (pgid == s.get("managed_pgid") or not any(table[p][2] in SHELLS for p in members)))
            if whole_group:
                targets += members
                os.killpg(pgid, signal.SIGTERM)  # same as Ctrl-C'ing the job
                continue
            tree, frontier = [root], [root]
            while frontier:
                kids = [p for p, (pp, _, _) in table.items() if pp in frontier]
                tree += kids
                frontier = kids
            for p in tree:
                try:
                    os.kill(p, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            targets += tree
        if not targets:
            raise ValueError("process changed; refresh and try again")
        self.event(s, "stop requested", "from dashboard")
        self.save()
        for _ in range(30):
            await asyncio.sleep(0.2)
            if not any(alive(p) for p in targets):
                return
        for p in targets:
            try:
                os.kill(p, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def public(self, s):
        root, group, rel = self.place(s["cwd"])
        return {k: s.get(k) for k in ("id", "name", "cwd", "command", "running", "ports", "primary_port",
                                      "first_seen", "last_started", "last_stopped", "last_seen",
                                      "framework")} | {
            "managed": bool(s.get("managed_pgid")) and s.get("running"),
            "has_log": bool(s.get("log")) and os.path.exists(s.get("log", "")),
            "display_cwd": s["cwd"].replace(str(HOME), "~", 1),
            "hidden": bool(s.get("hidden")), "discovered": bool(s.get("discovered")),
            "root": root, "group": group, "rel": rel,
            "procs": [{k: p.get(k) for k in ("command", "ports", "cpu", "mem")} for p in s.get("procs") or []],
            "alternatives": [a["command"] for a in s.get("alternatives") or []],
            "stop_command": s.get("stop_command") or "",
            "always_on": bool(s.get("always_on")), "paused": bool(s.get("paused")),
            "gave_up": bool(s.get("gave_up")),
            "starting": not s.get("running") and time.time() - (s.get("launched_at") or 0)
                        < self.cfg["start_grace_seconds"],
            "web": s.get("primary_port") not in NON_WEB_PORTS,
            "service": NON_WEB_PORTS.get(s.get("primary_port"), ""),
        }


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def tailscale_info():
    exe = next((b for b in TAILSCALE_BINS if os.path.exists(b)), shutil.which("tailscale"))
    if not exe:
        return {"state": "not installed", "ips": [], "dns": ""}
    try:
        data = json.loads(run([exe, "status", "--json"], timeout=10) or "{}")
    except ValueError:
        data = {}
    me = data.get("Self") or {}
    user = (data.get("User") or {}).get(str(me.get("UserID")), {})
    return {"state": data.get("BackendState", "unknown"), "ips": me.get("TailscaleIPs") or [],
            "dns": (me.get("DNSName") or "").rstrip(".").lower(), "host": me.get("HostName", ""),
            "login": user.get("LoginName", "")}


# ---------------------------------------------------------------- HTTP plumbing

class Request:
    def __init__(self, raw):
        lines = raw.decode("latin-1").split("\r\n")
        self.method, self.target, self.version = lines[0].split(" ", 2)
        self.headers = []
        for line in lines[1:]:
            if line:
                k, _, v = line.partition(":")
                self.headers.append((k.strip(), v.strip()))
        self.path = self.target.split("?", 1)[0]

    def get(self, name, default=""):
        name = name.lower()
        return next((v for k, v in self.headers if k.lower() == name), default)

    @property
    def host(self):
        h = self.get("host").lower()
        if h.startswith("["):
            return h[:h.find("]") + 1]
        return h.rsplit(":", 1)[0] if ":" in h else h

    @property
    def upgrade(self):
        return bool(self.get("upgrade")) and "upgrade" in self.get("connection").lower()

    @property
    def keep_alive(self):
        conn = self.get("connection").lower()
        return "close" not in conn and (self.version == "HTTP/1.1" or "keep-alive" in conn)

    def cookie(self, name):
        for part in self.get("cookie").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return ""


def parse_response_head(raw):
    lines = raw.decode("latin-1").split("\r\n")
    status_line = lines[0]
    parts = status_line.split(" ", 2)
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 502
    headers = []
    for line in lines[1:]:
        if line:
            k, _, v = line.partition(":")
            headers.append((k.strip(), v.strip()))
    return status_line, status, headers


def head_bytes(first, headers):
    return (first + "\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers) + "\r\n").encode("latin-1")


async def copy_exact(r, w, n):
    while n > 0:
        data = await r.read(min(n, 65536))
        if not data:
            raise ConnectionError("unexpected EOF")
        w.write(data)
        await w.drain()
        n -= len(data)


async def copy_chunked(r, w):
    while True:
        line = await r.readuntil(b"\r\n")
        w.write(line)
        size = int(line.split(b";")[0].strip() or b"0", 16)
        if size == 0:
            while True:
                trailer = await r.readuntil(b"\r\n")
                w.write(trailer)
                if trailer == b"\r\n":
                    break
            await w.drain()
            return
        await copy_exact(r, w, size + 2)


async def copy_eof(r, w):
    try:
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
    except (ConnectionError, OSError):
        pass


def body_framing(headers):
    """'chunked', an int length, or None if the message has no framing headers."""
    te = next((v for k, v in headers if k.lower() == "transfer-encoding"), "")
    if "chunked" in te.lower():
        return "chunked"
    cl = next((v for k, v in headers if k.lower() == "content-length"), None)
    return int(cl) if cl and cl.strip().isdigit() else None


async def close(w):
    try:
        w.close()
        await w.wait_closed()
    except (ConnectionError, OSError):
        pass


# ---------------------------------------------------------------- the hub

class Hub:
    def __init__(self, cfg):
        self.cfg = cfg
        self.store = Store(cfg)
        self.ts = {"state": "unknown", "ips": [], "dns": ""}
        self.domain_ips = []
        self.whois_cache = {}
        self.tls = None
        self.rescan = asyncio.Event()

    # ---- background loops

    def extra_roots(self):
        return [s["cwd"] for s in self.store.servers.values()
                if not any(under(s["cwd"], r) for r in self.cfg["roots"])]

    async def scan_loop(self):
        while True:
            try:
                groups = await asyncio.to_thread(scan, self.cfg, {os.getpid()}, {self.cfg["port"]}, self.extra_roots())
                self.store.reconcile(groups)
                self.store.keep_alive()
            except Exception as e:  # keep the hub alive whatever a scan hits
                log("scan failed:", repr(e))
            try:
                await asyncio.wait_for(self.rescan.wait(), self.cfg["poll_seconds"])
            except asyncio.TimeoutError:
                pass
            self.rescan.clear()

    async def tailscale_loop(self):
        while True:
            info = await asyncio.to_thread(tailscale_info)
            if info["state"] != self.ts["state"] or info["ips"] != self.ts["ips"]:
                log(f"tailscale {info['state']} {' '.join(info['ips'])} {info['dns']}")
            # `tailscale status` blips (NoState) while it reconnects; keep what we knew.
            for k in ("login", "dns", "ips"):
                if not info.get(k) and self.ts.get(k):
                    info[k] = self.ts[k]
            self.ts = info
            if self.cfg["domain"]:  # lets the dashboard warn if DNS no longer points here
                try:
                    addrs = await asyncio.to_thread(socket.getaddrinfo, self.cfg["domain"], None)
                    self.domain_ips = sorted({a[4][0] for a in addrs})
                except OSError:
                    self.domain_ips = []
            await asyncio.sleep(20)

    async def discover_loop(self):
        while True:
            try:
                self.store.merge_discovered(await asyncio.to_thread(discover, self.cfg))
            except Exception as e:
                log("discovery failed:", repr(e))
            await asyncio.sleep(self.cfg["discover_minutes"] * 60)

    # ---- connection handling

    async def peer_ok(self, writer):
        """Localhost, or a Tailscale device signed in as an allowed user. Anyone else is dropped."""
        peer = writer.get_extra_info("peername")
        try:
            ip = ipaddress.ip_address(peer[0].split("%")[0])
        except (ValueError, TypeError, IndexError):
            return False
        ip = getattr(ip, "ipv4_mapped", None) or ip
        if ip.is_loopback:
            return True
        if not self.cfg["listen_tailscale"] or not any(ip in net for net in TRUSTED_NETS):
            return False
        allowed = set(self.cfg["allowed_users"]) or {self.ts.get("login")}
        return "*" in allowed or await self.whois(str(ip)) in allowed

    async def whois(self, ip):
        """Tailscale login of the device at `ip` (cached for 5 minutes)."""
        login, at = self.whois_cache.get(ip, ("", 0))
        if time.time() - at < 300:
            return login
        exe = next((b for b in TAILSCALE_BINS if os.path.exists(b)), "tailscale")
        try:
            data = json.loads(await asyncio.to_thread(run, [exe, "whois", "--json", ip], 10) or "{}")
            login = (data.get("UserProfile") or {}).get("LoginName", "")
        except ValueError:
            login = ""
        if login:
            self.whois_cache[ip] = (login, time.time())
        else:
            log(f"rejected {ip}: not a known Tailscale user")
        return login

    def host_ok(self, host):
        d = self.cfg["domain"]
        return (host in ("localhost", "127.0.0.1", "[::1]") or host in self.ts["ips"]
                or host == self.ts.get("dns") or host.endswith(".ts.net")
                or bool(d) and (host == d or host.endswith("." + d)))

    async def handle(self, reader, writer):
        if not await self.peer_ok(writer):
            return await close(writer)
        try:
            first = True
            while True:
                try:
                    raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30 if first else 75)
                except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                    return
                first = False
                req = Request(raw)
                req.tls = writer.get_extra_info("ssl_object") is not None
                if not await self.dispatch(req, reader, writer) or not req.keep_alive:
                    return
        except (ConnectionError, OSError, ValueError):
            pass
        finally:
            await close(writer)

    def route(self, req):
        """-> (server, port, upstream target, prefix) or None for the hub itself."""
        d = self.cfg["domain"]
        if d and req.host.endswith("." + d):
            label = req.host[: -len(d) - 1]
            name, _, port = label.partition("--")  # optional <name>--<port>.<domain>
            return self.store.by_name(name), port, req.target, ""
        m = re.match(r"^/([^/?#]+)(.*)$", req.target)
        if m and m[1] != "_hub":
            seg = unquote(m[1])
            name, _, port = seg.partition("@")  # optional /<name>@<port>/
            s = self.store.by_name(name)
            if s:
                return s, port, m[2] or "/", f"/{m[1]}"
        if req.path in ("/", "/favicon.ico") and not req.upgrade or req.path.startswith("/_hub"):
            return None
        # Absolute URLs from an app (/static/x.js, /@vite/client, HMR websockets) carry no
        # prefix: send them to whichever app the referring page / last visit belongs to.
        ref = urlsplit(req.get("referer"))
        rm = re.match(r"^/([^/?#]+)", ref.path or "")
        if rm and ref.netloc.lower().split(":")[0] == req.host:
            seg = unquote(rm[1])
            s = self.store.by_name(seg.partition("@")[0])
            if s and s.get("running"):
                return s, seg.partition("@")[2], req.target, ""
        last = req.cookie("devhub_app")
        s = self.store.by_name(last.partition("@")[0]) if last else None
        if s and s.get("running"):
            return s, last.partition("@")[2], req.target, ""
        return None

    async def dispatch(self, req, reader, writer):
        """Serve one request. Returns True if the connection may be reused."""
        d = self.cfg["domain"]
        if self.tls and not req.tls and d and (req.host == d or req.host.endswith("." + d)):
            await self.drain_body(req, reader)
            port = "" if self.cfg["https_port"] == 443 else f":{self.cfg['https_port']}"
            return self.reply(writer, 308, "", headers=[("Location", f"https://{req.host}{port}{req.target}")])
        hit = self.route(req)
        if hit is None:
            return await self.hub(req, reader, writer)
        s, port, target, prefix = hit
        if prefix and not req.target[len(prefix):]:
            return self.reply(writer, 308, "", headers=[("Location", prefix + "/")])
        if not s or not s.get("running"):
            return self.reply(writer, 404, self.not_running_page(s, req))
        port = int(port) if str(port).isdigit() and int(port) in s["ports"] else s["primary_port"]
        return await self.proxy(req, reader, writer, s, port, target, prefix)

    # ---- reverse proxy

    async def proxy(self, req, reader, writer, s, port, target, prefix):
        up = None
        for host in s["hosts"].get(str(port)) or ["127.0.0.1", "::1"]:
            try:
                up = await asyncio.wait_for(asyncio.open_connection(host, port), 5)
                break
            except (OSError, asyncio.TimeoutError):
                continue
        if not up:
            await self.drain_body(req, reader)
            return self.reply(writer, 502, self.message_page(
                "Not answering", f"<b>{s['name']}</b> is listed on port {port} but refused the connection."))
        up_r, up_w = up
        proto = "https" if req.tls or req.host.endswith(".ts.net") else req.get("x-forwarded-proto") or "http"
        public = f"{proto}://{req.get('host')}"
        local = f"http://localhost:{port}"
        headers = [(k, v) for k, v in req.headers if k.lower() not in HOP_HEADERS]
        for i, (k, v) in enumerate(headers):
            kl = k.lower()
            if kl == "origin":
                headers[i] = (k, local)
            elif kl == "referer" and v.startswith(public):
                path = v[len(public):]
                headers[i] = (k, local + (path[len(prefix):] if prefix and path.startswith(prefix) else path))
        headers += [("Host", f"localhost:{port}"), ("X-Forwarded-Host", req.get("host")),
                    ("X-Forwarded-Proto", proto), ("X-Forwarded-For", writer.get_extra_info("peername")[0])]
        if prefix:
            headers.append(("X-Forwarded-Prefix", prefix))
        framing = body_framing(req.headers)
        if req.upgrade:
            headers += [("Connection", "Upgrade"), ("Upgrade", req.get("upgrade"))]
        else:
            headers.append(("Connection", "close"))
            if framing == "chunked":
                headers.append(("Transfer-Encoding", "chunked"))
        try:
            up_w.write(head_bytes(f"{req.method} {target} HTTP/1.1", headers))
            if framing == "chunked":
                await copy_chunked(reader, up_w)
            elif framing:
                await copy_exact(reader, up_w, framing)
            await up_w.drain()

            while True:  # skip interim 1xx responses other than 101
                status_line, status, rh = parse_response_head(
                    await asyncio.wait_for(up_r.readuntil(b"\r\n\r\n"), 300))
                if status == 101 or status >= 200:
                    break

            out = []
            for k, v in rh:
                kl = k.lower()
                if kl in ("connection", "keep-alive"):
                    continue
                if kl == "location":
                    for base in (local, f"http://127.0.0.1:{port}"):
                        if v.startswith(base):
                            v = public + prefix + v[len(base):]
                    if prefix and v.startswith("/") and not v.startswith("//") and not v.startswith(prefix + "/"):
                        v = prefix + v
                out.append((k, v))
            if prefix:
                out.append(("Set-Cookie", f"devhub_app={prefix[1:]}; Path=/; SameSite=Lax"))

            if status == 101:
                out += [("Connection", "Upgrade")]
                writer.write(head_bytes(status_line, out))
                await writer.drain()
                tasks = [asyncio.create_task(copy_eof(reader, up_w)), asyncio.create_task(copy_eof(up_r, writer))]
                _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for t in pending:
                    t.cancel()
                return False

            resp_framing = None if req.method == "HEAD" or status in (204, 304) else body_framing(rh)
            reusable = req.method == "HEAD" or status in (204, 304) or resp_framing is not None
            out.append(("Connection", "keep-alive" if reusable and req.keep_alive else "close"))
            if reusable:  # framing is explicit, so HTTP/1.0 upstreams can be presented as 1.1
                status_line = "HTTP/1.1 " + status_line.split(" ", 1)[1]
            writer.write(head_bytes(status_line, out))
            if resp_framing == "chunked":
                await copy_chunked(up_r, writer)
            elif isinstance(resp_framing, int):
                await copy_exact(up_r, writer, resp_framing)
            elif not reusable:
                await copy_eof(up_r, writer)
            await writer.drain()
            return reusable
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError):
            return False
        finally:
            await close(up_w)

    async def drain_body(self, req, reader):
        framing = body_framing(req.headers)
        if isinstance(framing, int):
            await reader.readexactly(framing)

    # ---- hub responses

    def reply(self, writer, status, body, ctype="text/html; charset=utf-8", headers=()):
        reasons = {200: "OK", 308: "Permanent Redirect", 400: "Bad Request", 403: "Forbidden",
                   404: "Not Found", 409: "Conflict", 502: "Bad Gateway"}
        data = body.encode() if isinstance(body, str) else body
        hdrs = [("Content-Type", ctype), ("Content-Length", str(len(data))),
                ("Cache-Control", "no-store"), ("Connection", "keep-alive"), *headers]
        writer.write(head_bytes(f"HTTP/1.1 {status} {reasons.get(status, 'OK')}", hdrs) + data)
        return True

    def json(self, writer, obj, status=200):
        return self.reply(writer, status, json.dumps(obj), "application/json")

    def message_page(self, title, html_body):
        return (f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
                f"<title>{title}</title><style>body{{font:16px system-ui;max-width:32rem;margin:15vh auto;padding:0 16px;"
                f"color:#222;background:#fafaf9}}@media(prefers-color-scheme:dark){{body{{color:#e7e5e4;background:#1c1917}}}}"
                f"a,button{{font:inherit}}button{{padding:.5rem 1rem;border-radius:8px;border:0;background:#2563eb;color:#fff;cursor:pointer}}"
                f"</style><h2>{title}</h2><p>{html_body}</p><p><a href='/'>← all servers</a></p>")

    def not_running_page(self, s, req):
        if not s:
            return self.message_page("Unknown app", "No server with that name. It may have been renamed.")
        btn = ""
        if s.get("command"):
            btn = (f"<br><br><button onclick=\"this.disabled=1;this.textContent='Starting…';"
                   f"fetch('/_hub/api/servers/{s['id']}/start',{{method:'POST',headers:{{'X-Devhub':'1'}}}})"
                   f".then(()=>setTimeout(()=>location.reload(),4000))\">Start it</button>")
        return self.message_page(f"{s['name']} isn't running",
                                 f"<code>{s['command'] or 'no command recorded'}</code><br>in "
                                 f"<code>{self.store.public(s)['display_cwd']}</code>{btn}")

    async def hub(self, req, reader, writer):
        if req.path in ("/", "/_hub", "/_hub/"):
            await self.drain_body(req, reader)
            try:
                return self.reply(writer, 200, UI_PATH.read_bytes())
            except OSError:
                return self.reply(writer, 404, "dashboard.html missing")
        if req.path == "/favicon.ico":
            return self.reply(writer, 404, "")
        if not req.path.startswith("/_hub/api/"):
            await self.drain_body(req, reader)
            return self.reply(writer, 404, self.message_page("Not found",
                              "Nothing here. Open an app first so devhub knows where this request belongs."))

        if not self.host_ok(req.host):
            return self.json(writer, {"error": "host not allowed"}, 403)
        body = {}
        framing = body_framing(req.headers)
        if req.method == "POST":
            if req.get("x-devhub") != "1":  # blocks cross-site form posts (CSRF)
                return self.json(writer, {"error": "missing X-Devhub header"}, 403)
            if isinstance(framing, int) and framing:
                try:
                    body = json.loads(await reader.readexactly(framing) or b"{}")
                except ValueError:
                    return self.json(writer, {"error": "bad json"}, 400)
        else:
            await self.drain_body(req, reader)

        parts = req.path[len("/_hub/api/"):].strip("/").split("/")
        st = self.store
        if parts == ["servers"] and req.method == "POST":  # add a project discovery can't find
            cwd = os.path.realpath(os.path.expanduser(str(body.get("cwd", ""))))
            command = str(body.get("command", "")).strip()
            if not os.path.isdir(cwd) or not command:
                return self.json(writer, {"error": "need an existing folder (cwd) and a command"}, 400)
            s = next((x for x in st.servers.values() if x["cwd"] == cwd), None)
            if not s:
                sid = uuid.uuid4().hex[:10]
                s = st.servers[sid] = {"id": sid, "name": st.unique_name(cwd), "cwd": cwd, "env": {},
                                       "first_seen": time.time(), "running": False, "ports": [],
                                       "hosts": {}, "procs": []}
                if cwd in st.dismissed:
                    st.dismissed.remove(cwd)
            s["command"] = command
            s.pop("discovered", None)
            for k in ("stop_command", "framework"):
                if body.get(k):
                    s[k] = str(body[k]).strip()
            if body.get("name"):
                name = slug(str(body["name"]))
                if st.by_name(name) not in (None, s):
                    return self.json(writer, {"error": f"name '{name}' is taken"}, 409)
                s["name"] = name
            s["always_on"] = bool(body.get("always_on"))
            st.save()
            self.rescan.set()
            return self.json(writer, {"ok": True, "server": st.public(s)})
        if parts == ["discover"] and req.method == "POST":
            added = st.merge_discovered(await asyncio.to_thread(discover, self.cfg))
            return self.json(writer, {"ok": True, "added": added})
        if parts == ["state"]:
            servers = sorted(st.servers.values(), key=lambda s: (not s.get("running"), -(s.get("last_seen") or 0)))
            return self.json(writer, {
                "hub": {"port": self.cfg["port"], "domain": self.cfg["domain"], "tailscale": self.ts,
                        "domain_ips": self.domain_ips, "https": bool(self.tls),
                        "roots": [r.replace(str(HOME), "~", 1) for r in self.cfg["roots"]]},
                "servers": [st.public(s) for s in servers],
                "events": st.events[-60:][::-1],
            })
        if len(parts) >= 2 and parts[0] == "servers":
            s = st.servers.get(parts[1])
            if not s:
                return self.json(writer, {"error": "unknown server"}, 404)
            action = parts[2] if len(parts) > 2 else ""
            try:
                if action == "log" and req.method == "GET":
                    text = ""
                    if s.get("log") and os.path.exists(s["log"]):
                        with open(s["log"], "rb") as f:
                            f.seek(max(0, os.path.getsize(s["log"]) - 60000))
                            text = f.read().decode("utf-8", "replace")
                    return self.json(writer, {"log": re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)})
                if req.method != "POST":
                    return self.json(writer, {"error": "use POST"}, 400)
                if action == "start":
                    st.start(s)
                elif action == "stop":
                    await st.stop(s)
                elif action == "restart":
                    if s.get("running"):
                        await st.stop(s, pause=False)
                        for _ in range(150):  # up to 30s for a graceful shutdown
                            await asyncio.sleep(0.2)
                            groups = await asyncio.to_thread(scan, self.cfg, {os.getpid()}, {self.cfg["port"]}, self.extra_roots())
                            st.reconcile(groups)
                            if not s.get("running"):
                                break
                    st.start(s)
                elif action == "forget":
                    if s.get("running"):
                        raise ValueError("stop it before forgetting it")
                    st.dismissed.append(s["cwd"])
                    del st.servers[s["id"]]
                    st.save()
                elif action == "":
                    if "name" in body:
                        name = slug(str(body["name"]))
                        if st.by_name(name) not in (None, s):
                            raise ValueError(f"name '{name}' is taken")
                        s["name"] = name
                    if "command" in body:  # the old Start command stays available as an alternative
                        new, old = str(body["command"]).strip(), s.get("command", "")
                        if new != old:
                            alts = s.setdefault("alternatives", [])
                            picked = next((a for a in alts if a["command"] == new), None)
                            alts[:] = [a for a in alts if a["command"] != new]
                            if old:
                                alts.insert(0, {"command": old, "env": s.get("env") or {},
                                                "last_used": s.get("last_seen")})
                            s["command"] = new
                            if picked:
                                s["env"] = picked.get("env") or s.get("env") or {}
                    if "remove_alternative" in body:
                        s["alternatives"] = [a for a in s.get("alternatives", [])
                                             if a["command"] != body["remove_alternative"]]
                    if "stop_command" in body:
                        s["stop_command"] = str(body["stop_command"]).strip()
                    if "always_on" in body:
                        s["always_on"] = bool(body["always_on"])
                        s.pop("gave_up", None)
                        s["paused"] = False
                    if "primary_port" in body and int(body["primary_port"]) in s.get("ports", []):
                        s["primary_port"] = int(body["primary_port"])
                    if "hidden" in body:
                        s["hidden"] = bool(body["hidden"])
                    st.save()
                else:
                    return self.json(writer, {"error": "unknown action"}, 404)
            except (ValueError, OSError) as e:
                return self.json(writer, {"error": str(e)}, 409)
            self.rescan.set()
            return self.json(writer, {"ok": True, "server": st.public(s) if s["id"] in st.servers else None})
        return self.json(writer, {"error": "not found"}, 404)

    async def tls_loop(self):
        """Pick up renewed certificates without a restart."""
        cert, key = self.cfg["tls_cert"], self.cfg["tls_key"]
        seen = None
        while True:
            try:
                mtime = os.path.getmtime(cert)
                if mtime != seen:
                    self.tls.load_cert_chain(cert, key)
                    seen = mtime
                    log("loaded TLS certificate", cert)
            except (OSError, ssl.SSLError) as e:
                log("TLS certificate problem:", e)
            await asyncio.sleep(3600)

    async def serve(self):
        path = await asyncio.to_thread(login_path)
        if path:
            self.store.base_path = path
        self.ts = await asyncio.to_thread(tailscale_info)  # know who we are before accepting peers
        # macOS only lets unprivileged processes take ports < 1024 on the wildcard address,
        # so listen everywhere and filter peers in peer_ok().
        servers = [await asyncio.start_server(self.handle, ["0.0.0.0", "::"], self.cfg["port"])]
        loops = [self.scan_loop(), self.tailscale_loop()]
        if self.cfg["discover_minutes"]:
            loops.append(self.discover_loop())
        if os.path.exists(self.cfg["tls_cert"]) and os.path.exists(self.cfg["tls_key"]):
            tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            try:
                tls.load_cert_chain(self.cfg["tls_cert"], self.cfg["tls_key"])
                servers.append(await asyncio.start_server(self.handle, ["0.0.0.0", "::"],
                                                          self.cfg["https_port"], ssl=tls))
                self.tls = tls
                loops.append(self.tls_loop())
                log(f"HTTPS on port {self.cfg['https_port']}")
            except (OSError, ssl.SSLError) as e:  # keep serving HTTP rather than not at all
                log(f"HTTPS disabled: {e}")
        log(f"devhub on http://localhost:{self.cfg['port']}  watching {', '.join(self.cfg['roots'])}")
        await asyncio.gather(*loops, *(s.serve_forever() for s in servers))


def cmd_list():
    if not STATE_PATH.exists():
        return print("no servers recorded yet")
    servers = json.loads(STATE_PATH.read_text()).get("servers", {}).values()
    for s in sorted(servers, key=lambda s: (not s.get("running"), s["name"])):
        state = f"● :{s['primary_port']}" if s.get("running") else "○      "
        print(f"{state:9} {s['name']:28} {s['cwd'].replace(str(HOME), '~', 1)}\n{'':38} {s['command']}")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if cmd == "serve":
        try:
            asyncio.run(Hub(load_config()).serve())
        except KeyboardInterrupt:
            pass
    elif cmd == "list":
        cmd_list()
    elif cmd == "add":  # devhub.py add <folder> <command> [--stop CMD] [--always-on] [--name NAME]
        import argparse
        import urllib.request
        ap = argparse.ArgumentParser(prog="devhub.py add")
        ap.add_argument("folder")
        ap.add_argument("command")
        ap.add_argument("--stop", default="", help="command that stops it gracefully")
        ap.add_argument("--name", default="")
        ap.add_argument("--always-on", action="store_true", help="start it whenever it isn't running")
        a = ap.parse_args(sys.argv[2:])
        body = json.dumps({"cwd": a.folder, "command": a.command, "stop_command": a.stop,
                           "name": a.name, "always_on": a.always_on}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{load_config()['port']}/_hub/api/servers", body,
                                     {"Content-Type": "application/json", "X-Devhub": "1", "Host": "localhost"})
        print(json.load(urllib.request.urlopen(req))["server"]["name"], "added")
    elif cmd == "discover":  # dry run: what would be added
        for f in discover(load_config()):
            print(f"{f['framework']:10} {f['cwd'].replace(str(HOME), '~', 1):60} {f['command']}")
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
