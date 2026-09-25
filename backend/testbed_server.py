import base64
import json
import re
import shlex
import subprocess
from pathlib import Path

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

APP_ROOT = Path(__file__).resolve().parents[1]
FRONTEND = APP_ROOT / "frontend"

WSL_PROJECT = "/home/nikhil/ipsec-vpn-testbed"
WSL_USER = "nikhil"

# Windows UNC paths to access WSL files directly
WSL_UNC_PREFIXES = [
    Path(r"\\wsl$\Ubuntu-24.04\home\nikhil\ipsec-vpn-testbed"),
    Path(r"\\wsl.localhost\Ubuntu-24.04\home\nikhil\ipsec-vpn-testbed"),
    Path(r"\\wsl$\Ubuntu\home\nikhil\ipsec-vpn-testbed"),
    Path(r"\\wsl.localhost\Ubuntu\home\nikhil\ipsec-vpn-testbed"),
]

app = Flask(__name__)
CORS(app)

ALLOWED = {
    "mode": {"tunnel", "transport"},
    "ike_version": {"ikev2"},
    "encryption": {"aes128", "aes256", "aes-gcm"},
    "integrity": {"sha256", "sha384", "sha512"},
    "dh_group": {"modp2048", "modp3072", "modp4096"},
    "pfs": {"true", "false"},
    "ip_version": {"ipv4", "ipv6"},
    "traffic_type": {
        "icmp",
        "web",
        "video",
        "voip",
        "email"
    },
}

def validate(cfg):
    if not isinstance(cfg, dict):
        raise ValueError("Configuration must be a JSON object")
    for key, allowed_values in ALLOWED.items():
        value = cfg.get(key)
        if value not in allowed_values:
            raise ValueError(
                f"Invalid {key}: {value}. Allowed values: {sorted(allowed_values)}"
            )
    return cfg

def run_wsl(command, timeout=None):
    cmd = [
        "wsl.exe",
        "-u",
        WSL_USER,
        "bash",
        "-lc",
        f"cd {shlex.quote(WSL_PROJECT)} && {command}"
    ]
    try:
        result = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=timeout
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout[-12000:],
            "stderr": result.stderr[-12000:]
        }
    except subprocess.TimeoutExpired:
        return {
            "returncode": 124,
            "stdout": "",
            "stderr": "WSL command timed out"
        }
    except Exception as e:
        return {
            "returncode": 1,
            "stdout": "",
            "stderr": str(e)
        }

def find_wsl_file(rel_path: str):
    """Attempt to locate a file on Windows via WSL UNC paths."""
    for prefix in WSL_UNC_PREFIXES:
        candidate = prefix / rel_path
        if candidate.exists():
            return candidate
    return None

@app.get("/api/health")
def health():
    return jsonify({
        "ok": True,
        "backend": "windows",
        "wsl_user": WSL_USER,
        "wsl_project": WSL_PROJECT
    })

@app.get("/api/status")
def status():
    result = run_wsl('docker ps --format "{{.Names}}|{{.Status}}"')
    containers = {}
    for line in result["stdout"].splitlines():
        if "|" not in line:
            continue
        name, state = line.split("|", 1)
        if name in ("vpn-client", "vpn-server"):
            containers[name] = state

    return jsonify({
        "ok": result["returncode"] == 0,
        "containers": containers,
        "docker_rc": result["returncode"],
        "stdout": result["stdout"],
        "stderr": result["stderr"]
    })

@app.get("/api/config")
def get_config():
    command = """
if [ -f web_config.json ]; then
    cat web_config.json
else
    printf '%s\n' '{"mode":"tunnel","ike_version":"ikev2","encryption":"aes256","integrity":"sha256","dh_group":"modp2048","pfs":"true","ip_version":"ipv4","traffic_type":"icmp"}'
fi
"""
    result = run_wsl(command)
    if result["returncode"] != 0:
        return jsonify({
            "ok": False,
            "error": result["stderr"]
        }), 500

    try:
        config = json.loads(result["stdout"])
        ui_config = {
            key: config.get(key)
            for key in ALLOWED.keys()
        }
        validate(ui_config)
        return jsonify(ui_config)
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": f"Invalid WSL configuration: {e}"
        }), 500

@app.post("/api/config")
def save_config():
    try:
        cfg = validate(request.get_json(force=True))
        config_json = json.dumps(cfg)
        encoded = base64.b64encode(config_json.encode("utf-8")).decode("ascii")

        command = (
            "python3 -c "
            "\"import base64,json; "
            "data=json.loads(base64.b64decode('"
            + encoded +
            "').decode('utf-8')); "
            "json.dump(data,open('web_config.json','w'),indent=2)\""
        )
        result = run_wsl(command)
        if result["returncode"] != 0:
            return jsonify({
                "ok": False,
                "stage": "save_config",
                "error": result["stderr"],
                "stdout": result["stdout"]
            }), 500

        return jsonify({
            "ok": True,
            "config": cfg,
            "location": f"{WSL_PROJECT}/web_config.json"
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

def get_next_run_id():
    command = (
        "find dataset/runs -maxdepth 1 -type d -name 'run_*' -printf '%f\\n' "
        "| sort -V | tail -n 1"
    )
    result = run_wsl(command)
    if result["returncode"] != 0:
        raise RuntimeError("Could not determine latest run ID: " + result["stderr"])

    latest = result["stdout"].strip()
    if not latest:
        return "run_001"

    match = re.fullmatch(r"run_(\d+)", latest)
    if not match:
        return "run_001"

    number = int(match.group(1)) + 1
    return f"run_{number:03d}"

@app.post("/api/run")
def start_run():
    try:
        body = request.get_json(force=True)
        cfg = validate(body.get("config", {}))
        traffic = cfg["traffic_type"]
        run_id = get_next_run_id()

        config_json = json.dumps(cfg)
        encoded = base64.b64encode(config_json.encode("utf-8")).decode("ascii")

        save_command = (
            "python3 -c "
            "\"import base64,json; "
            "data=json.loads(base64.b64decode('"
            + encoded +
            "').decode('utf-8')); "
            "json.dump(data,open('web_config.json','w'),indent=2)\""
        )
        save_result = run_wsl(save_command)
        if save_result["returncode"] != 0:
            return jsonify({
                "ok": False,
                "stage": "save_config",
                "run_id": run_id,
                "error": save_result["stderr"],
                "stdout": save_result["stdout"]
            }), 500

        adapter_command = "python3 scripts/web_apply_config.py " + shlex.quote(config_json)
        adapter = run_wsl(adapter_command, timeout=120)
        if adapter["returncode"] != 0:
            return jsonify({
                "ok": False,
                "stage": "apply",
                "run_id": run_id,
                "config": cfg,
                "error": adapter["stderr"] or "Configuration adapter failed",
                "adapter": adapter
            }), 500

        capture_command = f"bash scripts/capture_run.sh {shlex.quote(run_id)} {shlex.quote(traffic)}"
        capture = run_wsl(capture_command, timeout=180)

        return jsonify({
            "ok": capture["returncode"] == 0,
            "run_id": run_id,
            "config": cfg,
            "adapter": adapter,
            "capture": capture,
            "dataset_dir": f"{WSL_PROJECT}/dataset/runs/{run_id}",
            "pcap": f"{WSL_PROJECT}/captures/{run_id}.pcap",
            "download_url": f"/api/pcap/download/{run_id}"
        }), (200 if capture["returncode"] == 0 else 500)

    except Exception as e:
        return jsonify({"ok": False, "stage": "run", "error": str(e)}), 400

@app.get("/api/pcap/download/<run_id>")
def download_pcap(run_id):
    if not re.fullmatch(r"run_\d{3,}", run_id):
        return jsonify({"ok": False, "error": "Invalid run_id"}), 400

    rel_candidates = [
        f"captures/{run_id}.pcap",
        f"dataset/runs/{run_id}/{run_id}.pcap"
    ]
    file_path = None
    for rel in rel_candidates:
        f = find_wsl_file(rel)
        if f and f.is_file():
            file_path = f
            break

    if file_path:
        return send_file(
            file_path,
            as_attachment=True,
            download_name=f"{run_id}.pcap",
            mimetype="application/vnd.tcpdump.pcap"
        )

    # Fallback: fetch binary content using wsl base64
    wsl_cmd = f"base64 -w 0 captures/{run_id}.pcap 2>/dev/null || base64 -w 0 dataset/runs/{run_id}/{run_id}.pcap"
    res = run_wsl(wsl_cmd)
    if res["returncode"] == 0 and res["stdout"].strip():
        import io
        pcap_bytes = base64.b64decode(res["stdout"].strip())
        return send_file(
            io.BytesIO(pcap_bytes),
            as_attachment=True,
            download_name=f"{run_id}.pcap",
            mimetype="application/vnd.tcpdump.pcap"
        )

    return jsonify({"ok": False, "error": f"PCAP for {run_id} not found"}), 404

if __name__ == "__main__":
    print("=" * 60)
    print("IPsec Web Control Panel - Flask Backend with PCAP Download")
    print("=" * 60)
    print("API      : http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=False)
