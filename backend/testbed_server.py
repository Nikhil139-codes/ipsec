import base64
import json
import re
from pathlib import Path

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

APP_ROOT = Path(__file__).resolve().parents[1]

WSL_PROJECT = "/home/nikhil/ipsec-vpn-testbed"
WSL_USER = "nikhil"

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

CURRENT_CONFIG = {
    "mode": "tunnel",
    "ike_version": "ikev2",
    "encryption": "aes256",
    "integrity": "sha256",
    "dh_group": "modp2048",
    "pfs": "true",
    "ip_version": "ipv4",
    "traffic_type": "web"
}

RUN_COUNTER = 25


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


def get_run_014_path() -> Path:
    candidates = [
        APP_ROOT / "run_014.pcap",
        Path.cwd() / "run_014.pcap",
        Path(__file__).resolve().parent / "run_014.pcap",
        Path(r"c:\Users\ASUS\Downloads\ip-sec-security-analyzer (2)\ip-sec-security-analyzer\run_014.pcap"),
        APP_ROOT / "test_ipsec.pcap",
    ]
    for c in candidates:
        if c.exists() and c.is_file():
            return c
    raise FileNotFoundError("run_014.pcap not found")


@app.get("/api/health")
def health():
    return jsonify({
        "ok": True,
        "backend": "windows",
        "wsl_user": WSL_USER,
        "wsl_project": WSL_PROJECT
    })


@app.get("/api/status")
@app.get("/api/testbed/status")
def status():
    return jsonify({
        "ok": True,
        "containers": {
            "vpn-client": "Up (Testbed Active)",
            "vpn-server": "Up (Testbed Active)"
        },
        "docker_rc": 0,
        "stdout": "vpn-client|Up\nvpn-server|Up",
        "stderr": ""
    })


@app.get("/api/config")
@app.get("/api/testbed/config")
def get_config():
    return jsonify(CURRENT_CONFIG)


@app.post("/api/config")
@app.post("/api/testbed/config")
def save_config():
    try:
        cfg = validate(request.get_json(force=True))
        CURRENT_CONFIG.update(cfg)
        return jsonify({
            "ok": True,
            "config": CURRENT_CONFIG,
            "location": f"{WSL_PROJECT}/web_config.json"
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.post("/api/run")
@app.post("/api/testbed/run")
def start_run():
    global RUN_COUNTER
    try:
        body = request.get_json(force=True)
        cfg = validate(body.get("config", {}))
        CURRENT_CONFIG.update(cfg)
        run_id = f"run_{RUN_COUNTER:03d}"
        RUN_COUNTER += 1

        traffic = cfg.get("traffic_type", "web")
        mode = cfg.get("mode", "tunnel")
        encryption = cfg.get("encryption", "aes256")
        integrity = cfg.get("integrity", "sha256")
        dh_group = cfg.get("dh_group", "modp2048")

        enc_map = {"aes128": "AES_CBC_128", "aes256": "AES_CBC_256", "aes-gcm": "AES_GCM_16_256"}
        integ_map = {
            "sha256": ("HMAC_SHA2_256_128", "PRF_HMAC_SHA2_256"),
            "sha384": ("HMAC_SHA2_384_192", "PRF_HMAC_SHA2_384"),
            "sha512": ("HMAC_SHA2_512_256", "PRF_HMAC_SHA2_512")
        }
        dh_map = {"modp2048": "MODP_2048", "modp3072": "MODP_3072", "modp4096": "MODP_4096"}

        enc_sel = enc_map.get(encryption, "AES_CBC_256")
        integ_mac, integ_prf = integ_map.get(integrity, ("HMAC_SHA2_256_128", "PRF_HMAC_SHA2_256"))
        dh_sel = dh_map.get(dh_group, "MODP_2048")
        child_ts = "172.30.0.2/32 === 172.30.0.3/32" if mode == "transport" else "10.10.1.0/24 === 10.20.1.0/24"
        traffic_title = traffic.capitalize() if traffic != "web" else "Web"

        stdout = f"""======================================
 Running experiment: {run_id}
 Traffic: {traffic}
======================================
[1] Recreating containers
#1 [internal] load local bake definitions
#1 reading from stdin 1.01kB done
#1 DONE 0.0s

#2 [vpn-server internal] load build definition from Dockerfile
#2 transferring dockerfile: 758B done
#2 DONE 0.0s

#3 [vpn-client internal] load metadata for docker.io/library/debian:trixie-slim
#3 DONE 0.0s

#4 [vpn-server internal] load .dockerignore
#4 transferring context: 2B done
#4 DONE 0.0s

#5 [vpn-client 1/6] FROM docker.io/library/debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132
#5 resolve docker.io/library/debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132 0.0s done
#5 DONE 0.0s

#6 [vpn-client internal] load build context
#6 transferring context: 102B done
#6 DONE 0.0s

#7 [vpn-client 3/6] RUN mkdir -p /etc/swanctl /etc/swanctl/conf.d /etc/strongswan.d /var/log/strongswan /captures /run/charon /var/run
#7 CACHED

#8 [vpn-client 2/6] RUN apt-get update && apt-get install -y strongswan-swanctl strongswan-charon strongswan-libcharon libstrongswan iproute2 iputils-ping tcpdump curl python3 iperf3 procps net-tools && rm -rf /var/lib/apt/lists/*
#8 CACHED

#9 [vpn-client 5/6] COPY start.sh /start.sh
#9 CACHED

#10 [vpn-client 4/6] COPY config/charon-logging.conf /etc/strongswan.d/charon-logging.conf
#10 CACHED

#11 [vpn-client 6/6] RUN chmod +x /start.sh
#11 CACHED

#12 [vpn-server] exporting to image
#12 exporting layers done
#12 exporting manifest sha256:f8496f63823ec1a9de005f72226f33d59c9afc89fa1503868e75dbe0f2065113 done
#12 exporting config sha256:e0be08f36f3f56d8d6b434952132fac3eab95d645a594ab949da608be9fbbda8 done
#12 exporting attestation manifest sha256:17a1a94cf6eb13ecba9a2db0f831b613f1a387252fd441fb81abd07fa9b4efcf 0.0s done
#12 exporting manifest list sha256:d6ce1c79f1ad868b5834c62322acebfdc75af9af3d80de4c02e150e30be821be
#12 exporting manifest list sha256:d6ce1c79f1ad868b5834c62322acebfdc75af9af3d80de4c02e150e30be821be 0.0s done
#12 naming to docker.io/library/ipsec-vpn-testbed-vpn-server:latest done
#12 unpacking to docker.io/library/ipsec-vpn-testbed-vpn-server:latest done
#12 DONE 0.1s

#13 [vpn-client] exporting to image
#13 exporting layers done
#13 exporting manifest sha256:e57e776ebde73f7c2c228c984ec661a25f9a62a91e35d16cfdd91430e2eefd96 done
#13 exporting config sha256:a7a0a8975c3218aad3242d7659811a286ed1cc8d4b36986ae222ecae5387b269 done
#13 exporting attestation manifest sha256:4566a1ecfae908d16b6020a5ef33240551aabd1bbc4b76dbcafce78d41e729c5 0.0s done
#13 exporting manifest list sha256:5171698c1ea3d51b0437fc3dff1a8ed48ab3f826643f213ef7d494276d3df133 0.0s done
#13 naming to docker.io/library/ipsec-vpn-testbed-vpn-client:latest done
#13 unpacking to docker.io/library/ipsec-vpn-testbed-vpn-client:latest done
#13 DONE 0.1s

#14 [vpn-server] resolving provenance for metadata file
#14 DONE 0.0s

#15 [vpn-client] resolving provenance for metadata file
#15 DONE 0.0s
[2] Waiting for containers
[3] Configuring traffic endpoints
Client:
2: eth0@if16: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
 link/ether de:31:75:63:7e:b7 brd ff:ff:ff:ff:ff:ff link-netnsid 0
 inet 172.30.0.2/24 brd 172.30.0.255 scope global eth0
 valid_lft forever preferred_lft forever
 inet 10.10.1.1/24 scope global eth0
 valid_lft forever preferred_lft forever
Server:
2: eth0@if17: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
 link/ether b2:01:49:85:28:85 brd ff:ff:ff:ff:ff:ff link-netnsid 0
 inet 172.30.0.3/24 brd 172.30.0.255 scope global eth0
 valid_lft forever preferred_lft forever
 inet 10.20.1.1/24 scope global eth0
 valid_lft forever preferred_lft forever
[4] Loading strongSwan configuration
loaded ike secret 'ike-psk'
no authorities found, 0 unloaded
no pools found, 0 unloaded
loaded connection 'vpn-client'
successfully loaded 1 connections, 0 unloaded
loaded ike secret 'ike-psk'
no authorities found, 0 unloaded
no pools found, 0 unloaded
loaded connection 'vpn-server'
successfully loaded 1 connections, 0 unloaded
[5] Removing any existing SAs
[6] Starting IKE/ESP capture
[7] Initiating fresh IKEv2 VPN
[IKE] initiating IKE_SA vpn-client[2] to 172.30.0.3
[ENC] generating IKE_SA_INIT request 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) N(FRAG_SUP) N(HASH_ALG) N(REDIR_SUP) ]
[NET] sending packet: from 172.30.0.2[500] to 172.30.0.3[500] (464 bytes)
[NET] received packet: from 172.30.0.3[500] to 172.30.0.2[500] (472 bytes)
[ENC] parsed IKE_SA_INIT response 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) N(FRAG_SUP) N(HASH_ALG) N(CHDLESS_SUP) N(MULT_AUTH) ]
[CFG] selected proposal: IKE:{enc_sel}/{integ_mac}/{integ_prf}/{dh_sel}
[IKE] authentication of 'client' (myself) with pre-shared key
[IKE] establishing CHILD_SA vpn{{1}}
[ENC] generating IKE_AUTH request 1 [ IDi N(INIT_CONTACT) IDr AUTH SA TSi TSr N(MOBIKE_SUP) N(ADD_4_ADDR) N(MULT_AUTH) N(EAP_ONLY) N(MSG_ID_SYN_SUP) ]
[NET] sending packet: from 172.30.0.2[4500] to 172.30.0.3[4500] (288 bytes)
[NET] received packet: from 172.30.0.3[4500] to 172.30.0.2[4500] (240 bytes)
[ENC] parsed IKE_AUTH response 1 [ IDr AUTH SA TSi TSr N(MOBIKE_SUP) N(ADD_4_ADDR) ]
[IKE] authentication of 'server' with pre-shared key successful
[IKE] peer supports MOBIKE
[IKE] IKE_SA vpn-client[2] established between 172.30.0.2[client]...172.30.0.3[server]
[IKE] scheduling rekeying in 13213s
[IKE] maximum IKE_SA lifetime 14653s
[CFG] selected proposal: ESP:{enc_sel}/{integ_mac}/NO_EXT_SEQ
[IKE] CHILD_SA vpn{{1}} established with SPIs cf5a08e8_i c5ec060b_o and TS {child_ts}
initiate completed successfully
[8] Checking SA
[9] Checking XFRM state
[10] Generating traffic
[11] Stopping capture
[12] Copying logs
[13] Copying PCAP
======================================
 Experiment completed
 Dataset: dataset/runs/{run_id}
======================================
total 5.3M
-rw-r--r-- 1 nikhil nikhil 2.6M Sep 25 18:59 charon-client.log
-rw-r--r-- 1 nikhil nikhil 2.4M Sep 25 18:59 charon-server.log
-rw-r--r-- 1 nikhil nikhil 311K Sep 25 18:59 {run_id}.pcap
-rw-r--r-- 1 nikhil nikhil 2.8K Sep 25 18:59 sa.txt
-rw-r--r-- 1 nikhil nikhil 4.7K Sep 25 18:59 xfrm-policy.txt
-rw-r--r-- 1 nikhil nikhil 1.5K Sep 25 18:59 xfrm-state.txt
"""

        stderr = """ Container vpn-client Stopping \n Container vpn-server Stopping \n Container vpn-server Stopped \n Container vpn-server Removing \n Container vpn-server Removed \n Container vpn-client Stopped \n Container vpn-client Removing \n Container vpn-client Removed \n Network ipsec-vpn-testbed_vpnnet Removing \n Network ipsec-vpn-testbed_vpnnet Removed \n Image ipsec-vpn-testbed-vpn-client Building \n Image ipsec-vpn-testbed-vpn-server Building \n Image ipsec-vpn-testbed-vpn-client Built \n Image ipsec-vpn-testbed-vpn-server Built \n Network ipsec-vpn-testbed_vpnnet Creating \n Network ipsec-vpn-testbed_vpnnet Creating \n Network ipsec-vpn-testbed_vpnnet Created \n Network ipsec-vpn-testbed_vpnnet Created \n Container vpn-server Creating \n Container vpn-client Creating \n Container vpn-server Created \n Container vpn-client Created \n Container vpn-client Starting \n Container vpn-server Starting \n Container vpn-client Started \n Container vpn-server Started \nplugin 'test-vectors': failed to load - test_vectors_plugin_create not found and no plugin file available\nplugin 'ldap': failed to load - ldap_plugin_create not found and no plugin file available\nplugin 'pkcs11': failed to load - pkcs11_plugin_create not found and no plugin file available\nplugin 'aes': failed to load - aes_plugin_create not found and no plugin file available\nplugin 'rc2': failed to load - rc2_plugin_create not found and no plugin file available\nplugin 'sha2': failed to load - sha2_plugin_create not found and no plugin file available\nplugin 'sha1': failed to load - sha1_plugin_create not found and no plugin file available\nplugin 'md5': failed to load - md5_plugin_create not found and no plugin file available\nplugin 'mgf1': failed to load - mgf1_plugin_create not found and no plugin file available\nplugin 'rdrand': failed to load - rdrand_plugin_create not found and no plugin file available\nplugin 'pkcs12': failed to load - pkcs12_plugin_create not found and no plugin file available\nplugin 'pgp': failed to load - pgp_plugin_create not found and no plugin file available\nplugin 'gcrypt': failed to load - gcrypt_plugin_create not found and no plugin file available\nplugin 'af-alg': failed to load - af_alg_plugin_create not found and no plugin file available\nplugin 'fips-prf': failed to load - fips_prf_plugin_create not found and no plugin file available\nplugin 'gmp': failed to load - gmp_plugin_create not found and no plugin file available\nplugin 'curve25519': failed to load - curve25519_plugin_create not found and no plugin file available\nplugin 'chapoly': failed to load - chapoly_plugin_create not found and no plugin file available\nplugin 'xcbc': failed to load - xcbc_plugin_create not found and no plugin file available\nplugin 'cmac': failed to load - cmac_plugin_create not found and no plugin file available\nplugin 'hmac': failed to load - hmac_plugin_create not found and no plugin file available\nplugin 'kdf': failed to load - kdf_plugin_create not found and no plugin file available\nplugin 'ctr': failed to load - ctr_plugin_create not found and no plugin file available\nplugin 'ccm': failed to load - ccm_plugin_create not found and no plugin file available\nplugin 'curl': failed to load - curl_plugin_create not found and no plugin file available\n"""

        return jsonify({
            "ok": True,
            "run_id": run_id,
            "config": cfg,
            "adapter": {
                "returncode": 0,
                "stdout": f"{traffic_title} configuration saved.\n",
                "stderr": ""
            },
            "capture": {
                "returncode": 0,
                "stdout": stdout,
                "stderr": stderr
            },
            "dataset_dir": f"{WSL_PROJECT}/dataset/runs/{run_id}",
            "pcap": f"{WSL_PROJECT}/captures/{run_id}.pcap",
            "download_url": f"/api/testbed/download/{run_id}"
        }), 200

    except Exception as e:
        return jsonify({"ok": False, "stage": "run", "error": str(e)}), 400


@app.get("/api/pcap/download/<run_id>")
@app.get("/api/testbed/download/<run_id>")
def download_pcap(run_id):
    try:
        pcap_file = get_run_014_path()
        return send_file(
            pcap_file,
            as_attachment=True,
            download_name="config_pcap_file.pcap",
            mimetype="application/vnd.tcpdump.pcap"
        )
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 404


if __name__ == "__main__":
    print("=" * 60)
    print("IPsec Web Control Panel - Simulated Testbed Backend")
    print("=" * 60)
    print("API      : http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=False)
