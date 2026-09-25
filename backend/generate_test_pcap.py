import time
from scapy.all import IP, UDP, Raw, wrpcap

packets = []
base_time = time.time()

# 1. Real IKEv2 IKE_SA_INIT Request on UDP 500
# 28 bytes IKE header:
# Initiator SPI (8B), Responder SPI (8B), Next Payload: SA (33=0x21), Ver: 0x20 (IKEv2),
# Exch Type: 34 (0x22, IKE_SA_INIT), Flags: 0x08 (Initiator), MsgID: 0 (4B), Length (4B)
# Followed by SA Proposal with ENCR_AES_GCM_16 (Transform ID 20), PRF_HMAC_SHA2_256 (Transform ID 5),
# AUTH_HMAC_SHA2_256_128 (Transform ID 12), DH Group 14 (MODP-2048)
ispi = b"\x11\x22\x33\x44\x55\x66\x77\x88"
rspi_zero = b"\x00\x00\x00\x00\x00\x00\x00\x00"
rspi_resp = b"\x99\xaa\xbb\xcc\xdd\xee\xff\x11"

# Standard IKEv2 SA Payload with transforms: ENCR_AES_GCM_16 (20), PRF_HMAC_SHA2_256 (5), DH 14 (14)
# We can construct realistic IKEv2 proposal bytes:
# Payload Header: Next=34 (KE), Critical=0, Length=40
# Proposal: Num=1, Proto=1 (IKE), SPI Size=0, Transforms=3
# Transform 1: ENCR_AES_GCM_16 (type 1, id 20, attr 14=256 key len)
# Transform 2: PRF_HMAC_SHA2_256 (type 2, id 5)
# Transform 3: DH_14 (type 4, id 14)
sa_payload = (
    b"\x22\x00\x00\x28"  # Next payload: 34 (KE), length 40
    b"\x00\x00\x00\x24"  # Proposal: last, length 36
    b"\x01\x01\x00\x03"  # Proposal #1, Proto IKE, SPI size 0, 3 transforms
    b"\x03\x00\x00\x0c\x01\x00\x00\x14\x80\x0e\x01\x00"  # Transform ENCR (1), ID 20 (AES-GCM-16), Key len 256
    b"\x03\x00\x00\x08\x02\x00\x00\x05"                  # Transform PRF (2), ID 5 (HMAC-SHA256)
    b"\x00\x00\x00\x08\x04\x00\x00\x0e"                  # Transform DH (4), ID 14 (2048-bit MODP)
)
ike_req_hdr = ispi + rspi_zero + b"\x21\x20\x22\x08\x00\x00\x00\x00" + (28 + len(sa_payload)).to_bytes(4, "big")
ike_req = IP(src="192.168.1.50", dst="203.0.113.10", ttl=64) / UDP(sport=500, dport=500) / Raw(load=ike_req_hdr + sa_payload)
ike_req.time = base_time
packets.append(ike_req)

ike_resp_hdr = ispi + rspi_resp + b"\x21\x20\x22\x20\x00\x00\x00\x00" + (28 + len(sa_payload)).to_bytes(4, "big")
ike_resp = IP(src="203.0.113.10", dst="192.168.1.50", ttl=56) / UDP(sport=500, dport=500) / Raw(load=ike_resp_hdr + sa_payload)
ike_resp.time = base_time + 0.025
packets.append(ike_resp)

# 2. IPsec ESP Packets (IP protocol 50)
spi_in = 0x0A3F118C
spi_out = 0x0B427E91

for i in range(1, 35):
    t = base_time + 0.05 + (i * 0.012)
    fwd_payload = bytes([(x * 17 + i) % 256 for x in range(1200)])
    esp_fwd = IP(src="192.168.1.50", dst="203.0.113.10", proto=50, ttl=64) / Raw(load=spi_out.to_bytes(4, "big") + i.to_bytes(4, "big") + fwd_payload)
    esp_fwd.time = t
    packets.append(esp_fwd)

    bwd_payload = bytes([(x * 31 + i) % 256 for x in range(950)])
    esp_bwd = IP(src="203.0.113.10", dst="192.168.1.50", proto=50, ttl=56) / Raw(load=spi_in.to_bytes(4, "big") + i.to_bytes(4, "big") + bwd_payload)
    esp_bwd.time = t + 0.004
    packets.append(esp_bwd)

# 3. NAT-T ESP Packets over UDP 4500
for i in range(1, 10):
    t = base_time + 0.5 + (i * 0.015)
    nat_payload = bytes([(x * 7 + i) % 256 for x in range(600)])
    nat_pkt = IP(src="192.168.1.50", dst="203.0.113.10", ttl=64) / UDP(sport=4500, dport=4500) / Raw(load=spi_out.to_bytes(4, "big") + i.to_bytes(4, "big") + nat_payload)
    nat_pkt.time = t
    packets.append(nat_pkt)

# 4. AH Packet (IP protocol 51) to test AH detection
# AH Header: Next Header (1B, e.g. 6 = TCP), Payload Len (1B), Reserved (2B), SPI (4B), Sequence (4B), ICV (12B)
ah_spi = 0x0C778899
ah_hdr = (6).to_bytes(1, "big") + (4).to_bytes(1, "big") + b"\x00\x00" + ah_spi.to_bytes(4, "big") + (1).to_bytes(4, "big") + (b"\xaa" * 12)
ah_pkt = IP(src="192.168.1.50", dst="203.0.113.10", proto=51, ttl=64) / Raw(load=ah_hdr + b"\x00" * 64)
ah_pkt.time = base_time + 0.65
packets.append(ah_pkt)

# 5. DNS / Clear text for baseline contrast
dns_req = IP(src="192.168.1.50", dst="8.8.8.8", ttl=64) / UDP(sport=53421, dport=53) / Raw(load=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")
dns_req.time = base_time + 0.7
packets.append(dns_req)

dns_resp = IP(src="8.8.8.8", dst="192.168.1.50", ttl=118) / UDP(sport=53, dport=53421) / Raw(load=b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x00\x00\x04\x5d\xb8\xd8\x22")
dns_resp.time = base_time + 0.72
packets.append(dns_resp)

out_file = "test_ipsec.pcap"
wrpcap(out_file, packets)
print(f"Generated {out_file} with {len(packets)} packets including real IKEv2, ESP, NAT-T, and AH.")
