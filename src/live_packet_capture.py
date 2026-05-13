from scapy.all import sniff, IP, TCP, UDP  # type: ignore
from collections import deque
from predict_live import predict_flow
import time

# Global state
flows = {}
recent_flows = deque()

FLOW_TIMEOUT = 30         
RECENT_WINDOW = 120        # sliding window for flow history
MIN_HISTORY = 5            # warmup before predictions begin
ATTACK_THRESHOLD = 0.75    # confidence required to alert

# Permissive scoring rules — allows scan-like one-sided flows through
# MIN_DPKTS = 0 is intentional: nmap sends SYN packets that never get
# a response, so requiring dpkts > 0 would skip all scan traffic
MIN_SPKTS = 1
MIN_DPKTS = 0
MIN_SBYTES = 0

# Live-safe features — matches the retrained model exactly
# ct_* and handshake timing features removed because they cannot be
# reproduced reliably from live packet capture
LIVE_FEATURES = [
    'sttl', 'dttl',
    'rate', 'sload', 'dload',
    'dmean', 'smean',
    'dbytes', 'sbytes',
    'dpkts', 'spkts',
    'state', 'proto', 'service', 'dur'
]

SERVICE_MAP = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
}

# Basic helpers
def get_proto(packet):
    if TCP in packet:
        return "tcp"
    if UDP in packet:
        return "udp"
    return "other"

def get_ports(packet):
    if TCP in packet:
        return packet[TCP].sport, packet[TCP].dport
    if UDP in packet:
        return packet[UDP].sport, packet[UDP].dport
    return 0, 0

def get_flow_key(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port, dst_port = get_ports(packet)
    proto = get_proto(packet)

    a = (src_ip, src_port)
    b = (dst_ip, dst_port)

    if a <= b:
        return (src_ip, src_port, dst_ip, dst_port, proto)
    return (dst_ip, dst_port, src_ip, src_port, proto)

def infer_service(flow):
    return SERVICE_MAP.get(flow["origin_dst_port"], "other")

def tcp_flags_str(packet):
    if TCP not in packet:
        return ""
    return str(packet[TCP].flags)

# Completeness check
def is_flow_scoreable(flow):
    """
    Gate flows before scoring.
    MIN_DPKTS = 0 deliberately allows one-sided flows through so that
    nmap SYN scans (which never receive a response) are still classified.
    """
    if flow["spkts"] < MIN_SPKTS:
        return False, f"too few source packets ({flow['spkts']} < {MIN_SPKTS})"
    if flow["dpkts"] < MIN_DPKTS:
        return False, f"too few destination packets ({flow['dpkts']} < {MIN_DPKTS})"
    if flow["sbytes"] < MIN_SBYTES:
        return False, f"source bytes too small ({flow['sbytes']} < {MIN_SBYTES})"
    return True, "ok"

# State inference
def infer_state(flow):
    proto = flow["proto"]

    if proto == "udp":
        return "CON" if flow["spkts"] > 0 and flow["dpkts"] > 0 else "INT"

    if proto != "tcp":
        return "CON" if flow["spkts"] > 0 and flow["dpkts"] > 0 else "INT"

    saw_syn    = flow["syn_time"] is not None
    saw_synack = flow["synack_time"] is not None
    saw_ack    = flow["ack_time"] is not None
    saw_rst    = flow["saw_rst"]
    saw_fin    = flow["saw_fin"]

    if saw_rst:
        return "RST"
    if saw_syn and saw_synack and saw_ack:
        return "CON"
    if saw_syn and not saw_ack:
        return "INT"
    if saw_fin:
        return "FIN"
    return "UNK"

# Feature computation
# Only computes the 15 live_features the retrained model expects.
def compute_features(flow):
    dur = max(flow["last_seen"] - flow["start_time"], 1e-6)  # avoid div by zero
    total_bytes = flow["sbytes"] + flow["dbytes"]

    sttl = flow["sttl_values"][0] if flow["sttl_values"] else 0
    dttl = flow["dttl_values"][0] if flow["dttl_values"] else 0

    smean = flow["sbytes"] / flow["spkts"] if flow["spkts"] > 0 else 0.0
    dmean = flow["dbytes"] / flow["dpkts"] if flow["dpkts"] > 0 else 0.0

    rate  = total_bytes / dur
    sload = flow["sbytes"] / dur
    dload = flow["dbytes"] / dur

    service = infer_service(flow)
    state   = infer_state(flow)

    return {
        "sttl":    sttl,
        "dttl":    dttl,
        "rate":    rate,
        "sload":   sload,
        "dload":   dload,
        "dmean":   dmean,
        "smean":   smean,
        "dbytes":  flow["dbytes"],
        "sbytes":  flow["sbytes"],
        "dpkts":   flow["dpkts"],
        "spkts":   flow["spkts"],
        "state":   state,
        "proto":   flow["proto"],
        "service": service,
        "dur":     dur,
    }

# Finalization
def finalize_flow(flow_key):
    if flow_key not in flows:
        return None

    flow = flows.pop(flow_key)

    # Gate — skip flows that are too incomplete to score
    scoreable, reason = is_flow_scoreable(flow)
    if not scoreable:
        print(f"[SKIPPED]    {flow_key} — {reason}")
        return None

    features = compute_features(flow)

    # Warmup — let history accumulate before trusting predictions
    # Recent flows count is used here as a simple proxy for how long
    # the capture has been running
    recent_flows.append(flow_key)
    if len(recent_flows) < MIN_HISTORY:
        print(f"[WARMING UP] {len(recent_flows)}/{MIN_HISTORY} flows seen — skipping prediction")
        return features

    label, probability = predict_flow(features)

    if probability >= ATTACK_THRESHOLD:
        display_label = "⚠️  ATTACK"
    elif probability >= 0.50:
        display_label = "⚡ SUSPICIOUS"
    else:
        display_label = "✓  NORMAL"

    print("\nFinalized Flow")
    print(f"Flow Key:   {flow_key}")
    for k in LIVE_FEATURES:
        print(f"  {k}: {features.get(k)}")
    print(f"Prediction: {display_label}  (p={probability:.4f})")
    print("-" * 70)

    return features

def cleanup_expired_flows():
    now = time.time()
    expired = [k for k, v in flows.items() if now - v["last_seen"] > FLOW_TIMEOUT]
    for flow_key in expired:
        finalize_flow(flow_key)

# Packet handling
def handle_packet(packet):
    cleanup_expired_flows()

    if IP not in packet:
        return

    flow_key = get_flow_key(packet)
    pkt_len  = len(packet)
    now      = time.time()

    if flow_key not in flows:
        src_port, dst_port = get_ports(packet)
        flows[flow_key] = {
            "start_time":      now,
            "last_seen":       now,
            "origin_src_ip":   packet[IP].src,
            "origin_dst_ip":   packet[IP].dst,
            "origin_src_port": src_port,
            "origin_dst_port": dst_port,
            "proto":           get_proto(packet),

            "spkts":  0,
            "dpkts":  0,
            "sbytes": 0,
            "dbytes": 0,

            "sttl_values": [],
            "dttl_values": [],

            "src_times": [],
            "dst_times": [],

            "tcp_flags_seen": set(),
            "syn_time":    None,
            "synack_time": None,
            "ack_time":    None,
            "saw_rst":     False,
            "saw_fin":     False,
        }

    flow = flows[flow_key]
    flow["last_seen"] = now

    forward = (
        packet[IP].src == flow["origin_src_ip"]
        and packet[IP].dst == flow["origin_dst_ip"]
        and get_ports(packet)[0] == flow["origin_src_port"]
        and get_ports(packet)[1] == flow["origin_dst_port"]
    )

    if forward:
        flow["spkts"] += 1
        flow["sbytes"] += pkt_len
        flow["sttl_values"].append(packet[IP].ttl)
        flow["src_times"].append(now)
    else:
        flow["dpkts"] += 1
        flow["dbytes"] += pkt_len
        flow["dttl_values"].append(packet[IP].ttl)
        flow["dst_times"].append(now)

    if TCP in packet:
        flags = tcp_flags_str(packet)
        flow["tcp_flags_seen"].add(flags)

        if "R" in flags:
            flow["saw_rst"] = True
        if "F" in flags:
            flow["saw_fin"] = True

        if forward:
            if "S" in flags and "A" not in flags and flow["syn_time"] is None:
                flow["syn_time"] = now
            if "A" in flags and "S" not in flags and flow["synack_time"] is not None and flow["ack_time"] is None:
                flow["ack_time"] = now
        else:
            if "S" in flags and "A" in flags and flow["synack_time"] is None:
                flow["synack_time"] = now

        # Finalize immediately on connection teardown
        if flow["saw_rst"] or flow["saw_fin"]:
            finalize_flow(flow_key)


if __name__ == "__main__":
    print("Starting live IDS packet capture...")
    print(f"  Model features: {len(LIVE_FEATURES)} live-safe features")
    print(f"  Warm-up:        {MIN_HISTORY} flows before predictions begin")
    print(f"  CT window:      {RECENT_WINDOW}s sliding history")
    print(f"  Threshold:      {ATTACK_THRESHOLD} confidence to alert")
    print(f"  Flow timeout:   {FLOW_TIMEOUT}s\n")

    try:
        sniff(prn=handle_packet, store=False)
    except KeyboardInterrupt:
        print("\nStopping. Finalizing remaining flows...")
        for key in list(flows.keys()):
            finalize_flow(key)
        print("Done.")