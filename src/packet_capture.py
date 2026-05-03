from scapy.all import sniff, IP, TCP, UDP  # type: ignore
from collections import deque
from predict_live import predict_flow
import time

# -----------------------------
# Global state
# -----------------------------
flows = {}
recent_flows = deque()

FLOW_TIMEOUT = 30          # seconds before an inactive flow is finalized
RECENT_WINDOW = 60         # seconds for ct_* features

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

# -----------------------------
# Basic helpers
# -----------------------------
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

def avg_interarrival(times):
    if len(times) < 2:
        return 0.0
    gaps = [times[i] - times[i - 1] for i in range(1, len(times))]
    return sum(gaps) / len(gaps)

def jitter(times):
    if len(times) < 3:
        return 0.0
    gaps = [times[i] - times[i - 1] for i in range(1, len(times))]
    diffs = [abs(gaps[i] - gaps[i - 1]) for i in range(1, len(gaps))]
    return sum(diffs) / len(diffs) if diffs else 0.0

def infer_service(flow):
    return SERVICE_MAP.get(flow["origin_dst_port"], "other")

def tcp_flags_str(packet):
    if TCP not in packet:
        return ""
    return str(packet[TCP].flags)

# -----------------------------
# State inference
# -----------------------------
def infer_state(flow):
    proto = flow["proto"]

    if proto == "udp":
        return "CON" if flow["spkts"] > 0 and flow["dpkts"] > 0 else "INT"

    if proto != "tcp":
        return "CON" if flow["spkts"] > 0 and flow["dpkts"] > 0 else "INT"

    saw_syn = flow["syn_time"] is not None
    saw_synack = flow["synack_time"] is not None
    saw_ack = flow["ack_time"] is not None
    saw_rst = flow["saw_rst"]
    saw_fin = flow["saw_fin"]

    if saw_rst:
        return "RST"
    if saw_syn and saw_synack and saw_ack:
        return "CON"
    if saw_syn and not saw_ack:
        return "INT"
    if saw_fin:
        return "FIN"
    return "UNK"

# -----------------------------
# Recent-flow counting for ct_* features
# -----------------------------
def trim_recent_flows(now):
    while recent_flows and now - recent_flows[0]["end_time"] > RECENT_WINDOW:
        recent_flows.popleft()

def count_recent_dst_ltm(dst_ip, now):
    return sum(
        1 for f in recent_flows
        if now - f["end_time"] <= RECENT_WINDOW
        and f["dst_ip"] == dst_ip
    )

def count_recent_dst_src_ltm(src_ip, dst_ip, now):
    return sum(
        1 for f in recent_flows
        if now - f["end_time"] <= RECENT_WINDOW
        and f["src_ip"] == src_ip
        and f["dst_ip"] == dst_ip
    )

def count_recent_srv_src(src_ip, service, now):
    return sum(
        1 for f in recent_flows
        if now - f["end_time"] <= RECENT_WINDOW
        and f["src_ip"] == src_ip
        and f["service"] == service
    )

def count_recent_srv_dst(dst_ip, service, now):
    return sum(
        1 for f in recent_flows
        if now - f["end_time"] <= RECENT_WINDOW
        and f["dst_ip"] == dst_ip
        and f["service"] == service
    )

def count_recent_dst_sport_ltm(dst_ip, src_port, now):
    return sum(
        1 for f in recent_flows
        if now - f["end_time"] <= RECENT_WINDOW
        and f["dst_ip"] == dst_ip
        and f["src_port"] == src_port
    )

def count_recent_state_ttl(state, sttl, now):
    return sum(
        1 for f in recent_flows
        if now - f["end_time"] <= RECENT_WINDOW
        and f["state"] == state
        and f["sttl"] == sttl
    )

# -----------------------------
# Feature computation
# -----------------------------
def compute_features(flow):
    dur = flow["last_seen"] - flow["start_time"]
    total_bytes = flow["sbytes"] + flow["dbytes"]

    sttl = flow["sttl_values"][0] if flow["sttl_values"] else 0
    dttl = flow["dttl_values"][0] if flow["dttl_values"] else 0

    smean = flow["sbytes"] / flow["spkts"] if flow["spkts"] > 0 else 0.0
    dmean = flow["dbytes"] / flow["dpkts"] if flow["dpkts"] > 0 else 0.0
    rate = total_bytes / dur if dur > 0 else 0.0

    service = infer_service(flow)
    state = infer_state(flow)

    sinpkt = avg_interarrival(flow["src_times"])
    dinpkt = avg_interarrival(flow["dst_times"])
    sjit = jitter(flow["src_times"])
    djit = jitter(flow["dst_times"])

    synack = 0.0
    ackdat = 0.0
    tcprtt = 0.0

    if flow["syn_time"] is not None and flow["synack_time"] is not None:
        synack = max(0.0, flow["synack_time"] - flow["syn_time"])

    if flow["synack_time"] is not None and flow["ack_time"] is not None:
        ackdat = max(0.0, flow["ack_time"] - flow["synack_time"])

    if flow["syn_time"] is not None and flow["ack_time"] is not None:
        tcprtt = max(0.0, flow["ack_time"] - flow["syn_time"])

    now = flow["last_seen"]
    trim_recent_flows(now)

    ct_dst_ltm = count_recent_dst_ltm(flow["origin_dst_ip"], now)
    ct_dst_src_ltm = count_recent_dst_src_ltm(flow["origin_src_ip"], flow["origin_dst_ip"], now)
    ct_srv_src = count_recent_srv_src(flow["origin_src_ip"], service, now)
    ct_srv_dst = count_recent_srv_dst(flow["origin_dst_ip"], service, now)
    ct_dst_sport_ltm = count_recent_dst_sport_ltm(flow["origin_dst_ip"], flow["origin_src_port"], now)
    ct_state_ttl = count_recent_state_ttl(state, sttl, now)

    return {
        "sttl": sttl,
        "ct_state_ttl": ct_state_ttl,
        "dload": flow["dbytes"] / dur if dur > 0 else 0.0,
        "rate": rate,
        "sload": flow["sbytes"] / dur if dur > 0 else 0.0,
        "dttl": dttl,
        "dmean": dmean,
        "ackdat": ackdat,
        "ct_srv_dst": ct_srv_dst,
        "synack": synack,
        "tcprtt": tcprtt,
        "ct_srv_src": ct_srv_src,
        "dbytes": flow["dbytes"],
        "ct_dst_src_ltm": ct_dst_src_ltm,
        "sinpkt": sinpkt,
        "djit": djit,
        "dpkts": flow["dpkts"],
        "state": state,
        "ct_dst_sport_ltm": ct_dst_sport_ltm,
        "spkts": flow["spkts"],
        "ct_dst_ltm": ct_dst_ltm,
        "sbytes": flow["sbytes"],
        "smean": smean,
        "proto": flow["proto"],
        "service": service,
        "dur": dur,

        # extra useful diagnostics
        "dinpkt": dinpkt,
        "sjit": sjit,
    }

# -----------------------------
# Finalization
# -----------------------------
def add_flow_to_recent_history(flow, features):
    recent_flows.append({
        "src_ip": flow["origin_src_ip"],
        "dst_ip": flow["origin_dst_ip"],
        "src_port": flow["origin_src_port"],
        "dst_port": flow["origin_dst_port"],
        "service": features["service"],
        "state": features["state"],
        "sttl": features["sttl"],
        "end_time": flow["last_seen"],
    })

def finalize_flow(flow_key):
    if flow_key not in flows:
        return None

    flow = flows.pop(flow_key)
    features = compute_features(flow)
    add_flow_to_recent_history(flow, features)

    label, probability = predict_flow(features)

    print("\nFinalized Flow")
    print(f"Flow Key: {flow_key}")
    for k, v in features.items():
        print(f"{k}: {v}")
    print(f"Prediction: {label}")
    print(f"Attack probability: {probability:.4f}")
    print("-" * 70)

    return features

def cleanup_expired_flows():
    now = time.time()
    expired = []

    for flow_key, flow in flows.items():
        if now - flow["last_seen"] > FLOW_TIMEOUT:
            expired.append(flow_key)

    for flow_key in expired:
        finalize_flow(flow_key)

# -----------------------------
# Packet handling
# -----------------------------
def handle_packet(packet):
    cleanup_expired_flows()

    if IP not in packet:
        return

    flow_key = get_flow_key(packet)
    pkt_len = len(packet)
    now = time.time()

    if flow_key not in flows:
        src_port, dst_port = get_ports(packet)
        flows[flow_key] = {
            "start_time": now,
            "last_seen": now,
            "origin_src_ip": packet[IP].src,
            "origin_dst_ip": packet[IP].dst,
            "origin_src_port": src_port,
            "origin_dst_port": dst_port,
            "proto": get_proto(packet),

            "spkts": 0,
            "dpkts": 0,
            "sbytes": 0,
            "dbytes": 0,

            "sttl_values": [],
            "dttl_values": [],

            "src_times": [],
            "dst_times": [],

            "tcp_flags_seen": set(),
            "syn_time": None,
            "synack_time": None,
            "ack_time": None,
            "saw_rst": False,
            "saw_fin": False,
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
            # SYN from originator
            if "S" in flags and "A" not in flags and flow["syn_time"] is None:
                flow["syn_time"] = now
            # final ACK from originator after SYN-ACK
            if "A" in flags and "S" not in flags and flow["synack_time"] is not None and flow["ack_time"] is None:
                flow["ack_time"] = now
        else:
            # SYN-ACK from responder
            if "S" in flags and "A" in flags and flow["synack_time"] is None:
                flow["synack_time"] = now

        # finalize immediately on RST or FIN if you want faster flow closure
        if flow["saw_rst"] or flow["saw_fin"]:
            finalize_flow(flow_key)

# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    print("Sniffing packets and building live IDS features...")
    try:
        sniff(prn=handle_packet, store=False)
    except KeyboardInterrupt:
        print("\nStopping sniff. Finalizing remaining flows...")
        for key in list(flows.keys()):
            finalize_flow(key)
        print("Done.") 