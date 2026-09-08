#!/usr/bin/env python3
"""
analyze_pcap.py
----------------
Reads a .pcap/.pcapng file and detects candidate threats in UNIDIRECTIONAL
IP traffic (i.e. we only see one side of each conversation -> no reliable
handshake completion, no RTT, no ACK-based flow state).

Usage:
    python analyze_pcap.py <path_to_pcap> [--model model.pkl]

Output:
    Single JSON object printed to stdout (Node reads this from stdout).

Design notes (why features are chosen this way):
- Because only one direction is visible, we CANNOT trust bidirectional
  flow completion (SYN/SYN-ACK/ACK) to say "this connection succeeded".
- Instead we lean on features that are valid from a single vantage point:
    * volumetric (packet/byte rates, fan-out to many dst IPs/ports)
    * temporal (inter-arrival time regularity -> beaconing)
    * content (DNS query names -> DGA, TXT record sizes -> tunneling)
    * source diversity (many src IPs to one dst -> DDoS; one src to many
      dst ports -> port scan / recon)
"""

import sys
import json
import math
import argparse
import statistics
import numpy as np
from collections import defaultdict, Counter

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, Raw
except ImportError:
    print(json.dumps({"error": "scapy not installed. pip install scapy"}))
    sys.exit(1)

THRESHOLDS = {
    "ddos_min_pps_to_single_dst": 200,
    "ddos_min_unique_srcs": 20,
    "portscan_min_unique_dst_ports": 15,
    "portscan_min_unique_dst_hosts": 10,
    "beacon_min_occurrences": 6,
    "beacon_max_jitter_ratio": 0.15,
    "dga_min_entropy": 3.5,
    "dga_min_len": 12,
    "exfil_min_bytes_per_src_dst": 5_000_000,
    "dns_tunnel_min_txt_len": 150,
}

KNOWN_MALWARE_PORTS = {4444, 4899, 31337, 12345, 6667, 6666, 1080}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_private_ip(ip: str) -> bool:
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("172.16.") or ip.startswith("172.17.")
        or ip.startswith("172.18.") or ip.startswith("172.19.")
        or ip.startswith("172.20.") or ip.startswith("172.21.")
        or ip.startswith("172.22.") or ip.startswith("172.23.")
        or ip.startswith("172.24.") or ip.startswith("172.25.")
        or ip.startswith("172.26.") or ip.startswith("172.27.")
        or ip.startswith("172.28.") or ip.startswith("172.29.")
        or ip.startswith("172.30.") or ip.startswith("172.31.")
        or ip.startswith("127.")
    )


def load_packets(path):
    try:
        return rdpcap(path)
    except Exception as e:
        print(json.dumps({"error": f"failed to read pcap: {e}"}))
        sys.exit(1)


def extract_flows(packets):
    flow_bytes = defaultdict(int)
    flow_pkts = defaultdict(int)
    flow_times = defaultdict(list)
    src_to_dst_ports = defaultdict(set)
    src_to_dst_hosts = defaultdict(set)
    dst_srcs = defaultdict(set)
    dst_syn_count = defaultdict(int)
    dns_queries = []
    dns_record_sizes = []
    icmp_count = defaultdict(int)
    total_bytes_per_src = defaultdict(int)
    timestamps = []

    for pkt in packets:
        if IP in pkt:
            ip_layer = pkt[IP]
        elif IPv6 in pkt:
            ip_layer = pkt[IPv6]
        else:
            continue

        src, dst = ip_layer.src, ip_layer.dst
        ts = float(pkt.time)
        timestamps.append(ts)
        size = len(pkt)

        flow_bytes[(src, dst)] += size
        flow_pkts[(src, dst)] += 1
        flow_times[(src, dst)].append(ts)
        total_bytes_per_src[src] += size
        dst_srcs[dst].add(src)

        if TCP in pkt:
            tcp = pkt[TCP]
            src_to_dst_ports[src].add(tcp.dport)
            src_to_dst_hosts[src].add(dst)
            if tcp.flags & 0x02 and not tcp.flags & 0x10:
                dst_syn_count[dst] += 1

        if UDP in pkt:
            udp = pkt[UDP]
            src_to_dst_ports[src].add(udp.dport)
            src_to_dst_hosts[src].add(dst)

        if ICMP in pkt:
            icmp_count[src] += 1
            src_to_dst_hosts[src].add(dst)

        if pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                dns_queries.append((qname, ts, src))
            except Exception:
                pass

        if pkt.haslayer(DNS) and Raw in pkt:
            dns_record_sizes.append(len(pkt[Raw].load))

    duration = (max(timestamps) - min(timestamps)) if len(timestamps) > 1 else 1.0
    duration = max(duration, 0.001)

    return {
        "flow_bytes": flow_bytes,
        "flow_pkts": flow_pkts,
        "flow_times": flow_times,
        "src_to_dst_ports": src_to_dst_ports,
        "src_to_dst_hosts": src_to_dst_hosts,
        "dst_srcs": dst_srcs,
        "dst_syn_count": dst_syn_count,
        "dns_queries": dns_queries,
        "dns_record_sizes": dns_record_sizes,
        "icmp_count": icmp_count,
        "total_bytes_per_src": total_bytes_per_src,
        "duration": duration,
        "packet_count": len(packets),
    }


def detect_ddos(agg):
    findings = []
    for dst, srcs in agg["dst_srcs"].items():
        pkt_total = sum(agg["flow_pkts"][(s, dst)] for s in srcs)
        pps = pkt_total / agg["duration"]
        syns = agg["dst_syn_count"].get(dst, 0)
        if pps >= THRESHOLDS["ddos_min_pps_to_single_dst"] and len(srcs) >= THRESHOLDS["ddos_min_unique_srcs"]:
            findings.append({
                "target": dst,
                "unique_sources": len(srcs),
                "packets_per_second": round(pps, 2),
                "syn_packets": syns,
                "subtype": "SYN flood" if syns / max(pkt_total, 1) > 0.6 else "volumetric flood",
            })
    return findings


def detect_recon(agg):
    findings = []
    for src, ports in agg["src_to_dst_ports"].items():
        hosts = agg["src_to_dst_hosts"].get(src, set())
        if len(ports) >= THRESHOLDS["portscan_min_unique_dst_ports"]:
            findings.append({"source": src, "unique_dst_ports": len(ports), "unique_dst_hosts": len(hosts), "subtype": "port scan"})
        elif len(hosts) >= THRESHOLDS["portscan_min_unique_dst_hosts"]:
            findings.append({"source": src, "unique_dst_ports": len(ports), "unique_dst_hosts": len(hosts), "subtype": "host sweep"})
    for src, count in agg["icmp_count"].items():
        hosts = agg["src_to_dst_hosts"].get(src, set())
        if count >= THRESHOLDS["portscan_min_unique_dst_hosts"] and len(hosts) >= THRESHOLDS["portscan_min_unique_dst_hosts"]:
            findings.append({"source": src, "icmp_probes": count, "subtype": "ICMP sweep"})
    return findings


def detect_dga(agg):
    findings = []
    seen = set()
    for qname, ts, src in agg["dns_queries"]:
        label = qname.split(".")[0] if "." in qname else qname
        ent = shannon_entropy(label)
        if len(label) >= THRESHOLDS["dga_min_len"] and ent >= THRESHOLDS["dga_min_entropy"]:
            key = (src, qname)
            if key not in seen:
                seen.add(key)
                findings.append({"source": src, "query": qname, "entropy": round(ent, 2), "label_length": len(label)})
    return findings


def detect_c2_beaconing(agg):
    findings = []
    for (src, dst), times in agg["flow_times"].items():
        if is_private_ip(dst):
            continue
        if len(times) < THRESHOLDS["beacon_min_occurrences"]:
            continue
        times_sorted = sorted(times)
        intervals = [t2 - t1 for t1, t2 in zip(times_sorted, times_sorted[1:]) if (t2 - t1) > 0]
        if len(intervals) < 3:
            continue
        mean_iv = statistics.mean(intervals)
        stdev_iv = statistics.pstdev(intervals)
        jitter_ratio = (stdev_iv / mean_iv) if mean_iv > 0 else 1.0
        if jitter_ratio <= THRESHOLDS["beacon_max_jitter_ratio"]:
            findings.append({
                "source": src,
                "destination": dst,
                "contacts": len(times),
                "avg_interval_sec": round(mean_iv, 2),
                "jitter_ratio": round(jitter_ratio, 3),
                "subtype": "regular beaconing",
            })
    return findings


def detect_exfiltration(agg):
    findings = []
    for (src, dst), byte_count in agg["flow_bytes"].items():
        if is_private_ip(dst):
            continue
        if byte_count >= THRESHOLDS["exfil_min_bytes_per_src_dst"]:
            findings.append({"source": src, "destination": dst, "bytes": byte_count, "subtype": "bulk outbound transfer"})
    large_dns = [r for r in agg["dns_record_sizes"] if r >= THRESHOLDS["dns_tunnel_min_txt_len"]]
    if len(large_dns) >= 10:
        findings.append({"subtype": "possible DNS tunneling", "oversized_dns_records": len(large_dns)})
    return findings


def detect_malware_indicators(agg):
    findings = []
    for src, ports in agg["src_to_dst_ports"].items():
        hits = ports & KNOWN_MALWARE_PORTS
        if hits:
            findings.append({"source": src, "suspicious_ports": list(hits), "subtype": "known malware/backdoor port"})
    return findings


def score_risk(threats: dict) -> int:
    weight = {"ddos": 25, "recon": 10, "dga": 20, "c2": 25, "exfiltration": 25, "malware": 20}
    score = 0
    for name, findings in threats.items():
        if findings:
            score += min(weight.get(name, 10) * len(findings), weight.get(name, 10) * 3)
    return min(score, 100)


def build_feature_vector(agg):
    """
    Build a fixed-length feature vector from aggregated traffic statistics
    for ML classification. This vector captures key characteristics of the
    network traffic that can be used to distinguish between benign and malicious behavior.
    """
    # Basic traffic statistics
    packet_count = agg["packet_count"]
    duration = agg["duration"]
    unique_sources = len(agg["total_bytes_per_src"])
    unique_destinations = len(agg["dst_srcs"])
    total_bytes = sum(agg["flow_bytes"].values())
    
    # Rate-based features
    packets_per_second = packet_count / duration if duration > 0 else 0
    bytes_per_second = total_bytes / duration if duration > 0 else 0
    
    # Flow diversity features
    avg_flows_per_source = len(agg["flow_bytes"]) / max(unique_sources, 1)
    avg_bytes_per_source = total_bytes / max(unique_sources, 1)
    
    # Port and host scanning features
    if unique_sources > 0:
        max_ports_per_source = max(len(ports) for ports in agg["src_to_dst_ports"].values())
        avg_ports_per_source = sum(len(ports) for ports in agg["src_to_dst_ports"].values()) / unique_sources
        max_hosts_per_source = max(len(hosts) for hosts in agg["src_to_dst_hosts"].values())
        avg_hosts_per_source = sum(len(hosts) for hosts in agg["src_to_dst_hosts"].values()) / unique_sources
    else:
        max_ports_per_source = avg_ports_per_source = max_hosts_per_source = avg_hosts_per_source = 0
    
    # DDoS-related features
    if unique_destinations > 0:
        max_sources_per_destination = max(len(srcs) for srcs in agg["dst_srcs"].values())
        avg_sources_per_destination = sum(len(srcs) for srcs in agg["dst_srcs"].values()) / unique_destinations
    else:
        max_sources_per_destination = avg_sources_per_destination = 0
    
    # DNS-related features
    dns_query_count = len(agg["dns_queries"])
    avg_dns_record_size = sum(agg["dns_record_sizes"]) / len(agg["dns_record_sizes"]) if agg["dns_record_sizes"] else 0
    max_dns_record_size = max(agg["dns_record_sizes"]) if agg["dns_record_sizes"] else 0
    
    # ICMP activity
    total_icmp_count = sum(agg["icmp_count"].values())
    avg_icmp_per_source = total_icmp_count / max(unique_sources, 1)
    
    # TCP SYN flood indicators
    total_syn_count = sum(agg["dst_syn_count"].values())
    syn_ratio = total_syn_count / max(packet_count, 1)
    
    # Flow size statistics
    flow_sizes = list(agg["flow_bytes"].values())
    if flow_sizes:
        max_flow_size = max(flow_sizes)
        avg_flow_size = sum(flow_sizes) / len(flow_sizes)
        std_flow_size = (sum((x - avg_flow_size) ** 2 for x in flow_sizes) / len(flow_sizes)) ** 0.5
    else:
        max_flow_size = avg_flow_size = std_flow_size = 0
    
    # Flow packet statistics
    flow_packets = list(agg["flow_pkts"].values())
    if flow_packets:
        max_flow_packets = max(flow_packets)
        avg_flow_packets = sum(flow_packets) / len(flow_packets)
    else:
        max_flow_packets = avg_flow_packets = 0
    
    # Return as a fixed-length numpy array
    return [
        packet_count,
        duration,
        unique_sources,
        unique_destinations,
        total_bytes,
        packets_per_second,
        bytes_per_second,
        avg_flows_per_source,
        avg_bytes_per_source,
        max_ports_per_source,
        avg_ports_per_source,
        max_hosts_per_source,
        avg_hosts_per_source,
        max_sources_per_destination,
        avg_sources_per_destination,
        dns_query_count,
        avg_dns_record_size,
        max_dns_record_size,
        total_icmp_count,
        avg_icmp_per_source,
        total_syn_count,
        syn_ratio,
        max_flow_size,
        avg_flow_size,
        std_flow_size,
        max_flow_packets,
        avg_flow_packets,
    ]


def maybe_run_ml_model(agg, model_path):
    """
    Optional hook: if you have a trained scikit-learn model (.pkl) built on
    labeled flow features, load it here and return its predictions to merge
    with the rule-based findings above.
    """
    if not model_path:
        return None
    try:
        import pickle
        import numpy as np
        import os
        
        # Load model
        with open(model_path, "rb") as f:
            model = pickle.load(f)
        
        # Load scaler if it exists in the same directory
        model_dir = os.path.dirname(model_path)
        scaler_path = os.path.join(model_dir, "threat_detection_scaler.pkl")
        
        # Build feature vector from aggregated statistics
        feature_vector = build_feature_vector(agg)
        
        # Scale features if scaler is available
        if os.path.exists(scaler_path):
            with open(scaler_path, "rb") as f:
                scaler = pickle.load(f)
            feature_vector_scaled = scaler.transform([feature_vector])
        else:
            feature_vector_scaled = [feature_vector]
        
        # Get prediction and probability
        prediction = model.predict(feature_vector_scaled)[0]
        probabilities = model.predict_proba(feature_vector_scaled)[0]
        
        # Map prediction to threat type
        threat_classes = list(model.classes_) if hasattr(model, 'classes_') else ['benign', 'malicious']
        predicted_class = threat_classes[prediction] if prediction < len(threat_classes) else 'unknown'
        confidence = max(probabilities) if len(probabilities) > 0 else 0.0
        
        # Convert numpy types to native Python types for JSON serialization
        return {
            "ml_prediction": str(predicted_class),
            "confidence": float(round(confidence, 3)),
            "feature_vector_length": int(len(feature_vector)),
            "model_type": str(type(model).__name__),
            "scaler_used": bool(os.path.exists(scaler_path))
        }
    except Exception as e:
        return {"error": f"ML model inference failed: {str(e)}"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap_path")
    parser.add_argument("--model", default=None, help="optional path to trained .pkl model")
    args = parser.parse_args()

    packets = load_packets(args.pcap_path)
    agg = extract_flows(packets)

    threats = {
        "ddos": detect_ddos(agg),
        "recon": detect_recon(agg),
        "dga": detect_dga(agg),
        "c2": detect_c2_beaconing(agg),
        "exfiltration": detect_exfiltration(agg),
        "malware": detect_malware_indicators(agg),
    }

    ml_result = maybe_run_ml_model(agg, args.model)

    result = {
        "summary": {
            "packet_count": agg["packet_count"],
            "duration_sec": round(agg["duration"], 2),
            "unique_sources": len(agg["total_bytes_per_src"]),
            "unique_destinations": len(agg["dst_srcs"]),
        },
        "threats": threats,
        "risk_score": score_risk(threats),
        "ml_result": ml_result,
    }

    print(json.dumps(result))


if __name__ == "__main__":
    main()
