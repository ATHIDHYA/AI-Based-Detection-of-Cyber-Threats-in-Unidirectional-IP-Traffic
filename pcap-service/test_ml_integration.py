#!/usr/bin/env python3
"""
test_ml_integration.py
----------------------
Quick test to verify the ML model integration works correctly.
"""

import json
import numpy as np

# Import the functions from analyze_pcap
import sys
sys.path.insert(0, '/home/athidhya/Downloads/project/pcap-service')

# Import the specific functions we need to test
from analyze_pcap import build_feature_vector, maybe_run_ml_model

def test_feature_vector_builder():
    """Test the feature vector builder with sample data."""
    print("Testing feature vector builder...")
    
    # Create sample aggregated data
    sample_agg = {
        "flow_bytes": {("192.168.1.1", "10.0.0.1"): 1500, ("192.168.1.2", "10.0.0.1"): 2000},
        "flow_pkts": {("192.168.1.1", "10.0.0.1"): 10, ("192.168.1.2", "10.0.0.1"): 15},
        "flow_times": {("192.168.1.1", "10.0.0.1"): [1.0, 2.0], ("192.168.1.2", "10.0.0.1"): [1.5, 2.5]},
        "src_to_dst_ports": {"192.168.1.1": {80, 443}, "192.168.1.2": {22, 80}},
        "src_to_dst_hosts": {"192.168.1.1": {"10.0.0.1"}, "192.168.1.2": {"10.0.0.1", "10.0.0.2"}},
        "dst_srcs": {"10.0.0.1": {"192.168.1.1", "192.168.1.2"}, "10.0.0.2": {"192.168.1.2"}},
        "dst_syn_count": {"10.0.0.1": 5, "10.0.0.2": 2},
        "dns_queries": [("example.com", 1.0, "192.168.1.1")],
        "dns_record_sizes": [100, 150],
        "icmp_count": {"192.168.1.1": 3, "192.168.1.2": 1},
        "total_bytes_per_src": {"192.168.1.1": 1500, "192.168.1.2": 2000},
        "duration": 10.0,
        "packet_count": 25,
    }
    
    try:
        feature_vector = build_feature_vector(sample_agg)
        print(f"✓ Feature vector built successfully with {len(feature_vector)} features")
        print(f"Sample features: {feature_vector[:5]}...")
        return True
    except Exception as e:
        print(f"✗ Feature vector builder failed: {e}")
        return False

def test_ml_model_loading():
    """Test loading and using the ML model."""
    print("\nTesting ML model loading and inference...")
    
    # Create sample aggregated data (more malicious-like)
    malicious_agg = {
        "flow_bytes": {("192.168.1.1", "10.0.0.1"): 50000, ("192.168.1.2", "10.0.0.1"): 60000},
        "flow_pkts": {("192.168.1.1", "10.0.0.1"): 500, ("192.168.1.2", "10.0.0.1"): 600},
        "flow_times": {("192.168.1.1", "10.0.0.1"): [1.0, 2.0, 3.0], ("192.168.1.2", "10.0.0.1"): [1.5, 2.5, 3.5]},
        "src_to_dst_ports": {"192.168.1.1": {80, 443, 22, 3389, 8080}, "192.168.1.2": {21, 23, 25, 53, 110}},
        "src_to_dst_hosts": {"192.168.1.1": {"10.0.0.1", "10.0.0.2", "10.0.0.3"}, "192.168.1.2": {"10.0.0.1", "10.0.0.4", "10.0.0.5"}},
        "dst_srcs": {"10.0.0.1": {"192.168.1.1", "192.168.1.2"}, "10.0.0.2": {"192.168.1.1"}, "10.0.0.3": {"192.168.1.1"}, "10.0.0.4": {"192.168.1.2"}, "10.0.0.5": {"192.168.1.2"}},
        "dst_syn_count": {"10.0.0.1": 300, "10.0.0.2": 150, "10.0.0.3": 100, "10.0.0.4": 50, "10.0.0.5": 25},
        "dns_queries": [("malicious.com", 1.0, "192.168.1.1"), ("suspicious.net", 2.0, "192.168.1.2")] * 10,
        "dns_record_sizes": [200, 250, 300] * 10,
        "icmp_count": {"192.168.1.1": 50, "192.168.1.2": 75},
        "total_bytes_per_src": {"192.168.1.1": 50000, "192.168.1.2": 60000},
        "duration": 5.0,
        "packet_count": 1100,
    }
    
    model_path = "/home/athidhya/Downloads/project/pcap-service/threat_detection_model.pkl"
    
    try:
        result = maybe_run_ml_model(malicious_agg, model_path)
        print(f"✓ ML model inference completed")
        print(f"Result: {json.dumps(result, indent=2)}")
        return True
    except Exception as e:
        print(f"✗ ML model inference failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("=" * 60)
    print("ML Integration Test")
    print("=" * 60)
    
    test1 = test_feature_vector_builder()
    test2 = test_ml_model_loading()
    
    print("\n" + "=" * 60)
    if test1 and test2:
        print("✓ All tests passed! ML integration is working correctly.")
    else:
        print("✗ Some tests failed. Please check the errors above.")
    print("=" * 60)

if __name__ == "__main__":
    main()