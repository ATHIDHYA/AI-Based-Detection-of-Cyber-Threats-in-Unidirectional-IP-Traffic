#!/usr/bin/env python3
"""
train_model.py
--------------
Training script for the threat detection ML model.
This script generates synthetic training data based on network traffic patterns
and trains a Random Forest classifier to distinguish between benign and malicious traffic.

Since real labeled network traffic datasets are not provided, this creates a
demonstration model using synthetic data that mimics common attack patterns.
"""

import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import random


def generate_synthetic_traffic_data(n_samples=1000):
    """
    Generate synthetic network traffic data for training.
    Creates both benign and malicious traffic patterns.
    """
    print(f"Generating {n_samples} synthetic traffic samples...")
    
    features = []
    labels = []
    
    for i in range(n_samples):
        # Randomly choose class (0 = benign, 1 = malicious)
        is_malicious = random.random() < 0.4  # 40% malicious
        
        # Initialize all variables with default values
        packet_count = random.randint(50, 2000)
        duration = random.uniform(5, 120)
        unique_sources = random.randint(1, 10)
        unique_destinations = random.randint(1, 20)
        total_bytes = packet_count * random.randint(64, 500)
        packets_per_second = packet_count / duration
        bytes_per_second = total_bytes / duration
        max_ports_per_source = random.randint(1, 10)
        max_hosts_per_source = random.randint(1, 10)
        max_sources_per_destination = random.randint(1, 5)
        syn_ratio = random.uniform(0.01, 0.2)
        total_icmp_count = random.randint(0, 20)
        max_flow_size = total_bytes / max(unique_destinations, 1)
        
        if is_malicious:
            # Malicious traffic patterns
            attack_type = random.choice(['ddos', 'recon', 'exfil', 'malware'])
            
            if attack_type == 'ddos':
                # DDoS: high packet rate, many sources to single destination
                packet_count = random.randint(5000, 50000)
                duration = random.uniform(1, 10)
                unique_sources = random.randint(50, 500)
                unique_destinations = random.randint(1, 5)
                total_bytes = packet_count * random.randint(64, 1500)
                packets_per_second = packet_count / duration
                bytes_per_second = total_bytes / duration
                max_sources_per_destination = random.randint(30, 200)
                syn_ratio = random.uniform(0.3, 0.8)
                
            elif attack_type == 'recon':
                # Reconnaissance: port scanning behavior
                packet_count = random.randint(100, 2000)
                duration = random.uniform(10, 60)
                unique_sources = random.randint(1, 5)
                unique_destinations = random.randint(10, 100)
                total_bytes = packet_count * random.randint(64, 200)
                packets_per_second = packet_count / duration
                bytes_per_second = total_bytes / duration
                max_ports_per_source = random.randint(20, 100)
                max_hosts_per_source = random.randint(15, 80)
                max_sources_per_destination = random.randint(1, 3)
                syn_ratio = random.uniform(0.1, 0.4)
                
            elif attack_type == 'exfil':
                # Data exfiltration: high volume to few destinations
                packet_count = random.randint(1000, 10000)
                duration = random.uniform(30, 300)
                unique_sources = random.randint(1, 3)
                unique_destinations = random.randint(1, 3)
                total_bytes = packet_count * random.randint(1000, 1500)
                packets_per_second = packet_count / duration
                bytes_per_second = total_bytes / duration
                max_flow_size = random.randint(500000, 5000000)
                syn_ratio = random.uniform(0.01, 0.1)
                
            else:  # malware
                # Malware: suspicious patterns
                packet_count = random.randint(200, 3000)
                duration = random.uniform(5, 60)
                unique_sources = random.randint(1, 10)
                unique_destinations = random.randint(1, 20)
                total_bytes = packet_count * random.randint(100, 500)
                packets_per_second = packet_count / duration
                bytes_per_second = total_bytes / duration
                max_ports_per_source = random.randint(1, 10)
                max_hosts_per_source = random.randint(1, 15)
                total_icmp_count = random.randint(0, 50)
                syn_ratio = random.uniform(0.05, 0.3)
            
            label = 1  # malicious
            
        else:
            # Benign traffic patterns (already initialized above)
            label = 0  # benign
        
        # Calculate derived features consistently
        num_flows = random.randint(1, max(unique_sources * unique_destinations, 1))
        avg_flows_per_source = num_flows / max(unique_sources, 1)
        avg_bytes_per_source = total_bytes / max(unique_sources, 1)
        avg_ports_per_source = max_ports_per_source / max(unique_sources, 1)
        avg_hosts_per_source = max_hosts_per_source / max(unique_sources, 1)
        avg_sources_per_destination = max_sources_per_destination / max(unique_destinations, 1)
        
        # DNS features
        dns_query_count = random.randint(0, 50) if not is_malicious else random.randint(0, 200)
        avg_dns_record_size = random.randint(50, 100)
        max_dns_record_size = avg_dns_record_size + random.randint(0, 50)
        
        # ICMP features
        total_icmp_count = random.randint(0, 20) if not is_malicious else random.randint(0, 100)
        avg_icmp_per_source = total_icmp_count / max(unique_sources, 1)
        
        # Flow statistics
        avg_flow_size = total_bytes / max(unique_destinations, 1) if unique_destinations > 0 else total_bytes
        std_flow_size = avg_flow_size * random.uniform(0.1, 0.5)
        max_flow_packets = packet_count / max(unique_destinations, 1) if unique_destinations > 0 else packet_count
        avg_flow_packets = packet_count / max(unique_destinations, 1) if unique_destinations > 0 else packet_count
        
        # Calculate total SYN count from syn_ratio
        total_syn_count = int(packet_count * syn_ratio)
        
        # Create feature vector (28 features to match build_feature_vector)
        feature_vector = [
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
        
        features.append(feature_vector)
        labels.append(label)
    
    return np.array(features), np.array(labels)


def train_model(X, y):
    """
    Train a Random Forest classifier on the provided data.
    """
    print("Training Random Forest classifier...")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train model
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        min_samples_split=5,
        min_samples_leaf=2
    )
    model.fit(X_train_scaled, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test_scaled)
    print("\nModel Evaluation:")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious']))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Feature importance
    feature_names = [
        'packet_count', 'duration', 'unique_sources', 'unique_destinations', 'total_bytes',
        'packets_per_second', 'bytes_per_second', 'avg_flows_per_source', 'avg_bytes_per_source',
        'max_ports_per_source', 'avg_ports_per_source', 'max_hosts_per_source', 'avg_hosts_per_source',
        'max_sources_per_destination', 'avg_sources_per_destination', 'dns_query_count',
        'avg_dns_record_size', 'max_dns_record_size', 'total_icmp_count', 'avg_icmp_per_source',
        'total_syn_count', 'syn_ratio', 'max_flow_size', 'avg_flow_size', 'std_flow_size',
        'max_flow_packets', 'avg_flow_packets'
    ]
    
    print("\nTop 10 Most Important Features:")
    importance = model.feature_importances_
    indices = np.argsort(importance)[::-1]
    for i in range(min(10, len(feature_names))):
        print(f"{i+1}. {feature_names[indices[i]]}: {importance[indices[i]]:.4f}")
    
    return model, scaler


def main():
    """
    Main training pipeline.
    """
    print("=" * 60)
    print("Threat Detection ML Model Training")
    print("=" * 60)
    
    # Generate synthetic data
    X, y = generate_synthetic_traffic_data(n_samples=2000)
    
    # Train model
    model, scaler = train_model(X, y)
    
    # Save model and scaler
    model_path = "threat_detection_model.pkl"
    scaler_path = "threat_detection_scaler.pkl"
    
    print(f"\nSaving model to {model_path}...")
    with open(model_path, "wb") as f:
        pickle.dump(model, f)
    
    print(f"Saving scaler to {scaler_path}...")
    with open(scaler_path, "wb") as f:
        pickle.dump(scaler, f)
    
    print("Training complete!")
    print(f"Model saved as: {model_path}")
    print(f"Scaler saved as: {scaler_path}")
    print("\nTo use this model, set ML_MODEL_PATH in backend/.env to:")
    print(f"/home/athidhya/Downloads/project/pcap-service/{model_path}")


if __name__ == "__main__":
    main()