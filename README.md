Home SOC Lab – Detection Engineering with Wazuh
1. Project Objective

This project was built to simulate a realistic Windows credential compromise scenario within a controlled home SOC environment using Wazuh SIEM.

The goal was not just to generate alerts, but to understand how raw Windows authentication logs are collected, parsed, correlated, and transformed into high-confidence security detections.

The lab models attacker behavior across multiple stages, including brute-force login attempts, successful authentication after repeated failures, and privilege escalation through local administrator group modification.

By engineering custom correlation rules and validating detections against raw Windows event logs, this project demonstrates practical detection engineering, rule tuning, and attack timeline reconstruction inside a SIEM.

2. Lab Architecture

This lab was built using a dual-VM architecture inside Oracle VirtualBox to simulate a monitored enterprise endpoint environment.

# Environment Overview

The setup consists of two virtual machines:

# 1. Wazuh Server (Monitoring System)

* Operating System: Ubuntu 24.04 (64-bit)
* RAM: 8 GB
* CPU: 4 cores
* Network Mode: Bridged Adapter

Installed Components:

* Wazuh Manager
* Wazuh Indexer
* Wazuh Dashboard
* Filebeat

This machine acts as the centralized monitoring and detection engine.

---

# 2. Windows Endpoint (Monitored Target)

* Operating System: Windows 11 (64-bit)
* RAM: 8 GB
* CPU: 4 cores
* Network Mode: Bridged Adapter

Installed Component:

* Wazuh Agent

This machine generates Windows Security Event logs that are collected and analyzed by the Wazuh server.

---

# Network Configuration

Both machines were configured using a Bridged Adapter to obtain IP addresses on the same local network.

Example configuration from lab:

* Ubuntu Server IP: 192.168.29.40
* Windows Endpoint IP: 192.168.29.76

Connectivity was validated using ICMP ping tests between both systems.

This ensured proper agent-to-manager communication.

---

# Data Flow Architecture

The log pipeline follows this flow:

Windows Security Logs
→ Wazuh Agent
→ Wazuh Manager
→ Wazuh Indexer
→ Wazuh Dashboard

This pipeline enables raw authentication events to be collected, correlated, and transformed into actionable alerts.

---

# System Tuning & Prerequisites

To ensure stable operation of the Wazuh Indexer (Elasticsearch backend), system parameters were configured:

* `vm.max_map_count` increased
* OpenJDK 17 installed
* Package conflicts resolved during installation
* Repository connectivity validated

Service validation confirmed successful startup of:

* wazuh-manager
* wazuh-indexer
* wazuh-dashboard
* filebeat

---
4. Attack Scenario Simulated
5. Detection Engineering Approach
6. Attack Timeline Reconstruction
7. MITRE ATT&CK Mapping
8. Key Learning Outcomes
9. Future Improvements
