# Home SOC Lab – Detection Engineering with Wazuh

## 1. Project Objective

This project was built to simulate a realistic Windows credential compromise scenario within a controlled home SOC environment using Wazuh SIEM.

The goal was not just to generate alerts, but to understand how raw Windows authentication logs are collected, parsed, correlated, and transformed into high-confidence security detections.

The lab models attacker behavior across multiple stages, including brute-force login attempts, successful authentication after repeated failures, and privilege escalation through local administrator group modification.

By engineering custom correlation rules and validating detections against raw Windows event logs, this project demonstrates practical detection engineering, rule tuning, and attack timeline reconstruction inside a SIEM.

---

## 2. Lab Architecture

This lab was built using a dual-VM architecture inside Oracle VirtualBox to simulate a monitored enterprise endpoint environment.

### Environment Overview

The setup consists of two virtual machines.

#### 2.1 Wazuh Server (Monitoring System)

- Operating System: Ubuntu 24.04 (64-bit)
- RAM: 8 GB
- CPU: 4 cores
- Network Mode: Bridged Adapter

Installed Components:
- Wazuh Manager
- Wazuh Indexer
- Wazuh Dashboard
- Filebeat

This machine acts as the centralized monitoring and detection engine.

#### 2.2 Windows Endpoint (Monitored Target)

- Operating System: Windows 11 (64-bit)
- RAM: 8 GB
- CPU: 4 cores
- Network Mode: Bridged Adapter

Installed Component:
- Wazuh Agent

This machine generates Windows Security Event logs that are collected and analyzed by the Wazuh server.

---

### Network Configuration

Both machines were configured using a Bridged Adapter to obtain IP addresses on the same local network.

Example configuration from lab:

- Ubuntu Server IP: 192.168.29.40  
- Windows Endpoint IP: 192.168.29.76  

Connectivity was validated using ICMP ping tests between both systems.

This ensured proper agent-to-manager communication.

---

### Data Flow Architecture

The log pipeline follows this flow:

Windows Security Logs  
→ Wazuh Agent  
→ Wazuh Manager  
→ Wazuh Indexer  
→ Wazuh Dashboard  

This pipeline enables raw authentication events to be collected, correlated, and transformed into actionable alerts.

---

### System Tuning & Prerequisites

To ensure stable operation of the Wazuh Indexer (Elasticsearch backend), system parameters were configured:

- `vm.max_map_count` increased  
- OpenJDK 17 installed  
- Package conflicts resolved during installation  
- Repository connectivity validated  

Service validation confirmed successful startup of:

- wazuh-manager  
- wazuh-indexer  
- wazuh-dashboard  
- filebeat  

---

## 3. Attack Scenario Simulated

This lab simulates a credential-based attack against a monitored Windows endpoint to test multi-stage detection within Wazuh.

The objective was to reproduce a realistic attack sequence involving authentication abuse followed by privilege escalation.

---

### Stage 1: Brute-Force Login Attempts

Multiple failed login attempts were generated against a Windows user account to simulate password guessing behavior.

**Windows Event ID: 4625 — Failed Logon**

Each failed attempt produces a security event in the Windows Security log.  

Repeated 4625 events within a short timeframe indicate potential brute-force activity.

---

### Stage 2: Successful Authentication After Repeated Failures

After several failed login attempts, a successful login was performed using valid credentials.

**Windows Event ID: 4624 — Successful Logon**

A successful login occurring shortly after multiple failed attempts can indicate credential compromise.

This stage validates correlation logic that detects suspicious login patterns rather than isolated events.

---

### Stage 3: Privilege Escalation via Group Modification

Following successful authentication, the user account was added to the local Administrators group.

**Windows Event ID: 4732 — Member Added to Security-Enabled Local Group**

This simulates privilege escalation, where an attacker attempts to gain elevated permissions after gaining initial access.

---

### Attack Chain Summary

The full attack sequence followed this progression:

1. Multiple 4625 events (failed logins)
2. One 4624 event (successful login)
3. One 4732 event (privilege escalation)

This structured progression was used to test detection logic, rule correlation, and alert escalation within the SIEM.

---

## 4. Detection Engineering Approach

(Section to be completed)

## 5. Attack Timeline Reconstruction

(Section to be completed)

## 6. MITRE ATT&CK Mapping

(Section to be completed)

## 7. Key Learning Outcomes

(Section to be completed)

## 8. Future Improvements

(Section to be completed)
