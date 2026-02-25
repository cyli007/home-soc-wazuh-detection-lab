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

This section explains how raw Windows authentication events were transformed into correlated, high-confidence security detections within Wazuh.

---

### 4.1 Log Ingestion and Rule Evaluation

Windows Security events were generated on the endpoint and collected by the Wazuh Agent.

The data flow followed this path:

Windows Security Logs  
→ Wazuh Agent  
→ Wazuh Manager  
→ Wazuh Indexer  
→ Wazuh Dashboard  

The Wazuh Manager evaluates incoming events against built-in detection rules before applying custom correlation logic.

---

### 4.2 Built-In Rule Detection

Wazuh includes default rules for Windows authentication events:

- Event ID 4625 → Failed logon detection
- Event ID 4624 → Successful logon detection
- Event ID 4732 → Security-enabled group modification

These rules detect individual events but do not automatically correlate multi-stage attack behavior.

---

### 4.3 Custom Correlation Design

To simulate realistic detection engineering, custom correlation rules were created in `local_rules.xml`.

The objective was to detect attack progression rather than isolated events.

---

### 4.4 Rule 100010 – Brute Force Followed by Successful Login

This rule triggers when built-in brute-force detection (Rule 60204) is followed by a successful login event.

```xml
<rule id="100010" level="14">
  <if_matched_sid>60204</if_matched_sid>
  <if_sid>60118</if_sid>
  <description>POSSIBLE ACCOUNT COMPROMISE: brute force followed by successful login</description>
  <mitre>
    <id>T1078</id>
  </mitre>
</rule>
```

Logic Explanation:

* `if_matched_sid 60204` → A brute-force pattern was already detected.
* `if_sid 60118` → A successful login occurred.
* Level 14 → High severity.
* MITRE T1078 → Valid Accounts technique.

This rule correlates repeated failures with a successful login, indicating potential credential compromise.

---

### 4.5 Rule 100020 – Privilege Escalation After Compromise

This rule escalates severity when a compromised account is added to the local Administrators group.

```xml
<rule id="100020" level="15">
  <if_matched_sid>100010</if_matched_sid>
  <field name="win.system.eventID">4732</field>
  <description>CRITICAL: Compromised account escalated to local administrator</description>
  <mitre>
    <id>T1098</id>
    <id>T1068</id>
  </mitre>
</rule>
```

Logic Explanation:

* `if_matched_sid 100010` → The compromise rule already triggered.
* `eventID 4732` → Account added to local group.
* Level 15 → Critical severity.
* MITRE T1098 and T1068 → Account Manipulation and Privilege Escalation.

This models full attack progression: compromise → escalation.

---

### 4.6 Alert Validation

Detections were validated using:

* Wazuh Dashboard alert timeline
* `alerts.json` inspection on the manager
* Windows Event Viewer comparison

This cross-validation ensured that detection logic accurately represented real authentication activity.

---

## 5. Attack Timeline Reconstruction

(Section to be completed)

## 6. MITRE ATT&CK Mapping

(Section to be completed)

## 7. Key Learning Outcomes

(Section to be completed)

## 8. Future Improvements

(Section to be completed)
