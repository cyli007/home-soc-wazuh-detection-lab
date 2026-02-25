# Home SOC Lab – Detection Engineering with Wazuh

## 1. Project Objective

This project simulated a Windows credential compromise scenario within a controlled home SOC environment using Wazuh SIEM.

The objective was to move beyond basic alert generation and examine how raw Windows authentication telemetry is collected, parsed, correlated, and elevated into high-confidence detections.

The lab modeled multi-stage adversary behavior, including brute-force authentication attempts, successful credential use following repeated failures, and privilege escalation through local administrator group modification.

By implementing custom correlation rules and validating detections against raw Windows event logs, this project demonstrated structured detection engineering, severity tuning, and evidence-based attack timeline reconstruction within a SIEM environment.

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

This machine acted as the centralized monitoring and detection engine.

#### 2.2 Windows Endpoint (Monitored Target)

- Operating System: Windows 11 (64-bit)
- RAM: 8 GB
- CPU: 4 cores
- Network Mode: Bridged Adapter

Installed Component:
- Wazuh Agent

This machine generated Windows Security Event logs that were collected and analyzed by the Wazuh server.

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

This pipeline enabled raw authentication events to be collected, correlated, and transformed into actionable alerts.

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

This lab simulated a credential-based attack against a monitored Windows endpoint to test multi-stage detection within Wazuh.

The objective was to model authentication abuse followed by privilege escalation in a structured, observable sequence.

### Stage 1: Brute-Force Login Attempts

Multiple failed login attempts were generated against a Windows user account to simulate password guessing behavior.

**Windows Event ID: 4625 — Failed Logon**

Each failed attempt produces a security event in the Windows Security log.  

Repeated 4625 events within a short timeframe indicate potential brute-force activity.

### Stage 2: Successful Authentication After Repeated Failures

After several failed login attempts, a successful login was performed using valid credentials.

**Windows Event ID: 4624 — Successful Logon**

A successful login occurring shortly after multiple failed attempts can indicate credential compromise.

This stage validated correlation logic that detects suspicious login patterns rather than isolated events.

### Stage 3: Privilege Escalation via Group Modification

Following successful authentication, the user account was added to the local Administrators group.

**Windows Event ID: 4732 — Member Added to Security-Enabled Local Group**

This simulated privilege escalation, where an attacker attempted to gain elevated permissions after initial access.

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

### 4.1 Log Ingestion and Rule Evaluation

Windows Security events were generated on the endpoint and collected by the Wazuh Agent.

The data flow followed this path:

Windows Security Logs  
→ Wazuh Agent  
→ Wazuh Manager  
→ Wazuh Indexer  
→ Wazuh Dashboard  

The Wazuh Manager evaluated incoming events against built-in detection rules before applying layered custom correlation logic.

### 4.2 Built-In Rule Detection

Wazuh includes default rules for Windows authentication events:

- Event ID 4625 → Failed logon detection
- Event ID 4624 → Successful logon detection
- Event ID 4732 → Security-enabled group modification

These rules detect individual events but do not automatically correlate multi-stage attack behavior.

### 4.3 Custom Correlation Design

Custom correlation rules were implemented in `local_rules.xml` to model multi-stage attack progression and reduce isolated event noise.

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

This rule correlated repeated failures with a successful login, indicating successful credential abuse following brute-force activity.

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

This rule modeled full attack progression: compromise → escalation.

### 4.6 Alert Validation

Detections were validated using:

* Wazuh Dashboard alert timeline
* `alerts.json` inspection on the manager
* Windows Event Viewer comparison

This cross-validation ensured that detection logic accurately reflected underlying host telemetry.

---

## 5. Attack Timeline Reconstruction

This section documents the chronological reconstruction of the simulated attack using raw Windows logs and Wazuh alerts.

The objective was to validate that detection rules accurately reflected real system activity.

### 5.1 Timeline of Events

| Time     | Event ID | Description                          | Detection Outcome                           |
| -------- | -------- | ------------------------------------ | ------------------------------------------- |
| 10:47:56 | 4625     | Multiple failed login attempts begin | Built-in brute-force rule triggered (60204) |
| 10:48:20 | 4624     | Successful login recorded            | Custom Rule 100010 triggered                |
| 10:48:30 | 4732     | User added to Administrators group   | Custom Rule 100020 triggered (CRITICAL)     |

### 5.2 Stage 1 – Brute-Force Activity

Repeated Event ID 4625 entries were observed in Windows Event Viewer.

Wazuh correlated these events using the built-in brute-force detection rule (60204).

This confirmed abnormal authentication failure patterns.

### 5.3 Stage 2 – Credential Compromise Confirmation

A successful authentication (Event ID 4624) was observed shortly after repeated failures.

Custom Rule 100010 triggered, correlating the brute-force activity with a successful login.

This elevated the alert severity to reflect likely credential compromise.

### 5.4 Stage 3 – Privilege Escalation

Event ID 4732 confirmed the compromised account was added to the local Administrators group.

Custom Rule 100020 triggered a CRITICAL alert.

This validated end-to-end attack progression from initial access to privilege escalation.

### 5.5 Cross-Validation Sources

The attack chain was verified using multiple data sources:

- Windows Event Viewer (raw logs)
- Wazuh Dashboard timeline
- `/var/ossec/logs/alerts/alerts.json`
- Alert severity escalation in correlation view

Cross-validation confirmed temporal and logical consistency between host telemetry and SIEM alerts.

### 5.6 Final Attack Chain Validation

The confirmed progression was:

Brute Force (4625)  
→ Successful Login (4624)  
→ Privilege Escalation (4732)  
→ SIEM Correlated Critical Alert  

The correlation model reduced false positives by enforcing sequential behavioral dependencies rather than isolated event triggers.

---

## 6. MITRE ATT&CK Mapping

This lab was mapped to MITRE ATT&CK techniques to align detection logic with real-world adversary behavior patterns.

The objective was not only to detect events, but to understand how those events represent stages in an attack lifecycle.

### T1110 – Brute Force

**Stage:** Initial Access  

Repeated Windows Event ID 4625 entries indicate password guessing attempts against a valid account.

Detection of multiple failed logins within a defined timeframe modeled adversary credential brute-force behavior.

This technique was validated using built-in Wazuh brute-force detection (Rule 60204).

### T1078 – Valid Accounts

**Stage:** Persistence / Defense Evasion  

A successful authentication (Event ID 4624) following repeated failures indicates the attacker has obtained valid credentials.

Custom Rule 100010 correlated this sequence, modeling adversary use of legitimate credentials after compromise.

### T1098 – Account Manipulation

**Stage:** Privilege Escalation  

Event ID 4732 confirms a user was added to the local Administrators group.

This represents modification of account privileges to maintain or expand access.

Custom Rule 100020 escalated this activity to CRITICAL severity.

### T1068 – Privilege Escalation

Although no exploit was used, privilege escalation behavior was simulated by granting administrative rights to a compromised account.

The technique mapping reflects behavioral privilege escalation rather than exploitation-based escalation.

---

### Technique Correlation Model

The mapped attack progression:

T1110 (Brute Force)  
→ T1078 (Valid Accounts)  
→ T1098 (Account Manipulation)  
→ T1068 (Privilege Escalation)

This structured mapping demonstrates how low-level authentication events translate into adversary tradecraft patterns.

---

## 7. Key Learning Outcomes

This lab provided practical exposure to structured detection engineering beyond basic SIEM configuration.

### 7.1 Understanding Telemetry vs Detection

Raw logs represent telemetry; detection requires contextual correlation.

Security events become meaningful only when correlated using structured rule logic.

This project reinforced the difference between:

- Event generation
- Rule evaluation
- Multi-stage correlation
- Context-based alert escalation

### 7.2 Correlation Reduces Noise

Individual failed logins are common and may generate noise.

By correlating:

Failed logins → Successful login → Privilege escalation

the detection confidence increased while alert noise decreased.

This models real SOC tuning practices.

### 7.3 Importance of Validation

Alerts were validated against:

- Windows Event Viewer
- `alerts.json`
- Dashboard timeline

This reinforced the importance of cross-verification rather than trusting a single data source.

### 7.4 Attack Progression Thinking

Instead of detecting isolated events, the lab focused on modeling adversary progression.

This reflects real-world detection engineering where behavior patterns matter more than single log entries.

---

## 8. Future Improvements

This lab can be expanded to simulate more advanced adversary behavior and detection strategies.

### 8.1 Low-and-Slow Brute Force Detection

Implement correlation logic to detect distributed or slow brute-force attempts across longer timeframes.

### 8.2 Lateral Movement Simulation

Simulate remote logon types (e.g., RDP logons) and detect abnormal logon patterns across hosts.

### 8.3 Logon Type Analysis

Enhance detection rules by analyzing specific Windows logon types (e.g., interactive vs network logons).

### 8.4 Baseline Modeling

Implement baseline behavior analysis to differentiate between normal administrative activity and suspicious privilege changes.

### 8.5 Detection-as-Code Workflow

Store detection rules in version-controlled directories and simulate structured detection lifecycle management.
