# Home SOC Lab – Detection Engineering with Wazuh

## Overview

This project demonstrates a simulated credential compromise scenario within a **home Security Operations Center (SOC) lab** using **Wazuh SIEM**.

The lab explores how raw Windows authentication telemetry can be collected, parsed, correlated, and transformed into high-confidence security detections.

The simulated attack models a realistic adversary progression:

1. Brute-force authentication attempts  
2. Successful login using compromised credentials  
3. Privilege escalation via administrator group modification  

Custom Wazuh correlation rules were implemented to detect this multi-stage attack chain and escalate alerts appropriately. The generated alerts were validated against raw Windows Security Event logs to confirm detection accuracy.

This project demonstrates practical **detection engineering**, including telemetry analysis, correlation rule design, alert validation, and attack timeline reconstruction.

---

# Technologies Used

- Wazuh SIEM (Manager, Indexer, Dashboard)
- Windows Security Event Logging
- Ubuntu Linux Server
- Windows 11 Endpoint
- Oracle VirtualBox
- Custom Wazuh Detection Rules
- MITRE ATT&CK Framework

---

# 1. Lab Environment

The SOC lab was built using **two virtual machines inside Oracle VirtualBox** to simulate a monitored endpoint and centralized monitoring system.

## Virtual Machines

### Wazuh Server (Monitoring System)

| Component | Configuration |
|---|---|
| OS | Ubuntu 24.04 |
| RAM | 6 GB |
| CPU | 4 Cores |
| Network | Bridged Adapter |

Installed components:

- Wazuh Manager
- Wazuh Indexer
- Wazuh Dashboard
- Filebeat

This system acts as the **central SIEM platform**, responsible for log collection, rule evaluation, and alert generation.

---

### Windows Endpoint (Monitored Host)

| Component | Configuration |
|---|---|
| OS | Windows 11 |
| RAM | 6 GB |
| CPU | 4 Cores |
| Network | Bridged Adapter |

Installed component:

- Wazuh Agent

The agent forwards Windows Security Event logs to the Wazuh manager.

---

# 2. SOC Lab Architecture


            Home SOC Lab Architecture

    +-------------------------------------+
    |          Windows 11 Endpoint        |
    |                                     |
    |  - Windows Security Event Logs      |
    |  - Event IDs: 4625, 4624, 4732      |
    |  - Wazuh Agent Installed            |
    +--------------------+----------------+
                         |
                         | Log Forwarding
                         v
    +-------------------------------------+
    |          Wazuh Manager Server       |
    |            Ubuntu 24.04             |
    |                                     |
    |  - Wazuh Manager                    |
    |  - Custom Detection Rules           |
    |  - Event Correlation Engine         |
    +--------------------+----------------+
                         |
                         v
    +-------------------------------------+
    |           Wazuh Indexer             |
    |        (Elasticsearch Backend)      |
    +--------------------+----------------+
                         |
                         v
    +-------------------------------------+
    |          Wazuh Dashboard            |
    |     Alert Visualization & Search    |
    +-------------------------------------+


Windows endpoints generate authentication telemetry which is forwarded to the Wazuh manager.  
Events are evaluated against detection rules, stored in the indexer, and visualized through the Wazuh dashboard.

---

# 3. Network Configuration

Both machines were configured using **Bridged Adapter networking**, allowing them to obtain IP addresses on the same network.

Example configuration:

| System | IP Address |
|---|---|
| Ubuntu Wazuh Server | 192.168.29.208 |
| Windows Endpoint | 192.168.29.250 |

Connectivity between the systems was verified using ICMP ping tests to ensure proper agent-to-manager communication.

---

# 4. Data Flow Pipeline

The SIEM log pipeline operates as follows:

```

Windows Security Logs
↓
Wazuh Agent
↓
Wazuh Manager
↓
Wazuh Indexer
↓
Wazuh Dashboard

```

This architecture enables authentication events to be ingested, processed, and visualized as security alerts.

---

# 5. System Validation

To ensure stable operation of the Wazuh platform:

- `vm.max_map_count` was increased
- OpenJDK 17 installed
- Repository connectivity verified
- Package conflicts resolved

Service validation confirmed successful startup of:

- wazuh-manager
- wazuh-indexer
- wazuh-dashboard
- filebeat

---

# 6. Attack Simulation

A credential-based attack scenario was simulated to test detection capabilities.

The attack followed a realistic adversary workflow.

```

4625 Failed Logon Attempts
↓
4625 Failed Logon Attempts
↓
4625 Failed Logon Attempts
↓
4624 Successful Authentication
↓
4732 User Added to Administrators Group

```

This sequence represents a common attack progression:

1. Password brute force
2. Credential compromise
3. Privilege escalation

---

# 7. Detection Engineering

Raw authentication events were transformed into correlated security detections using **custom Wazuh rules**.

The rules were implemented in:

```

/var/ossec/etc/rules/local_rules.xml

````

---

## Rule 100010 — Credential Compromise Detection

Detects a successful login following brute-force activity.

```xml
<rule id="100010" level="14">
  <if_matched_sid>60204</if_matched_sid>
  <if_sid>60118</if_sid>
  <description>POSSIBLE ACCOUNT COMPROMISE: brute force followed by successful login</description>
  <mitre>
    <id>T1078</id>
  </mitre>
</rule>
````

Logic:

* `60204` → Built-in brute force detection
* `60118` → Successful login event

This rule correlates repeated failed logins with a successful authentication.

---

## Rule 100020 — Privilege Escalation Detection

Detects administrator group modification after compromise.

```xml
<rule id="100020" level="15">
  <if_sid>60154</if_sid>
  <if_matched_sid>100010</if_matched_sid>
  <description>CRITICAL: Compromised account escalated to local administrator</description>
  <mitre>
    <id>T1098</id>
    <id>T1068</id>
  </mitre>
</rule>
```

Logic:

* `60154` → Built-in rule detecting administrator group modification
* `100010` → Credential compromise previously detected

This rule models the full attack chain:

```
Compromise → Privilege Escalation
```

---

# 8. Evidence Collection

Evidence for the simulated attack was gathered from multiple sources:

* Windows Event Viewer logs
* Wazuh Discover dashboard
* Alert JSON event view
* Correlation rule alerts

This multi-source validation ensured detection accuracy.

---

# 9. Attack Timeline Reconstruction

The attack sequence was reconstructed using Wazuh alert timestamps.

| Time     | Event | Description                        |
| -------- | ----- | ---------------------------------- |
| 12:38:35 | 4625  | Multiple failed login attempts     |
| 12:39:05 | 4624  | Successful login                   |
| 12:39:24 | 4732  | User added to Administrators group |

Attack progression:

```
Brute Force
    ↓
Credential Compromise
    ↓
Privilege Escalation
    ↓
Critical SIEM Alert
```

This confirms that the correlation rules accurately modeled attacker behavior.

---

# 10. MITRE ATT&CK Mapping

The simulated behaviors align with the following MITRE ATT&CK techniques.

| Technique | Description          |
| --------- | -------------------- |
| T1110     | Brute Force          |
| T1078     | Valid Accounts       |
| T1098     | Account Manipulation |
| T1068     | Privilege Escalation |

Attack chain mapping:

```
T1110 (Brute Force)
        ↓
T1078 (Valid Accounts)
        ↓
T1098 (Account Manipulation)
        ↓
T1068 (Privilege Escalation)
```

This mapping demonstrates how low-level authentication logs translate into adversary tactics.

---

# 11. Key Learning Outcomes

This lab provided practical experience in:

* Understanding the difference between telemetry and detection
* Designing multi-stage correlation rules
* Validating SIEM alerts against raw host logs
* Reconstructing attack timelines from security events
* Mapping detections to MITRE ATT&CK techniques

The project demonstrates how authentication telemetry can be transformed into meaningful detections through structured correlation logic.
