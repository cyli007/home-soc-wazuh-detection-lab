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

---

# 12. Incident Analysis & Response

## Incident Summary

**Incident Type:** Credential Compromise with Privilege Escalation  
**Severity:** Critical  

A multi-stage attack was detected involving brute-force authentication attempts, followed by a successful login and unauthorized privilege escalation. The correlated alerts indicate a high-confidence compromise of a user account.

---

## Triage & Initial Assessment

The alert was triggered by a correlation rule detecting:

- Multiple failed login attempts (Event ID 4625)
- A subsequent successful login (Event ID 4624)
- Followed by privilege escalation activity (Event ID 4732)

At the triage stage, this pattern was immediately suspicious because:

- A successful login following repeated failures is a strong indicator of brute-force success  
- The rapid transition to privilege escalation suggests malicious intent rather than normal user behavior  

**Initial Classification:** High Priority — Likely True Positive  

---

## Investigation & Analysis

The alert was validated through structured investigation:

### 1. Authentication Pattern Analysis
- Reviewed Event ID 4625 logs to confirm repeated failed login attempts  
- Verified frequency and timing to rule out normal user error  

### 2. Successful Login Verification
- Correlated Event ID 4624 with prior failed attempts  
- Confirmed login occurred shortly after brute-force sequence  

### 3. Privilege Escalation Confirmation
- Analyzed Event ID 4732 (user added to Administrators group)  
- Verified the same user account was involved in previous authentication events  

### 4. Timeline Correlation
Reconstructed event sequence using timestamps:

```

Failed Logins → Successful Login → Privilege Escalation

```

This confirmed a clear attacker progression.

---

## Why This is a True Positive

This activity was classified as a confirmed compromise because:

- Sequential failed logins followed by success strongly indicate credential compromise  
- Immediate privilege escalation is not typical of legitimate user behavior  
- Events are tightly correlated in time and context  
- Multiple independent indicators (4625, 4624, 4732) support the same conclusion  

**Conclusion:** Confirmed True Positive  

---

## Impact Assessment

- Compromised account gained **administrator privileges**  
- Potential full control over the system  
- High risk of:
  - Lateral movement  
  - Persistence mechanisms  
  - Data exfiltration  
  - Further privilege abuse  

**Impact Level:** Critical  

---

## Response Actions (Recommended)

To contain and remediate the incident:

- Disable or lock the compromised account immediately  
- Reset credentials and enforce strong password policies  
- Enable Multi-Factor Authentication (MFA)  
- Review recent login activity across systems  
- Audit privileged group memberships  
- Investigate for lateral movement across the network  
- Strengthen alerting and correlation thresholds  

---

## Detection Improvement Opportunities

During analysis, the following improvements were identified:

- Implement account lockout thresholds to prevent brute-force success  
- Add source IP or geolocation anomaly detection  
- Enhance correlation rules with time-based thresholds  
- Integrate additional telemetry (e.g., Sysmon, network logs)  

---

## SOC Workflow Mapping

This project demonstrates a complete Tier 1 SOC workflow:

1. Alert Detection  
2. Triage & Prioritization  
3. Investigation & Correlation  
4. Validation (True Positive Confirmation)  
5. Impact Assessment  
6. Response & Mitigation  

This reflects real-world SOC operations for handling credential-based attacks.
