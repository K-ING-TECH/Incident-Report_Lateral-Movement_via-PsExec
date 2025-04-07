Network Forensics Lab ["PsExec Hunt Lab" in CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/psexec-hunt/)

# Technical Incident Report: Lateral Movement via PsExec
- Analyst Name: Kyle I.
- Date of Analysis: 4/7/2025
- Incident Reference: PCAP Review – psexec-hunt.pcapng
### Executive Summary
The Security Operations Center (SOC) detected an alert from the Intrusion Detection System (IDS) indicating potential lateral movement involving PsExec, a known remote administration tool often abused by threat actors. A full packet capture (psexec-hunt.pcapng) was analyzed in Wireshark. The analysis confirms that an internal host (10.0.0.130) performed unauthorized lateral movement to at least two machines within the network, using stolen credentials and deploying a remote execution service (PSEXESVC.exe).

## Key Findings
| Field                           | Value        |
|---------------------------------|--------------|
| Attacker IP                     |   10.0.0.130 |
| Initial Target (Pivot 1)	      |  10.0.0.133  |
| Hostname of Pivot 1	            | SALES-PC     |
| Username Used	                  | \ssales      |
| PsExec Binary Deployed          |	PSEXESVC.exe |
| Shares Used	                    | IPC$, ADMIN$ |
| Second Target (Pivot 2)	        | 10.0.0.131   |
| Hostname of Pivot 2	            | MARKETING-PC |
| Authentication Protocol	| NTLMSSP (NTLM Challenge/Response)|
| Protocol Used	          | SMB over TCP (port 445)|


## Timeline of Events

| Timestamp | Source IP   | Destination IP | Action                                |
|-----------|-------------|----------------|----------------------------------------|
| 283.37s   | 10.0.0.130  | 10.0.0.133     | TCP SYN to port 445                    |
| 283.39s   | 10.0.0.130  | 10.0.0.133     | SMB2 NEGOTIATE and SESSION SETUP       |
| 283.41s   | 10.0.0.130  | 10.0.0.133     | Tree Connect to IPC$, ADMIN$           |
| 283.41s   | 10.0.0.130  | 10.0.0.133     | File creation: PSEXESVC.exe            |
| 534.49s   | 10.0.0.130  | 10.0.0.131     | New TCP 445 session                    |
| 534.51s   | 10.0.0.130  | 10.0.0.131     | NTLMSSP negotiation with MARKETING-PC  |

## Detailed Analysis
**1. Initial Access and Lateral Movement**
- The attacker initiated a connection from IP 10.0.0.130 to 10.0.0.133 over TCP port 445.
- SMB2 negotiation and NTLM authentication were completed using the compromised credentials of user \ssales.
- This form of NTLM authentication is commonly abused during lateral movement, especially using tools like PsExec.


  ![alt text](https://github.com/K-ING-TECH/Incident-Report_Lateral-Movement_via-PsExec/blob/main/FilterbyEndpoint.png)

**2. Host Enumeration and Network Share Access**
- The attacker connected to the IPC$ and ADMIN$ shares on 10.0.0.133.
- These are administrative shares used for inter-process communication and file transfer during remote execution.

  
![alt text](https://github.com/K-ING-TECH/Incident-Report_Lateral-Movement_via-PsExec/blob/main/Question1_Resolution.png)


**3. Remote Payload Deployment**
- PsExec dropped the file PSEXESVC.exe onto the target.
- This binary was written without any access denied response, indicating the credentials had sufficient administrative rights.

#### Observed Packets

```
Create Request File: PSEXESVC.exe
Write Request File: PSEXESVC.exe
```

**4. System Identification via NTLM Challenge**
- During NTLMSSP_CHALLENGE responses, the following system hostnames were leaked:
![alt text](https://github.com/K-ING-TECH/Incident-Report_Lateral-Movement_via-PsExec/blob/main/Question2-3_Resolution.png)

#### Target IP	Hostnames:
- 10.0.0.133	SALES-PC
- 10.0.0.131	MARKETING-PC
This confirmed that the attacker moved laterally from SALES-PC to MARKETING-PC.

![alt text](https://github.com/K-ING-TECH/Incident-Report_Lateral-Movement_via-PsExec/blob/main/Question7_Resolution.png)

**5. Second Pivot Attempt**
- The attacker continued from `10.0.0.130` to `10.0.0.131` (MARKETING-PC).
- NTLM authentication was attempted again using the same credentials.
- Successful NTLMSSP negotiation confirmed the second host compromise.

## Indicators of Compromise (IOCs)
| Type                 | Value                               |
|----------------------|--------------------------------------|
| IP Address (Attacker)| 10.0.0.130                          |
| IP Address (Targets) | 10.0.0.133, 10.0.0.131              |
| Hostnames            | SALES-PC, MARKETING-PC             |
| Username             | ssales                             |
| Executable Name      | PSEXESVC.exe                       |
| Protocol             | SMB over TCP/445                   |
| Shares Accessed      | IPC$, ADMIN$                       |




## MITRE ATT&CK Matrix Mapping
| Tactic              | Technique                            | ID         |
|---------------------|----------------------------------------|------------|
| Initial Access      | Valid Accounts                        | T1078      |
| Execution           | Windows Service                       | T1543.003  |
| Persistence         | Create or Modify System Process       | T1543      |
| Privilege Escalation| Valid Accounts (Admin Access)         | T1078      |
| Defense Evasion     | Obfuscated Files or Information (PsExec)| T1027     |
| Discovery           | Remote System Discovery               | T1018      |
| Lateral Movement    | SMB/Windows Admin Shares              | T1021.002  |
| Command and Control | Application Layer Protocol: SMB       | T1071.002  |
| Collection          | File and Directory Discovery          | T1083      |


### Conclusion and Recommendations

The attacker successfully moved laterally using **PsExec**, exploiting **SMB** with valid credentials (`ssales`) to access `SALES-PC` and `MARKETING-PC`. Their activity involved authentication, remote service installation (`PSEXESVC.exe`), and likely remote command execution.

---

### Recommendations

1. **Credential Reset**  
   Immediately reset and investigate accounts involved (`ssales`).

2. **Network Segmentation**  
   Limit administrative SMB access between workstations.

3. **Audit Admin Shares**  
   Restrict and monitor use of `ADMIN$`, `IPC$`.

4. **Deploy Endpoint Detection**  
   Use EDR tools to detect remote service creation (PsExec behavior).

5. **Harden NTLM Usage**  
   - Disable or restrict NTLM where possible  
   - Implement SMB signing

6. **Enable Logging & Monitoring**  
   Enable security auditing for service creation, authentication, and process creation.

7. **Threat Hunt**  
   Search for signs of `PSEXESVC.exe` and similar remote admin tools across the network.

