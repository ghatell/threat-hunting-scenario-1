# 🔍**Devices Accidentally Exposed to the Internet**

![ChatGPT Image Apr 4, 2025 at 04_49_10 PM](https://github.com/user-attachments/assets/bd8532e1-0c45-41ab-9379-4c18c1f74361)

## Example Scenario:
During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources. Internal shared services device (e.g., a domain controller) is mistakenly exposed to the internet due to misconfiguration.

---

## Table:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceInfo|
| **Info**| [Microsoft Defender Info](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table)|
| **Purpose**| The DeviceInfo table in the advanced hunting schema contains information about devices in the organization, including OS version, active users, and computer name.|

---

### **Timeline Summary and Findings:**  

sa-mde-test-2 has been internet-facing for several days, the public IPAddress was in the Logs.
First internet facing time: `2025-03-22T17:10:25.6259676Z`
Last internet facing time: `2025-04-03T00:10:40.9746278Z`

```kql
DeviceInfo
| where DeviceName == "sa-mde-test-2"
| where IsInternetFacing == true
| order by Timestamp desc
```
<img width="1256" alt="log1" src="https://github.com/user-attachments/assets/41df32fd-20e7-432c-a94b-3b2c9d574984" />

---

Several bad actors have been discovered attempting to log on to the target machine

```kql
DeviceLogonEvents
| where DeviceName == "sa-mde-test-2"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```
<img width="774" alt="log2" src="https://github.com/user-attachments/assets/2cb2d4ea-554b-432d-a5cd-ea013f5207a8" />

---

The top 5 most failed login attempt IP addresses have not been able to successfully break into VM.

```kql
// Take the top 10 IPs with the most logon failures and see if any succeeded to logon
let RemoteIPsInQuestion = dynamic(["123.201.153.51", "31.184.215.139", "37.52.46.99", "103.143.108.116", "185.243.96.107", "92.63.197.9", "94.102.52.73", "185.156.73.169", "185.243.96.116", "92.63.197.9"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```
**<Query no results>**

<img width="1228" alt="log3" src="https://github.com/user-attachments/assets/9ecfa03f-3ea1-49b9-9dad-320927c6be47" />

___

The only successful logon in the last 30 days for `sa-mde-test-2` VM was from the `cyberSentinel_92` account.

```kql
DeviceLogonEvents
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where DeviceName == "sa-mde-test-2"
| where RemoteDeviceName != "local-scan-engi"
```
<img width="1251" alt="log4" src="https://github.com/user-attachments/assets/ee19c24c-ce4d-4837-9c43-659a3fa2fd64" />

---

There were (0) failed logons for the cyberSentinel_92 account, indicating that a brute force attempt for this account didn’t take place, and a one time password guess is unlikely.

```kql
DeviceLogonEvents
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where DeviceName == "sa-mde-test-2"
| where AccountName == "cyberSentinel_92"
| summarize count()
```
<img width="773" alt="log5" src="https://github.com/user-attachments/assets/dad384bd-6e34-4900-a1b2-9a3d81d7cc52" />

---
We checked all of the successful IP addresses for “cybersentinel_92” account to see if any of them were unusual or from an unexpected location. All were normal.

```kql
DeviceLogonEvents
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where DeviceName == "sa-mde-test-2"
| where AccountName == "cyberSentinel_92"
| summarize count()
```
<img width="1217" alt="log6" src="https://github.com/user-attachments/assets/4530b3ca-2662-4f75-878a-c36ddf71c2c9" />

___
Though the device was exposed to the internet and clear brute force attempts have taken place, there is no evidence of any brute force success or unauthorized access from the legitimate account 'cybersentinel_92'.

Here's how the relevant TTPs and detection elements can be organized into a chart for easy reference:

---

# 🛡️ MITRE ATT&CK TTPs for Incident Detection

| **TTP ID** | **TTP Name**                     | **Description**                                                                                          | **Detection Relevance**                                                         |
|------------|-----------------------------------|----------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| T1071      | Application Layer Protocol        | Observing network traffic and identifying misconfigurations (e.g., device exposed to the internet).       | Helps detect exposed devices via application protocols, identifying misconfigurations. |
| T1075      | Pass the Hash                     | Failed login attempts suggesting brute-force or password spraying attempts.                               | Identifies failed login attempts from external sources, indicative of password spraying.  |
| T1110      | Brute Force                       | Multiple failed login attempts from external sources trying to gain unauthorized access.                 | Identifies brute-force login attempts and suspicious login behavior.            |
| T1046      | Network Service Scanning          | Exposure of internal services to the internet, potentially scanned by attackers.                         | Indicates potential reconnaissance and scanning by external actors.            |
| T1021      | Remote Services                   | Remote logins via network/interactive login types showing external interaction attempts.                   | Identifies legitimate and malicious remote service logins to an exposed device.  |
| T1070      | Indicator Removal on Host         | No indicators of success in the attempted brute-force attacks, showing system defenses were effective.     | Confirms the lack of successful attacks due to effective defense measures.      |
| T1213      | Data from Information Repositories| Device exposed publicly, indicating potential reconnaissance activities.                                  | Exposes possible adversary reconnaissance when a device is publicly accessible.  |
| T1078      | Valid Accounts                    | Successful logins from the legitimate account ('labuser') were normal and monitored.                      | Monitors legitimate access and excludes unauthorized access attempts.           |

---

This chart clearly organizes the MITRE ATT&CK techniques (TTPs) used in this incident, detailing their relevance to the detection process.

**📝 Response:**  
- Did a Audit, Malware Scan, Vulnerability Management Scan, Hardened the NSG attached to windows-target-1 to allow only RDP traffic from specific endpoints (no public internet access), Implemented account lockout policy, Implemented MFA, awaiting further instructions.

---

## Steps to Reproduce:
1. Provision a virtual machine with a public IP address.
2. Ensure the device is actively communicating or available on the internet. (Test ping, etc.)
3. Onboard the device to Microsoft Defender for Endpoint.
4. Verify the relevant logs (e.g., network traffic logs, exposure alerts) are being collected in MDE.
5. Execute the KQL query in the MDE advanced hunting to confirm detection.

---

## Supplemental:
- **More on "Shared Services" in the context of PCI DSS**: [PCI DSS Scoping and Segmentation](https://www.pcisecuritystandards.org%2Fdocuments%2FGuidance-PCI-DSS-Scoping-and-Segmentation_v1.pdf)

---

## Created By:
- **Author Name**: Soroush Asadi  
- **Author Contact**: [LinkedIn](https://www.linkedin.com/in/soroush-asadi-881098178/)  
- **Date**: April 2025

## Validated By:
- **Reviewer Name**: Josh Madakor  
- **Reviewer Contact**: [LinkedIn](https://www.linkedin.com/in/joshmadakor/)  
- **Validation Date**: April 2025

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `April 2025`    | `Soroush Asadi`   |
```
