# Threat Hunt Report: Unauthorized TOR Usage

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

- [Scenario Creation](https://github.com/Benjamin-Lawson23/threat-hunt-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

I searched the `DeviceFileEvents` table for any file that contained the string “tor” and discovered that the user `ben` downloaded a TOR installer. This resulted in the creation of a number of Tor-related files. A file called `tor-shopping-list.txt` was also created on the desktop of the user’s machine. These events started at `2026-02-11T21:25:56.5879743Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "ben-test-vm-md"
| where InitiatingProcessAccountName == "ben"
| where FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1216" height="598" alt="Screenshot 2026-02-13 at 2 07 43 PM" src="https://github.com/user-attachments/assets/a36745bb-7eb7-479e-bd14-4a87deac9d1d" />

---

### 2. Searched the `DeviceProcessEvents` Table

I searched the `DeviceProcessEvents` table for any `ProcessComandLine` that contained the string `tor-browser-windows-x86_64-portable-15.0.5.exe  /S`. The logs indicated that on February 11, 2026 at 2:33:57 PM, the user `ben` on the device `ben-test-vm-md` started (created) a process for the file `tor-browser-windows-x86_64-portable-15.0.5.exe` from the `Downloads` folder (C:\Users\ben\Downloads\), running it silently with the /S option. The file has the SHA256 hash `15448e951583b624c3f8fdfa8bc55fa9b65e1bcafd474f3f2dfd5444e4178846`.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "ben-test-vm-md"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.5.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1410" height="164" alt="Screenshot 2026-02-13 at 2 28 41 PM" src="https://github.com/user-attachments/assets/c42c7ead-6b54-481f-805a-5c84cab80144" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

I searched the `DeviceProcessEvents` table for any indication that the user `ben` opened the TOR browser. There was evidence that the employee did open the browser at `2026-02-11T21:35:31.7002897Z`. Several other instances of `firefox.exe` (TOR) were also created after this point. 

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "ben-test-vm-md"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1412" height="607" alt="Screenshot 2026-02-13 at 2 46 05 PM" src="https://github.com/user-attachments/assets/0a225b7c-7c08-46ff-979d-78b84d7266de" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

I search the `DeviceNetworkEvents` table for any indication the TOR browser was used to establish a connection using any of the known TOR port numbers. On February 11, 2026 at 2:35:44 PM, the user `ben` on the device `ben-test-vm-md` successfully established a network connection using `tor.exe` to the remote IP address `198.98.61.60` on port `9001`. There were an additional five connections. 

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "ben-test-vm-md"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9050", "9150", "9001", "9030", "9040")
| project Timestamp, DeviceName,InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="1243" height="347" alt="Screenshot 2026-02-13 at 2 57 10 PM" src="https://github.com/user-attachments/assets/ebf8a0e1-eba0-46ac-a6d1-d440561888b2" />


---

## Chronological Event Timeline 

### 2026-02-11T21:25:56.5879743Z
- User ben on device `ben-test-vm-md` downloaded a Tor installer.
- Multiple Tor-related files were created.
- A file named `tor-shopping-list.txt` was created on the Desktop.
- **Source:** `DeviceFileEvents`

### 2026-02-11T21:33:57Z (2:33:57 PM)
-**Process created:** `tor-browser-windows-x86_64-portable-15.0.5.exe`
-**Executed from:** `C:\Users\ben\Downloads\`
-**Execution method:** Silent installation using `/S` switch
-**SHA256:** `15448e951583b624c3f8fdfa8bc55fa9b65e1bcafd474f3f2dfd5444e4178846`
-**Source:** 'DeviceProcessEvents`

### 2026-02-11T21:35:31.7002897Z
- User ben launched the Tor Browser.
- `firefox.exe` (Tor Browser) process created.
- Additional instances of Tor-related processes (`tor.exe`, `firefox.exe`, `tor-browser.exe`) followed.
- **Source:** `DeviceProcessEvents`

### 2026-02-11T21:35:44Z (2:35:44 PM)
- `tor.exe` established a successful outbound network connection.
- **Remote IP:** `198.98.61.60`
- **Remote Port:** `9001` (commonly associated with Tor relay traffic)
- Additional five similar connections observed.
- **Source:** `DeviceNetworkEvents`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
