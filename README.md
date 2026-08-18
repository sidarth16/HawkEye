# HawkEye - Smart Contract Security Scanner

> Identify critical vulnerabilities in smart contracts related to input validation, access control, minting permissions, and missing critical overrides.  

---

# Detector Modules

| **Module Code** | **Type** | **Description** | **Severity** |
|------------------|------------------|------------------|---------------|
| **IVC-001** | Input Validation on Calls | `delegateCall` without proper input validation | 🔴 High |
| **IVC-002** | Input Validation on Calls  | `callcode` without proper input validation | 🔴 High |
| **IVC-003** | Input Validation on Calls  | Low-level `call` without proper input validation | 🔴 High |
| **IVC-004** | Input Validation on Calls  | `externalCall` without proper input validation | 🔴 High |
| **IVC-005** | Input Validation on Calls  | `staticcall` without proper input validation | 🟡 Low |
| **AC-001** | Access Control | Unrestricted Admin/Governance Update | 🔴 High |
| **AC-002** | Access Control | Unrestricted Upgrade/Init | 🔴 High |
| **AC-003** | Access Control | Unrestricted Flashloan/Callback Entrypoint | 🔴 High |
| **AC-101** | Access Control | Weak Validation | 🟠 Medium |
| **ACM-001** | Access Control Mint | Unbounded Admin Mint | 🔴 High |
| **ACM-002** | Access Control Mint | Public Mint Without Economic Gate | 🔴 High |
| **ACM-101** | Access Control Mint | Weak Validation | 🟠 Medium |
| **MCO-001** | Missing Critical Override | Vault Core not overridden | 🔴 High |
| **MCO-002** | Missing Critical Override | Token Core not overridden | 🔴 High |
| **MCO-003** | Missing Critical Override | Upgrade Core not overridden | 🔴 High |
| **MCO-004** | Missing Critical Override | Access Role Core not overridden | 🟡 Medium |


## How to use :
**1. Create a Virtual Environment**
```bash
python3 -m venv venv
```
**2. Activate the Environment**
- On MacOs or Linux : 
    ```bash
    source venv/bin/activate
    ```
- On Windows : 
    ```bash
    venv\Scripts\activate
    ```
**3. Install Dependencies**
```bash
pip install -r requirements.txt
```

**4. Run the Detector Dapp**
```bash
cp .env.example .env
python main.py
```
**5. Open in Browser** <br/>
- Visit your local instance at:<br/>
 [localhost:8000](http://localhost:8000)

---

**Note:** On the first run, scanning a contract may take some time as the required Solidity compilers (solc versions) are installed to parse the source code.


## Module Summaries

### **1. Input Validation Call Module (IVC)**

This module flags functions that make calls to target addresses **derived from user-controlled inputs** (either directly from function parameters or computed from them) **without proper validation or sanitization**.

#### **Detections**

| Code | Description | Severity |
|------|--------------|----------|
| **IVC-001** | `delegateCall` without proper input validation | 🔴 High |
| **IVC-002** | `callcode` without proper input validation | 🔴 High |
| **IVC-003** | Low-level `call` without proper input validation | 🔴 High |
| **IVC-004** | `externalCall` without proper input validation | 🔴 High |
| **IVC-005** | `staticcall` without proper input validation | 🟡 Low |

---

### **2. Access Control Module (AC)**

This module detects **administrative or governance-level functions** that lack proper authorization or validation checks.  
It identifies critical functions that:
- Modify system configuration
- Perform upgrades
- Execute sensitive callbacks  
without restricting access to **trusted roles**.

#### **Detections**

| Code | Description | Severity |
|------|--------------|----------|
| **AC-001** | Unrestricted Admin/Governance Update | 🔴 High |
| **AC-002** | Unrestricted Upgrade/Init | 🔴 High |
| **AC-003** | Unrestricted Flashloan/Callback Entrypoint | 🔴 High |
| **AC-101** | Weak Validation | 🟠 Medium |

---

### **3. Access Control Mint Module (ACM)**

An extension of the Access Control module focused on **token minting and supply management**.  
This detector identifies mint functions lacking **access control or economic constraints**, which can result in:
- Infinite token creation
- Unauthorized minting
- Inflationary exploits

#### **Detections**

| Code | Description | Severity |
|------|--------------|----------|
| **ACM-001** | Unbounded Admin Mint | 🔴 High |
| **ACM-002** | Public Mint Without Economic Gate | 🔴 High |
| **ACM-101** | Weak Validation | 🟠 Medium |

---

### **4. Missing Critical Override Module (MCO)**

This module identifies contracts that **fail to override critical inherited functions** from core modules (vaults, tokens, upgrade-proxy, or role managers).  
Unmodified inherited logic can lead to:
- Bypassed security checks  
- Broken invariants  
- Privilege escalation or fund loss  

#### **Detections**

| Code | Description | Severity |
|------|--------------|----------|
| **MCO-001** | Vault Core not overridden | 🔴 High |
| **MCO-002** | Token Core not overridden | 🔴 High |
| **MCO-003** | Upgrade Core not overridden | 🔴 High |
| **MCO-004** | Access Role Core not overridden | 🟡 Medium |

---
<br/>

# Real Defi Attacks that would have been prevented  : 
- Li.Fi Hack
    - ETH : 0xf28A352377663cA134bd27B582b1a9A4dad7e534

- Arcadia Finance
    - Base : 0xC729213B9b72694F202FeB9cf40FE8ba5F5A4509

- SuperRare
    - ETH : 0xfFB512B9176D527C5D32189c3e310Ed4aB2Bb9eC

- MoonHacker
    - optimism : 0xD9B45e2c389b6Ad55dD3631AbC1de6F2D2229847

- Silo: 
    - ETH : 0xCbEe4617ABF667830fe3ee7DC8d6f46380829DF9

- MetaPool
    - ETH : 0x3747484567119592fF6841df399cf679955A111A

