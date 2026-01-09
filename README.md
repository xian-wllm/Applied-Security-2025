# iMoves CA

## Running the iMoves CA

```bash
cd lab
./start.sh
```

- Access the Client at http://localhost:6080 (password: money4band)
- Access the Portal UI at https://portal.imovies.lan inside the Client Browser
- Test issuing EMPLOYEE or CA_ADMIN certificates with user: `ps`, password: `KramBamBuli`
- After getting a CA_ADMIN certificate and installing it in the browser, access https://portal.imovies.lan/admin/dashboard
- With the preinstalled ms.imovies.lan SYS_ADMIN certificate, access Guacamole at https://guac.imovies.lan/guacamole and click on connect with certificate/smartcard
- Wazuh Manager UI at https://kibana.imovies.lan (username: `kibanaserver`, password: `kibanaserver`) for SOC_ANALYST

Stop the lab with:

```bash
./stop.sh
```

# 🔐 PKI Lab Environment – Passwordless Authentication Infrastructure

## 📖 Overview

This project implements a **realistic enterprise-grade lab environment** focused on **Public Key Infrastructure (PKI)** and **passwordless authentication**.

The main objective is to reduce reliance on passwords by introducing **certificate-based identities** issued by an **internal Certificate Authority (CA)**.  
After an initial authentication using classic credentials, employees receive a **personal private key and certificate**, allowing them to authenticate securely **without passwords**.

The infrastructure is designed following **security best practices**, including segmentation, least privilege, defense in depth, and full auditability.

---

## 🎯 Project Goals

- Deploy an **internal PKI** for employee identity management  
- Enable **passwordless authentication** using certificates  
- Secure administrative access via a centralized gateway  
- Enforce strict **network segmentation and access control**  
- Provide **monitoring, logging, and incident detection**

---

## 🔑 Authentication Flow

1. The employee authenticates using **username and password**
2. The system issues a **unique private key and X.509 certificate**
3. The certificate is delivered securely to the employee
4. Subsequent access is performed **without passwords**, using:
   - Mutual TLS (mTLS)
   - SSH authentication with keys
   - Certificate-based web authentication

This approach significantly reduces exposure to phishing, brute-force attacks, and credential reuse.

---

## 🛠️ Technologies Used

### 🔐 PKI & Secret Management
- **:contentReference[oaicite:0]{index=0}**
  - Intermediate Certificate Authority
  - Private key generation
  - Certificate issuance and revocation
  - Encrypted secret storage

### 🧑‍💻 Secure Access & Administration
- **:contentReference[oaicite:1]{index=1}**
  - Centralized remote access via browser
  - Certificate-based authentication
  - No direct SSH access from the Internet
  - Full session auditing

### 🌐 Web Services
- **:contentReference[oaicite:2]{index=2}**
  - Secure web portal
  - TLS termination
  - Support for mutual TLS authentication

### 🛡️ Monitoring & Security
- **:contentReference[oaicite:3]{index=3}**
  - Log collection and correlation
  - Intrusion and anomaly detection
  - SIEM dashboard for visibility

### 🧩 Infrastructure & Automation
- **Docker** – containerization  
- **FRR (Free Range Routing)** – network routing  
- **iptables** – firewalling and segmentation  
- **Bash** – automation and configuration  
- **Linux** – operating system for all components  

---

## ✅ Security Benefits

- Passwordless authentication after enrollment  
- Strong cryptographic identities per employee  
- Reduced attack surface (phishing, brute force)  
- Centralized access control and auditing  
- Enterprise-like architecture for security training and testing  

---

## 📜 License

This project is provided for educational and laboratory purposes.

---

## 🙌 Acknowledgements

This lab was developed as part of an **Applied Security** project to demonstrate real-world PKI design, secure authentication workflows, and defensive security architecture.
