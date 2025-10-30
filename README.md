# T-Pot Honeypot Threat Analysis Project

## 🎯 Project Overview
This project documents my deployment and analysis of a T-Pot honeypot system on a cloud-based virtual machine. Over the course of one week, I captured and investigated real-world cyber attacks, documenting threat intelligence findings and attack patterns that demonstrate practical SOC analyst skills.

**Skills Demonstrated:**
- Cloud infrastructure deployment and management
- Honeypot configuration and monitoring
- Threat intelligence analysis
- Incident documentation and reporting
- Security tool utilization (Kibana, Elasticsearch, Suricata)
- Attack pattern recognition and classification

---

## 🛠️ Deployment Process

### 1. Initial VM Setup
Created a Vultr cloud instance with initial specifications:
- **RAM:** 2GB
- **Storage:** 55GB SSD
- **OS:** Ubuntu Server
- **Location:** New Jersey, USA

![Vultr Instance](image1.png)
*Initial Vultr cloud compute instance*

### 2. SSH Connection & User Configuration
```bash
# SSH into the VM
ssh root@149.28.62.100

# Created new user with admin privileges
sudo adduser aryan
sudo usermod -aG sudo aryan

# Switched to new user
su - aryan
cd ~
```

![SSH Connection](image2.png)
*SSH terminal connection established*

### 3. T-Pot Installation
```bash
# Clone T-Pot repository
git clone https://github.com/telekom-security/tpotce

# Navigate to installation directory
cd tpotce

# Run installer
./install.sh
```

![Installation Directory](image3.png)
*T-Pot installation files*

![Installation Script](image4.png)
*Running the T-Pot installation script*

### 4. Installation Configuration
Selected installation type: **HIVE (Full Installation)**
- Includes all honeypots and sensors
- Full distributed setup with WebUI
- Elasticsearch and Kibana for log analysis

![Installation Options](image5.png)
*T-Pot installation type selection*

### 5. Network Configuration
Reviewed port mappings and service configurations to ensure proper honeypot exposure:
- Port 64297: T-Pot Web UI (HTTPS)
- Port 64295: SSH management
- Multiple honeypot services on standard ports (22, 23, 80, 443, 8728, etc.)

![Port Configuration](image6.png)
*Active network ports and service configurations*

### 6. Infrastructure Upgrade
**Challenge:** Initial deployment failed to load web interface properly due to insufficient resources.

**Solution:** Upgraded VM specifications:
- **RAM:** 2GB → 8GB
- **Storage:** 55GB → 200GB SSD
- Performed system reboot

After upgrade, all services initialized successfully.

![Upgraded VM](image1.png)
*VM after resource upgrade*

### 7. Web Interface Access
Successfully accessed T-Pot dashboard at `https://149.28.62.100:64297`

![Web Login](image7.png)
*T-Pot web interface login*

![Dashboard](image8.png)
*T-Pot main dashboard with analysis tools*

---

## ✅ System Validation

### Test Attack - Nmap Port Scan
Verified honeypot functionality by conducting an authorized Nmap scan from my local machine:

```bash
nmap -sV 149.28.62.100
```

![Nmap Scan](image10.png)
*Port scan test from local machine*

**Results:**
- ✅ Honeypot successfully detected and logged the scan
- ✅ Source IP (173.71.120.207) appeared in attack map
- ✅ Multiple honeypots triggered (Honeytrap)
- ✅ All data captured in Kibana logs

![Attack Detection](image10.png)
*Successful attack detection in T-Pot dashboard*

---

## 📊 Monitoring & Analysis Tools

### Main Dashboard
The T-Pot dashboard provides real-time visualization of:
- Total honeypot attacks (218 captured in 24 hours)
- Attack distribution by honeypot type
- Geographic attack origins
- Targeted ports and services
- Attack timelines

![Main Dashboard](image11.png)
*T-Pot main dashboard showing attack statistics*

### Attack Analysis
After just hours of deployment, captured attacks from multiple countries:
- **United States:** 207 attacks
- **Netherlands:** 2 attacks
- Multiple attack vectors detected (SSH, port scanning, RouterOS exploitation)

![Attack Breakdown](image12.png)
*Detailed attack source and ASN analysis in Kibana*

### External Threat Correlation
The SecurityMeter (Sicherheitstacho) integration shows real-time global attack patterns:

![Security Meter](image13.png)
*Real-time global attack visualization from Sicherheitstacho*

---

## 🔍 Threat Intelligence Analysis

### Investigation Workflow
For each suspicious IP detected, I performed the following analysis:

1. **Honeypot Data Collection** - Review attack details in T-Pot dashboard
2. **Kibana Deep Dive** - Search logs for attack patterns, credentials, commands
3. **Threat Intel Lookups:**
   - AbuseIPDB - Check abuse confidence score and report history
   - GreyNoise - Identify if IP is mass scanner or targeted attacker
   - VirusTotal - Check security vendor detections
4. **MITRE ATT&CK Mapping** - Classify tactics and techniques
5. **Documentation** - Write detailed incident report

### Example: High-Severity Finding

**IP:** 87.120.191.13  
**Classification:** MALICIOUS - RouterOS Bruteforce Campaign  
**Abuse Score:** 100% (26,518 reports)  
**Status:** Actively attacking globally

![AbuseIPDB Report](image1.png)
![GreyNoise Classification](image3.png)
![VirusTotal Detection](image4.png)

---

## 📁 Investigation Reports

I documented **10 distinct security incidents** over one week of monitoring:

- **Incident #1:** Self-initiated port scan validation
- **Incident #2:** RouterOS bruteforce campaign (87.120.191.13)
- **Incidents #3-10:** [Reports to be added as separate files]

Each report includes:
- Attack timeline and detection details
- Threat intelligence lookups (AbuseIPDB, GreyNoise, VirusTotal)
- Attack classification and MITRE ATT&CK mapping
- IOC extraction and recommended response actions

**See individual incident reports in the `/incidents` directory.**

---

## 🎓 Key Learnings

1. **Real-World Threat Landscape:** Within hours, honeypot was bombarded with automated attacks targeting SSH, RouterOS, and other services
2. **Threat Intelligence Integration:** Learned to correlate honeypot data with external threat feeds
3. **Attack Pattern Recognition:** Identified difference between automated scanning vs. targeted attacks
4. **Cloud Security Operations:** Gained hands-on experience with cloud-based security infrastructure
5. **SOC Analyst Workflow:** Practiced incident triage, investigation, and documentation

---

## 🔧 Tools & Technologies Used

- **Honeypot Platform:** T-Pot (Telekom Security)
- **Cloud Provider:** Vultr
- **Operating System:** Ubuntu Server
- **Analysis Tools:** 
  - Kibana (log analysis)
  - Elasticsearch (data storage)
  - Suricata (IDS/IPS)
  - Spiderfoot (OSINT)
  - CyberChef (data manipulation)
- **Threat Intelligence:**
  - AbuseIPDB
  - GreyNoise
  - VirusTotal
  - Sicherheitstacho

---

## 📈 Statistics Summary (Week 1)

- **Total Attacks Captured:** 218+ in first 24 hours
- **Unique Source IPs:** 50+
- **Countries:** 10+
- **Most Targeted Ports:** 8728 (MikroTik), 22 (SSH), 23 (Telnet)
- **Incident Reports:** 10

---

## 🚀 Future Enhancements

- [ ] Automate IOC extraction and threat feed integration
- [ ] Create custom Suricata rules for detected attack patterns
- [ ] Build automated reporting dashboard
- [ ] Integrate with MISP for threat intelligence sharing
- [ ] Develop Python scripts for attack analysis automation

---

## 📝 Author

**Aryan Vij**  
Aspiring SOC Analyst  
[LinkedIn](#) | [GitHub](#) | [Email](#)

---

## 📚 References

- [T-Pot GitHub Repository](https://github.com/telekom-security/tpotce)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [AbuseIPDB](https://www.abuseipdb.com)
- [GreyNoise Intelligence](https://www.greynoise.io)

---

**Note:** All attacks documented in this project were captured in a controlled honeypot environment. No production systems were compromised. This project is for educational and portfolio purposes only.
