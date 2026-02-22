# CIS FortiGate Benchmark v1.3.0 – Rule Mapping

## Level 1 Rules (Basic – 35 controls)

| Rule ID | CIS Section | Title | Severity | Category |
|---------|-------------|-------|----------|----------|
| 1.1 | 1.1 | Ensure DNS server is configured | Medium | Network |
| 1.2 | 1.2 | Ensure intra-zone traffic is restricted | High | Network |
| 1.3 | 1.3 | Ensure management services disabled on WAN | Critical | Network |
| 2.1.1 | 2.1.1 | Ensure Pre-Login Banner is set | Medium | System |
| 2.1.2 | 2.1.2 | Ensure Post-Login Banner is set | Medium | System |
| 2.1.3 | 2.1.3 | Ensure timezone is configured | Low | System |
| 2.1.4 | 2.1.4 | Ensure NTP is configured | Medium | System |
| 2.1.5 | 2.1.5 | Ensure hostname is set | Low | System |
| 2.1.7 | 2.1.7 | Ensure USB auto-install is disabled | High | System |
| 2.1.8 | 2.1.8 | Ensure static keys for TLS are disabled | High | System |
| 2.1.9 | 2.1.9 | Ensure Global Strong Encryption is enabled | Critical | System |
| 2.1.10 | 2.1.10 | Ensure GUI uses secure TLS | High | System |
| 2.1.11 | 2.1.11 | Ensure CDN is enabled | Low | System |
| 2.2.1 | 2.2.1 | Ensure Password Policy is enabled | High | Password |
| 2.2.2 | 2.2.2 | Ensure admin lockout is configured | High | Password |
| 2.3.1 | 2.3.1 | Ensure only SNMPv3 is enabled | High | SNMP |
| 2.4.4 | 2.4.4 | Ensure idle timeout is configured | Medium | Admin |
| 2.4.5 | 2.4.5 | Ensure only encrypted access channels | Critical | Admin |
| 2.4.9 | 2.4.9 | Ensure HA is configured | Medium | Admin |
| 2.4.10 | 2.4.10 | Ensure HA monitor interfaces enabled | Medium | Admin |
| 2.4.11 | 2.4.11 | Ensure HA reserved management interface | Medium | Admin |
| 3.2 | 3.2 | Ensure no 'ALL' service in policies | High | Firewall |
| 3.4 | 3.4 | Ensure logging on all policies | Medium | Firewall |
| 4.1.2 | 4.1.2 | Ensure IPS is applied | High | Security Profiles |
| 4.2.1 | 4.2.1 | Ensure AV Definition Updates configured | High | Security Profiles |
| 4.2.3 | 4.2.3 | Ensure Outbreak Prevention enabled | Medium | Security Profiles |
| 4.2.4 | 4.2.4 | Ensure AI/ML malware detection | Medium | Security Profiles |
| 4.2.5 | 4.2.5 | Ensure Grayware detection enabled | Medium | Security Profiles |
| 4.3.1 | 4.3.1 | Ensure Botnet C&C DNS blocking | High | Security Profiles |
| 4.4.3 | 4.4.3 | Ensure Application Control applied | High | Security Profiles |
| 5.1.1 | 5.1.1 | Ensure compromised host quarantine | High | Security Fabric |
| 5.2.1.1 | 5.2.1.1 | Ensure Security Fabric configured | Medium | Security Fabric |
| 7.1.1 | 7.1.1 | Ensure Event Logging enabled | High | Logging |
| 7.2.2 | 7.2.2 | Ensure FortiAnalyzer logging enabled | Medium | Logging |
| 7.3.1 | 7.3.1 | Ensure Syslog enabled | Medium | Logging |

## Level 2 Rules (Advanced – 21 controls)

| Rule ID | CIS Section | Title | Severity | Category |
|---------|-------------|-------|----------|----------|
| 2.1.6 | 2.1.6 | Ensure latest firmware installed | High | System |
| 2.4.6 | 2.4.6 | Ensure Local-in Policies applied | High | Admin |
| 2.4.7 | 2.4.7 | Ensure default admin ports changed | Medium | Admin |
| 3.3 | 3.3 | Ensure Tor/malicious traffic blocked | High | Firewall |
| 4.1.1 | 4.1.1 | Ensure Botnet connections detected | High | Security Profiles |
| 4.2.6 | 4.2.6 | Ensure sandbox inspection enabled | High | Security Profiles |
| 4.3.2 | 4.3.2 | Ensure DNS Filter logging enabled | Medium | Security Profiles |
| 4.3.4 | 4.3.4 | Ensure high-risk categories blocked | High | Security Profiles |
| 4.4.2 | 4.4.2 | Ensure App Control logging enabled | Medium | Security Profiles |
| 4.5.1 | 4.5.1 | Ensure SSL/SSH inspection configured | High | Security Profiles |
| 4.5.2 | 4.5.2 | Ensure Web Filtering enabled | Medium | Security Profiles |
| 4.5.3 | 4.5.3 | Ensure CDR enabled | Medium | Security Profiles |
| 4.5.4 | 4.5.4 | Ensure Email Filtering configured | Medium | Security Profiles |
| 4.5.5 | 4.5.5 | Ensure File Filtering configured | Medium | Security Profiles |
| 6.1.1 | 6.1.1 | Ensure trusted VPN certificate | High | VPN |
| 6.1.2 | 6.1.2 | Ensure limited TLS for SSL VPN | High | VPN |
| 6.2.1 | 6.2.1 | Ensure IPsec AES-256 encryption | High | VPN |
| 6.2.2 | 6.2.2 | Ensure IPsec strong DH group | High | VPN |
| 7.2.1 | 7.2.1 | Ensure log encryption enabled | High | Logging |

## Severity Distribution

| Severity | L1 Count | L2 Count | Total |
|----------|----------|----------|-------|
| Critical | 3 | 0 | 3 |
| High | 14 | 14 | 28 |
| Medium | 15 | 7 | 22 |
| Low | 3 | 0 | 3 |
| **Total** | **35** | **21** | **56** |
