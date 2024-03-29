# Identify
* [CVE Alerting Platform](#cve-alerting-platform)
* [Network Exposure and Discovery](#network-exposure-and-discovery)
* [Public Exposure](#public-exposure)
* [Vulnerability Management](#vulnerability-management)
* [Cloud Security Auditing](#cloud-security-auditing)
* [Pentesting](#pentesting)
* [Threat Hunting](#threat-hunting)
* [Cyber Threat Intelligence](#cyber-threat-intelligence)

## CVE Alerting Platform
This service aims to notify owners about new vulnerabilies related to their products. Such platform should be connected to an issue tracker system for remediations follow-up.

> Open source solutions:
> - [OpenCVE](https://www.opencve.io/)

## Network Exposure and Discovery
The purpose of this service is running continuously scans in the WAN and Internet faced subnets for discovering specific weaknesses in the Corporate IS such as weak credentials, unprotected services (e.g. Redis), unprotected management interfaces, specific ports (e.g. industrial modbus and S7), etc.

In large environments, fast solutions must be considered. Otherwise, the next service "Vulnerability Management" is enough.

Results of continuous scans should be processed by the Automation Engine for prioritisation, remediation issues creation and assignment.

Network scanner:
> Open source solutions: 
> - [Nmap](https://nmap.org/) the ultimate tools;
> - [Masscan](https://github.com/robertdavidgraham/masscan).

For consolidating port scans results:
> Open source solution:
> - [IVRE](https://github.com/cea-sec/ivre) an on-premise shodan like.

For testing specific weaknesses/vulnerabilities:
> Open source scripts: 
> - [Nmap Scripting Engine (nse)](https://nmap.org/book/nse.html);
> - [Github](https://github.com/).

A lot of scripts used for specific weaknesse/vulnerabilitie detections provide results in flat format: these results should be imported in the "CyberSOC Data Store" (e.g. "Core Components" section).

## Public Exposure
Search for data related to the company accessible in publicly available sources. public data that an attacker could exploit against the company.
> Open source solution:
> - [Datasploit](https://github.com/DataSploit/datasploit/).

## Vulnerability Management
This service assesses the security of Corporate IT components, including network equipment, operating systems, middlewares and applications.
Scans of this service are exhaustive: they are slower than the scans executed by the service "Continuous Exposure Discovery": both services could be paired by the Automation Engine: when a new host or a new opened port is detected, a full vulnerability scan could be launched automatically.
Results of vulnerability scans should be processed by the Automation Engine for prioritisation, remediation issues creation and assignment.
Scans could also be executed on-demand by the Automation Engine to verify that the remediation associated with a security bulletin is efficient. 

> Open source solution: 
> - [Archery](https://www.archerysec.com/): a vulnerability assessment and management tool. Archery uses popular opensource tools to perform comprehensive scanning for web application and network (OpenVAS, OWASP ZAP, etc.)
> - [OpenVAS](https://www.openvas.org/): a full-featured vulnerability scanner
> - [Grype](https://github.com/anchore/grype): a vulnerability scanner for container images and filesystems;
> - [Webvulnscan](https://github.com/hhucn/webvulnscan): security scanner for Web Applications;
> - [Lynis](https://cisofy.com/lynis/): Security auditing and hardening tool for Linux/Unix;
> - [Carnivore](https://github.com/nccgroup/Carnivore): Microsoft External Assessment Tool;
> - [VulnWhisperer](https://github.com/HASecuritySolutions/VulnWhisperer): Vulnerability management tool and report aggregator.

This service includes security bulletins processing sent by vendors and CERT (Take a look to the example provided in the “Core Components” section).

## Cloud Security Auditing
This service assesses the security of cloud environments. This service returns a series of potential misconfigurations and security risks.

> Open source solutions: 
> - [Scout Suite](https://github.com/nccgroup/ScoutSuite);
> - [CloudSploit by Aqua](https://github.com/aquasecurity/cloudsploit).
> - [OpenCSPM](https://github.com/OpenCSPM/opencspm)

## Pentesting
This service is more related to technical skills of pentesters.
Pentest actions and results should be consolidated in a central platform.
> Open source solutions: 
> - [Faraday](https://github.com/infobyte/faraday) a multiuser pentest IDE.

Red Teaming
> - [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)

## Threat Hunting
This service proactively and iteratively searches through Corporate IT to detect and isolate advanced threats that evade existing security solutions.
Two kinds of threat hunting should be considered:
- Network hunting for analyzing network traffic to detect suspicious network activities (VPN and Tor traffic, suspicious targets, etc.);
> Open source solution: 
> - [Ntop](https://www.ntop.org/).

- Host hunting for collecting artefacts that could be associated with a suspicious activity (running processes, binaries, task scheduler entries, etc.).
> Open source solution:
> - [Osquery](https://osquery.io/) for threat hunting and [Kolide Fleet](https://github.com/kolide/fleet) for managing an osquery infrastructure;
> - [Security Onion](https://securityonionsolutions.com/software).

Threat Hunting campaigns are executed on-demand manually otherwise it is a detection topic.

## Cyber Threat Intelligence
This service collects, stores, distributes and shares cyber security indicators and threats about cyber security incidents analysis and malware analysis.
With the Automation Engine alerts generated by the SIEM and also Threat Hunting campaigns are enriched by this service.

> Open source solutions:
> - [OpenCTI](https://github.com/OpenCTI-Platform/opencti);
> - [MISP](https://www.misp-project.org/);
> - [Watcher](https://github.com/Felix83000/Watcher).

Because the content of the CTI platform is populated with external sources, a high number of connectors and the relevance of these sources are essential.

[Table of Content](https://github.com/skhemissa/Open-Source-CyberSOC#table-of-content)
