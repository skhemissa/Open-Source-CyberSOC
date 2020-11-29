# Open Source CyberSOC
>Author: Sabri Khemissa sabri.khemissa@gmail.com.

>Status: working copy.

“...there is no favourable wind for someone who does not know where he is heading”. Seneca

The purpose of this initiative is to provide a way of initiating and developing CyberSOC services based on open source solutions.

No feedback will be given on solutions listed in this initiaive: each organisation must tests the listed solutions and make sure they work in their context.

Services developed in this initiative cover the following capabilities of the CyberSOC:
- **Core components**: this section lists the structural components that constitute the CyberSOC Information System (CyberSOC IS);
- **Ecosystem**: this section covers services that enrich data processed by CyberSOC services for improving the accuracy and efficiency of CyberSOC operations;
- **Identify**: this section focuses on fundamental services that support the organisation to identify weaknesses in the Corporate Information System (Corporate IS) that could be exploited by a malicious activity. Furthermore, services described in this section enrich detect and react capabilities;
- **Detect**: this section describes the heart of the CyberSOC that identifies the occurrence of a cybersecurity event that raises a cybersecurity incident;
- **React**: this section describes services that take action, including forensics, for addressing a detected cybersecurity incident.

The following capability is not covered in this initiative: management of protection solutions that generate events processed by the CyberSOC. Protecting a Corporate IS based on open solutions is another subject. It is not covered in this initiative.

This initiative is not intended to debate about the competition between open source and commercial solutions. Starting with open source solutions is a good way for, with a minimum of CAPEX: 
1. Developing skills on a new topic;
2. Understanding the needs of the organisation;
3. Focus on developing the organisation and the processes.

Furthermore, the ROI of investing on full featured commercial solutions for a new topic could be a waste of money because few tens of percent of its capacities are used during a long time.

Of course, a shift to commercial solutions could be considered when limits of implemented open source solutions for developing new/advanced services are reached. For maximizing the ROI undertaken on commercial solutions, this shift could also be considered when the organisation reached a certain level of maturity:
- Needs and use cases are clearly documented and efficient;
- Processes are in place.

... and why not outsourcing some services!

**Risk to be considered in the decision making:** some open source solutions are supported by specific companies with a paid service based on fees. But for most of open sources solutions, the support is provided by the associated community of developers: no SLA to consider for solving bugs and issues. For mitigating this risk, it is important to select robust and proven open source solutions > this risk must be considered in the decision making.

Anyway, there is no doubt that the target CyberSOC will be a mix of commercial solutions, open source solutions and home made tools.

## Table of content
* [Core Components](#core-components) 
  * [Technological Breakthrough](#technological-breakthrough)  
  * [Dedicate IS vs Corporate IS](#dedicate-is-vs-corporate-is)
  * [Automation Engine](#automation-engine)
  * [CyberSOC Data Store](#cybersoc-data-store)
  * [Project Management and Issues Tracker](#project-management-and-issues-tracker)
  * [Development Platform](#development-platform)
  * [Knowledge Management](#knowledge-management)
  * [Business Intelligence and Reporting](#business-intelligence-and-reporting)
  * [Securing Access to CyberSOC services](#securing-access-to-cybersoc-services)
  * [Peoples](#peoples)
* [Ecosystem](#ecosystem)
  * [Asset Database](#asset-database)
  * [Network Subnets Ownership](#network-subnets-ownership)
* [Identify](#identify)
  * [Continuous Exposure Discovery](#continuous-exposure-discovery)
  * [Vulnerability Management](#vulnerability-management)
  * [Pentesting](#pentesting)
  * [Threat Hunting](#threat-hunting)
  * [Cyber Threat Intelligence](#cyber-threat-intelligence)
* [Detect](#detect)
  * [Intrusion Detection Systems](#intrusion-detection-systems)
  * [Decoy and Deception](#decoy-and-deception)
  * [Network Behaviour Analysis](#network-behaviour-analysis)
  * [Log Collectors and Log Aggregators](#log-collectors-and-log-aggregators)
  * [SIEM Engine](#siem-engine)
  * [Artefact Analyzers](#artefacts-analyzers)
* [React](#react)
  * [Incident Tracking](#incident-tracking)
  * [Digital Forensics](#digital-forensics)


## Core Components
### Technological Breakthrough
It could be interesting to consider the implementation of an operating system and middlewares that are not used in Corporate IS: this technological breakthrough reduces the risk of collateral damages on CyberSOC operations in case of Corporate IS compromise. 

> Open Source Operating System to consider:
> - [Debian Linux](https://www.debian.org/);
> - [Ubuntu](https://ubuntu.com/);
> - [CentOS](https://www.centos.org/);
> - [Fedora](https://getfedora.org/f).
> - if the organisation uses Red Hat Enterprise Linux), CentOS and Fedora should be avoided because both Linux flavours are based on Red Hat Enterprise Linux.

### Dedicate IS vs Corporate IS
It's a real and fundamental position to be decided related to the hosting of the CyberSOC infrastructure: does the CyberSOC infrastructure have to be hosted in the Corporate IS or in a Dedicated IS?

Dedicated IS means networks, servers, authentication infrastructure, email servers, dhcp, dns, ntp, backups, internet access, monitoring, update servers, etc.

The implementation of a dedicated IS for the CyberSOC reduces the risk of collateral damages on CyberSOC operations in case of Corporate IS compromise.

The answer to this question is not trivial: the answer could be addressed by balancing the risk mentioned above and the cost of building a dedicated infrastructure and associated organisation and processes.

Building an IS based on open solutions is another subject. It is not covered in this initiative.

### Automation Engine
The automation engine accelerates and automates decision making on events. This purpose is achieved by streamlining manual and repetitive tasks in automated and orchestrated workflows based on rules, triggers, and events. In the context of a CyberSOC, these workflows are designed by "playbooks".

Example 1:
An alert, generated by the SIEM (eg. “SIEM” section) should be enriched by running a specific playbook:
1. Check in the asset database (e.g. “Ecosystem” section):

if so

2. Get criticality of assets concerned by the alert, its owners, assigned security officers, etc.;
3. When required, update alert severity;
4. For external resources concerned by the alert, get additional information eg. IP reputation, GeoIP, etc.;
5. For internal ressources concerned by the alerts :
  - Perform IP/domain lookups; 
  - Run a hunting task to get artefacts from the asset: process list dump, get  hashes, etc.;
  - Run analyses on collected artefacts (local tools or provided cloud services;
- (For critical incident) create a collaboration workgroup to simplify information sharing and invite stakeholders (eg. [Microsoft O365 Teams Channel API](https://docs.microsoft.com/en-us/graph/teams-create-group-and-team));
- Assign the alert to the right security officer

Otherwise:

2. Get from the IPAM platform (e.g. “Ecosystem” section) the security officers assigned to subnet associated to internal IPs or the location concerned by the alert;
3. Assign the alert to the right security officer.

Example 2:
When a security bulletin related to a vulnerability is raised by a vendor or a CERT, a specific playbook is executed for security bulletin contextualization in the organisation:
Review in the asset database (e.g. “Ecosystem” section) if the concerned product is implemented in the organisation.
if so, the automation engine:
1. Check the criticality of the asset, remediation SLA, and get the asset owner;
2. For adjusting remediation priorities, get the level of exposure of concerned assets from firewall rules;
3. Notify asset owners,  additional stakeholders could be notified in case of emergency security bulletin vs. number of assets concerned vs. criticality of concerned assets;
4. Create remediation actions (e.g. “Core Components” section) with a calculated priority, a due date and assigned to the asset owner ... automatic remediation could also be considered;
5. When the remediation is done, execute a vulnerability scan for ensuring that the remediation is efficient.
Otherwise no action is done.

> Open source solutions:

> - [Shuffle](https://shuffler.io/) This automation solution supports OpenAPI that accelerates the implementation of  playbooks;
> - [WALKOFF](https://nsacyber.github.io/WALKOFF/).

### CyberSOC Data Store
Some tools used by the CyberSOC generate data that are interesting for further analysis or for reporting purposes. A dedicated database for consolidating such data should be considered.  
> Open source database:
> - [Postgresql](https://www.postgresql.org/);
> - [MariaDB](https://mariadb.com/kb/en/documentation/).

Data stored in the database must be accessed using a standard interface. RestAPI for accessing such data should be considered. Some solutions act as a RestAPI gateway between a requester and a database.
> Open source solutions:
> - [PostgREST](http://postgrest.org) for Postgresql;
> - [MaxScale](https://mariadb.com/kb/en/maxscale/) for MariaDB.

### Project Management and Issues Tracker
Building a CyberSOC is a complete and complex project that involves multiple stakeholders. It's important to use a robust and flexible solution for managing this project.
Furthermore, a lot of actions such as vulnerabilities and post-incident remediations are raised by the CyberSOC. These actions must be followed up and reported. 
> Open source solution:
> - [Redmine](https://www.redmine.org/).

### Development Platform
The development of new services requires a lot of developments that should be centralised in one place. This place is also the opportunity to have strong collaboraton between team members. 
> Open Source solution:
> - [GitLab](https://gitlab.com/gitlab-org/gitlab)

### Knowledge Management
A wiki for consolidating knowledge and information such as processes, installations documents, technical manuals, etc. should be considered.
> Open source solutions:
> - [DokuWiki](https://www.dokuwiki.org/dokuwiki);
> - [MediaWiki](https://www.mediawiki.org/wiki/MediaWiki);
> - [PmWiki](https://www.pmwiki.org/);
> - [Tiki](https://tiki.org/).
> - ….
### Business Intelligence and Reporting
Business Intelligence and reporting are important for:
1. The follow-up of the CyberSOC operations performances;
2. Improving the services of the CyberSOC;
3. Providing the visibility and the value of the CyberSOC to external and internal stakeholders.

> Open source solutions:
> - [Dashbuilder](http://dashbuilder.org/);
> - [Grafana](https://grafana.com/).

### Securing access to CyberSOC services
The access to the CyberSOC services must be protected by an IPSec VPN with Multi Factor Authentication (MFA), even from internal networks.
> Open source solution:
> - VPN: [OpenVPN](https://openvpn.net/);
> - MFA: **TODO**.

### Peoples
A skilled technical core team must be considered.
This team is : 
1. Accountable for maintaining the consistency of the software architecture/urbanization (especially when several solutions offer the same functionality) and the security of the CyberSOC IS;
2. Responsible of developing the technical part of the services that will be described in next sections;
3. Responsible for managing, including patching and upgrading, all the technical components of the CyberSOC IS.

## Ecosystem
### Asset Database
The Asset Database is crucial for the efficiency of all automated tasks of the CyberSOC. The Asset Database should includes all assets implemented in the organisation, including hardware configuration, operating system, middlewares, applications/services, location, criticality, asset Owner, Security Officer, etc.

> Open source solution that could be considered by IT Teams of the organisation:
> - [GLPI](https://glpi-project.org/).

### Network Subnets Ownership
This component is a subset of the previous one. The purpose of this service is to get the right contact related to an event that contains internal IPs not not associated to a asset from the Asset Database.
For covering this case, each subnet assigned in the organization must be associated with a contact, at least a Security Officer. 

> Open source solution that could be considered by Telecom Team of the organisation:
> - [phpIPAM](https://phpipam.net/).

## Detect
### Continuous Exposure Discovery
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

### Vulnerability Management
This service assesses the security of Corporate IT components, including network equipment, operating systems, middlewares and applications.
Scans of this service are exhaustive: they are slower than the scans executed by the service "Continuous Exposure Discovery": both services could be paired by the Automation Engine: when a new host or a new opened port is detected, a full vulnerability scan could be launched automatically.
Results of vulnerability scans should be processed by the Automation Engine for prioritisation, remediation issues creation and assignment.
Scans could also be executed on-demand by the Automation Engine to verify that the remediation associated with a security bulletin is efficient. 

> Open source solution: 
> - [OpenVAS](https://www.openvas.org/).

This service includes security bulletins processing sent by vendors and CERT (Take a look to the example provided in the “Core Components” section).

### Pentesting
This service is more related to technical skills of pentesters.
Pentest actions and results should be consolidated in a central platform.
> Open source solutions: 
> - [Faraday](https://github.com/infobyte/faraday) a multiuser pentest IDE.

Red Teaming
> - [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)

### Threat Hunting
This service proactively and iteratively searches through Corporate IT to detect and isolate advanced threats that evade existing security solutions.
Two kinds of threat hunting should be considered:
- Network hunting for analyzing network traffic to detect suspicious network activities (VPN and Tor traffic, suspicious targets, etc.);
> Open source solution: 
> - [Ntop](https://www.ntop.org/).

- Host hunting for collecting artefacts that could be associated with a suspicious activity (running processes, binaries, task scheduler entries, etc.).
> Open source solution:
> - [Osquery](https://osquery.io/) for threat hunting and [Kolide Fleet](https://github.com/kolide/fleet) for managing an osquery infrastructure.

Usually, Threat Hunting campaigns are executed on-demand: manually or from Automation Engine.

### Cyber Threat Intelligence
This service collects, stores, distributes and shares cyber security indicators and threats about cyber security incidents analysis and malware analysis.
With the Automation Engine alerts generated by the SIEM and also Threat Hunting campaigns are enriched by this service.

> Open source solutions:
> - [OpenCTI](https://github.com/OpenCTI-Platform/opencti);
> - [MISP](https://www.misp-project.org/).

Because the content of the CTI platform is populated with external sources, a high number of connectors and the relevance of these sources are essential.

## Detect
### Intrusion Detection Systems
> Open source solutions:
> - [Suricata](https://suricata-ids.org/);
> - [Snort](https://www.snort.org/);
> - [Zeek (formerly Bro)](https://zeek.org/);
> - [Maltrail (malicious traffic detection system)](https://github.com/stamparm/maltrail).

### Decoy and Deception
To catch enumerations and lateral movements not detected by existing security solutions.
> Open source solution:
> - [DejaVU](https://github.com/bhdresh/Dejavu) Open Source Deception Framework;
> - [Kippo](https://github.com/desaster/kippo) SSH honeypot;
> - [Conpot](https://github.com/mushorg/conpot) ICS honeypot.
### Network Behaviour Analysis
Ntop?
### Log Collectors and Log Aggregators 
Log collectors:
> Open source solutions:
> - [Filebeat](https://www.elastic.co/beats/filebeat) for collecting logs from files (e.g. web server logs) 
> - [RSyslog](https://www.rsyslog.com/) for syslog based events;

> Not an open source solution for collecting Microsoft Windows events:
> - [Windows Event Forwarding](https://docs.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection) for collecting Microsoft Windows events on dedicated Windows machine and [winlogbeat](https://www.elastic.co/fr/beats/winlogbeat) to transfers event to log aggregator;
> - [Specific Microsoft Windows events to monitor](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
> - [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) should be deployed.

Log aggregators consolidate logs sent by different sources then forward some of them to the SIEM Engine based on specific rules. Some solutions could run simple rules for detecting suspicious activities (pre-correlation) ex. multiple tcp connections from the same source to different destinations (required collecting firewall logs).

Multiple log aggregators should be considered for addressing specific area (e.g. remote sites with low bandwidth) and also for processing a high number of events (e.g. firewalls logs or Active Directory events).
> Open source solutions:
> - [Elastic Stack Basic Plan](https://www.elastic.co/siem);
> - [Graylog](https://www.graylog.org/products/open-source).
> - [Logstash](https://www.elastic.co/logstash) is required for connecting Filebeat agents to Graylog
>  Greylog have a specific plugin for enriching events [Threat Intelligence Plugin for Graylog](https://github.com/Graylog2/graylog-plugin-threatintel)

### SIEM Engine
> Open source solutions:
> - [OSSEC](https://www.ossec.net/);
> - [Wazuh](https://wazuh.com/) a fork of OSSEC;
> - [Elastic Stack Basic Plan](https://www.elastic.co/siem);
> - [Apache Motron](https://metron.apache.org/);
> - [MozDef (Mozilla Defense Platform)](https://github.com/mozilla/MozDef) (Pre Beta).

### Artefact Analyzers
Analyzer Engine connects to different tools to run specific action to enrich the content of a query (e.g. nslookup, public IP reputation) or executes a specific action (e.g. parsing file to extract meta or malicious content, run a URL and a file in a sandbox).
Please note that some features provided by the Automation Engine could be provided by the Analyzer Engine. Thanks to the urbanization of the CyberSOC IS to define the relevant use cases to be implemented on each solution. 
> Open source solution:
> - [Cortex](https://github.com/TheHive-Project/Cortex).

Analyzers (connectors):
> Free / open source solution:
> - [Take a look to Cortex dedicated page](https://github.com/TheHive-Project/CortexDocs/blob/master/analyzer_requirements.md).

## React
### Incident Tracking
> Open source solution:
> - [TheHive](https://github.com/TheHive-Project/TheHive)
> Multiple automated actions done by TheHive could be interfaced with Automation Engine and Analyzer Engine.

### Digital Forensics
> Open source solutions:
> - [GRR - Google Rapid Response](https://github.com/google/grr);
> - [DFIRTrack](https://github.com/stuhli/dfirtrack)
> - [Kali Linux](https://www.kali.org/);
> - [Rescue & Forensic Disk](https://github.com/skhemissa/Rescue-Forensic-Disk) my personal project.
