# Open Source CyberSOC
> Author: Sabri Khemissa sabri.khemissa@gmail.com

The purpose of this initiative is providing a way of initiating and developing CyberSOC services based on open source solutions.

No feedback will be given on the solutions: each organization must test the listed solutions and make sure they work in their context.

Don't hesitate to suggest additional open solutions that could be listed in this initiative. Suggested solutions must be mature (the definition of "mature" should be done).

Services developed in this initiative cover the following capabilities of the CyberSOC:
- **Core components**: this section lists the structural components that constitute the CyberSOC Information System (CyberSOC IS);
- **Ecosystem**: this section covers services that enrich data processed by CyberSOC services for improving the accuracy and efficiency of CyberSOC operations;
- **Identify**: this section focuses on fundamental services that support the organisation for identifying weaknesses in the Corporate IS that could be exploited by a malicious activity. Furthermore, services described in this section enrich detect and react capabilities.
- **Detect**: this section describes the heart of the CyberSOC that identifies the occurrence of a cybersecurity event that raises a cybersecurity incident.
- **React**: this section describes services that take action, including forensics, regarding a detected cybersecurity incident.

The following two capabilities are not covered in this initiative:
- Pentesting because it’s related to the skills of pentesters. However, results of pentest campaigns could enrich detect and react capabilities.
- Management of protection solutions that generate events processed by the CyberSOC. Protecting a Corporate Information Systems (Corporate IS) based on open solutions is another subject. It is not covered in this initiative.

When relevant, tips from structuring the CyberSOC organisation on each capability are provided.

This initiative is not intended to debate about the competition between open source and commercial solutions. Starting with open source solutions is a good way for, with a minimum of CAPEX: 
1. Developing skills on a new topic;
2. Understanding the needs of the organisation;
3. Focus on developing the organisation and the processes.

Furthermore, the ROI of investing on full featured commercial solutions for a new topic could be a waste of money because few tens of percent of its capacities are used during a long time.

Of course, a shift to commercial solutions could be considered when limits of implemented open source solutions for developing new/advanced services are reached. For maximizing the ROI undertaken on commercial solutions, this shift could also be considered when the organisation reached a certain level of maturity:
- Needs and use cases are clearly documented and efficient;
- Processes are in place.

Please note that some open source solutions are supported by specific companies with a paid service based on annual fees. But for most of open sources solutions, the support is provided by the associated community of developers: no SLA to consider for solving bugs and issues. For mitigating this risk, it is important to select robust and proven open source solution > the residual risk must be considered in the decision making.

Anyway, there is no doubt that the target CyberSOC will be a mix of commercial solutions, open source solutions and home made tools.

## Table of content
* [Core Components](#core-components) 
  * [Technological Breakthrough](#technological-breakthrough)  
  * [Dedicate IS vs Corporate IS](#dedicate-is-vs-corporate-is)
  * [Automation Engine](#automation-engine)
  * [CyberSOC Data Store](#cybersoc-data-store)
  * [Project Management and Issues Tracker](#project-management-and-issues-tracker)
  * [Knowledge Management](#knowledge-management)
  * [Business Intelligence and Reporting](#business-intelligence-and-reporting)
  * [Securing Access to CyberSOC services](#securing-access-to-cybersoc-services)
  * [Organisation](#organisation)

* [Ecosystem](#ecosystem) **IN PROGRESS**
  * [Asset Database](#asset-database)
  * [Network Subnets Ownerships](#network-subnets-ownerships)

* [Identify](#identify) **TODO**
   * Exposure Discovery
   * Vulnerability Management
   * Threat Hunting
   * Cyber Threat Intelligence
   * Organisation
   
* [Detect](#detect) **TODO**
  * Intrusion Detection Systems
  * Decoy and Deception
  * Network Behaviour Analysis
  * Collectors
  * SIEM Engine
  * Artefacts and Observables Analyzers
  * Organisation
  
* [React](#react) **TODO**
  * Incident Tracking
  * Rescue Disk
  * Digital Forensics
  * Organisation

## Core Components
### Technological Breakthrough
It could be interesting to consider the implementation of an operating system and middlewares that are not used in Corporate Information System (Corporate IS): this technological breakthrough reduces the risk of collateral damages on CyberSOC operations in case of Corporate IS compromise. 

> Open Source Operating System to consider: [Debian Linux](https://www.debian.org/), [Ubuntu](https://ubuntu.com/), [CentOS](https://www.centos.org/), [Fedora](https://getfedora.org/f), etc.
> if the organisation use Red Hat Enterprise Linux), CentOS and Fedora should be avoided because both Linux flavours are based on Red Hat Enterprise Linux.

### Dedicate IS vs Corporate IS
It's a real and fundamental position to be decided related to the hosting of the CyberSOC infrastructure: does the CyberSOC infrastructure have to be hosted in the Corporate IS or in a Dedicated IS?

Dedicated IS means networks, servers, authentication infrastructure, email servers, dhcp, dns, ntp, backups, internet access, monitoring, update servers, etc.

The implementation of a dedicated IS for the CyberSOC reduces the risk of collateral damages on CyberSOC operations in case of Corporate IS compromise.

The answer to this question is not trivial: the answer could be addressed by balancing the risk mentioned above and the cost of building a dedicated infrastructure and associated organisation and processes.

Building an IS based on open solutions is another subject. It is not covered in this initiative.

### Automation Engine
The purpose of the automation engine is accelerating and automating decision making on events that workflows could be modelled. This purpose is achieved by streamlining manual and repetitive tasks in playbooks.

A playbook carries out various tasks and workflows based on rules, triggers, and events.

Example 1:
An alert, generated by the SIEM (eg. “SIEM” section) should be enriched by running a specific playbook :
1. Check in the asset database (e.g. “Ecosystem” section):

if so

2. Get criticality of assets concerned by the alert, its owners, assigned security officers, etc.;
3. When required, update alert severity;
4. For external resources concerned by the alert, get additional information eg. IP reputation, GeoIP, etc.;
5. For internal ressources concerned by the alerts :
  - Perform IP/domain lookups; 
  - Run a hunting task to get artefacts from the asset: process list dump, get  hashes, etc.;
  - Run artefacts analysis tools (local or provided a cloud service);
- (For critical incident) create a collaboration workgroup to simplify information sharing and invite stakeholders;
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

> - [Shuffle](#https://shuffler.io/) This automation solution supports OpenAPI that accelerates the implementation of  playbooks;
> - [WALKOFF](#https://nsacyber.github.io/WALKOFF/).

### CyberSOC Data Store
Some tools used by the CyberSOC generate data that are interesting for further analysis or for reporting purposes. A dedicated database for consolidating such data should be considered.  
> Open source database:
> - [Postgresql](https://www.postgresql.org/);
> - [MariaDB](https://mariadb.com/kb/en/documentation/), etc.

Data stored in the database must be accessed using a standard interface. RestAPI for accessing such data should be considered.
> Open source RESTful API:
> - [PostgREST](http://postgrest.org) for Postgresql;
> - [MaxScale for MariaDB](https://mariadb.com/kb/en/maxscale/).

### Project Management and Issues Tracker
Building a CyberSOC is a complete and complex project that involves multiple stakeholders. It's important to use a robust and flexible solution for managing this project.
Furthermore, a lot of actions such as vulnerabilities and post-incident remediations are raised by the CyberSOC. These actions must be followed up and reported. 
> Open source solution:
> - [Redmine](https://www.redmine.org/).

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
> - [Dashbuilder](http://dashbuilder.org/)
> - [Grafana](https://grafana.com/)

https://www.goodfirms.co/blog/best-free-open-source-dashboard-software

### Securing access to CyberSOC services
The access to the CyberSOC services must be protected by an IPSec VPN with Multi Factor Authentication (MFA), even from internal networks.
> Open source solution:
> - VPN: [OpenVPN](https://openvpn.net/);
> - MFA: **TODO**.

### Organisation
A skilled technical core team must be considered. This team is : 
1. Accountable for maintaining the consistency of the software architecture/urbanization and the security of the CyberSOC IS;
2. Responsible of developing the technical part of the services that will be described in next sections;
3. Responsible for managing, including patching and upgrading, all the technical components of the CyberSOC IS.
