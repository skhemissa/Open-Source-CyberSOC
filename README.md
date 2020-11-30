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
* [Core Components](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/01_Core_Components.md)
  * Technological Breakthrough
  * Dedicate IS vs Corporate IS
  * Automation Engine
  * CyberSOC Data Store
  * Project Management and Issues Tracker
  * Development Platform
  * Knowledge Management
  * Business Intelligence and Reporting
  * Securing Access to CyberSOC services
  * Peoples](#peoples)
* [Ecosystem](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/02_Ecosystem.md)
  * Asset Database
  * Network Subnets Ownership]
* [Identify](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/03_Identify.md)
  * Continuous Exposure Discovery
  * Vulnerability Management
  * Pentesting
  * Threat Hunting
  * Cyber Threat Intelligence
* [Detect](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/04_Detect.md)
  * Intrusion Detection Systems
  * Decoy and Deception
  * Network Behaviour Analysis
  * Log Collectors and Log Aggregators
  * SIEM Engine
  * Artefact Analyzers](#artefacts-analyzers)
* [React](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/05_React.md)
  * Incident Tracking
  * Digital Forensics
