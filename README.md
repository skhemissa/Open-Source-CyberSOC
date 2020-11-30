# Open Source CyberSOC
>Author: Sabri Khemissa sabri.khemissa@gmail.com.

>Status: working copy.

>[Table of Content](https://github.com/skhemissa/Open-Source-CyberSOC#table-of-content)

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
* [Introduction](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/README.md)
* [Core Components](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/01_Core_Components.md)
  * [Technological Breakthrough](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/01_Core_Components.md#technological-breakthrough)
  * [Dedicate IS vs Corporate IS](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/01_Core_Components.md#dedicate-is-vs-corporate-is)
  * [Automation Engine](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/01_Core_Components.md#automation-engine)
  * [CyberSOC Data Store](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/01_Core_Components.md#cybersoc-data-store)
  * [Project Management and Issues Tracker](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/01_Core_Components.md#project-management-and-issues-tracker)
  * [Development Platform](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/01_Core_Components.md#development-platform)
  * [Knowledge Management](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/01_Core_Components.md#knowledge-management)
  * [Business Intelligence and Reporting](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/01_Core_Components.md#business-intelligence-and-reporting)
  * [Securing Access to CyberSOC services](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/01_Core_Components.md#securing-access-to-cybersoc-services)
  * [Peoples](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/01_Core_Components.md#peoples)
* [Ecosystem](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/02_Ecosystem.md)
  * [Asset Database](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/02_Ecosystem.md#asset-database)
  * [Network Subnets Ownership](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/02_Ecosystem.md#network-subnets-ownership)
* [Identify](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/03_Identify.md)
  * [Continuous Exposure Discovery](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/03_Identify.md#continuous-exposure-discovery)
  * [Vulnerability Management](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/03_Identify.md#vulnerability-management)
  * [Pentesting](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/03_Identify.md#pentesting)
  * [Threat Hunting](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/03_Identify.md#threat-hunting)
  * [Cyber Threat Intelligence](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/03_Identify.md#cyber-threat-intelligence)
* [Detect](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/04_Detect.md)
  * [Intrusion Detection Systems](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/04_Detect.md#intrusion-detection-systems)
  * [Decoy and Deception](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/04_Detect.md#decoy-and-deception)
  * [Network Behaviour Analysis](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/04_Detect.md#network-behaviour-analysis)
  * [Log Collectors and Log Aggregators](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/04_Detect.md#log-collectors-and-log-aggregators)
  * [SIEM Engine](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/04_Detect.md#siem-engine)
  * [Artefact Analyzers](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/04_Detect.md#artefact-analyzers)
* [React](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/05_React.md)
  * [Incident Tracking](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/05_React.md#incident-tracking)
  * [Digital Forensics](https://github.com/skhemissa/Open-Source-CyberSOC/blob/main/05_React.md#digital-forensics)
