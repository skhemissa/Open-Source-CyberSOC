
# Detect
  * [Intrusion Detection Systems](#intrusion-detection-systems)
  * [Decoy and Deception](#decoy-and-deception)
  * [Network Behaviour Analysis](#network-behaviour-analysis)
  * [Log Collectors and Log Aggregators](#log-collectors-and-log-aggregators)
  * [SIEM Engine](#siem-engine)
  * [Artefact Analyzers](#artefacts-analyzers)

## Intrusion Detection Systems
> Open source solutions:
> - [Suricata](https://suricata-ids.org/);
> - [Snort](https://www.snort.org/);
> - [Zeek (formerly Bro)](https://zeek.org/);
> - [Maltrail (malicious traffic detection system)](https://github.com/stamparm/maltrail).

## Decoy and Deception
To catch enumerations and lateral movements not detected by existing security solutions.
> Open source solution:
> - [DejaVU](https://github.com/bhdresh/Dejavu) Open Source Deception Framework;
> - [Kippo](https://github.com/desaster/kippo) SSH honeypot;
> - [Conpot](https://github.com/mushorg/conpot) ICS honeypot.

## Network Behaviour Analysis
Ntop?

## Log Collectors and Log Aggregators 
Log collectors:
> Open source solutions:
> - [Filebeat](https://www.elastic.co/beats/filebeat) for collecting logs from files (e.g. web server logs) 
> - [RSyslog](https://www.rsyslog.com/) for syslog based events;

> Not an open source solution for collecting Microsoft Windows events:
> - [Windows Event Forwarding](https://docs.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection) for collecting Microsoft Windows events on dedicated Windows machine and [winlogbeat](https://www.elastic.co/fr/beats/winlogbeat) to transfers event to log aggregator;
> - [Specific Microsoft Windows events to monitor](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
> - [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) should be deployed.

### Additional Resources
[Australian Cyber Security Centre: Windows Event Logging and Forwarding](https://www.cyber.gov.au/sites/default/files/2020-06/PROTECT%20-%20Windows%20Event%20Logging%20and%20Forwarding%20%28June%202020%29.pdf)

Log aggregators consolidate logs sent by different sources then forward some of them to the SIEM Engine based on specific rules. Some solutions could run simple rules for detecting suspicious activities (pre-correlation) ex. multiple tcp connections from the same source to different destinations (required collecting firewall logs).

Multiple log aggregators should be considered for addressing specific area (e.g. remote sites with low bandwidth) and also for processing a high number of events (e.g. firewalls logs or Active Directory events).
> Open source solutions:
> - [Elastic Stack Basic Plan](https://www.elastic.co/siem);
> - [Graylog](https://www.graylog.org/products/open-source).
> - [Logstash](https://www.elastic.co/logstash) is required for connecting Filebeat agents to Graylog
>  Greylog have a specific plugin for enriching events [Threat Intelligence Plugin for Graylog](https://github.com/Graylog2/graylog-plugin-threatintel)

## SIEM Engine
> Open source solutions:
> - [OSSEC](https://www.ossec.net/);
> - [Wazuh](https://wazuh.com/) a fork of OSSEC;
> - [Elastic Stack Basic Plan](https://www.elastic.co/siem);
> - [Dsiem](https://github.com/defenxor/dsiemis): security event correlation engine for Elastic;
> - [Apache Motron](https://metron.apache.org/);
> - [MozDef (Mozilla Defense Platform)](https://github.com/mozilla/MozDef) (Pre Beta).

### Additional Resources
[Paladion 45 use cases for Security Monitoring](https://www.paladion.net/siem-use-cases)

## Artefact Analyzers
Analyzer Engine connects to different tools to run specific action to enrich the content of a query (e.g. nslookup, public IP reputation) or executes a specific action (e.g. parsing file to extract meta or malicious content, run a URL and a file in a sandbox).
Please note that some features provided by the Automation Engine could be provided by the Analyzer Engine. Thanks to the urbanization of the CyberSOC IS to define the relevant use cases to be implemented on each solution. 
> Open source solution:
> - [Cortex](https://github.com/TheHive-Project/Cortex).

### Additional Resources
> Free / open source solution:
> - [Take a look to Cortex dedicated page](https://github.com/TheHive-Project/CortexDocs/blob/master/analyzer_requirements.md).

[Table of Content](https://github.com/skhemissa/Open-Source-CyberSOC#table-of-content)
