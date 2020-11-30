# Ecosystem
* [Asset Database](#asset-database)
* [Network Subnets Ownership](#network-subnets-ownership)

## Asset Database
The Asset Database is crucial for the efficiency of all automated tasks of the CyberSOC. The Asset Database should includes all assets implemented in the organisation, including hardware configuration, operating system, middlewares, applications/services, location, criticality, asset Owner, Security Officer, etc.

> Open source solution that could be considered by IT Teams of the organisation:
> - [GLPI](https://glpi-project.org/).

## Network Subnets Ownership
This component is a subset of the previous one. The purpose of this service is to get the right contact related to an event that contains internal IPs not not associated to a asset from the Asset Database.
For covering this case, each subnet assigned in the organization must be associated with a contact, at least a Security Officer. 

> Open source solution that could be considered by Telecom Team of the organisation:
> - [phpIPAM](https://phpipam.net/).
