---
title: "Simple Network Management Protocol"
date: 2025-08-23
tags: [snmp,snmpwalk, braa, onesixtyone service]
port: [tcp, 25, 465, 587]
---

# Simple Mail Transfer Protocol

## Enumeration

*Common Commands:*

*SNMPwalk*

`$ snmpwalk -v2c -c public 10.129.14.128`

*onesixtyone*

`$ onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt 10.129.14.128`

*Braa*

```bash
braa <community string>@<IP>:.1.3.6.*   # Syntax`
braa public@10.129.14.128:.1.3.6.*`
```

## Service Information

### MIB

To ensure that SNMP access works across manufacturers and with different client-server combinations, the `Management Information Base` (`MIB`) was created. MIB is an independent format for storing device information. A MIB is a text file in which all queryable SNMP objects of a device are listed in a standardized tree hierarchy. It contains at least one `Object Identifier` (`OID`), which, in addition to the necessary unique address and a name, also provides information about the type, access rights, and a description of the respective object. MIB files are written in the `Abstract Syntax Notation One` (`ASN.1`) based ASCII text format. The MIBs do not contain data, but they explain where to find which information and what it looks like, which returns values for the specific OID, or which data type is used.

### OID

An OID represents a node in a hierarchical namespace. A sequence of numbers uniquely identifies each node, allowing the node's position in the tree to be determined. The longer the chain, the more specific the information. Many nodes in the OID tree contain nothing except references to those below them. The OIDs consist of integers and are usually concatenated by dot notation. We can look up many MIBs for the associated OIDs in the [Object Identifier Registry](https://www.alvestrand.no/objectid/).

### Community Strings

Community strings can be seen as passwords that are used to determine whether the requested information can be viewed or not. It is important to note that many organizations are still using `SNMPv2`, as the transition to `SNMPv3` can be very complex, but the services still need to remain active. This causes many administrators a great deal of concern and creates some problems they are keen to avoid. The lack of knowledge about how the information can be obtained and how we as attackers use it makes the administrators' approach seem inexplicable. At the same time, the lack of encryption of the data sent is also a problem. Because every time the community strings are sent over the network, they can be intercepted and read.