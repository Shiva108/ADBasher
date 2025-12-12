# Active Directory Penetration Testing with ADBasher

## Documentation Overview

This directory contains a comprehensive, production-ready guide for conducting Active Directory penetration tests using the ADBasher framework.

## Document Structure

The guide is organized into the following files for better manageability:

### [📘 Main Guide](AD_PENETRATION_TESTING_GUIDE.md)

Contains sections 1-4:

- **Section 1:** Introduction and Prerequisites
- **Section 2:** Reconnaissance and Information Gathering
- **Section 3:** Enumeration Techniques
- **Section 4:** Credential Access and Harvesting

### [📂 Additional Sections](sections/)

Organized in separate files for easier navigation:

- **[Section 5: Privilege Escalation Paths](sections/05_privilege_escalation.md)**

  - Exploiting misconfigurations
  - ACL abuse techniques
  - GPO manipulation
  - Delegation attacks (unconstrained, constrained, RBCD)

- **[Section 6: Lateral Movement](sections/06_lateral_movement.md)**

  - Pass-the-Hash and Pass-the-Ticket
  - Remote code execution methods (WMIExec, PSExec, AtExec, SMBExec)
  - Session hijacking
  - Golden and Silver Ticket attacks

- **[Section 7: Persistence Mechanisms](sections/07_persistence.md)**

  - Backdoor accounts
  - Skeleton keys and directory replication
  - AdminSDHolder abuse
  - DCSync rights persistence

- **[Section 8: Case Studies](sections/08_case_studies.md)**

  - Real-world penetration test scenario (external to Domain Admin)
  - Lessons learned and common pitfalls
  - Statistics from 50+ real engagements

- **[Section 9: Conclusion](sections/09_conclusion.md)**

  - Key takeaways and essential principles
  - ADBasher workflow summary
  - Further resources (tools, training, communities)

- **[Section 10: Appendices](sections/10_appendices.md)**
  - Pre-engagement checklist
  - Post-engagement and cleanup checklist
  - ADBasher command reference guide

## Quick Start

1. **Read the main guide first**: Start with [AD_PENETRATION_TESTING_GUIDE.md](AD_PENETRATION_TESTING_GUIDE.md) for foundational concepts and initial phases

2. **Follow the attack lifecycle**: Progress through sections sequentially as they match the typical penetration testing workflow

3. **Reference appendices**: Use [Section 10](sections/10_appendices.md) command reference during execution

4. **Review case studies**: See [Section 8](sections/08_case_studies.md) for real-world application examples

## Key Features

This guide provides:

✅ **Comprehensive Coverage** - Complete AD attack lifecycle from reconnaissance to persistence  
✅ **Practical Examples** - ADBasher commands with expected outputs and success criteria  
✅ **OPSEC Guidance** - Detection likelihood ratings and evasion techniques  
✅ **Production-Ready** - Immediately usable in authorized penetration tests  
✅ **Real-World Context** - Case studies, statistics, and lessons learned  
✅ **Complete Checklists** - Pre/post-engagement procedures for professional delivery

## Target Audience

- Penetration Testers
- Red Team Operators
- Security Consultants
- Security Researchers

## Prerequisites

- Basic Active Directory knowledge
- Linux command line proficiency (Kali/Parrot)
- Understanding of network protocols (SMB, LDAP, Kerberos)
- Python 3.10+
- ADBasher framework installed

## Usage

This guide is designed to be used:

1. **During engagements**: As a field reference for commands and techniques
2. **For training**: Teaching AD penetration testing methodology
3. **For planning**: Understanding attack paths and estimating effort

4. **For reporting**: Remediation guidance and detection recommendations

## Legal Notice

> [!CAUTION] > **AUTHORIZED USE ONLY:** This guide is for legal, authorized security assessments only. Unauthorized access to computer systems is illegal. Always obtain written authorization before conducting any penetration testing activities.

## Document Navigation

```
docs/
├── AD_PENETRATION_TESTING_GUIDE.md  ← Start here (Sections 1-4)
├── sections/
│   ├── 05_privilege_escalation.md
│   ├── 06_lateral_movement.md
│   ├── 07_persistence.md
│   ├── 08_case_studies.md
│   ├── 09_conclusion.md
│   └── 10_appendices.md
└── README.md  ← This file
```

## Contributing

If you discover errors, have suggestions for improvements, or want to contribute additional case studies, please submit issues or pull requests to the main ADBasher repository.

## Version

**Version:** 1.0  
**Last Updated:** December 12, 2025  
**Framework Version:** ADBasher 1.0

---

**Start Reading:** [AD Penetration Testing Guide - Main Document](AD_PENETRATION_TESTING_GUIDE.md)
