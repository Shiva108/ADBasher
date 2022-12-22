# ADBasher
**Under Development**

This repo is a shell-script implementation of the "Active Directory pentesting mind map" found here (also see below):
https://github.com/esidate/pentesting-active-directory

[Orange Pentesting AD](resources/pentest_ad_dark_2022_11.svg)

Version 0.1.1
"No credentials" part is "PoC" done.

### Todo:
Pretty much everything!

### The famous tree:
.
├── 1 nocreds
│   ├── ADnetscan.sh
│   ├── ADpoison.sh
│   ├── bannergrap.sh
│   ├── coerce.sh
│   ├── FindDCip.sh
│   ├── kerbscan.sh
│   ├── ldapenum.sh
│   ├── nmapldap.sh
│   └── smbscan.sh
├── 2 quick
│   ├── CVE-2020-1472
│   │   ├── cve-2020-1472-exploit.py
│   │   ├── README.md
│   │   ├── relaying
│   │   │   ├── dcsyncattack.py
│   │   │   └── dcsyncclient.py
│   │   └── restorepassword.py
│   ├── eternalblue.sh
│   ├── log4shell.sh
│   ├── miscquickAV.sh
│   ├── msfscripts
│   ├── proxylogon.sh
│   ├── proxyshell.sh
│   ├── zerologon
│   │   ├── nrpc.py
│   │   ├── __pycache__
│   │   │   └── nrpc.cpython-39.pyc
│   │   ├── README.md
│   │   └── zerologon.py
│   └── zeroscan.sh
├── 4 mitm
├── 5 nopass
├── 6 knownvulns
├── example.conf
├── install.sh
├── notes.md
├── rainbow.sh
├── README.md
├── resources
│   └── pentest_ad_dark_2022_11.svg
└── restartNM.sh