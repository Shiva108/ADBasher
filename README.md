# ADBasher
**Under Development**

<div align="center">
    <img src="/resources/ADBasherlogo.png" alt="Logo" width="300"> <!-- Adjust the width as needed -->
</div>

An Active Directory penetration testing framework written in shell script.

This repo is a shell-script implementation of the "Active Directory pentesting mind map" found here:
https://github.com/esidate/pentesting-active-directory and seen here:

![Orange Pentesting AD](/resources/pentest_ad_dark_2022_11.svg "Orange Pentesting AD")


Version 0.4.0
* Many scripts added
* Userfriendliness improved with GPT

Version 0.1.1
* "No credentials" part is "PoC" done.

**Tested with:**
* PowerShell 7.2.1 (for linux)
* zsh 5.8 (x86_64-debian-linux-gnu)
* GNU bash, version 5.1.4(1)-release
* Metasploit v6.2.22-dev
* Parrot OS 5.1 (Electro Ara) x86_64 / 6.0.0-2parrot1-amd64
* Kali Rolling (2022.3) x64 2022-08-08

**Todo:**
* Pretty much everything!

**The famous tree:**

Will be updated...

```
*|-- 1 nocreds
*|   |-- 1 nocreds/ADnetscan.sh
*|   |-- 1 nocreds/ADpoison.sh
*|   |-- 1 nocreds/bannergrap.sh
*|   |-- 1 nocreds/Coercer
*|   |-- 1 nocreds/coerce.sh
*|   |-- 1 nocreds/findcertserv.sh
*|   |-- 1 nocreds/FindDCip.sh
*|   |-- 1 nocreds/kerbscan.sh
*|   |-- 1 nocreds/ldapenum.sh
*|   |-- 1 nocreds/nmapldap.sh
*|   |-- 1 nocreds/PetitPotam
*|   `-- 1 nocreds/smbscan.sh
*|-- 2 quick
*|   |-- 2 quick/CVE-2020-1472
*|   |-- 2 quick/eternalblue.sh
*|   |-- 2 quick/log4shell.sh
*|   |-- 2 quick/msfscripts
*|   |-- 2 quick/proxylogon.sh
*|   |-- 2 quick/proxyshell.sh
*|   |-- 2 quick/zerologon
*|   |-- 2 quick/zeroscanmsf.sh
*|   `-- 2 quick/zeroscan.sh
*|-- 3 nopass
*|   |-- 3 nopass/roast
*|   `-- 3 nopass/spray
*|-- 4 mitm
*|-- 5 knownvulns
*|-- 6 validcreds
*|   |-- 6 validcreds/enumAD.sh
*|   `-- 6 validcreds/rpccon.sh
*|-- 7 privesc
*|-- 8 weakADCSconfig
*|-- adenum.sh
*|-- install.sh
*|-- prep.sh
*|-- rainbow.sh
*|-- resources
*|   |-- resources/template.sh
*|   `-- resources/treemaker.sh
*`-- restartNM.sh
```

## License
ADBasher is released under the [Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0)](https://creativecommons.org/licenses/by-nc/4.0/).
