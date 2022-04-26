# Incident-Response-Resources
A store of resources associated with the Pluralsight Incident Response Path that can be used for general incident response capabilities.  All general IR capabilities developed by PS will be contained here even if they are not referenced in the courses.

## Initial Triage

Initial-Triage contains a powershell script(meant to be used as a guide not fully automated) that walks throuhg initial triage and live resopnse actions on a device that you suspect has been compromised. Collecting data and information that can be used for initial scoping and analysis as well as preserving larger amounts of data like the memeory capture for later deeper analysis.

## Automated First Responder Script

The existing initial triage script that supports this course was not able to be ran on a given machine automatically and had more Sysinternal executables than you really needed. Build on that, I created a Powershell script you CAN run from the command line as admin, and it will automatically collect the information required for an incident responder first analysis. This is release v1, so feel free to create issues :).

You can find it here: [First Responder Scripted](./first-responder-scripted)

The process for this goes like this:
1) Copy the zipped first-responder-scripted folder to potentially compromised machine. (64bit Windows)
2) Unzip the folder on the target machine.
3) Open an Administratrive powershell prompt and change directory to the unzipped first-responder-srcipted folder.
4) Run the script ./Run-Initial-Triage.ps1 and follow the prompts.

> If you run into execution issues, use ```set-executionpolicy 0``` execute, but remember to set the execution policy back to the restricted state. Set-Executionpolicy RemoteSigned

## Zeek Scripts

This directory contains useful scripts for network analysis with Zeek.

file-extract.zeek
- Filters for port 445 and performs MD5 hashing and extraction for all files seen

dnsentropy.zeek
- Calculates an entropy score for all DNS queries made and alerts on high-values

---

Happy Hunting!