#Resources for Incident Response: Detection and Analysis
#Pluralsight Course: https://app.pluralsight.com/library/courses/incident-response-detection-analysis/table-of-contents

# WinPmem Download Location:
# https://github.com/Velocidex/WinPmem

# Sysinternals Sutie
# https://docs.microsoft.com/en-us/sysinternals/

# Rawcap
# https://www.netresec.com/?page=RawCap

# Remember to decide on the timezone you are using for normalization of actions, logs, and records

# Have to store things somewhere, ideally this is all launched from and recorded to your external media.
## Computer name as folder
$name = $env:computername
$domain = $env:USERDOMAIN
$datapath = "$name-$domain"
new-item -Name $datapath -Path . -ItemType directory

## Start the timer, and record your actions.
function captains_log($entry, $datapath){
    $datetime = Get-Date 
    $timezone = (Get-TimeZone).DisplayName
    $stardate = "Captains Log Entry, Startdate: $datetime $timezone \n"
    $stardate| out-file -Append -FilePath ./$datapath/master-station-log.txt
    $entry | out-file -Append -FilePath ./$datapath/master-station-log.txt
    write-host "Captains log entry complete." -ForegroundColor Green
}


#creates master station log to record all your actions
get-date >> ./$datapath/master-station-log.txt
Get-TimeZone >> ./$datapath/master-station-log.txt
Get-NetIPInterface >> $datapath/master-station-log.txt
Get-NetIPAddress >> $datapath/master-station-log.txt
#records all your activity
start-transcript -Path ./$datapath/powershelltranscript.txt -Append
psr
get-computerinfo
wmic OS get OSArchitecture



## Memory Dump - Do a quick memory pull we will look more at this later.
./winpmem_mini_x64_rc2.exe $datapath/$computername-memorydump.dmp 
captains_log "Took full memory image." $datapath


## Get file hash & Time Stamp of Ransome note.
captains_log "Desktop has ransom note file, grabbing properties and hash as potential IOC" $datapath
$note_file_details = get-itemproperty -Path c:\Users\Administrator\Desktop\theinvincibleironcat.txt; $note_file_details
$note_file_details | out-file -Filepath $datapath/IOC-ransom-note.txt -append
$filehash = get-filehash -Algorithm md5 -Path C:\Users\Administrator\Desktop\theinvincibleironcat.txt; $filehash
$filehash | out-file -Filepath $datapath/IOC-ransom-note.txt -append
copy-item -Path c:\Users\Administrator\Desktop\theinvincibleironcat.txt  $datapath
### Take a guess here to scope and look for this file name/hash throughout the file system.
get-childitem c:\ -filter *theinvincibleironcat* #this version hits the user folder.
captains_log "IOC - Found ransom notes in all affected directories with the same name and hash only in c:\Users\*. This can be used to look for this acitivity acrosss the enterprise for scoping." $datapath

#Logs Check
get-winevent 

#volume shadowcopy check
vssadmin list shadows


## Dump network connection
##net connections but then use tcpview and portmon to properly catch beaconing
captains_log "Running network inspection to look for expected network beaconing behavior related to popup." $datapath
$netConn = get-nettcpconnection; $netConn
netstat -anob
$netconn | export-clixml -Path $datapath/netconn.xml
$netconn | out-file -FilePath $datapath/netconn.txt
### May or may not catch connection information.
## tcpview & portmon
./SysInternalsSuite/tcpvcon64.exe -a /accepteula


# Identify network activity to resolved hello.iamironcat.com & find process

# Dump and Analyze Process Information
$procs = Get-Process; $procs #find process name to use as IOC
$procs |out-file -path $datapath/processes.txt
#WMIC get specific process information based on PID found in get-process info.
wmic process list full /format:htable >> $datapath/process.html
./SysInternalsSuite/procexp64.exe -accepteula
#Procexp process explorer to inspect this process and understand its tcp activity!

#tcpview
./SysInternalsSuite/tcpview64.exe
## browse to domain & ip
stop-transcript



#DEMO: Use IOC's to find other devices.

## Asset list from ARP table, layer 2
## Asset list from Active Directory Pull 
#Get-adcomputers -filter *

foreach ($c in $computers) {
    get-childitem -Path #if note file ending in ENCRYPTED or HASH matches
    Get-Process #if process like ironcatwuzhere
    get-nettcpconnection #if port like 8080 but doesn't come back in line with the other behavior!
}



#Module: Host Collection

## Now you have more time to collect a Triage Image --> this is not the full disk image.
systeminfo

## DNS Cache
$dnsCache = Get-DnsClientCache
$dnsCache
$dnsCache  | Export-Clixml -Path $datapath/dnscache.xml
$dnsCache | out-file $datapath/dnscache.txt
### Host File

## ARP Cache
$arpCache  = Get-NetNeighbor | select *
$arpCache
$arpCache  | Export-Clixml -Path $datapath/arpcache.xml
$arpCache | out-file $datapath/arpcache.txt

#routing profile
$routeTable = Get-NetRoute
$routeTable 
$routeTable | Export-Clixml -Path $datapath/routetable.xml
$routeTable | out-file $datapath/routetable.txt

#Firewall rules

# Getting user information on local devices, different from commands used for identifying domain users.
net user
lusrmgr
net local group administrators
net group administrators


./SysInternalsSuite/psloggedon64.exe -accepteula
./SysInternalsSuite/loggedonsessions.exe -accepteula

# Looking for all AD users and associated readable information
get-adusers -filter "surname -like '*'"

# You can do the same for computers
get-adcomputers -filter "name -like '*'"

#Attached 
net use


#services
sc query # remember this needs to be ran with "cmd /c" or in a command terminal

wmic service list config

#autoruns
./SysInternalsSuite/autoruns64.exe

#scheduled tasks
schtasks

#disk information
./SysInternalsSuite/volumeid64.exe
./SysInternalsSuite/diskmon.exe
./SysInternalsSuite/ntfsinfo.exe
./SysInternalsSuite/DiskView.exe

#additonal process info
./SysInternalsSuite/listdll.exe
./SysInternalsSuite/handle.exe


#event logs
wevutil qe security /f:text

#logs

new-item -type directory winevent_logs

copy-item -Recurse -path C:\Windows\System32\Winevt\Logs\ -Destination ./winevent_logs

copy-item -recurse -path C:\Windows\System32\LogFiles\ -Destination ./winevent_logs

#full disk image
## Live boot and use dd

#Module: Network Collection
#Demo: Network Collection 
## Windows Victim Network Connection & Wireshark Analysis
## https://www.netresec.com/?page=rawcap
 rawpcap.exe $datapath/$computername-init-pcap.pcap # doesn't require install of separate dll
 captains_log "Initial dump of 1 Minute of Packet Capture Created"


## Targeted Network Collection: HTTP Traffic just to hello.iamironcat.com & 

## Transfer Network Information
scp 


## Surricata Analysis with Current Threats
suricata

##Inbound http traffic to the specified ports would indicate .....attacker activity!
zeek -r pcap
## Inspect logs with zeek cut conn log specifically
zeekcut




