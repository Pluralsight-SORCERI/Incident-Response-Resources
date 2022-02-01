#IRONCAT - 2-1-2022
#Pluralsight Course: https://app.pluralsight.com/library/courses/incident-response-detection-analysis/table-of-contents

# WinPmem Download Location:
# https://github.com/Velocidex/WinPmem

# Sysinternals Sutie
# https://docs.microsoft.com/en-us/sysinternals/

# Rawcap
# https://www.netresec.com/?page=RawCap

# Remember to decide on the timezone you are using for normalization of actions, logs, and records
Write-host -ForegroundColor yellow "!!!Ensure you have changed your active directory to the folder containing this script befor you run, or many of the capabilities will not work!!!"
Write-host -ForegroundColor yellow "+++Ensure you are running this from an administrative Terminal+++"

Read-host "If both of the items above are true, press `"ENTER`" otherwise, `"Ctrl+C`""

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
get-computerinfo
wmic OS get OSArchitecture

## Memory Dump - Do a quick memory pull we will look more at this later.
./winpmem_mini_x64_rc2.exe $datapath/$computername-memorydump.dmp 
captains_log "Took full memory image." $datapath


## Get file hash & Time Stamp of Ransome note.
<# captains_log "Desktop has ransom note file, grabbing properties and hash as potential IOC" $datapath
$note_file_details = get-itemproperty -Path c:\Users\Administrator\Desktop\theinvincibleironcat.txt; $note_file_details
$note_file_details | out-file -Filepath $datapath/IOC-ransom-note.txt -append
$filehash = get-filehash -Algorithm md5 -Path C:\Users\Administrator\Desktop\theinvincibleironcat.txt; $filehash
$filehash | out-file -Filepath $datapath/IOC-ransom-note.txt -append
copy-item -Path c:\Users\Administrator\Desktop\theinvincibleironcat.txt  $datapath
### Take a guess here to scope and look for this file name/hash throughout the file system.
get-childitem c:\ -filter *theinvincibleironcat* #this version hits the user folder.
captains_log "IOC - Found ransom notes in all affected directories with the same name and hash only in c:\Users\*. This can be used to look for this acitivity acrosss the enterprise for scoping." $datapath
#>
#Logs Check

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
./SysInternalsSuite/tcpvcon64.exe -a /accepteula >> $datapath/tcpcon.txt

# Identify network activity to resolved hello.iamironcat.com & find process

# Dump and Analyze Process Information
$procs = Get-Process; $procs #find process name to use as IOC
$procs |out-file -path $datapath/processes.txt
#WMIC get specific process information based on PID found in get-process info.
wmic process list full /format:htable >> $datapath/process.html


## Asset list from ARP table, layer 2
## Asset list from Active Directory Pull 




#Module: Host Collection

## Now you have more time to collect a Triage Image --> this is not the full disk image.
systeminfo >> $datapath/systeminfo.txt

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
$fwrules = get-netfirewallrule
$fwrules | Export-Clixml -Path $datapath/localfwrules.xml
$fwrules | Export-Clixml $datapath/localfwrules.txt
# Getting user information on local devices, different from commands used for identifying domain users.
net user >> $datapath/netusers.txt
net us >> $datapath/netusedrives.txt

./SysInternalsSuite/psloggedon64.exe -accepteula >> $datapath/psloggedon.txt
./SysInternalsSuite/logonsessions64.exe -accepteula >> $datapath/logonsessions.txt




#services
cmd /c sc query >> $datapath/scservices.txt # remember this needs to be ran with "cmd /c" or in a command terminal

wmic service list config >> $datapath/wmicservices.txt

#autoruns
./SysInternalsSuite/autoruns64.exe -e -a $datapath/autoruns.arn

#scheduled tasks
schtasks >> $datapath/scheduledtasks.txt

#disk information
./SysInternalsSuite/ntfsinfo64.exe -accepteula c >> $datapath/nftscdrive.txt
./SysInternalsSuite/ntfsinfo64.exe -accepteula e >> $datapaht/nftsedrive.txt

#additonal process info
./SysInternalsSuite/listdll.exe >> $datapath/listdll.txt
./SysInternalsSuite/handle.exe >> $datapath/handles.txt


#event logs
cmd /c wevtutil qe security /f:text >> $datapath/currentseclogs.txt

#logs
new-item -type directory $datapath/winevent_logs

copy-item -Recurse -path C:\Windows\System32\Winevt\Logs\ -Destination $datapath/winevent_logs

copy-item -recurse -path C:\Windows\System32\LogFiles\ -Destination $datapath/winevent_logs

#add if IIS is needed
new-item -type directory $datapath/inetpub
copy-item -recurse -path c:\inetpub\  -Destination $datapath/inetpub
#uniq remove later
new-item -type directory $datapath/lcso-sitefinity
copy-item -recurse E:\Website_files\LCSOweb\ -Destination $datapath/lcso-sitefinity
stop-transcript
#Module: Network Collection
#Demo: Network Collection 
## Windows Victim Network Connection & Wireshark Analysis
## https://www.netresec.com/?page=rawcap
Write-host -foregroundcolor "Almost done!  Now this requires a bit of interaction.  A new window will launch and ask you to enter the number of the interface assocaited with the external IP address. Then create a name that ends in `".pcap`" and press enter. It will now start capturing packets. Let it run for 5 minutes and then Ctrl+c to stop it.  Once it is done.  Zip up the whole first-responser-scripted folder and send it prep it for transport."

 rawpcap.exe  # doesn't require install of separate dll
 captains_log "Initial dump of 5 Minute of Packet Capture Created"







