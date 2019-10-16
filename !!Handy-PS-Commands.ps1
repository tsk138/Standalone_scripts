# VSS - search event logs
Get-EventLog -LogName Application -Source vss -Newest 4 | fl *
Get-WinEvent -LogName Microsoft-Windows-Hyper-V-VMMS-Admin -MaxEvents 4 | fl *
#
# list VssWriters to CSV
$Computers = Get-Content ".\MyComputerList.txt"
$VssWriters = Get-VssWriters $Computers -Verbose | 
    Where { $_.StateDesc -ne 'Stable' } | Sort "ComputerName" 
$VssWriters | Out-GridView # Displays it in GridView
$VssWriters | Export-CSV ".\myReport.csv" -NoTypeInformation # Exports it to CSV
#



Get-Snapshot * | Select-Object -Property VM, Name, Created, @{n="SizeGB"; e={[math]::Round($_.sizegb,2)}}, Children | Sort-Object -Property Created -Descending | ft -AutoSize    

Get-VM | Get-Snapshot | select vm,name,description,created, @{n="SizeGB"; e={[math]::Round($_.sizegb,2)}} | ft -autosize

Get-ClusterNode | foreach { Get-VM -ComputerName $_.Name } | Get-VMHardDiskDrive | Select VMName,Path

Get-ClusterGroup -Cluster <CLUSTER> | Where-Object {$_.GroupType –eq 'VirtualMachine' } | Get-VM | Get-VMHardDiskDrive | Select VMName,Path    

cat file -wait -tail 5
Get-Content C:\logs\logfile.txt -Tail 2 -Wait

Enter-PSSession -ComputerName <X> -Credential $C

Get-EventLog -LogName Application -Newest 100 | ? EntryType -in "Critical","Error" | Out-GridView

tnc 127.0.0.1 -p 443

Set-NetFirewallProfile -Name 'Public', 'Private', 'Domain' -Enabled "False"

Get-Aduser <samname> -properties *

Get-process | Out-Gridview

Reset-ComputerMachinePassword -credential DomainAdminAccount

Search-ADAccount -lockedout


get-hotfix -computername nameofbox -id kbXXXXXXX


[System.Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String("QQBsAGwAIAB5AG8AdQAgAGIAYQBzAGUAIABhAHIAZQAgAGIAZQBsAG8AbgBnACAAdABvACAAdQBzACEA"))


icm -cn "server1","server2" -Command {gpupdate /target:computer}



# Get just the VSS writers' status, more compactly.
vssadmin list writers | select-string "Writer name", "State", "Last error"

# Get external IP from command line. Thanks, opendns!
nslookup myip.opendns.com. resolver1.opendns.com

# Send wake-on-lan packet. Well, technically it's one line.
[Byte[]]$MagicPacket = (,0xFF * 6) + (((Read-Host -Prompt "MAC") -split "[:-]" | Foreach-Object { [Byte] "0x$_"}) * 16); $UdpClient = New-Object System.Net.Sockets.UdpClient; $UdpClient.Connect(([System.Net.IPAddress]::Broadcast),7); $UdpClient.Send($MagicPacket,$MagicPacket.Length); $UdpClient.Close()

# Not one line but super useful: as an administrator, take ownernship and NON-DESTRUCTIVELY grant your user full permissions. Leaves existing perms intact!
takeown /r /d n /f .
icacls . /grant $env:username`:`(F`) /t /c
takeown /r /d n /f *.*
icacls *.* /grant $env:username`:`(F`) /t /c

# Get uptime. If Cim doesn't work, use WMI. Leave out -ComputerName for local system.
Get-CimInstance -ComputerName $c -ClassName win32_operatingsystem | select csname, lastbootuptime
Get-WmiObject -Computername $c win32_operatingsystem | select csname, @{LABEL=’LastBootUpTime’;EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}
permalink embedsave report



--------------netdom equiv check

Test-Connection = (Get-ADDomainController -Filter *)

OR

Test-Connection (Get-ADDomain).ReplicaDirectoryServers

-----------------Get-Process
invoke-command -ComputerName Win2012r2 -ScriptBlock {param($procName) Get-Process -Name $processName} -ArgumentList $ProcName

-------Function Get-Uptime {
Param ( [string] $ComputerName = $env:COMPUTERNAME )
$os = Get-WmiObject win32_operatingsystem -ComputerName $ComputerName -ErrorAction SilentlyContinue
if ($os.LastBootUpTime) {
$uptime = (Get-Date) - $os.ConvertToDateTime($os.LastBootUpTime)
Write-Output ("$Computer Uptime : " + $uptime.Days + " Days " + $uptime.Hours + " Hours " + $uptime.Minutes + " Minutes" )
}
else {
Write-Warning "Unable to connect to $computername"
}
}
$computers = get-content c:\scripts\6july.txt
foreach ($computer in $computers)
{Get-Uptime -ComputerName $computer}

-------------Get-ADComputer ALL PROPERTIES
Get-ADComputer -Filter * -SearchBase "OU=Computers,DC=contoso,DC=com" -Properties Name,LastLogonDate,OperatingSystem,OperatingSystemServicePack,whenCreated | Select-Object Name,LastLogonDate,OperatingSystem,OperatingSystemServicePack,whenCreated | Export-Csv c:\temp\Computers.csv -NoTypeInformation


----------AllServer.csv
Get-ADComputer -Filter * -Property * | Select-Object Name,OperatingSystem,OperatingSystemServicePack,OperatingSystemVersion | Export-CSV AllWindows.csv -NoTypeInformation -Encoding UTF8

#-----Get all Pc's
Get-ADComputer -Properties * | Select-Object CanonicalName, CN,Created,Enabled,IPv4Address,DNSHostName,DistinguishedName,LastLogonDate,OperatingSystem,OperatingSystemServicePack,OperatingSystemVersion,Location,DNSHostName,Description

--------------Mailbox sizes Office 365

connect to msonline posh: 

Get-Mailbox -ResultSize Unlimited | Get-MailboxStatistics | ft DisplayName,TotalItem

---------------Powercli Check for invalid of inaccessible VMs:
Get-View -ViewType VirtualMachine | Where {-not $_.Config.Template} | Where{$_.Runtime.ConnectionState -eq “invalid” -or $_.Runtime.ConnectionState -eq “inaccessible”} | Select Name

VMs with more than 2 vCPUs:
Get-VM | Where {$_.NumCPU -gt 2} | Select Name, NumCPU
Check for invalid of inaccessible VMs:
Get-View -ViewType VirtualMachine | Where {-not $_.Config.Template} | Where{$_.Runtime.ConnectionState -eq “invalid” -or $_.Runtime.ConnectionState -eq “inaccessible”} | Select Name
Get Errors in the last week:
Get-VIEvent -maxsamples 10000 -Type Error -Start $date.AddDays(-7) | Select createdTime, fullFormattedMessage
Get VMs with Memory Reservations:
Get-VM | Get-VMResourceConfiguration | Where {$_.MemReservationMB -ne 0} | Select VM,MemReservationMB
Get VMs with CPU Reservations:
Get-VM | Get-VMResourceConfiguration | Where {$_.CpuReservationMhz -ne 0} | Select VM,CpuReservationMhz
Delete all Snapshots with Certain Name:
Get-VM | Sort Name | Get-Snapshot | Where { $_.Name.Contains(“Consolid

---------------Windows Dedup
Check stats: Get-DedupStatus | FL

UnOptimise: start-dedupjob -Volume <VolumeLetter> -Type Unoptimization

Check the status: get-dedupjob

Clean up the Garbage: start-dedupjob -Volume <VolumeLetter> -Type GarbageCollection

Check the status: get-dedupjob

-------------------------Find all locked files

IF((Test-Path -Path $FileOrFolderPath) -eq $false) {
Write-Warning "File or directory does not exist." 
}
Else {
$LockingProcess = CMD /C "openfiles /query /fo table | find /I ""$FileOrFolderPath"""
Write-Host $LockingProcess
}

#------------------Veeam get all VM's in jobs with 'blah' in name

asnp VeeamPSSnapin
$JobList = Get-VBRJob | ?{$_.Name -match "blah"}
foreach($Jobobject in $JobList)
{$Objects = $JobObject.GetObjectsInJob()
$Objects.name}

-------------- kill remote rds sessions 
qwinsta
rwinsta /SERVER:mywebserver ID


---------------------Test Exchange Mail Flow

Get-TransportServer | Get-Queue | Get-Message -ResultSize unlimited | where{$_.Subject -eq "Status Request" -and $_.Queue -notlike "*\Submission*"} | Suspend-Message

Get-TransportServer | Get-Queue | Get-Message -ResultSize unlimited | where {$_.Subject -eq "Status Request"} | Suspend-Message

This command removes messages that have the string "Friday Party" in the message subject in all queues on Hub Transport servers:

Get-TransportServer | Get-Queue | Get-Message -ResultSize unlimited | Where {$_.Subject -eq "Status Request"} | Remove-Message -WithNDR $False

RemoveReplicaFromPFRecursive.ps1 –Server EXCH01
–TopPublicFolder \ –ServerToRemove EXCH02

Get-ReceiveConnector "Unauthenticated" | Add-ADPermission -User "NT AUTHORITY\ANONYMOUS LOGON" -ExtendedRights "Ms-Exch-SMTP-Accept-Any-Recipient"

New-ReceiveConnector -Name "Anonymous Relay" -Usage Custom -AuthMechanism ExternalAuthoritative -PermissionGroups ExchangeServers -Bindings 10.2.3.4:25 -RemoteIpRanges 192.168.5.77


--------------------------MIgrate scripts

Move-OfflineAddressBook -Identity "My OAB" -Server SERVER01

Offline Address Book: Set-OABVirtualDirectory <CAS2010>\OAB* -ExternalURL https://mail.contoso.com/OAB
Web Services: Set-WebServicesVirtualDirectory <CAS2010>\EWS* -ExternalURL https://mail.contoso.com/ews/exchange.asmx
Exchange ActiveSync: Set-ActiveSyncVirtualDirectory -Identity <CAS2010>\Microsoft-Server-ActiveSync -ExternalURL https://mail.contoso.com
Outlook Web App: Set-OWAVirtualDirectory <CAS2010>\OWA* -ExternalURL https://mail.contoso.com/OWA
Exchange Control Panel: Set-ECPVirtualDirectory <CAS2010>\ECP* -ExternalURL https://mail.contoso.com/ECP

.\MoveAllReplicas.ps1 -Server Server01 -NewServer Server02
