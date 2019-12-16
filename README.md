# AwesomeReconDetectionStrings
Lists of exes launched from CMD commonly associated with noisy attacker recon from compromised devices:

arp.exe
at.exe
ceipdata.exe
ceiprole.exe
chcp.exe
compmgmtlauncher.exe
csvde.exe
dsadd.exe
dsget.exe
dsquery.exe
esentutl.exe
eventvwr.msc
for.exe
fsutil.exe
hostname.exe
inver.exe
ldifde.exe
lusrmgr.msc
mofcomp.exe
mshta.exe
netdom.exe
nltest.exe
psexec.exe
qprocess.exe
query.exe
quser.exe
qwinsta.exe
restart.exe
sc.exe
scrcons.exe
secpol.msc
servermanagercmd.exe
services.msc
set.exe
taskmgr.exe
time.exe
tracert.exe
tree.exe
vds.exe
vdsldr.exe
ver.exe
vssadmin.exe
wevtutil.exe
wget.exe
whoami.exe
WinrsHost.exe
wsmprovhost.exe
wusa.exe

//----------SPLUNK VERSION-With Freqency of Occurence---------//

sourcetype="WinEventLog:Security" index=coe_* EventCode=4688 Creator_Process_Name="C:\\Windows\\System32\\cmd.exe"
New_Process_Name="C:\\*\\arp.exe" OR
New_Process_Name="C:\\*\\at.exe" OR
New_Process_Name="C:\\*\\ceipdata.exe" OR
New_Process_Name="C:\\*\\ceiprole.exe" OR
New_Process_Name="C:\\*\\chcp.exe" OR
New_Process_Name="C:\\*\\compmgmtlauncher.exe" OR
New_Process_Name="C:\\*\\csvde.exe" OR
New_Process_Name="C:\\*\\dsadd.exe" OR
New_Process_Name="C:\\*\\dsget.exe" OR
New_Process_Name="C:\\*\\dsquery.exe" OR
New_Process_Name="C:\\*\\esentutl.exe" OR
New_Process_Name="C:\\*\\mshta.exe" OR
New_Process_Name="C:\\*\\eventvwr.msc" OR
New_Process_Name="C:\\*\\for.exe" OR
New_Process_Name="C:\\*\\fsutil.exe" OR
New_Process_Name="C:\\*\\hostname.exe" OR
New_Process_Name="C:\\*\\inver.exe" OR
New_Process_Name="C:\\*\\ldifde.exe" OR
New_Process_Name="C:\\*\\mofcomp.exe" OR
New_Process_Name="C:\\*\\wsmprovhost.exe" OR
New_Process_Name="C:\\*\\scrcons.exe" OR
New_Process_Name="C:\\*\\lusrmgr.msc" OR
New_Process_Name="C:\\*\\netdom.exe" OR
New_Process_Name="C:\\*\\nltest.exe" OR
New_Process_Name="C:\\*\\psexec.exe" OR
New_Process_Name="C:\\*\\qprocess.exe" OR
New_Process_Name="C:\\*\\query.exe" OR
New_Process_Name="C:\\*\\quser.exe" OR
New_Process_Name="C:\\*\\qwinsta.exe" OR
New_Process_Name="C:\\*\\restart.exe" OR
New_Process_Name="C:\\*\\sc.exe" OR
New_Process_Name="C:\\*\\secpol.msc" OR
New_Process_Name="C:\\*\\servermanagercmd.exe" OR
New_Process_Name="C:\\*\\services.msc" OR
New_Process_Name="C:\\*\\set.exe" OR
New_Process_Name="C:\\*\\taskmgr.exe" OR
New_Process_Name="C:\\*\\time.exe" OR
New_Process_Name="C:\\*\\tracert.exe" OR
New_Process_Name="C:\\*\\tree.exe" OR
New_Process_Name="C:\\*\\vds.exe" OR
New_Process_Name="C:\\*\\vdsldr.exe" OR
New_Process_Name="C:\\*\\ver.exe" OR
New_Process_Name="C:\\*\\vssadmin.exe" OR
New_Process_Name="C:\\*\\wevtutil.exe" OR
New_Process_Name="C:\\*\\wget.exe" OR
New_Process_Name="C:\\*\\whoami.exe" OR
New_Process_Name="C:\\*\\WinrsHost.exe" OR
New_Process_Name="C:\\*\\wusa.exe"

|STATS dc(New_Process_Name)  as uProc values(New_Process_Name) as ProcName values(Process_Command_Line) as CmdLine count by host | SEARCH uProc>3


