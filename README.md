# UmbrellaTelescope

Telescope is offensive, it will record all the access from its controlled internal network   
Except you really want to do it, otherwise you don't need it   

Telescope will record every access to target IP from internal security controlled network external access with timestamp   
within database, also access domain name will be recorded    

# Traffic Monitor System    

## Logging all traffic to Database     
  1. FreeBSD router configuration with log NATed traffic    
  2. FreeBSD syslog-ng call this python script to log all outgoing traffic to databases    
  3. Need another nat_monitor to record access to a faster data structure than direct to mysql database

## NAT_Monitoring done
  1. with some proper analysis and other data it shall able to capture out the periodic transmission

## Logging all Builtin Service    
  1. iscsi/Samba access    
  2. management access   
        detailed to uri   


### traffic_monitor.py    
Called by syslog-ng to direct push access to SQL database



## UmbrellaTelescope is mainly the middle of the Defense in Depth  
   1. it analysis the internal security controlled network behavior   
   2. records int -> ext traffic  
   3. lockdown internal devices, close limited configured devices ext network access behavior   

