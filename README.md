# UmbrellaTelescope

WARNING: 

Telescope is offensive, it will record all accesses from its controlled internal network   
Except you really want to do it, otherwise you don't need it   

## Traffic Monitor System    
```
/etc/syslog-ng.conf

add below contents to syslog configuration


source s_net {
    network(ip(192.168.*.*) port(514)); # Replace the IP address which receive the traffic from router
};


destination d_security { 
  python(
    class(traffic_monitor.AuditorDestination) 
    options(debug False)
  ); 
};

```
and put traffic_monitor.py to the folder /etc/syslog-ng/python/    


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

## Umbrella Telescop Audit   

Telescope will record all the access from IP protocol port level from internal to external access require to have    
NAT translate    
```
nat_out_dst_ips:
| ?.?.?.?/32  | 42761 | 132312 | datetime | UDP      |
| ?.?.?.?/32  | 37894 | 132313 | datetime | UDP      |


outgoing_target_ips:
| ? | ?.?.?.?   | 45179 |         | datetime | UDP   | 192.168.10.?      | mac_address |
| ? | ?.?.?.?   | 50015 |         | datetime | UDP   | 192.168.10.?      | mac_address |

```

Telescope will record all the access to Main Router   
```
controller_ssh_service:
| 383 | b0:68:e6:9c:?:? | 192.168.10.? | Alex's Desktop | 2023-?-? 20:47:48 |
| 384 | b0:68:e6:9c:?:? | 192.168.10.? | Alex's Desktop | 2023-?-? 19:05:10 |
| 385 | b0:68:e6:9c:?:? | 192.168.10.? | Alex's Desktop | 2023-?-? 11:44:44 |

also vnc, iscsi, smb, ....
```

## Umbrella Telescope Monitor  (ongoing work)  
When there is new device connected to Umbrella Controlled network (ARP/ND detection)
the device will automatically added to monitoring list for close check its access   

tele_cli.py can support different types of command:
```
{

    "result": "success",

    "devices": {

        "192.168.10.?": {

            "status": "monitoring",

            "mac_addr": "d4:da:?:?:?:?",

            "device": "Unknown"

        }

    }

}

and its access details:    
{

    "result": "success",

    "details": {

        "basic_info": {

            "source_ip": "192.168.10.?",

            "mac_addr": "d4:da:21:?:?:?",

            "device_name": "Unknown",

            "strict_mode": true

        },

        "udp_details": [],

        "tcp_details": [

            {

                "?.?.?.?": [

                    {

                        "80": 32

                    }

                ]

            },

            {

                "?.?.?.?": [

                    {

                        "80": 8

                    }

                ]

            }

        ],

        "lookup_details": [

            {

                "?.?.com.": 9292

            },

            {

                "?.?.com.m.?.com.": 1432

            }

        ],

        "direct_udp_access": [],

        "direct_tcp_access": [  # No DNS lookup direct access IP

            {

                "?.?.?.?": [

                    {

                        "port": "1884",

                        "count": 2182

                    }

                ]

            }
        ]

    }

}

it also support redeye dump, when there is no device connected, it will close updates idle time connected device to strict monitoring mode    

```



![Donate](./DONATE.JPG)
![Donate](./DONATE_Z.JPG)
