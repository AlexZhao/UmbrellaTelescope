# UmbrellaTelescope    

[English](README.md) | 简体中文    


## 网络访问审计系统        
```
修改 /etc/syslog-ng.conf， 使能syslog-ng接收FreeBSD路由器的防火墙日志    

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
添加 traffic_monitor.py 到目录 /etc/syslog-ng/python/    
traffic_monitor.py会被syslog-ng调用，记录经过NAT的连接到数据库    

## 记录内网中所有的访问数据到数据库        
   1. 通过网络访问行为来识别内网中被恶意软件感染的设备    
   2. 识别C2C通信     

## 记录系统中的服务访问         
   1. iSCSI/SMB文件共享服务访问       
   2. 路由器管理界面访问       

## Umbrella望远镜 纵深网络防御的中圈      
   1. 望远镜记录内网中所有设备的访问网络行为      
   2. 记录从内部向外部的网络访问         
   3. 控制网络中的IoT设备网络访问    

## Umbrella Telescope 自动Monitor网络接入     


Author: Zhao Zhe (Alex)

![Donate](./DONATE.JPG)
![Donate](./DONATE_Z.JPG)
