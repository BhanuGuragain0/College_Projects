# Cisco Packet Tracer Configuration Commands

This document provides a comprehensive, step-by-step guide to configuring the network devices in Cisco Packet Tracer, based on the network design outlined in the coursework. The commands are organized by device and then by configuration type, ensuring a logical and easy-to-follow process. This includes initial device setup, IP addressing, VLANs, routing protocols, Layer 2 technologies, security features, and service configurations.

**Note:** Replace placeholder values (e.g., `<BranchB_Router_Public_IP>`) with your specific network details. Interface names (e.g., GigabitEthernet0/1, FastEthernet0/1) should match your Packet Tracer topology.

## Global Configurations (All Devices)

These commands are common to most Cisco devices for basic setup.

```
enable
configure terminal
hostname <DEVICE_NAME>
no ip domain lookup
line con 0
 logging synchronous
 exec-timeout 0 0
 password console_pass
 login
line vty 0 4
 logging synchronous
 exec-timeout 0 0
 password vty_pass
 login
transport input ssh telnet
service password-encryption
!
```

## Router Configurations

### Router: Core-Router-1 (AS-10 in diagram)

**Interface IP Addressing:**

```
interface GigabitEthernet0/0
 ip address 100.0.0.1 255.255.255.252
 no shutdown
!
interface GigabitEthernet0/1
 ip address 11.0.0.1 255.255.255.252
 no shutdown
!
interface Serial0/0/0
 ip address 200.0.0.1 255.255.255.252
 clock rate 128000
 no shutdown
!
interface Serial0/0/1
 ip address 200.1.0.1 255.255.255.252
 clock rate 128000
 no shutdown
!
```

**OSPF Configuration:**

```
router ospf 1
 router-id 1.1.1.1
 network 100.0.0.0 0.0.0.3 area 0
 network 11.0.0.0 0.0.0.3 area 0
 network 200.0.0.0 0.0.0.3 area 0
 network 200.1.0.0 0.0.0.3 area 0
 passive-interface default
 no passive-interface GigabitEthernet0/0
 no passive-interface GigabitEthernet0/1
 no passive-interface Serial0/0/0
 no passive-interface Serial0/0/1
!
```

**Static Route (Example for Internet Gateway):**

```
ip route 0.0.0.0 0.0.0.0 203.0.113.1
!
```

**Syslog Configuration:**

```
logging host 192.168.60.100
logging trap informational
logging source-interface Loopback0
!
```

**SNMP Configuration:**

```
snmp-server community public RO
snmp-server community private RW
snmp-server host 192.168.60.101 traps version 2c public
snmp-server enable traps snmp authentication linkup linkdown
!
```

### Router: Core-Router-2 (AS-20 in diagram)

**Interface IP Addressing:**

```
interface GigabitEthernet0/0
 ip address 100.1.0.2 255.255.255.252
 no shutdown
!
interface GigabitEthernet0/1
 ip address 11.1.0.2 255.255.255.252
 no shutdown
!
interface Serial0/0/0
 ip address 200.0.0.2 255.255.255.252
 clock rate 128000
 no shutdown
!
interface Serial0/0/1
 ip address 200.1.0.2 255.255.255.252
 clock rate 128000
 no shutdown
!
```

**OSPF Configuration:**

```
router ospf 1
 router-id 2.2.2.2
 network 100.1.0.0 0.0.0.3 area 0
 network 11.1.0.0 0.0.0.3 area 0
 network 200.0.0.0 0.0.0.3 area 0
 network 200.1.0.0 0.0.0.3 area 0
 passive-interface default
 no passive-interface GigabitEthernet0/0
 no passive-interface GigabitEthernet0/1
 no passive-interface Serial0/0/0
 no passive-interface Serial0/0/1
!
```

**Static Route (Example for Internet Gateway):**

```
ip route 0.0.0.0 0.0.0.0 203.0.113.1
!
```

**Syslog Configuration:**

```
logging host 192.168.60.100
logging trap informational
logging source-interface Loopback0
!
```

**SNMP Configuration:**

```
snmp-server community public RO
snmp-server community private RW
snmp-server host 192.168.60.101 traps version 2c public
snmp-server enable traps snmp authentication linkup linkdown
!
```

### Router: Branch-Router (AS-30 in diagram)

**Interface IP Addressing:**

```
interface GigabitEthernet0/0
 ip address 200.200.100.1 255.255.255.252
 no shutdown
!
interface GigabitEthernet0/1
 ip address 200.200.200.1 255.255.255.252
 no shutdown
!
interface FastEthernet0/0
 ip address 12.0.0.1 255.255.255.0
 no shutdown
!
```

**OSPF Configuration:**

```
router ospf 1
 router-id 3.3.3.3
 network 200.200.100.0 0.0.0.3 area 0
 network 200.200.200.0 0.0.0.3 area 0
 network 12.0.0.0 0.0.0.255 area 0
 passive-interface default
 no passive-interface GigabitEthernet0/0
 no passive-interface GigabitEthernet0/1
 no passive-interface FastEthernet0/0
!
```

**Site-to-Site IPsec VPN Configuration (Branch-Router to Core-Router-1/2 - assuming one tunnel for simplicity):**

```
// Define Interesting Traffic
ip access-list extended VPN_TRAFFIC_BRANCH
 permit ip 12.0.0.0 0.0.0.255 192.168.60.0 0.0.0.255
 permit ip 12.0.0.0 0.0.0.255 192.168.61.0 0.0.0.255
 permit ip 12.0.0.0 0.0.0.255 192.168.62.0 0.0.0.255
 permit ip 12.0.0.0 0.0.0.255 192.168.63.0 0.0.0.255
!

// Configure IKE Phase 1 Policy
crypto isakmp policy 10
 encryption aes 256
 authentication pre-share
 group 5
 lifetime 86400
 hash sha
!

// Configure IKE Phase 1 Pre-shared Key (assuming Core-Router-1 is the peer)
crypto isakmp key YourStrongKey address 100.0.0.1
!

// Configure IKE Phase 2 (IPsec Transform Set)
crypto ipsec transform-set TS_ESP_AES_SHA esp-aes 256 esp-sha-hmac
 mode tunnel
!

// Create Crypto Map
crypto map CMAP 10 ipsec-isakmp
 set peer 100.0.0.1
 set transform-set TS_ESP_AES_SHA
 match address VPN_TRAFFIC_BRANCH
!

// Apply Crypto Map to Interface (public-facing interface)
interface GigabitEthernet0/0
 crypto map CMAP
!
```

**Syslog Configuration:**

```
logging host 192.168.60.100
logging trap informational
logging source-interface Loopback0
!
```

**SNMP Configuration:**

```
snmp-server community public RO
snmp-server community private RW
snmp-server host 192.168.60.101 traps version 2c public
snmp-server enable traps snmp authentication linkup linkdown
!
```

## Multilayer Switch Configurations

### Multilayer Switch: Distribution-Switch-1 (AS-40 in diagram)

**Global Configuration:**

```
ip routing
!
```

**VLAN Creation and Naming:**

```
vlan 10
 name Server_VLAN
!
vlan 20
 name Admin_VLAN
!
vlan 30
 name Management_VLAN
!
vlan 40
 name Guests_VLAN
!
```

**Switched Virtual Interfaces (SVIs) - Default Gateways for VLANs:**

```
interface Vlan10
 ip address 192.168.60.1 255.255.255.0
 no shutdown
!
interface Vlan20
 ip address 192.168.61.1 255.255.255.0
 no shutdown
!
interface Vlan30
 ip address 192.168.62.1 255.255.255.0
 no shutdown
!
interface Vlan40
 ip address 192.168.63.1 255.255.255.0
 no shutdown
!
```

**VTP Configuration:**

```
vtp mode server
vtp domain SecureNet
vtp password Cisco123
vtp pruning
!
```

**EtherChannel Configuration (to Core-Router-1/2 and Access Switches):**

```
// To Core-Router-1
interface Port-channel1
 switchport mode trunk
 switchport trunk encapsulation dot1q
 switchport trunk allowed vlan 10,20,30,40
!
interface GigabitEthernet0/0
 channel-group 1 mode active
!

// To Core-Router-2
interface Port-channel2
 switchport mode trunk
 switchport trunk encapsulation dot1q
 switchport trunk allowed vlan 10,20,30,40
!
interface GigabitEthernet0/1
 channel-group 2 mode active
!

// To Access-Switch-1 (assuming Gig0/2 and Gig0/3 are connected)
interface Port-channel3
 switchport mode trunk
 switchport trunk encapsulation dot1q
 switchport trunk allowed vlan 10,20,30,40
!
interface GigabitEthernet0/2
 channel-group 3 mode active
!
interface GigabitEthernet0/3
 channel-group 3 mode active
!
```

**HSRP Configuration (for VLANs):**

```
interface Vlan10
 standby 10 ip 192.168.60.1
 standby 10 priority 150
 standby 10 preempt
!
interface Vlan20
 standby 20 ip 192.168.61.1
 standby 20 priority 150
 standby 20 preempt
!
interface Vlan30
 standby 30 ip 192.168.62.1
 standby 30 priority 150
 standby 30 preempt
!
interface Vlan40
 standby 40 ip 192.168.63.1
 standby 40 priority 150
 standby 40 preempt
!
```

**DHCP Server Configuration:**

```
ip dhcp pool Server_VLAN_Pool
 network 192.168.60.0 255.255.255.0
 default-router 192.168.60.1
 dns-server 192.168.60.10
!
ip dhcp excluded-address 192.168.60.1 192.168.60.9
!

ip dhcp pool Admin_VLAN_Pool
 network 192.168.61.0 255.255.255.0
 default-router 192.168.61.1
 dns-server 192.168.60.10
!
ip dhcp excluded-address 192.168.61.1 192.168.61.9
!

ip dhcp pool Management_VLAN_Pool
 network 192.168.62.0 255.255.255.0
 default-router 192.168.62.1
 dns-server 192.168.60.10
!
ip dhcp excluded-address 192.168.62.1 192.168.62.9
!

ip dhcp pool Guests_VLAN_Pool
 network 192.168.63.0 255.255.255.0
 default-router 192.168.63.1
 dns-server 192.168.60.10
!
ip dhcp excluded-address 192.168.63.1 192.168.63.9
!
```

**Syslog Configuration:**

```
logging host 192.168.60.100
logging trap informational
logging source-interface Loopback0
!
```

**SNMP Configuration:**

```
snmp-server community public RO
snmp-server community private RW
snmp-server host 192.168.60.101 traps version 2c public
snmp-server enable traps snmp authentication linkup linkdown
!
```

### Multilayer Switch: Distribution-Switch-2 (AS-50 in diagram)

**Global Configuration:**

```
ip routing
!
```

**VLAN Creation and Naming:**

```
vlan 10
 name Server_VLAN
!
vlan 20
 name Admin_VLAN
!
vlan 30
 name Management_VLAN
!
vlan 40
 name Guests_VLAN
!
```

**Switched Virtual Interfaces (SVIs) - Default Gateways for VLANs:**

```
interface Vlan10
 ip address 192.168.60.2 255.255.255.0
 no shutdown
!
interface Vlan20
 ip address 192.168.61.2 255.255.255.0
 no shutdown
!
interface Vlan30
 ip address 192.168.62.2 255.255.255.0
 no shutdown
!
interface Vlan40
 ip address 192.168.63.2 255.255.255.0
 no shutdown
!
```

**VTP Configuration:**

```
vtp mode server
vtp domain SecureNet
vtp password Cisco123
vtp pruning
!
```

**EtherChannel Configuration (to Core-Router-1/2 and Access Switches):**

```
// To Core-Router-1
interface Port-channel1
 switchport mode trunk
 switchport trunk encapsulation dot1q
 switchport trunk allowed vlan 10,20,30,40
!
interface GigabitEthernet0/0
 channel-group 1 mode active
!

// To Core-Router-2
interface Port-channel2
 switchport mode trunk
 switchport trunk encapsulation dot1q
 switchport trunk allowed vlan 10,20,30,40
!
interface GigabitEthernet0/1
 channel-group 2 mode active
!

// To Access-Switch-1 (assuming Gig0/2 and Gig0/3 are connected)
interface Port-channel3
 switchport mode trunk
 switchport trunk encapsulation dot1q
 switchport trunk allowed vlan 10,20,30,40
!
interface GigabitEthernet0/2
 channel-group 3 mode active
!
interface GigabitEthernet0/3
 channel-group 3 mode active
!
```

**HSRP Configuration (for VLANs):**

```
interface Vlan10
 standby 10 ip 192.168.60.1
 standby 10 priority 100
 standby 10 preempt
!
interface Vlan20
 standby 20 ip 192.168.61.1
 standby 20 priority 100
 standby 20 preempt
!
interface Vlan30
 standby 30 ip 192.168.62.1
 standby 30 priority 100
 standby 30 preempt
!
interface Vlan40
 standby 40 ip 192.168.63.1
 standby 40 priority 100
 standby 40 preempt
!
```

**DHCP Relay Agent Configuration (on SVIs if DHCP server is external):**

```
interface Vlan10
 ip helper-address 192.168.60.10
!
interface Vlan20
 ip helper-address 192.168.60.10
!
interface Vlan30
 ip helper-address 192.168.60.10
!
interface Vlan40
 ip helper-address 192.168.60.10
!
```

**Syslog Configuration:**

```
logging host 192.168.60.100
logging trap informational
logging source-interface Loopback0
!
```

**SNMP Configuration:**

```
snmp-server community public RO
snmp-server community private RW
snmp-server host 192.168.60.101 traps version 2c public
snmp-server enable traps snmp authentication linkup linkdown
!
```

## Access Switch Configurations

### Access Switch: Access-Switch-1 (Connected to Distribution-Switch-1/2)

**VTP Configuration:**

```
vtp mode client
vtp domain SecureNet
vtp password Cisco123
!
```

**Spanning Tree Protocol (RPVST+) Configuration:**

```
spanning-tree mode rapid-pvst
spanning-tree vlan 10,20,30,40 root secondary
!
```

**EtherChannel Configuration (to Distribution-Switch-1/2):**

```
// To Distribution-Switch-1 (assuming Gig0/1 and Gig0/2 are connected)
interface Port-channel1
 switchport mode trunk
 switchport trunk encapsulation dot1q
 switchport trunk allowed vlan 10,20,30,40
!
interface GigabitEthernet0/1
 channel-group 1 mode active
!
interface GigabitEthernet0/2
 channel-group 1 mode active
!

// To Distribution-Switch-2 (assuming Gig0/3 and Gig0/4 are connected)
interface Port-channel2
 switchport mode trunk
 switchport trunk encapsulation dot1q
 switchport trunk allowed vlan 10,20,30,40
!
interface GigabitEthernet0/3
 channel-group 2 mode active
!
interface GigabitEthernet0/4
 channel-group 2 mode active
!
```

**Access Port Configuration (Example for Server VLAN):**

```
interface FastEthernet0/1
 switchport mode access
 switchport access vlan 10
 switchport port-security
 switchport port-security maximum 1
 switchport port-security violation shutdown
 switchport nonegotiate
 spanning-tree portfast
 spanning-tree bpduguard enable
!
```

**Syslog Configuration:**

```
logging host 192.168.60.100
logging trap informational
logging source-interface Loopback0
!
```

**SNMP Configuration:**

```
snmp-server community public RO
snmp-server community private RW
snmp-server host 192.168.60.101 traps version 2c public
snmp-server enable traps snmp authentication linkup linkdown
!
```

### Access Switch: Access-Switch-2 (Connected to Distribution-Switch-1/2)

**VTP Configuration:**

```
vtp mode client
vtp domain SecureNet
vtp password Cisco123
!
```

**Spanning Tree Protocol (RPVST+) Configuration:**

```
spanning-tree mode rapid-pvst
spanning-tree vlan 10,20,30,40 root secondary
!
```

**EtherChannel Configuration (to Distribution-Switch-1/2):**

```
// To Distribution-Switch-1 (assuming Gig0/1 and Gig0/2 are connected)
interface Port-channel1
 switchport mode trunk
 switchport trunk encapsulation dot1q
 switchport trunk allowed vlan 10,20,30,40
!
interface GigabitEthernet0/1
 channel-group 1 mode active
!
interface GigabitEthernet0/2
 channel-group 1 mode active
!

// To Distribution-Switch-2 (assuming Gig0/3 and Gig0/4 are connected)
interface Port-channel2
 switchport mode trunk
 switchport trunk encapsulation dot1q
 switchport trunk allowed vlan 10,20,30,40
!
interface GigabitEthernet0/3
 channel-group 2 mode active
!
interface GigabitEthernet0/4
 channel-group 2 mode active
!
```

**Access Port Configuration (Example for Admin VLAN):**

```
interface FastEthernet0/1
 switchport mode access
 switchport access vlan 20
 switchport port-security
 switchport port-security maximum 1
 switchport port-security violation shutdown
 switchport nonegotiate
 spanning-tree portfast
 spanning-tree bpduguard enable
!
```

**Syslog Configuration:**

```
logging host 192.168.60.100
logging trap informational
logging source-interface Loopback0
!
```

**SNMP Configuration:**

```
snmp-server community public RO
snmp-server community private RW
snmp-server host 192.168.60.101 traps version 2c public
snmp-server enable traps snmp authentication linkup linkdown
!
```

## Server Configurations

### DHCP Server (192.168.60.10)

If using a dedicated server for DHCP instead of a multilayer switch:

**Service Configuration (GUI in Packet Tracer):**

*   **DHCP Service:** On
*   **Default Gateway:** 192.168.60.1
*   **DNS Server:** 192.168.60.10 (itself or another DNS server)
*   **Start IP Address:** 192.168.60.11
*   **Subnet Mask:** 255.255.255.0
*   **Maximum Number of Users:** (e.g., 200)
*   **Add/Save**

### DNS Server (192.168.60.10)

**Service Configuration (GUI in Packet Tracer):**

*   **DNS Service:** On
*   **A Record:** (e.g., `www.securenet.com` -> `192.168.60.20` for Web Server)
*   **Add/Save**

### Web Server (192.168.60.20)

**IP Configuration:**

*   **Static IP Address:** 192.168.60.20
*   **Subnet Mask:** 255.255.255.0
*   **Default Gateway:** 192.168.60.1
*   **DNS Server:** 192.168.60.10

**Service Configuration (GUI in Packet Tracer):**

*   **HTTP Service:** On (default index.html can be used)

### Syslog Server (192.168.60.100)

**IP Configuration:**

*   **Static IP Address:** 192.168.60.100
*   **Subnet Mask:** 255.255.255.0
*   **Default Gateway:** 192.168.60.1
*   **DNS Server:** 192.168.60.10

**Service Configuration (GUI in Packet Tracer):**

*   **Syslog Service:** On

### SNMP Server (192.168.60.101)

**IP Configuration:**

*   **Static IP Address:** 192.168.60.101
*   **Subnet Mask:** 255.255.255.0
*   **Default Gateway:** 192.168.60.1
*   **DNS Server:** 192.168.60.10

**Service Configuration (GUI in Packet Tracer):**

*   **SNMP S
(Content truncated due to size limit. Use page ranges or line ranges to read remaining content)
