# netfilter-nattype
基于Linux Nat的RFC3489 Nat类型实现,包括:
- Full Cone
  - 类似下面的指令实现的实际上是dmz主机,详见https://blog.chionlab.moe/2018/02/09/full-cone-nat-with-linux/
  - sudo iptables -t nat -A PREROUTING -i ens33 -j DNAT --to-destination 192.168.99.101
- Address-Restricted Cone
  - 类似下面的命令实际无法实现
  - sudo iptables -A INPUT -i ens33 -p udp -m state --state ESTABLISHED,RELATED -j ACCEPT
  - sudo iptables -A INPUT -i ens33 -p udp -m state --state NEW -j DROP
- Port-Restricted Cone NAT
  - 其实也可以用下面的指令实现,但下挂多个NAT时不可靠,详见https://blog.csdn.net/u011245325/article/details/9294229
  - sudo iptables -t nat -A POSTROUTING -s 192.168.99.0/24 -o ens33 -j MASQUERADE

不包括:
- Symmetric NAT
  - 可以用下面的指令直接实现.
  - sudo iptables -t nat -A POSTROUTING -s 192.168.99.0/24 -o ens33 -j MASQUERADE --random

# How to use
````shell
sudo ./iptables -t nat -A POSTROUTING -o ens33 -j FULLCONENAT
sudo ./iptables -t nat -A PREROUTING -i ens33 -j FULLCONENAT --nat-type fc|ar|pr
````

# 注意
代码未经过严格测试,且存在部分work-around处理,请谨慎使用.

# 上游代码
https://github.com/Chion82/netfilter-full-cone-nat


Original Readme
======
Implementation of RFC3489-compatible full cone SNAT.

Assuming eth0 is external interface:
```
iptables -t nat -A POSTROUTING -o eth0 -j FULLCONENAT #same as MASQUERADE  
iptables -t nat -A PREROUTING -i eth0 -j FULLCONENAT  #automatically restore NAT for inbound packets
```
Currently only UDP traffic is supported for full-cone NAT. For other protos FULLCONENAT is equivalent to MASQUERADE.

Build
======
Prerequisites: 
* kernel source  
* iptables source ( git://git.netfilter.org/iptables.git ) 

Confirm the kernel configuration option `CONFIG_NF_CONNTRACK_EVENTS` is enabled. If this option is disabled on your system, enable it and rebuild your netfilter modules.

Kernel Module
-------------
```
$ make
# insmod xt_FULLCONENAT.ko
```

Iptables Extension
------------------

1. Copy libipt_FULLCONENAT.c to `iptables-source/extensions`.

2. Under the iptables source directory, `./configure`(use `--prefix` to replace your current `iptables` by looking at `which iptables`), `make` and `make install`

OpenWRT
-------
Package for openwrt is available at https://github.com/LGA1150/openwrt-fullconenat

Usage
=====

Assuming eth0 is external interface:

Basic Usage:

```
iptables -t nat -A POSTROUTING -o eth0 -j FULLCONENAT
iptables -t nat -A PREROUTING -i eth0 -j FULLCONENAT
```

Random port range:

```
iptables -t nat -A POSTROUTING -o eth0 ! -p udp -j MASQUERADE
iptables -t nat -A POSTROUTING -o eth0 -p udp -j FULLCONENAT --to-ports 40000-60000 --random-fully

iptables -t nat -A PREROUTING -i eth0 -p udp -m multiport --dports 40000:60000 -j FULLCONENAT
```

Hairpin NAT (Assuming eth1 is LAN interface and IP range for LAN is 192.168.100.0/24):
```
iptables -t nat -A POSTROUTING -o eth0 -j FULLCONENAT
iptables -t nat -A POSTROUTING -o eth1 -s 192.168.100.0/24 -j MASQUERADE
iptables -t nat -A PREROUTING -i eth0 -j FULLCONENAT
iptables -t nat -A PREROUTING -i eth1 -j FULLCONENAT
```

kernel Patch (Optional.)
========================
1. Copy xt_FULLCONENAT.c to `kernel-source/net/netfilter/xt_FULLCONENAT.c`   
2. Append following line to `kernel-source/net/netfilter/Makefile`:

```
obj-$(CONFIG_NETFILTER_XT_TARGET_FULLCONENAT) += xt_FULLCONENAT.o
```

3. Insert following section into `kernel-source/net/ipv4/netfilter/Kconfig` right after `config IP_NF_TARGET_NETMAP` section:

```
config IP_NF_TARGET_FULLCONENAT
  tristate "FULLCONENAT target support"
  depends on NETFILTER_ADVANCED
  select NETFILTER_XT_TARGET_FULLCONENAT
  ---help---
  This is a backwards-compat option for the user's convenience
  (e.g. when running oldconfig). It selects
  CONFIG_NETFILTER_XT_TARGET_FULLCONENAT.

```

4. Insert following section into `kernel-source/net/netfilter/Kconfig` right after `config NETFILTER_XT_TARGET_NETMAP` section:

```
config NETFILTER_XT_TARGET_FULLCONENAT
  tristate '"FULLCONENAT" target support'
  depends on NF_NAT
  ---help---
  Full Cone NAT

  To compile it as a module, choose M here. If unsure, say N.

```

5. Run `make menuconfig` and select:
    Networking support -> Network options -> Network packet filtering framework (Netfilter) -> IP: Netfilter Configuration -> \<M\> FULLCONENAT target support

License
=======
Copyright 2018 Chion Tang [betaidc](https://www.betaidc.com/contact.html)  
GPL-2.0  
See LICENSE
