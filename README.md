# ip_port_audit
Little Python application to compare open ports for a number of ip addresses to a pre-defined baseline

```
thomas@gentoo ip_port_audit % ./ip_port_audit.py   
2020-06-18 22:22:56,012 — ip_port_audit — WARNING — Found more open ports than defined in baseline
2020-06-18 22:22:56,012 — ip_port_audit — WARNING — 192.168.0.14 : ['tcp/139', 'tcp/445']
2020-06-18 22:22:56,012 — ip_port_audit — WARNING — 192.168.0.1 : ['tcp/21', 'tcp/22', 'tcp/23', 'tcp/443']
2020-06-18 22:22:56,012 — ip_port_audit — WARNING — Ports defined in baseline are not open any more
2020-06-18 22:22:56,012 — ip_port_audit — WARNING — 192.168.0.2 : ['tcp/21']
```
