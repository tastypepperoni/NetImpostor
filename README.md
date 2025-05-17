# NetImpostor
Gain another host's network access permissions by establishing a stateful connection with a spoofed source IP.


An overview of the techniques used in this tool can be found here: https://tastypepperoni.medium.com/stateful-connection-with-spoofed-source-ip-netimpostor-ece8b950a981

```
Usage:
  NetImpostor [OPTIONS]

Application Options:
      --lhost=       Local address to listen for connections [default: 127.0.0.1]
      --lport=       Local port to listen for connections [default: 1080]
  -i, --interface=   Local interface
      --mac=         Hardware address for arp poison [default: address of the -i interface. for virtual machines: **MIGHT** need to be address
                     of the host that runs the machine, not its own interface]
      --impersonate= Remote address to impersonate
  -t, --targets=     Comma seperated list of IPs that NetImpostor impersonates against
      --arpt=        Timeout for ARP resolve requests [seconds] [default: 2]
      --pi=          Interval between ARP poison iterations [seconds] [default: 10]
  -v, --verbose      Show verbose debug information
  -q, --quite        Quite mode. [overrides verbose]
  -c, --clean        Clean up NetImpostor configurations
```

**Example:**

```./NetImpostor -i eth0 --impersonate 192.168.118.89 --targets 192.168.118.24,192.168.118.25,192.168.118.26```

Impersonates to be 192.168.118.89 against 192.168.118.24,192.168.118.25,192.168.118.26


**TODO:**

Support for the UDP
