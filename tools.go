package main

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
)

const (
	MODE_MAIN   = "MAIN"
	MODE_SPOOF  = "SPOOF"
	MODE_POISON = "POISON"
)

const (
	DEFAULT_MACVLAN_NAME = "NetImpostor"
)

func LogStatus(modeName string, text string, isBad bool, isVerbose bool) {
	if OPTIONS.QUITE || isVerbose && !OPTIONS.VERBOSE {
		return
	}
	status := "output"
	if isBad {
		status = "error"
	}
	var callerName = "UnknownFunction"
	if info, _, _, ok := runtime.Caller(1); ok {
		details := runtime.FuncForPC(info)
		if details != nil {
			callerName = details.Name()
		}
	}
	callerNameSplit := strings.Split(callerName, ".")
	mode := fmt.Sprintf("[%s]", modeName)
	prefix := fmt.Sprintf("[%s]", "+")
	if isBad {
		prefix = fmt.Sprintf("[%s]", "-")
	}
	log := fmt.Sprintf("%s %s %s %s: %s", mode, prefix, status, callerNameSplit[len(callerNameSplit)-1], text)
	fmt.Println(log)
}

func validateArgs() bool {
	if OPTIONS.LHOST == "" {
		OPTIONS.LHOST = DEFAULT_LHOST
	}
	if net.ParseIP(OPTIONS.LHOST) == nil {
		LogStatus(MODE_MAIN, "invalid lhost", true, false)
		return false
	}

	if OPTIONS.LPORT == 0 {
		OPTIONS.LPORT = DEFAULT_LPORT
	}
	if OPTIONS.LPORT < 0 || OPTIONS.LPORT > 65535 {
		LogStatus(MODE_MAIN, "invalid lport", true, false)
		return false
	}

	if _, err := net.InterfaceByName(OPTIONS.INTERFACE); err != nil {
		LogStatus(MODE_MAIN, fmt.Sprintf("Invalid interface %s: %s", OPTIONS.INTERFACE, err), true, false)
		return false
	}

	if net.ParseIP(OPTIONS.IMPERSONATE) == nil {
		LogStatus(MODE_MAIN, "Invalid IMPERSONATE", true, false)
		return false
	}

	if OPTIONS.HARDWADDR != "" {
		if _, err := net.ParseMAC(OPTIONS.HARDWADDR); err != nil {
			LogStatus(MODE_MAIN, "Invalid MAC address", true, false)
		}
	}

	if OPTIONS.ARP_TIMEOUT < 0 {
		LogStatus(MODE_MAIN, "Invalid ARP timeout", true, false)
		return false
	}
	if OPTIONS.POISON_INTERVAL < 0 {
		LogStatus(MODE_MAIN, "Invalid poison timeout", true, false)
		return false
	}

	targetIps := strings.Split(OPTIONS.TARGETS, ",")
	for _, eachIp := range targetIps {
		if ip, err := netip.ParseAddr(eachIp); err != nil {
			LogStatus(MODE_MAIN, fmt.Sprintf("Invalid ip %s. skipping.", eachIp), true, false)
		} else {
			TARGET_IPS = append(TARGET_IPS, ip)
		}
	}

	if !(len(TARGET_IPS) > 0) {
		LogStatus(MODE_MAIN, fmt.Sprintf("No targets loaded"), true, false)
		return false
	}
	OPTIONS.TARGETS = strings.Join(func() []string {
		s := make([]string, len(TARGET_IPS))
		for i, ip := range TARGET_IPS {
			s[i] = ip.String()
		}
		return s
	}(), ",")

	return true
}

func CleanUp() {
	command := fmt.Sprintf("ip link delete %s", DEFAULT_MACVLAN_NAME)
	cmd := exec.Command("bash", "-c", command)
	cmd.Run()
}

func SetUpVirtualIf() {
	command := "sysctl -w net.ipv4.ip_nonlocal_bind=1"
	cmd := exec.Command("bash", "-c", command)
	cmd.Run()

	command = fmt.Sprintf("ip link add link %s name %s type macvlan mode bridge", OPTIONS.INTERFACE, DEFAULT_MACVLAN_NAME)
	cmd = exec.Command("bash", "-c", command)
	cmd.Run()

	command = fmt.Sprintf("ip addr add %s/32 dev %s", OPTIONS.IMPERSONATE, DEFAULT_MACVLAN_NAME)
	cmd = exec.Command("bash", "-c", command)
	cmd.Run()

	command = fmt.Sprintf("ip link set %s up", DEFAULT_MACVLAN_NAME)
	cmd = exec.Command("bash", "-c", command)
	cmd.Run()
}
