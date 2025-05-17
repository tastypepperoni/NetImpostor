package main

import (
	"errors"
	"fmt"
	"io"
	"net"
)

func handleRequest(clientConn *net.TCPConn) {
	destAddr, destPort, err := handleNewConn(clientConn)
	if err != nil {
		LogStatus(MODE_SPOOF, fmt.Sprintf("failed to handle new client connection from %s: %v", clientConn.RemoteAddr().String(), err), true, false)
		return
	}
	LogStatus(MODE_SPOOF, fmt.Sprintf("accepted new client connection from %s", clientConn.RemoteAddr().String()), false, true)

	spoofedAddr := &net.TCPAddr{IP: net.ParseIP(OPTIONS.IMPERSONATE), Port: 0}
	remoteAddr := &net.TCPAddr{IP: destAddr, Port: destPort}
	remoteConn, err := net.DialTCP("tcp", spoofedAddr, remoteAddr)
	if err != nil {
		LogStatus(MODE_SPOOF, fmt.Sprintf("failed to connect to remote destination %s:%d %v", destAddr.String(), destPort, err), true, false)
		return
	}
	if _, err = clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
		LogStatus(MODE_SPOOF, fmt.Sprintf("failed to write success message to client: %v", err), true, false)
		return
	}
	LogStatus(MODE_SPOOF, fmt.Sprintf("wrote success message to client tunnel for the connection"), false, true)

	LogStatus(MODE_SPOOF, fmt.Sprintf("starting new tunnel %s <-> %s:%d", clientConn.RemoteAddr().String(), destAddr.String(), destPort), false, false)

	go io.Copy(remoteConn, clientConn)
	io.Copy(clientConn, remoteConn)
}

func handleNewConn(clientConn *net.TCPConn) (net.IP, int, error) {
	err := validateSocks(clientConn)
	if err != nil {
		return nil, 0, errors.New(fmt.Sprintf("failed to validate SOCKS5 traffic: %v", err))
	}

	destType := make([]byte, 2)
	if _, err = io.ReadFull(clientConn, destType); err != nil {
		return nil, 0, errors.New("failed to read destination type")
	}

	var destAddr net.IP
	var destPort int
	switch destType[1] {
	case 0x01: // IPv4 address
		ipv4 := make([]byte, 4)
		if _, err = io.ReadFull(clientConn, ipv4); err != nil {
			return nil, 0, fmt.Errorf("error reading IPv4 address: %v", err)
		}
		destAddr = ipv4
	case 0x03: // Domain name
		domainLen := make([]byte, 1)
		if _, err = io.ReadFull(clientConn, domainLen); err != nil {
			return nil, 0, fmt.Errorf("error reading domain length: %v", err)
		}
		domain := make([]byte, domainLen[0])
		if _, err = io.ReadFull(clientConn, domain); err != nil {
			return nil, 0, fmt.Errorf("error reading domain: %v", err)
		}
		resolvedAddr, err := net.ResolveIPAddr("ip", string(domain))
		if err != nil {
			return nil, 0, fmt.Errorf("error resolving domain: %v", err)
		}
		destAddr = resolvedAddr.IP
	case 0x04:
		return nil, 0, fmt.Errorf("IPv6 addresses are not supported")
	default:
		return nil, 0, fmt.Errorf("unsupported address type: %v", destType[1])
	}

	port := make([]byte, 2)
	if _, err = io.ReadFull(clientConn, port); err != nil {
		return nil, 0, fmt.Errorf("error reading destination port: %v", err)
	}
	destPort = int(port[0])<<8 | int(port[1])

	return destAddr, destPort, nil
}

func validateSocks(clientConn *net.TCPConn) error {
	version := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, version); err != nil {
		return fmt.Errorf("error reading socks version: %v", err)
	}

	if version[0] != 0x05 {
		return errors.New("unsupported traffic version. only SOCKS5 is supported")
	}

	numMethods := int(version[1])
	authMethods := make([]byte, numMethods)
	if _, err := io.ReadFull(clientConn, authMethods); err != nil {
		return fmt.Errorf("error reading authentication methods: %v", err)
	}

	if _, err := clientConn.Write([]byte{0x05, 0x00}); err != nil {
		return fmt.Errorf("error sending server selection message: %v", err)

	}

	command := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, command); err != nil {
		return fmt.Errorf("error reading client request: %v", err)
	}

	if command[0] != 0x05 || command[1] != 0x01 {
		return fmt.Errorf("unsupported command: %v", command[1])
	}
	return nil
}
