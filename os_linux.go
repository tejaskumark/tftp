package tftp

import (
	"fmt"
	"log"
	"net"
	"syscall"
)

type osConn struct{}

func (cc *connConnection) getUDPConn(_ *bool, localAddr, _ *net.UDPAddr, dscp int) error {
	log.Printf("ListenUDP connection on %s with DSCP %d", localAddr.String(), dscp)
	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return err
	}
	cc.conn = conn
	if dscp != 0 {
		if err = cc.setDSCPOnConn(dscp); err != nil {
			// we are trying to set DSCP on best effort basis, so even if some error while
			// setting DSCP on connection we just log the error and return nil
			log.Printf("Failed to set DSCP on addr:%s - %s", localAddr.String(), err)
		}
	}
	return nil
}

func (cc *connConnection) setDSCPOnConn(dscp int) error {
	rawConn, err := cc.conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get raw conn: %w", err)
	}

	var innerErr error

	// 2. Control the raw file descriptor
	err = rawConn.Control(func(fd uintptr) {
		fdInt := int(fd)
		tos := dscp << 2

		// Determine the socket type
		var sa syscall.Sockaddr
		sa, err = syscall.Getsockname(fdInt)
		if err != nil {
			innerErr = err
			return
		}

		switch sa.(type) {
		case *syscall.SockaddrInet4:
			innerErr = syscall.SetsockoptInt(fdInt, syscall.IPPROTO_IP, syscall.IP_TOS, tos)
		case *syscall.SockaddrInet6:
			// For dual stack listenr type will be always IPv6 type and we need to set
			// IPv4/IPv6 TOS here at this place
			innerErr = syscall.SetsockoptInt(fdInt, syscall.IPPROTO_IP, syscall.IP_TOS, tos)
			innerErr = syscall.SetsockoptInt(fdInt, syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, tos)
		default:
			innerErr = fmt.Errorf("unsupported socket address type")
		}
	})
	if err != nil {
		return err
	}

	return innerErr
}

func (c *connConnection) unsetDSCPValue() error {
	return nil
}
