package tftp

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type osConn struct {
	qosHandle    windows.Handle
	socketHandle windows.Handle
	flowId       uint32
	dscpValue    int
}

const (
	QOS_NON_ADAPTIVE_FLOW   = 0x00000002
	QOSSetOutgoingDSCPValue = 2
)

type QOS_TRAFFIC_TYPE uint32

const (
	QOSTrafficTypeBestEffort QOS_TRAFFIC_TYPE = iota
	QOSTrafficTypeBackground
	QOSTrafficTypeExcellentEffort
	QOSTrafficTypeAudioVideo
	QOSTrafficTypeVoice
	QOSTrafficTypeControl
)

type clientVersion struct {
	MajorVersion uint16
	MinorVersion uint16
}

func (cc *connConnection) getUDPConn(connected *bool, localAddr,
	remoteAddr *net.UDPAddr, dscp int, mode string,
) error {
	switch mode {
	case "server":
		log.Printf("DialUDP connection on %s with DSCP %d", localAddr.String(), dscp)
		conn, err := net.DialUDP("udp", localAddr, remoteAddr)
		if err != nil {
			log.Printf("error while dialing UDP conn:%s", err)
			return err
		}
		*connected = true
		cc.conn = conn
		cc.osconn = &osConn{}
	case "client":
		log.Printf("ListenUDP connection on %s with DSCP %d", localAddr.String(), dscp)
		conn, err := net.ListenUDP("udp", localAddr)
		if err != nil {
			return err
		}
		cc.conn = conn
		cc.osconn = &osConn{}
		*connected = false
		cc.osconn.dscpValue = dscp
	default:
		return fmt.Errorf("invalid mode: %s for getUDPconn", mode)
	}

	if dscp != 0 {
		if err := cc.setDSCPOnConn(remoteAddr, dscp); err != nil {
			// we are trying to set DSCP on best effort basis, so even if some error while
			// setting DSCP on connection we just log the error and return nil
			log.Printf("Failed to set DSCP on addr:%s - %s", localAddr.String(), err)
		}
	}

	return nil
}

func (cc *connConnection) setDSCPOnConn(remoteAddr *net.UDPAddr, dscp int) error {
	var operr error
	uint32dscp := uint32(dscp)
	var ok bool
	rawConn, err := cc.conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get raw connection: %w", err)
	}
	if cc.osconn.qosHandle == 0 {
		var version clientVersion
		version.MajorVersion = 1
		version.MinorVersion = 0
		ok, err := winQoSCreateHandle(unsafe.Pointer(&version), &cc.osconn.qosHandle)
		if !ok || err != nil {
			return fmt.Errorf("critical error creating Qos handle:%s", err)
		}
	}

	var sockAddrPtr unsafe.Pointer
	if remoteAddr.IP.To4() != nil {
		var sockAddr *syscall.RawSockaddrInet4
		sockAddr, err = getSockAddrIntet4(remoteAddr.String())
		if err != nil {
			return err
		}
		sockAddrPtr = unsafe.Pointer(sockAddr)
	} else if remoteAddr.IP.To16() != nil {
		var sockAddr *syscall.RawSockaddrInet6
		sockAddr, err = getSockAddrIntet6(remoteAddr.String())
		if err != nil {
			return err
		}
		sockAddrPtr = unsafe.Pointer(sockAddr)
	} else {
		return fmt.Errorf("invalid IP protocol %s", remoteAddr.String())
	}

	ctrlErr := rawConn.Control(func(fd uintptr) {
		cc.osconn.socketHandle = windows.Handle(fd)
		ok, err = winQoSAddSocketToFlow(
			cc.osconn.qosHandle,
			cc.osconn.socketHandle,
			sockAddrPtr,
			uint32(QOSTrafficTypeExcellentEffort),
			QOS_NON_ADAPTIVE_FLOW,
			&cc.osconn.flowId,
		)
		if !ok {
			operr = fmt.Errorf("[Remote:%s]Failed to add to the flow: %s",
				remoteAddr.String(), err)
			return
		}
		ok, err = winQoSSetFlow(
			cc.osconn.qosHandle,
			cc.osconn.flowId,
			QOSSetOutgoingDSCPValue,
			4,
			unsafe.Pointer(&uint32dscp),
			0,
			nil,
		)
		if !ok {
			operr = fmt.Errorf("[Remote:%s]Failed to set DSCP: %s",
				remoteAddr.String(), err)
			return
		} else {
			log.Printf("DSCP set to %d on flow %d", dscp, cc.osconn.flowId)
		}
	})
	if ctrlErr != nil {
		return fmt.Errorf("failed to apply QoS at callback:%s", ctrlErr)
	}
	if operr != nil {
		return fmt.Errorf("failed to apply socket control: %v", operr)
	}
	return nil
}

// GetSockAddrInet4 creates the correct C-compatible struct for IPv4
// and returns an error if any.
func getSockAddrIntet4(address string) (*syscall.RawSockaddrInet4, error) {
	var sa syscall.RawSockaddrInet4
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	portInt, _ := strconv.Atoi(portStr)

	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP")
	}

	// Check if IPv4
	if ip4 := ip.To4(); ip4 != nil {
		sa.Family = syscall.AF_INET
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:], uint16(portInt))
		copy(sa.Addr[:], ip4)
		return &sa, nil
	}

	return &sa, fmt.Errorf("unknown IP family")
}

// GetSockAddrInet6 creates the correct C-compatible struct for IPv6
// and returns an error if any.
func getSockAddrIntet6(address string) (*syscall.RawSockaddrInet6, error) {
	var sa syscall.RawSockaddrInet6
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	portInt, _ := strconv.Atoi(portStr)
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP")
	}

	// Must be IPv6
	if ip6 := ip.To16(); ip6 != nil {
		sa.Family = syscall.AF_INET6
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:], uint16(portInt))
		copy(sa.Addr[:], ip6)
		// ScopeID is usually required for Link-Local addresses, skipping for simplicity here
		return &sa, nil
	}

	return &sa, fmt.Errorf("unknown IP family")
}

func (cc *connConnection) unsetDSCPValue() error {
	if cc.osconn == nil || cc.osconn.qosHandle == 0 {
		return nil
	}
	winQoSRemoveSocketFromFlow(cc.osconn.qosHandle, cc.osconn.socketHandle, cc.osconn.flowId, 0)
	winQoSCloseHandle(cc.osconn.qosHandle)
	return nil
}

// reconnectSocketForNewTID closes the current socket and creates a new
// connected socket to the new TID address. This is required on Windows
// because QOSAddSocketToFlow requires either a connected socket OR
// a destAddr parameter, and for updating flows we need to connect.
func (cc *connConnection) reconnectSocketForNewTID(connected *bool, newRemoteAddr *net.UDPAddr,
	dscp int,
) error {
	// Remove the old flow first
	if cc.osconn.flowId != 0 {
		if ok, err := winQoSRemoveSocketFromFlow(
			cc.osconn.qosHandle,
			cc.osconn.socketHandle,
			cc.osconn.flowId,
			0,
		); !ok {
			log.Printf("failed to remove socket from flow: %s", err)
		} else {
			log.Printf("Removed socket from flow: %d", cc.osconn.flowId)
		}
		cc.osconn.flowId = 0
	}

	// Get the local address before closing
	localAddr := cc.conn.LocalAddr().(*net.UDPAddr)

	// Close the old connection (this also cleans up old QoS flow)
	if cc.conn != nil {
		cc.conn.Close()
	}

	// Create a new CONNECTED socket using DialUDP
	// This connects to the specific remote IP:Port (the new TID)
	newConn, err := net.DialUDP("udp", localAddr, newRemoteAddr)
	if err != nil {
		return fmt.Errorf("failed to dial UDP to new TID %s: %w", newRemoteAddr.String(), err)
	}
	*connected = true
	// Update the connection
	cc.conn = newConn
	// Re-apply DSCP with the connected socket
	// Windows allows NULL destAddr when socket is connected
	return cc.setDSCPOnConn(newRemoteAddr, dscp)
}
