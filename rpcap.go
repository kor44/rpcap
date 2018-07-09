package rpcap

import (
	"time"
)

const (
	DefaultNetPort       = "2002" // Default port on which the RPCAP server is waiting for connections.
	DefaultNetPortActive = "2003" // Default port on which the client workstation is waiting for connections in case of active mode.

	DefaultNetAddr = "" // Default network address on which the RPCAP server binds to.
	Version_0      = 0  // Present version of the RPCAP protocol (0 = Experimental).

	TimeoutInit      = 5 * time.Second   // Initial timeout for RPCAP connections (default: 90 sec)
	TimeoutRuntime   = 180 * time.Second // Run-time timeout for RPCAP connections (default: 3 min)
	ActiveWait       = 30 * time.Second  // Waiting time betweek two attempts to open a connection, in active mode (default: 30 sec)
	SuspendWrongAuth = 1 * time.Second   // If the authentication is wrong, stops 1 sec before accepting a new auth message

	// In case you plan to have messages larger than this value, you have to increase it.
	MaxPacketSize = 64000

	// Separators used for the host list.
	// It is used:
	//  - by the rpcapd server, when you types a list of allowed connecting hosts
	//  - by the rpcap in active mode, when the client waits for incoming connections from other hosts
	HostListSep = " ,;\n\r"
)
