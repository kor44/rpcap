package rpcap

import "fmt"

// Error implement error interface. Can be used to return error in reponse to client.
type Error interface {
	Code() uint16
	Info() (uint16, string)
	Error() string
}

type err struct {
	code uint16
	desc string
}

func (e *err) Code() uint16 {
	return e.code
}

func (e *err) Info() (uint16, string) {
	return e.code, e.desc
}

func (e *err) Error() string {
	return fmt.Sprintf("%s: %x", e.desc, e.code)
}

func NewError(code uint16, desc string) Error {
	return &err{code, desc}
}

type errorImp uint16

func newError(v uint16) *errorImp {
	err := errorImp(v)
	return &err
}

var (
	ErrNetwork        = newError(1)  // Network error
	ErrInitIimeout    = newError(2)  // The RPCAP initial timeout has expired
	ErrAuth           = newError(3)  // Generic authentication error
	ErrFindAllIf      = newError(4)  // Generic findalldevs error
	ErrNoRemoteIf     = newError(5)  // The findalldevs was ok, but the remote end had no interfaces to list
	ErrOpen           = newError(6)  // Generic pcap_open error
	ErrUpdateFilter   = newError(7)  // Generic updatefilter error
	ErrGetStats       = newError(8)  // Generic pcap_stats error
	ErrReadex         = newError(9)  // Generic pcap_next_ex error
	ErrHostNoAuth     = newError(10) // The host is not authorized to connect to this server
	ErrRemoteAccept   = newError(11) // Generic pcap_remoteaccept error
	ErrStartCapture   = newError(12) // Generic pcap_startcapture error
	ErrEndCapture     = newError(13) // Generic pcap_endcapture error
	ErrRuntimeTimeout = newError(14) // The RPCAP run-time timeout has expired
	ErrSetSampling    = newError(15) // Error diring the settings of sampling parameters
	ErrWrongMsg       = newError(16) // The other end endpoint sent a message which has not been recognized
	ErrWrongVer       = newError(17) // The other end endpoint has a version number that is not compatible with our
	ErrLargeMessage   = newError(50) // Message too large
)

func (err *errorImp) Error() string {
	names := map[int]string{
		1:  "Network error",
		2:  "The RPCAP initial timeout has expired",
		3:  "Generic authentication error",
		4:  "Generic findalldevs error",
		5:  "The findalldevs was ok, but the remote end had no interfaces to list",
		6:  "Generic pcap_open error",
		7:  "Generic updatefilter error",
		8:  "Generic pcap_stats error",
		9:  "Generic pcap_next_ex error",
		10: "The host is not authorized to connect to this server",
		11: "Generic pcap_remoteaccept error",
		12: "Generic pcap_startcapture error",
		13: "Generic pcap_endcapture error",
		14: "The RPCAP run-time timeout has expired",
		15: "Error diring the settings of sampling parameters",
		16: "The other end endpoint sent a message which has not been recognized",
		17: "The other end endpoint sent a version number that is not compatible with our",

		50: "Message too large",
	}

	idx := int(*err)
	if name, ok := names[idx]; ok {
		return name
	}

	return fmt.Sprintf("Unknown error: 0x%x", idx)
}

func (err *errorImp) Info() (uint16, string) {
	return err.Code(), err.Error()
}

func (err *errorImp) Code() uint16 {
	return uint16(*err)
}
