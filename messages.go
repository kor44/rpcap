package rpcap

import (
	"bytes"
	"encoding/binary"
	"io"
	"io/ioutil"
)

// MessageType is type RPCAP message
type MessageType uint8

const (
	msgError             MessageType = 1                          // Message that keeps an error notification
	msgFindallIfReq      MessageType = 2                          // Request to list all the remote interfaces
	msgOpenReq           MessageType = 3                          // Request to open a remote device
	msgStartCapReq       MessageType = 4                          // Request to start a capture on a remote device
	msgUpdateFilterReq   MessageType = 5                          // Send a compiled filter into the remote device
	msgClose             MessageType = 6                          // Close the connection with the remote peer
	msgPacket            MessageType = 7                          // This is a 'data' message, which carries a network packet
	msgAuthReq           MessageType = 8                          // Message that keeps the authentication parameters
	msgStatsReq          MessageType = 9                          // It requires to have network statistics
	msgEndCapReq         MessageType = 10                         // Stops the current capture, keeping the device open
	msgSetSamplingReq    MessageType = 11                         // Set sampling parameters
	msgFindAllIfReply    MessageType = (128 + msgFindallIfReq)    // Keeps the list of all the remote interfaces
	msgOpenReply         MessageType = (128 + msgOpenReq)         // The remote device has been opened correctly
	msgStartCapReply     MessageType = (128 + msgStartCapReq)     // The capture is starting correctly
	msgUpdateFilterReply MessageType = (128 + msgUpdateFilterReq) // The filter has been applied correctly on the remote device
	msgAuthReply         MessageType = (128 + msgAuthReq)         // Sends a message that says 'ok, authorization successful'
	msgStatsReply        MessageType = (128 + msgStatsReq)        // Message that keeps the network statistics */
	msgEndCapReply       MessageType = (128 + msgEndCapReq)       // Confirms that the capture stopped succesfully
	msgSetsamplingReply  MessageType = (128 + msgSetSamplingReq)  // Confirms that the capture stopped succesfully
)

// Message is a interface used to represent all messages (request and replies)
type Message interface {
	header() *Header
	encode() ([]byte, error)
	decode(io.Reader) error
	ProtocolVersion() uint8
}

var headerSize = binary.Size(Header{})

func checkLargePacket(data []byte) error {
	if len(data) > MaxPacketSize {
		return ErrLargeMessage
	}

	return nil
}

// Common header for all the RPCAP messages.
type Header struct {
	// RPCAP version number
	Version uint8

	// RPCAP message type (error, findalldevs, ...)
	Type MessageType

	// Message-dependent value (not always used)
	Value uint16

	// Length of the payload of this RPCAP message
	pLength uint32
}

func (hdr *Header) ProtocolVersion() uint8 {
	return hdr.Version
}

func (hdr *Header) header() *Header {
	return hdr
}

func (hdr *Header) writeHeader(t MessageType, data []byte) {
	data[0] = hdr.Version
	data[1] = byte(t)
	binary.BigEndian.PutUint16(data[2:], hdr.Value)
	binary.BigEndian.PutUint32(data[4:], uint32(len(data)-headerSize))
}

// Request to list all the remote interfaces
type FindAllInterfaceRequest struct {
	Header
}

func (msg *FindAllInterfaceRequest) encode() ([]byte, error) {
	data := make([]byte, headerSize, headerSize)
	msg.writeHeader(msgFindallIfReq, data)
	return data, nil
}

func (msg *FindAllInterfaceRequest) decode(r io.Reader) error {
	return nil
}

// Message that keeps an error notification
type ErrorMsg struct {
	Header
	//Code        uint16 // Error code. Fake field. Real value is stored in Header.Value
	Description string // Error description
}

func (msg *ErrorMsg) Code() uint16 {
	return msg.Header.Value
}

func (msg *ErrorMsg) SetCode(code uint16) {
	msg.Header.Value = code
}

func (msg *ErrorMsg) encode() ([]byte, error) {
	w := bytes.NewBuffer(make([]byte, headerSize, headerSize))
	binary.Write(w, binary.BigEndian, []byte(msg.Description))
	data := w.Bytes()
	msg.writeHeader(msgError, data)
	return data, checkLargePacket(data)
}

func (msg *ErrorMsg) decode(r io.Reader) (err error) {
	desc := make([]byte, msg.Header.pLength)
	if err = binary.Read(r, binary.BigEndian, desc); err != nil {
		return err
	}

	msg.Description = string(desc)
	return
}

// Request to open a remote device
type OpenRequest struct {
	Header
	Interface string
}

func (msg *OpenRequest) encode() ([]byte, error) {
	w := bytes.NewBuffer(make([]byte, headerSize, headerSize))
	binary.Write(w, binary.BigEndian, []byte(msg.Interface))

	data := w.Bytes()
	msg.writeHeader(msgOpenReq, data)
	return data, checkLargePacket(data)
}

func (msg *OpenRequest) decode(r io.Reader) (err error) {
	iface := make([]byte, msg.Header.pLength)
	if err = binary.Read(r, binary.BigEndian, iface); err != nil {
		return err
	}

	// !!!! Здесь нужно посмотреть как проверять
	msg.Interface = string(iface)
	return
}

type Filter struct {
	Type       uint16
	Dummy      uint16 // must be zero
	ItemsCount uint32
	Data       []byte
}

func (f *Filter) write(w io.Writer) {
	binary.Write(w, binary.BigEndian, f.Type)
	binary.Write(w, binary.BigEndian, f.Dummy)
	binary.Write(w, binary.BigEndian, f.ItemsCount)
	binary.Write(w, binary.BigEndian, f.Data)
}

const (
	FlagStartCapturePromisc    uint16 = 1  // Enables promiscuous mode (default: disabled)
	FlagStartCaptureDgram      uint16 = 2  // Use a datagram (i.e. UDP) connection for the data stream (default: use TCP)
	FlagStartCaptureServerOpen uint16 = 4  // The server has to open the data connection toward the client
	FlagStartCaptureInbound    uint16 = 8  // Capture only inbound packets (take care: the flag has no effects with promiscuous enabled)
	FlagStartCaptureOutbound   uint16 = 16 // Capture only outbound packets (take care: the flag has no effects with promiscuous enabled)
)

// Request to start a capture on a remote device
type StartCaptureRequest struct {
	Header
	SnapLength uint32
	ReadTimout uint32
	Flags      uint16
	Port       uint16
	Filter     Filter
}

func (msg *StartCaptureRequest) encode() ([]byte, error) {
	w := bytes.NewBuffer(make([]byte, headerSize, headerSize))
	binary.Write(w, binary.BigEndian, msg.SnapLength)
	binary.Write(w, binary.BigEndian, msg.ReadTimout)
	binary.Write(w, binary.BigEndian, msg.Flags)
	binary.Write(w, binary.BigEndian, msg.Port)
	msg.Filter.write(w)

	data := w.Bytes()
	msg.writeHeader(msgStartCapReq, data)
	return data, checkLargePacket(data)
}

func (msg *StartCaptureRequest) decode(r io.Reader) (err error) {
	params := []interface{}{
		&msg.SnapLength,
		&msg.ReadTimout,
		&msg.Flags,
		&msg.Port,
		&msg.Filter.Type,
		&msg.Filter.Dummy,
		&msg.Filter.ItemsCount,
	}

	for _, param := range params {
		if err = binary.Read(r, binary.BigEndian, param); err != nil {
			return err
		}
	}

	msg.Filter.Data, err = ioutil.ReadAll(r)

	return err
}

// Send a compiled filter into the remote device
type UpdateFilterRequest struct {
	Header
	Filter Filter
}

func (msg *UpdateFilterRequest) encode() ([]byte, error) {
	w := bytes.NewBuffer(make([]byte, headerSize, headerSize))
	msg.Filter.write(w)

	data := w.Bytes()
	msg.writeHeader(msgUpdateFilterReq, data)
	return data, checkLargePacket(data)
}

func (msg *UpdateFilterRequest) decode(r io.Reader) (err error) {
	params := []interface{}{
		&msg.Filter.Type,
		&msg.Filter.Dummy,
		&msg.Filter.ItemsCount,
	}

	for _, param := range params {
		if err = binary.Read(r, binary.BigEndian, param); err != nil {
			return err
		}
	}

	msg.Filter.Data, err = ioutil.ReadAll(r)

	/*пока делаем без констант
	if msg.FilterType != FILTER_BPF {
		return fmt.Errorf("Only BPF/NPF filters are currently supported")
	}*/

	//	if err = binary.Read(r, binary.BigEndian, &msg.BpfItems); err != nil {
	//		return err
	//	}

	return err
}

// Request to close a remote device
type CloseMsg struct {
	Header
}

func (msg *CloseMsg) encode() ([]byte, error) {
	data := make([]byte, headerSize, headerSize)
	msg.writeHeader(msgClose, data)
	return data, nil
}

func (msg *CloseMsg) decode(r io.Reader) (err error) {
	return
}

// This is a 'data' message, which carries a network packet
type PacketMsg struct {
	Header
	PacketHeader
	Data []byte
}

func (msg *PacketMsg) encode() ([]byte, error) {
	return []byte{}, nil
}

func (msg *PacketMsg) decode(r io.Reader) (err error) {
	if err = binary.Read(r, binary.BigEndian, &msg.PacketHeader); err != nil {
		return err
	}
	_, err = io.ReadFull(r, msg.Data)
	return err
}

// Captured packet header
type PacketHeader struct {
	Seconds       uint32
	Microseconds  uint32
	CaptureLength uint32
	RealLength    uint32
	PacketNumber  uint32
}

const (
	AuthNullType     uint16 = 0
	AuthPasswordType uint16 = 1
)

// Message that keeps the authentication parameters
type AuthRequest struct {
	Header
	Type           uint16 // Authentication type
	Dummy          uint16 // Must be zero
	sLen1          uint16 // Length of the first authentication item (e.g. username)
	sLen2          uint16 // Length of the second authentication item (e.g. password)
	FirstAuthItem  []byte // First authentication item (e.g. username)
	SecondAuthItem []byte // Second authentication item (e.g. password)
}

func (msg *AuthRequest) encode() ([]byte, error) {
	w := bytes.NewBuffer(make([]byte, headerSize, headerSize))
	binary.Write(w, binary.BigEndian, msg.Type)
	binary.Write(w, binary.BigEndian, msg.Dummy)
	binary.Write(w, binary.BigEndian, uint16(len(msg.FirstAuthItem)))
	binary.Write(w, binary.BigEndian, uint16(len(msg.SecondAuthItem)))
	w.Write(msg.FirstAuthItem)
	w.Write(msg.SecondAuthItem)

	data := w.Bytes()
	msg.writeHeader(msgAuthReq, data)

	return data, checkLargePacket(data)
}

func (msg *AuthRequest) decode(r io.Reader) (err error) {
	params := []interface{}{
		&msg.Type,
		&msg.Dummy,
		&msg.sLen1,
		&msg.sLen2,
	}

	for _, param := range params {
		if err = binary.Read(r, binary.BigEndian, param); err != nil {
			return err
		}
	}

	if msg.sLen1 != 0 {
		msg.FirstAuthItem = make([]byte, msg.sLen1)
		if err = binary.Read(r, binary.BigEndian, msg.FirstAuthItem); err != nil {
			return err
		}
	}

	if msg.sLen2 != 0 {
		msg.SecondAuthItem = make([]byte, msg.sLen2)
		err = binary.Read(r, binary.BigEndian, msg.SecondAuthItem)
	}

	return
}

// Request statistics
type StatsRequest struct {
	Header
}

func (msg *StatsRequest) encode() ([]byte, error) {
	data := make([]byte, headerSize, headerSize)
	msg.writeHeader(msgStatsReq, data)
	return data, checkLargePacket(data)
}

func (msg *StatsRequest) decode(r io.Reader) (err error) {
	return
}

// Stops the current capture, keeping the device open
type EndCaptureRequest struct {
	Header
}

func (msg *EndCaptureRequest) encode() ([]byte, error) {
	data := make([]byte, headerSize, headerSize)
	msg.writeHeader(msgEndCapReq, data)
	return data, checkLargePacket(data)
}

func (msg *EndCaptureRequest) decode(r io.Reader) (err error) {
	return
}

// Set sampling parameters
type SetSamplingRequest struct {
	Header
	Method uint8  // Sampling method
	Dummy1 uint8  // Must be zero
	Dummy2 uint16 // Must be zero
	Value  uint32 // Depends on sampling method
}

func (msg *SetSamplingRequest) encode() ([]byte, error) {
	w := bytes.NewBuffer(make([]byte, headerSize, headerSize))
	binary.Write(w, binary.BigEndian, msg.Method)
	binary.Write(w, binary.BigEndian, msg.Dummy1)
	binary.Write(w, binary.BigEndian, msg.Dummy2)
	binary.Write(w, binary.BigEndian, msg.Value)

	data := w.Bytes()
	msg.writeHeader(msgSetSamplingReq, data)
	return data, checkLargePacket(data)
}

func (msg *SetSamplingRequest) decode(r io.Reader) (err error) {
	params := []interface{}{
		&msg.Method,
		&msg.Dummy1,
		&msg.Dummy2,
		&msg.Value,
	}

	for _, param := range params {
		if err = binary.Read(r, binary.BigEndian, param); err != nil {
			return err
		}
	}
	return
}

// FindAllInterfaceReply keeps the list of all the remote interfaces
type FindAllInterfaceReply struct {
	Header
	InterfaceList []InterfaceInfo
}

func (msg *FindAllInterfaceReply) encode() (data []byte, err error) {
	// msg.Header.Value - specifies number of interfaces
	msg.Header.Value = uint16(len(msg.InterfaceList))

	w := bytes.NewBuffer(make([]byte, headerSize, headerSize))
	for i := uint16(0); i < msg.Header.Value; i++ {
		err = msg.InterfaceList[i].encode(w)
		if err != nil {
			return []byte{}, err
		}
	}

	data = w.Bytes()
	msg.writeHeader(msgFindAllIfReply, data)
	return data, checkLargePacket(data)
}

func (msg *FindAllInterfaceReply) decode(r io.Reader) (err error) {
	// msg.Header.Value - specifies number of interfaces
	ifaceCount := msg.Header.Value

	msg.InterfaceList = make([]InterfaceInfo, ifaceCount, ifaceCount)
	for i := uint16(0); i < ifaceCount; i++ {
		err = msg.InterfaceList[i].decode(r)
		if err != nil {
			return err
		}
	}

	return nil
}

const addressLen = 512

// Interface description
type InterfaceInfo struct {
	nameLength   uint16             // Length of the interface name
	descLength   uint16             // Length of the interface description
	Flags        uint32             // Interface flags
	numberOfAddr uint16             // Number of addresses
	Dummy        uint16             // Must be zero
	Name         []byte             // Interface name
	Description  []byte             // Interface description
	Addresses    [][addressLen]byte // List of addresses
}

func (iface *InterfaceInfo) encode(w io.Writer) (err error) {
	binary.Write(w, binary.BigEndian, uint16(len(iface.Name)))
	binary.Write(w, binary.BigEndian, uint16(len(iface.Description)))
	binary.Write(w, binary.BigEndian, iface.Flags)
	binary.Write(w, binary.BigEndian, uint16(len(iface.Addresses)))
	binary.Write(w, binary.BigEndian, iface.Dummy)
	binary.Write(w, binary.BigEndian, []byte(iface.Name))
	binary.Write(w, binary.BigEndian, []byte(iface.Description))

	for _, addr := range iface.Addresses {
		binary.Write(w, binary.BigEndian, addr)
	}

	return err
}

func (msg *InterfaceInfo) decode(r io.Reader) (err error) {
	data := make([]byte, 12) // 12 = nameLength + descLength + Flags + numberOfAddr + Dummy

	err = binary.Read(r, binary.BigEndian, data)

	if err != nil {
		return err
	}
	msg.nameLength = binary.BigEndian.Uint16(data[0:])
	msg.descLength = binary.BigEndian.Uint16(data[2:])
	msg.Flags = binary.BigEndian.Uint32(data[4:])
	msg.numberOfAddr = binary.BigEndian.Uint16(data[8:])
	msg.Dummy = binary.BigEndian.Uint16(data[10:])

	msg.Name = make([]byte, msg.nameLength)
	if err = binary.Read(r, binary.BigEndian, &msg.Name); err != nil {
		return err
	}

	msg.Description = make([]byte, msg.descLength)
	if err = binary.Read(r, binary.BigEndian, &msg.Description); err != nil {
		return err
	}

	if msg.numberOfAddr == 0 {
		return
	}

	msg.Addresses = make([][addressLen]byte, msg.numberOfAddr, msg.numberOfAddr)
	for i := uint16(0); i < msg.numberOfAddr || err != nil; i++ {
		err = binary.Read(r, binary.BigEndian, &msg.Addresses[i])
	}

	return
}

// OpenReply confirms remote device has been opened correctly
type OpenReply struct {
	Header
	LinkType uint32
	Timezone int32
}

func (msg *OpenReply) encode() ([]byte, error) {
	w := bytes.NewBuffer(make([]byte, headerSize, headerSize))
	binary.Write(w, binary.BigEndian, msg.LinkType)
	binary.Write(w, binary.BigEndian, msg.Timezone)

	data := w.Bytes()
	msg.writeHeader(msgOpenReply, data)

	return data, checkLargePacket(data)
}

func (msg *OpenReply) decode(r io.Reader) (err error) {
	params := []interface{}{
		&msg.LinkType,
		&msg.Timezone,
	}

	for _, param := range params {
		if err = binary.Read(r, binary.BigEndian, param); err != nil {
			return err
		}
	}
	return
}

// StartCaptureReply devoted to start a remote capture (startcap reply command)
type StartCaptureReply struct {
	Header
	Bufsize int32  // Size of the user buffer allocated by WinPcap; it can be different from the one we choose
	Port    uint16 // Network port on which the server is waiting at (passive mode only)
	Dummy   uint16 // Must be zero
}

func (msg *StartCaptureReply) encode() ([]byte, error) {
	w := bytes.NewBuffer(make([]byte, headerSize, headerSize))
	binary.Write(w, binary.BigEndian, msg.Bufsize)
	binary.Write(w, binary.BigEndian, msg.Port)
	binary.Write(w, binary.BigEndian, msg.Dummy)

	data := w.Bytes()
	msg.writeHeader(msgStartCapReply, data)

	return data, checkLargePacket(data)
}

func (msg *StartCaptureReply) decode(r io.Reader) (err error) {
	params := []interface{}{
		&msg.Bufsize,
		&msg.Port,
		&msg.Dummy,
	}

	for _, param := range params {
		if err = binary.Read(r, binary.BigEndian, param); err != nil {
			return err
		}
	}
	return
}

// UpdateFilterReply confirms filter has been applied correctly on the remote device
type UpdateFilterReply struct {
	Header
}

func (msg *UpdateFilterReply) encode() ([]byte, error) {
	data := make([]byte, headerSize, headerSize)
	msg.writeHeader(msgUpdateFilterReply, data)
	return data, checkLargePacket(data)
}

func (msg *UpdateFilterReply) decode(r io.Reader) (err error) {
	return
}

// AuthReply says 'ok, authorization successful'
type AuthReply struct {
	Header
}

func (msg *AuthReply) encode() ([]byte, error) {
	data := make([]byte, headerSize, headerSize)
	msg.writeHeader(msgAuthReply, data)
	return data, checkLargePacket(data)
}

func (msg *AuthReply) decode(r io.Reader) (err error) {
	return
}

// StatsReply keeps the network statistics about the number of packets captured, dropped, etc.
type StatsReply struct {
	Header
	IfRecv   uint32 // Packets received by the kernel filter (i.e. pcap_stats.ps_recv)
	IfDrop   uint32 // Packets dropped by the network interface (e.g. not enough buffers) (i.e. pcap_stats.ps_ifdrop)
	KrnlDrop uint32 // Packets dropped by the kernel filter (i.e. pcap_stats.ps_drop)
	SvrCapt  uint32 // Packets captured by the RPCAP daemon and sent on the network
}

func (msg *StatsReply) encode() ([]byte, error) {
	w := bytes.NewBuffer(make([]byte, headerSize, headerSize))
	binary.Write(w, binary.BigEndian, msg.IfRecv)
	binary.Write(w, binary.BigEndian, msg.IfDrop)
	binary.Write(w, binary.BigEndian, msg.KrnlDrop)
	binary.Write(w, binary.BigEndian, msg.SvrCapt)

	data := w.Bytes()
	msg.writeHeader(msgStatsReply, data)

	return data, checkLargePacket(data)
}

func (msg *StatsReply) decode(r io.Reader) (err error) {
	params := []interface{}{
		&msg.IfRecv,
		&msg.IfDrop,
		&msg.KrnlDrop,
		&msg.SvrCapt,
	}

	for _, param := range params {
		if err = binary.Read(r, binary.BigEndian, param); err != nil {
			return err
		}
	}
	return

}

// EndCaptureReply confirms that the capture stopped succesfully
type EndCaptureReply struct {
	Header
}

func (msg *EndCaptureReply) encode() ([]byte, error) {
	data := make([]byte, headerSize, headerSize)
	msg.writeHeader(msgAuthReply, data)
	return data, checkLargePacket(data)
}

func (msg *EndCaptureReply) decode(r io.Reader) (err error) {
	return
}

// SetSamplingReply confirms that the capture stopped succesfully
type SetSamplingReply struct {
	Header
}

func (msg *SetSamplingReply) encode() ([]byte, error) {
	data := make([]byte, headerSize, headerSize)
	msg.writeHeader(msgSetsamplingReply, data)
	return data, checkLargePacket(data)
}

func (msg *SetSamplingReply) decode(r io.Reader) (err error) {
	return
}

// UnknownMessage is used to transfer non standard messages
type UnknownMessage struct {
	Header
	Payload []byte
}

func (msg *UnknownMessage) encode() ([]byte, error) {
	w := bytes.NewBuffer(make([]byte, headerSize, headerSize))
	w.Write(msg.Payload)

	data := w.Bytes()
	msg.writeHeader(msg.header().Type, data)

	return data, checkLargePacket(data)
}

func (msg *UnknownMessage) decode(r io.Reader) (err error) {
	msg.Payload = make([]byte, msg.header().pLength, msg.header().pLength)
	_, err = io.ReadFull(r, msg.Payload)
	return err
}
