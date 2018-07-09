package rpcap

import (
	"bytes"
	"encoding/binary"
	"io"
)

// Decoder is RPCAP message parser
type Decoder struct {
	r io.Reader // source of the data
}

// NewDecoder returns a new decoder that reads from the io.Reader.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r}
}

// Read new message from stream. Msg is nil if return error.
func (dec *Decoder) Decode() (msg Message, err error) {
	data := make([]byte, headerSize)
	if _, err := io.ReadFull(dec.r, data); err != nil {
		return nil, err
	}
	hdr := Header{
		Version: data[0],
		Type:    MessageType(data[1]),
		Value:   binary.BigEndian.Uint16(data[2:]),
		pLength: binary.BigEndian.Uint32(data[4:]),
	}

	if hdr.pLength > MaxPacketSize {
		return nil, ErrLargeMessage
	}

	payload := make([]byte, hdr.pLength)
	if _, err = io.ReadFull(dec.r, payload); err != nil {
		return nil, err
	}

	switch hdr.Type {
	case msgError:
		msg = &ErrorMsg{Header: hdr}
	case msgFindallIfReq:
		msg = &FindAllInterfaceRequest{Header: hdr}
	case msgOpenReq:
		msg = &OpenRequest{Header: hdr}
	case msgStartCapReq:
		msg = &StartCaptureRequest{Header: hdr}
	case msgUpdateFilterReq:
		msg = &UpdateFilterRequest{Header: hdr}
	case msgClose:
		msg = &CloseMsg{Header: hdr}
	case msgPacket:
		msg = &PacketMsg{Header: hdr}
	case msgAuthReq:
		msg = &AuthRequest{Header: hdr}
	case msgStatsReq:
		msg = &StatsRequest{Header: hdr}
	case msgEndCapReq:
		msg = &EndCaptureRequest{Header: hdr}
	case msgSetSamplingReq:
		msg = &SetSamplingRequest{Header: hdr}
	case msgFindAllIfReply:
		msg = &FindAllInterfaceReply{Header: hdr}
	case msgOpenReply:
		msg = &OpenReply{Header: hdr}
	case msgStartCapReply:
		msg = &StartCaptureReply{Header: hdr}
	case msgUpdateFilterReply:
		msg = &UpdateFilterReply{Header: hdr}
	case msgAuthReply:
		msg = &AuthReply{Header: hdr}
	case msgStatsReply:
		msg = &StatsReply{Header: hdr}
	case msgEndCapReply:
		msg = &EndCaptureReply{Header: hdr}
	case msgSetsamplingReply:
		msg = &SetSamplingReply{Header: hdr}
	default:
		//return nil, ErrWrongMsg
		msg = &UnknownMessage{Header: hdr}
	}

	r := bytes.NewReader(payload)
	if err = msg.decode(r); err != nil {
		return nil, err
	}

	return msg, nil
}
