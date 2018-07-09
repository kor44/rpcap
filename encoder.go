package rpcap

import "io"

// Encoder is RPCAP message encoder
type Encoder struct {
	w io.Writer // destination of the data
}

// NewEncoder returns a new encoder that writes  io.Writer.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w}
}

// Encode encodes msg
func (enc *Encoder) Encode(msg Message) (err error) {
	data, err := msg.encode()
	if err != nil {
		return err
	}

	_, err = enc.w.Write(data)
	return err
}
