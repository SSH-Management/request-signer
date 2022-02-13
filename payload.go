package signer

import "encoding/binary"

func makePayload(payload []byte, timestamp uint64, order binary.ByteOrder) []byte {
	data := make([]byte, 8, 8+len(payload))

	order.PutUint64(data, timestamp)

	copy(data, payload)

	return data
}
