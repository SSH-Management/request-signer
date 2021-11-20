package signer

import "encoding/binary"

func makePayload(payload []byte, timestamp uint64) []byte {
	data := make([]byte, 8, 8+len(payload))

	binary.LittleEndian.PutUint64(data, timestamp)

	copy(data, payload)

	return data
}
