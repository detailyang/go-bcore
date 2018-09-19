package bcore

import (
	"encoding/binary"
)

const (
	BufferDefaultSliceSize = 128
)

// Buffer little-endian
type Buffer struct {
	data []byte
	pos  int
}

func NewReadBuffer(data []byte) *Buffer {
	return &Buffer{
		data: data,
		pos:  0,
	}
}

func NewBuffer() *Buffer {
	return &Buffer{
		data: make([]byte, 0, BufferDefaultSliceSize),
		pos:  0,
	}
}

func (b *Buffer) PutUint8(u8 uint8) *Buffer {
	b.data = append(b.data, u8)
	b.pos += 1
	return b
}
func (b *Buffer) Uint8(u8 *uint8) *Buffer {
	*u8 = b.data[b.pos]
	b.pos += 1
	return b
}

func (b *Buffer) PutUint16(u16 uint16) *Buffer {
	binary.LittleEndian.PutUint16(b.data, u16)
	b.pos += 2
	return b
}

func (b *Buffer) Uint16(u16 *uint16) *Buffer {
	*u16 = binary.LittleEndian.Uint16(b.data[b.pos:])
	b.pos += 2
	return b
}

func (b *Buffer) PutUint32(u32 uint32) *Buffer {
	binary.LittleEndian.PutUint32(b.data, u32)
	b.pos += 4
	return b
}

func (b *Buffer) Uint32(u32 *uint32) *Buffer {
	*u32 = binary.LittleEndian.Uint32(b.data[b.pos:])
	b.pos += 4
	return b
}

func (b *Buffer) PutUint64(u64 uint64) *Buffer {
	binary.LittleEndian.PutUint64(b.data, u64)
	b.pos += 8
	return b
}

func (b *Buffer) Uint64(u64 *uint64) *Buffer {
	*u64 = binary.LittleEndian.Uint64(b.data[b.pos:])
	b.pos += 8
	return b
}

func (b *Buffer) PutHash(hash Hash) *Buffer {
	b.data = append(b.data, hash.Bytes()...)
	b.pos += len(hash)
	return b
}

func (b *Buffer) Hash(hash *Hash) *Buffer {
	data := b.data[b.pos : b.pos+HashSize]
	hash.SetBytes(data)
	b.pos += HashSize
	return b
}

func (b *Buffer) PutVarInt(n uint64) *Buffer {
	switch {
	case n < uint64(0xfd):
		b.PutUint8(uint8(n))
	case n <= 0xffff:
		b.PutUint16(uint16(n))
	case n <= 0xffffffff:
		b.PutUint32(uint32(n))
	default:
		b.PutUint64(n)
	}

	return b
}

func (b *Buffer) PutBytes(bytes []byte) *Buffer {
	b.data = append(b.data, bytes...)
	b.pos += len(bytes)
	return b
}

func (b *Buffer) Size() int {
	return b.pos
}

func (b *Buffer) Bytes() []byte {
	return b.data
}
