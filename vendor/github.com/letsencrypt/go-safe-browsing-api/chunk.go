/*
Copyright (c) 2014, Kilian Gilonne
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package safebrowsing

import proto "github.com/golang/protobuf/proto"

import (
	"encoding/binary"
	"unsafe"
)

type ChunkNum int32

const CHUNK_TYPE_ADD = ChunkData_ChunkType(0)
const CHUNK_TYPE_SUB = ChunkData_ChunkType(1)

const PREFIX_4B = ChunkData_PrefixType(0)
const PREFIX_32B = ChunkData_PrefixType(1)

const PREFIX_4B_SZ = 4
const PREFIX_32B_SZ = 32

func ReadChunk(data []byte, length uint32) (chunk *ChunkData, new_len uint32, err error) {

	chunk = new(ChunkData)
	uint32_sz := uint32(unsafe.Sizeof(uint32(1)))
	n := binary.BigEndian.Uint32(data[:uint32_sz])

	if length < uint32_sz {
		return nil, 0, nil
	}
	new_len = length - uint32_sz

	if (n <= 0) || (n > new_len) {
		return nil, new_len, nil
	}
	new_len = length - (n + uint32_sz)
	err = proto.Unmarshal(data[uint32_sz:(uint32_sz+n)], chunk)
	if err != nil {
		return nil, new_len, err
	}
	return chunk, new_len, err
}
