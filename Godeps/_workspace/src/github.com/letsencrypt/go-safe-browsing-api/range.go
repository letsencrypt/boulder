/*
Copyright (c) 2013, Richard Johnson
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

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

func buildChunkRanges(chunkIndexes map[ChunkNum]bool) string {
	if chunkIndexes == nil || len(chunkIndexes) == 0 {
		return ""
	}
	// find the highest and lowest chunk numbers
	lowest := int64(-1)
	highest := int64(-1)
	for chunkNumUint, _ := range chunkIndexes {
		chunkNum := int64(chunkNumUint)
		if lowest == -1 || lowest > chunkNum {
			lowest = chunkNum
		}
		if highest == -1 || highest < chunkNum {
			highest = chunkNum
		}
	}
	if len(chunkIndexes) == 1 {
		return fmt.Sprintf("%d", lowest)
	}
	output := &bytes.Buffer{}
	start := lowest
	end := lowest
	inRange := true
	for end = lowest; end <= highest; end++ {
		if _, exists := chunkIndexes[ChunkNum(end)]; exists {
			if inRange {
				continue
			}
			start = end
			inRange = true
			continue
		}
		if inRange {
			if start == end-1 {
				fmt.Fprintf(output, "%d,", start)
			} else {
				fmt.Fprintf(output, "%d-%d,", start, end-1)
			}
			inRange = false
			start = end
		}
	}
	if start == end-1 {
		fmt.Fprintf(output, "%d", start)
	} else {
		fmt.Fprintf(output, "%d-%d", start, end-1)
	}
	return output.String()
}

func parseChunkRange(rangeString string) (out map[ChunkNum]bool, err error) {
	out = make(map[ChunkNum]bool)
	rangeString = strings.TrimSpace(rangeString)
	ranges := strings.Split(rangeString, ",")
	for _, r := range ranges {
		if len(r) == 0 {
			return nil, fmt.Errorf("Invalid range")
		}
		numbers := strings.Split(r, "-")
		if len(numbers) > 2 {
			return nil, fmt.Errorf("Invalid range")
		}
		if len(numbers) == 1 {
			i, err := strconv.Atoi(numbers[0])
			if err != nil {
				return nil, fmt.Errorf("Invalid range")
			}
			out[ChunkNum(i)] = true
			continue
		}
		x, err := strconv.Atoi(numbers[0])
		if err != nil {
			return nil, fmt.Errorf("Invalid range")
		}
		y, err := strconv.Atoi(numbers[1])
		if err != nil {
			return nil, fmt.Errorf("Invalid range")
		}
		for ; x <= y; x++ {
			out[ChunkNum(x)] = true
		}
	}
	return out, nil
}
