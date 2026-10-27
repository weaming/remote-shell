package mcpserver

import (
	"sync"

	"remote-shell/execution"
)

// outputBuffer keeps a bounded window of task output in arrival order while
// tracking absolute byte offsets, so a reader can page through what is still
// retained and learn how much of the beginning was dropped.
//
// One buffer serves three views: the interleaved stdout+stderr sequence (an
// empty stream) and each stream on its own. Offsets are per view.
type outputBuffer struct {
	mu            sync.Mutex
	max           int64
	chunks        []outputChunk
	mixedTotal    int64
	streamTotal   map[execution.Stream]int64
	mixedDropped  int64
	streamDropped map[execution.Stream]int64
}

type outputChunk struct {
	stream      execution.Stream
	data        []byte
	mixedStart  int64
	streamStart int64
}

func newOutputBuffer(max int64) *outputBuffer {
	return &outputBuffer{
		max:           max,
		streamTotal:   make(map[execution.Stream]int64, 2),
		streamDropped: make(map[execution.Stream]int64, 2),
	}
}

// Append records one output chunk, trimming the oldest retained bytes past the
// limit. A non-positive max keeps everything, which callers do not request.
func (b *outputBuffer) Append(stream execution.Stream, data []byte) {
	if len(data) == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.chunks = append(b.chunks, outputChunk{
		stream:      stream,
		data:        append([]byte(nil), data...),
		mixedStart:  b.mixedTotal,
		streamStart: b.streamTotal[stream],
	})
	b.mixedTotal += int64(len(data))
	b.streamTotal[stream] += int64(len(data))
	b.trim()
}

// read returns retained bytes of one view starting at offset, at most limit
// bytes (limit <= 0 returns everything retained). start is the absolute offset
// of the first returned byte, which is later than offset once bytes were
// trimmed. more reports that bytes after the returned window still exist.
func (b *outputBuffer) read(stream execution.Stream, offset, limit int64) (data []byte, start, next int64, more bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	total, base := b.mixedTotal, b.mixedDropped
	if stream != "" {
		total, base = b.streamTotal[stream], b.streamDropped[stream]
	}
	if offset < base {
		offset = base
	}
	if offset > total {
		offset = total
	}
	end := total
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	data = make([]byte, 0, end-offset)
	for _, chunk := range b.chunks {
		var chunkStart int64
		switch {
		case stream == "":
			chunkStart = chunk.mixedStart
		case chunk.stream == stream:
			chunkStart = chunk.streamStart
		default:
			continue
		}
		chunkEnd := chunkStart + int64(len(chunk.data))
		if chunkEnd <= offset || chunkStart >= end {
			continue
		}
		from := max(offset-chunkStart, 0)
		to := min(end-chunkStart, int64(len(chunk.data)))
		data = append(data, chunk.data[from:to]...)
	}
	return data, offset, end, end < total
}

func (b *outputBuffer) retained(stream execution.Stream) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.retainedLocked(stream)
}

func (b *outputBuffer) retainedLocked(stream execution.Stream) int64 {
	if stream == "" {
		return b.mixedTotal - b.mixedDropped
	}
	return b.streamTotal[stream] - b.streamDropped[stream]
}

// streamBytes reports how many bytes a stream has produced, including bytes
// already dropped from the buffer.
func (b *outputBuffer) streamBytes(stream execution.Stream) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.streamTotal[stream]
}

// trimmed reports how many bytes were dropped from the beginning of a view.
func (b *outputBuffer) trimmed(stream execution.Stream) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if stream == "" {
		return b.mixedDropped
	}
	return b.streamDropped[stream]
}

// trim is called with the lock held.
func (b *outputBuffer) trim() {
	if b.max <= 0 {
		return
	}
	for b.retainedLocked("") > b.max && len(b.chunks) > 0 {
		excess := b.retainedLocked("") - b.max
		head := &b.chunks[0]
		size := int64(len(head.data))
		if size <= excess {
			b.mixedDropped += size
			b.streamDropped[head.stream] += size
			b.chunks = b.chunks[1:]
			continue
		}
		head.data = head.data[excess:]
		head.mixedStart += excess
		head.streamStart += excess
		b.mixedDropped += excess
		b.streamDropped[head.stream] += excess
	}
}
