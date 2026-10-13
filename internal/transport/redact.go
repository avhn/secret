// Package transport filters child output without buffering complete streams.
package transport

import (
	"bytes"
	"errors"
	"io"
)

const replacement = "<redacted>"
const maxPatterns = 4 << 20

type node struct {
	next map[byte]*node
	end  bool
}

// Matcher holds a bounded trie of every nonempty loaded literal.
type Matcher struct {
	root *node
	Max  int
}

func NewMatcher(values [][]byte) (*Matcher, error) {
	m := &Matcher{root: &node{}}
	total := 0
	for _, value := range values {
		if len(value) == 0 {
			continue
		}
		if total+len(value) > maxPatterns {
			return nil, errors.New("redaction pattern limit exceeded")
		}
		// Count the raw input too so duplicate records cannot evade the bound.
		total += len(value)
		if len(value) > m.Max {
			m.Max = len(value)
		}
		n := m.root
		for _, b := range value {
			if n.next == nil {
				n.next = make(map[byte]*node)
			}
			if n.next[b] == nil {
				n.next[b] = &node{}
			}
			n = n.next[b]
		}
		n.end = true
	}
	return m, nil
}

func (m *Matcher) longest(buf []byte) int {
	n := m.root
	longest := 0
	for i, b := range buf {
		n = n.next[b]
		if n == nil {
			break
		}
		if n.end {
			longest = i + 1
		}
	}
	return longest
}

// Filter uses the Perl filter's byte buffering: defer the last Max-1 possible
// starts until the next read or EOF. At a start, the longest literal wins.
func (m *Matcher) Filter(in io.Reader, out io.Writer) error {
	chunk := make([]byte, 8192)
	buf := make([]byte, 0, 8192+m.Max)
	for {
		count, readErr := in.Read(chunk)
		buf = append(buf, chunk[:count]...)
		limit := len(buf)
		if readErr == nil && m.Max > 0 {
			limit -= m.Max - 1
		}
		if limit < 0 {
			limit = 0
		}
		pos := 0
		var filtered bytes.Buffer
		for pos < limit {
			if n := m.longest(buf[pos:]); n > 0 {
				filtered.WriteString(replacement)
				pos += n
			} else {
				filtered.WriteByte(buf[pos])
				pos++
			}
		}
		if filtered.Len() > 0 {
			n, e := out.Write(filtered.Bytes())
			if e != nil {
				return e
			}
			if n != filtered.Len() {
				return io.ErrShortWrite
			}
		}
		copy(buf, buf[pos:])
		buf = buf[:len(buf)-pos]
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return errors.New("redaction input failed")
		}
		if count == 0 {
			return errors.New("redaction input made no progress")
		}
	}
}
