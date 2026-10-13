// Package transport filters child output without buffering complete streams.
package transport

import (
	"bytes"
	"errors"
	"io"
)

const replacement = "<redacted>"
const maxPatterns = 4 << 20

type edge struct {
	b  byte
	to *node
}
type node struct {
	next   []edge
	fail   *node
	output *node
	length int
	depth  int
}

// step follows a literal edge without allocating per-byte maps.
func (n *node) step(b byte) *node {
	for i := range n.next {
		if n.next[i].b == b {
			return n.next[i].to
		}
	}
	return nil
}

// Matcher holds a bounded Aho-Corasick automaton of every nonempty literal.
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
		if len(value) > maxPatterns-total {
			return nil, errors.New("redaction pattern limit exceeded")
		}
		total += len(value)
		if len(value) > m.Max {
			m.Max = len(value)
		}
		n := m.root
		for _, b := range value {
			child := n.step(b)
			if child == nil {
				child = &node{depth: n.depth + 1}
				n.next = append(n.next, edge{b, child})
			}
			n = child
		}
		n.length = len(value)
	}
	// Breadth-first failure links allow matching across arbitrary read boundaries.
	queue := make([]*node, 0, total)
	for _, e := range m.root.next {
		e.to.fail = m.root
		queue = append(queue, e.to)
	}
	for i := 0; i < len(queue); i++ {
		current := queue[i]
		for _, e := range current.next {
			fail := current.fail
			for fail != m.root && fail.step(e.b) == nil {
				fail = fail.fail
			}
			e.to.fail = fail.step(e.b)
			if e.to.fail == nil {
				e.to.fail = m.root
			}
			if e.to.fail.length != 0 {
				e.to.output = e.to.fail
			} else {
				e.to.output = e.to.fail.output
			}
			queue = append(queue, e.to)
		}
	}
	return m, nil
}

// Filter records longest matches by start and releases only starts that can no
// longer extend. The earliest remaining start wins, even across read chunks.
func (m *Matcher) Filter(in io.Reader, out io.Writer) error {
	if m.Max == 0 {
		_, err := io.Copy(out, in)
		return err
	}
	ring := make([]byte, m.Max)
	best := make([]int, m.Max)
	chunk := make([]byte, 8192)
	var filtered bytes.Buffer
	state := m.root
	position, start := 0, 0
	flush := func() error {
		if filtered.Len() == 0 {
			return nil
		}
		n, err := out.Write(filtered.Bytes())
		if err != nil {
			return err
		}
		if n != filtered.Len() {
			return io.ErrShortWrite
		}
		filtered.Reset()
		return nil
	}
	emit := func() error {
		index := start % m.Max
		length := best[index]
		if length > 0 {
			filtered.WriteString(replacement)
		} else {
			filtered.WriteByte(ring[index])
			length = 1
		}
		for i := 0; i < length; i++ {
			best[(start+i)%m.Max] = 0
		}
		start += length
		if filtered.Len() >= 8192 {
			return flush()
		}
		return nil
	}
	for {
		count, readErr := in.Read(chunk)
		for _, b := range chunk[:count] {
			for state != m.root && state.step(b) == nil {
				state = state.fail
			}
			if next := state.step(b); next != nil {
				state = next
			}
			ring[position%m.Max] = b
			for n := state; n != nil && n != m.root; n = n.output {
				if n.length == 0 {
					continue
				}
				candidate := position + 1 - n.length
				if candidate >= start && n.length > best[candidate%m.Max] {
					best[candidate%m.Max] = n.length
				}
			}
			position++
			unfinished := state
			for unfinished != m.root && len(unfinished.next) == 0 {
				unfinished = unfinished.fail
			}
			for start < position-unfinished.depth {
				if err := emit(); err != nil {
					return err
				}
			}
		}
		if err := flush(); err != nil {
			return err
		}
		if readErr == io.EOF {
			for start < position {
				if err := emit(); err != nil {
					return err
				}
			}
			return flush()
		}
		if readErr != nil {
			return errors.New("redaction input failed")
		}
		if count == 0 {
			return errors.New("redaction input made no progress")
		}
	}
}
