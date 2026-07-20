package pubsub

// ring is a fixed-capacity retention buffer of the most recent events, used to
// answer replay-from-sequence requests ("resume from where I dropped off").
// It is bounded on purpose: retention is memory, so a broker never keeps the
// whole history. When a subscriber asks for a sequence older than the oldest
// retained event, the caller learns retention was Truncated rather than
// silently receiving a short prefix — the "no silent caps" invariant.
type ring struct {
	buf  []Event
	head int // index of the oldest element when full
	n    int // number of valid elements
	cap  int
}

func newRing(capacity int) *ring {
	if capacity < 0 {
		capacity = 0
	}
	return &ring{buf: make([]Event, capacity), cap: capacity}
}

// add appends an event, evicting the oldest when at capacity.
func (r *ring) add(ev Event) {
	if r.cap == 0 {
		return
	}
	if r.n < r.cap {
		r.buf[(r.head+r.n)%r.cap] = ev
		r.n++
		return
	}
	// full: overwrite oldest, advance head
	r.buf[r.head] = ev
	r.head = (r.head + 1) % r.cap
}

// since returns retained events whose Seq is strictly greater than afterSeq,
// in order. truncated is true when the buffer no longer holds every event
// after afterSeq (i.e. afterSeq is older than the oldest retained event and
// afterSeq is not zero-for-empty), meaning the replay has an unavoidable gap.
func (r *ring) since(afterSeq uint64) (events []Event, truncated bool) {
	if r.n == 0 {
		return nil, false
	}
	oldest := r.buf[r.head].Seq
	// If the caller wants events strictly after afterSeq but our oldest
	// retained event is already past afterSeq+1, we cannot cover the gap.
	if oldest > afterSeq+1 {
		truncated = true
	}
	for i := 0; i < r.n; i++ {
		ev := r.buf[(r.head+i)%r.cap]
		if ev.Seq > afterSeq {
			events = append(events, ev)
		}
	}
	return events, truncated
}

// snapshot returns all retained events in order (oldest first). Used by tests
// and by chain verification of the live retained window.
func (r *ring) snapshot() []Event {
	out := make([]Event, 0, r.n)
	for i := 0; i < r.n; i++ {
		out = append(out, r.buf[(r.head+i)%r.cap])
	}
	return out
}
