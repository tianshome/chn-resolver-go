package china

import (
	"net/netip"
	"sort"
)

// span is an inclusive address range [lo, hi] within one address family.
type span struct {
	lo, hi netip.Addr
}

// Index classifies addresses via binary search over disjoint merged spans,
// one sorted slice per family.
type Index struct {
	v4 []span
	v6 []span
	// input counts, for logging
	V4Input, V6Input int
}

// Build merges overlapping prefixes into disjoint spans and sorts them.
func Build(prefixes []netip.Prefix) *Index {
	var v4, v6 []span
	v4n, v6n := 0, 0
	for _, p := range prefixes {
		if p.Addr().Is4() {
			v4n++
			v4 = append(v4, span{p.Addr(), lastAddr(p)})
		} else {
			v6n++
			v6 = append(v6, span{p.Addr(), lastAddr(p)})
		}
	}
	return &Index{v4: merge(v4), v6: merge(v6), V4Input: v4n, V6Input: v6n}
}

func (ix *Index) Counts() (v4, v6 int) {
	return len(ix.v4), len(ix.v6)
}

// Contains reports whether ip is inside any indexed prefix.
func (ix *Index) Contains(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.Is4() {
		return contains(ix.v4, ip)
	}
	return contains(ix.v6, ip)
}

func contains(spans []span, ip netip.Addr) bool {
	i := sort.Search(len(spans), func(i int) bool { return spans[i].hi.Compare(ip) >= 0 })
	if i == len(spans) || spans[i].lo.Compare(ip) > 0 {
		return false
	}
	return true
}

// lastAddr returns the highest address of a masked prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr()
	if p.Bits() == a.BitLen() {
		return a
	}
	b := a.As16()
	hostBits := a.BitLen() - p.Bits()
	for i := len(b) - 1; i >= 0 && hostBits > 0; i-- {
		bits := hostBits
		if bits > 8 {
			bits = 8
		}
		b[i] |= byte(0xFF >> (8 - bits))
		hostBits -= 8
	}
	return netip.AddrFrom16(b).Unmap()
}

// merge sorts spans and merges overlapping (and adjacent) ones.
func merge(spans []span) []span {
	if len(spans) <= 1 {
		return spans
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].lo.Compare(spans[j].lo) < 0 })
	out := spans[:0]
	cur := spans[0]
	for _, s := range spans[1:] {
		if s.lo.Compare(cur.hi) <= 0 || nextAddr(cur.hi).Compare(s.lo) == 0 {
			if s.hi.Compare(cur.hi) > 0 {
				cur.hi = s.hi
			}
			continue
		}
		out = append(out, cur)
		cur = s
	}
	return append(out, cur)
}

// nextAddr returns the successor of a, or a itself on overflow.
func nextAddr(a netip.Addr) netip.Addr {
	b := a.As16()
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
	return netip.AddrFrom16(b).Unmap()
}
