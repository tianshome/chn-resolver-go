package overrides

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// Set matches domain names against an override list: exact names plus
// wildcard entries of the form "*.example.com", which match any subdomain
// (qname.endswith("." + suffix)) but not the apex itself.
type Set struct {
	exact    map[string]struct{}
	wildcard []string // suffixes without the leading "*."
}

func New(exact []string, wildcard []string) *Set {
	s := &Set{exact: make(map[string]struct{}, len(exact))}
	for _, e := range exact {
		e = normalize(e)
		if e != "" {
			s.exact[e] = struct{}{}
		}
	}
	for _, w := range wildcard {
		w = normalize(w)
		if w != "" {
			s.wildcard = append(s.wildcard, w)
		}
	}
	return s
}

// Load reads an override file: one entry per line, blank lines and
// #/;// comments ignored.
func Load(path string) (*Set, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s, err := LoadFrom(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// LoadFrom parses override entries from a reader (used by tests).
func LoadFrom(r io.Reader) (*Set, error) {
	var exact, wildcard []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, ";") || strings.HasPrefix(raw, "//") {
			continue
		}
		for _, sep := range []string{" #", "\t#", " ;", "\t;", " //", "\t//"} {
			if i := strings.Index(raw, sep); i >= 0 {
				raw = strings.TrimSpace(raw[:i])
				break
			}
		}
		if raw == "" {
			continue
		}
		if strings.HasPrefix(raw, "*.") {
			wildcard = append(wildcard, raw[2:])
		} else {
			exact = append(exact, raw)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return New(exact, wildcard), nil
}

// Match reports whether qname is on the override list.
func (s *Set) Match(qname string) bool {
	q := normalize(qname)
	if q == "" {
		return false
	}
	if _, ok := s.exact[q]; ok {
		return true
	}
	for _, suffix := range s.wildcard {
		if strings.HasSuffix(q, "."+suffix) {
			return true
		}
	}
	return false
}

func normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}
