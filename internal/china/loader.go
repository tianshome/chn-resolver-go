package china

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
)

// ParsePrefixLine parses one line of a prefix file (see prefixes.py semantics:
// strip whitespace; blank and #/;// comment lines skipped; inline comments
// allowed after whitespace; host bits masked as with ip_network(strict=False)).
// ok=false means the line should be skipped (blank/comment).
func ParsePrefixLine(raw string) (p netip.Prefix, ok bool, err error) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
		return netip.Prefix{}, false, nil
	}
	for _, sep := range []string{" #", "\t#", " ;", "\t;", " //", "\t//"} {
		if i := strings.Index(line, sep); i >= 0 {
			line = strings.TrimSpace(line[:i])
			break
		}
	}
	if line == "" {
		return netip.Prefix{}, false, nil
	}
	p, err = netip.ParsePrefix(line)
	if err != nil {
		return netip.Prefix{}, false, fmt.Errorf("bad prefix %q: %w", line, err)
	}
	return p.Masked(), true, nil
}

// Load reads prefix files and builds an Index.
func Load(paths ...string) (*Index, error) {
	var all []netip.Prefix
	for _, path := range paths {
		n, err := loadFile(path, &all)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, fmt.Errorf("no prefixes found in %s", path)
		}
	}
	return Build(all), nil
}

// LoadFrom builds an Index from a reader (used by tests).
func LoadFrom(r io.Reader) (*Index, error) {
	var all []netip.Prefix
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		p, ok, err := ParsePrefixLine(sc.Text())
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if ok {
			all = append(all, p)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return Build(all), nil
}

func loadFile(path string, dst *[]netip.Prefix) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	before := len(*dst)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		p, ok, err := ParsePrefixLine(sc.Text())
		if err != nil {
			return 0, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		if ok {
			*dst = append(*dst, p)
		}
	}
	if err := sc.Err(); err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	return len(*dst) - before, nil
}
