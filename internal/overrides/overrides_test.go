package overrides

import (
	"strings"
	"testing"
)

func TestMatch(t *testing.T) {
	s := New([]string{"bing.com"}, []string{"linkedin.com", "apple.com"})
	cases := []struct {
		qname string
		want  bool
	}{
		{"bing.com.", true},
		{"BING.COM", true},
		{"www.bing.com", false},
		{"linkedin.com", false}, // wildcard does not match apex
		{"www.linkedin.com", true},
		{"a.b.linkedin.com", true},
		{"notlinkedin.com", false},
		{"www.apple.com", true},
		{"apple.com", false},
		{"apple.com.cn", false},
		{"", false},
	}
	for _, c := range cases {
		if got := s.Match(c.qname); got != c.want {
			t.Errorf("Match(%q) = %v, want %v", c.qname, got, c.want)
		}
	}
}

func TestLoad(t *testing.T) {
	s, err := LoadFrom(strings.NewReader(`
# comment
linkedin.com
*.linkedin.com

*.apple.com # inline
*.apple-mapkit.com
*.akadns.net

bing.com
*.bing.com
`))
	if err != nil {
		t.Fatal(err)
	}
	for q, want := range map[string]bool{
		"linkedin.com":     true,
		"www.linkedin.com": true,
		"maps.apple.com":   true,
		"bing.com":         true,
		"cn.bing.com":      true,
		"apple.com":        false,
		"example.com":      false,
	} {
		if got := s.Match(q); got != want {
			t.Errorf("Match(%q) = %v, want %v", q, got, want)
		}
	}
}

func TestDeployedList(t *testing.T) {
	s, err := Load("/home/ubuntu/multiresolver/assets/override_domains.txt")
	if err != nil {
		t.Skipf("asset file not available: %v", err)
	}
	// spot checks against the deployed list
	for q, want := range map[string]bool{
		"www.linkedin.com":   true,
		"linkedin.com":       true,
		"www.apple.com":      true,
		"apple.com":          false, // only *.apple.com, no exact apex entry
		"bing.com":           true,
		"www.bing.com":       true,
		"apple-mapkit.com":   false,
		"x.apple-mapkit.com": true,
		"example.com":        false,
	} {
		if got := s.Match(q); got != want {
			t.Errorf("Match(%q) = %v, want %v", q, got, want)
		}
	}
}
