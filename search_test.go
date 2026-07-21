package main

import "testing"

func TestMatchCriteriaBytes(t *testing.T) {
	cases := []struct {
		prefix, suffix, addr string
		want                 bool
	}{
		{"ab", "", "abcdef0000000000000000000000000000000000", true},
		{"ab", "", "cdabef0000000000000000000000000000000000", false},
		{"", "ef", "abcdef0000000000000000000000000000000000", false},
		{"", "00", "abcdef0000000000000000000000000000000000", true},
		{"ab", "00", "abcdef0000000000000000000000000000000000", true},
		{"ab", "99", "abcdef0000000000000000000000000000000000", false},
		{"", "", "abcdef0000000000000000000000000000000000", true},
	}
	for _, c := range cases {
		got := MatchCriteria{}.matchesBytes([]byte(c.prefix), []byte(c.suffix), []byte(c.addr))
		if got != c.want {
			t.Errorf("matchesBytes(prefix=%q, suffix=%q, addr=%q) = %v, want %v", c.prefix, c.suffix, c.addr, got, c.want)
		}
	}
}
