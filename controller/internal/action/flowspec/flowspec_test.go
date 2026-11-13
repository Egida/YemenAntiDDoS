package flowspec

import "testing"

func TestDescribe(t *testing.T) {
	r := Rule{Name: "x", Prefix: "198.51.100.7/32", Action: ActionDrop}
	want := "destination 198.51.100.7/32, drop (traffic-rate 0)"
	if got := Describe(r); got != want {
		t.Fatalf("Describe = %q, want %q", got, want)
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
		ok   bool
	}{
		{"missing name", Rule{Prefix: "1.2.3.4/32"}, false},
		{"missing prefix", Rule{Name: "r"}, false},
		{"default action drop", Rule{Name: "r", Prefix: "1.2.3.4/32"}, true},
		{"rate without value", Rule{Name: "r", Prefix: "1.2.3.4/32", Action: ActionRateLimit}, false},
		{"rate with value", Rule{Name: "r", Prefix: "1.2.3.4/32", Action: ActionRateLimit, RateLimit: 5}, true},
		{"bad action", Rule{Name: "r", Prefix: "1.2.3.4/32", Action: "redirect"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.rule.Validate()
			if (err == nil) != tc.ok {
				t.Fatalf("Validate() err=%v, want ok=%v", err, tc.ok)
			}
		})
	}
}
