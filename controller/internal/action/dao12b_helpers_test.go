package action

import "testing"

func dao12bWant(t *testing.T, name string, yes bool, detail any) {
	t.Helper()
	if !yes {
		t.Errorf("ASSERT %s FAIL %v", name, detail)
	} else {
		t.Logf("ASSERT %s PASS %v", name, detail)
	}
}
