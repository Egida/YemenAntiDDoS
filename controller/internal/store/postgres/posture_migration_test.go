package postgres

import (
	"regexp"
	"strings"
	"testing"
)

func TestNodePostureMigrationPresent(t *testing.T) {
	joined := strings.Join(migrations, "\n")
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS ts_node_posture",
		"ts_node_posture_node_time",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("migrations missing %q", want)
		}
	}
	// Idempotency: CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT EXISTS only.
	re := regexp.MustCompile(`(?s)CREATE TABLE IF NOT EXISTS ts_node_posture.*?CREATE INDEX IF NOT EXISTS ts_node_posture_node_time`)
	if !re.MatchString(joined) {
		t.Error("ts_node_posture DDL must be guarded with IF NOT EXISTS")
	}
}
