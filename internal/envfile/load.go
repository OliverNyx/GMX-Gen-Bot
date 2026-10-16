package envfile

import (
	"os"
	"strings"
)

// Load reads KEY=VALUE lines from path into the process environment.
// Values in the file replace variables already set, so .env is the project config.
func Load(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"'`)
		if k == "" {
			continue
		}
		_ = os.Setenv(k, v)
	}
}
