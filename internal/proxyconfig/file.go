package proxyconfig

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadLines reads non-empty, non-comment proxy lines from a file (host:port:user:pass).
func LoadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("no proxies in %s", path)
	}
	return lines, nil
}

// PickLine returns a random proxy line (caller provides rng.Intn).
func PickLine(lines []string, index int) string {
	if len(lines) == 0 {
		return ""
	}
	if index < 0 {
		index = 0
	}
	return lines[index%len(lines)]
}
