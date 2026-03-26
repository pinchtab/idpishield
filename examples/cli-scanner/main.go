// cli-scanner demonstrates using the idpishield Go library from a small CLI.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	idpi "github.com/pinchtab/idpishield"
)

func main() {
	mode := flag.String("mode", "balanced", "analysis mode: fast|balanced|deep")
	domains := flag.String("domains", "", "comma-separated allowed domains")
	url := flag.String("url", "", "source URL for domain checks")
	strict := flag.Bool("strict", false, "enable strict mode")
	text := flag.String("text", "", "text to scan (optional, otherwise stdin)")
	flag.Parse()

	input := strings.TrimSpace(*text)
	if input == "" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read stdin: %v\n", err)
			os.Exit(1)
		}
		input = string(b)
	}

	shield := idpi.New(idpi.Config{
		Mode:           idpi.ParseMode(*mode),
		AllowedDomains: parseDomains(*domains),
		StrictMode:     *strict,
	})

	result := shield.Assess(input, *url)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(result)
}

func parseDomains(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
