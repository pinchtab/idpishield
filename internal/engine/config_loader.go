package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type FileConfig struct {
	BanSubstrings  []string `json:"ban_substrings" yaml:"ban_substrings"`
	BanTopics      []string `json:"ban_topics" yaml:"ban_topics"`
	BanCompetitors []string `json:"ban_competitors" yaml:"ban_competitors"`
	CustomRegex    []string `json:"custom_regex" yaml:"custom_regex"`
}

const (
	yamlKeyBanSubstrings  = "ban_substrings"
	yamlKeyBanTopics      = "ban_topics"
	yamlKeyBanCompetitors = "ban_competitors"
	yamlKeyCustomRegex    = "custom_regex"
)

// ResolveConfig merges direct config values with optional config-file values,
// then deduplicates all user-defined rule lists.
func ResolveConfig(cfg Config) (Config, error) {
	resolved := cfg

	if strings.TrimSpace(cfg.ConfigFile) != "" {
		fc, err := loadConfigFile(cfg.ConfigFile)
		if err != nil {
			return Config{}, err
		}
		resolved.BanSubstrings = append(resolved.BanSubstrings, fc.BanSubstrings...)
		resolved.BanTopics = append(resolved.BanTopics, fc.BanTopics...)
		resolved.BanCompetitors = append(resolved.BanCompetitors, fc.BanCompetitors...)
		resolved.CustomRegex = append(resolved.CustomRegex, fc.CustomRegex...)
	}

	// Deduplication runs after all sources (config struct, file)
	// are merged so the same phrase from multiple sources is only
	// checked once, preventing inflated scores from duplicate rules.
	resolved.BanSubstrings = deduplicateStrings(resolved.BanSubstrings)
	resolved.BanTopics = deduplicateStrings(resolved.BanTopics)
	resolved.BanCompetitors = deduplicateStrings(resolved.BanCompetitors)
	resolved.CustomRegex = deduplicateStrings(resolved.CustomRegex)

	return resolved, nil
}

func loadConfigFile(path string) (FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return FileConfig{}, err
	}

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		var fc FileConfig
		if err := json.Unmarshal(data, &fc); err != nil {
			return FileConfig{}, err
		}
		return fc, nil
	case ".yaml", ".yml":
		return parseSimpleYAML(data)
	default:
		return FileConfig{}, fmt.Errorf("unsupported config file format %q: expected .json, .yaml, or .yml", ext)
	}
}

func parseSimpleYAML(data []byte) (FileConfig, error) {
	currentKey := ""
	items := map[string][]string{}

	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if key, ok := parseYAMLKey(line); ok {
			if !isSupportedYAMLKey(key) {
				return FileConfig{}, fmt.Errorf("unsupported YAML key %q at line %d", key, i+1)
			}
			currentKey = key
			continue
		}

		if value, ok := parseYAMLListItem(line); ok {
			if currentKey == "" {
				return FileConfig{}, fmt.Errorf("YAML list item without key at line %d", i+1)
			}
			value = stripQuotes(value)
			if value == "" {
				continue
			}
			items[currentKey] = append(items[currentKey], value)
			continue
		}

		return FileConfig{}, fmt.Errorf("unsupported YAML line format at line %d", i+1)
	}

	return buildFileConfig(currentKey, items), nil
}

func parseYAMLKey(line string) (key string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasSuffix(trimmed, ":") {
		return "", false
	}
	return strings.TrimSpace(strings.TrimSuffix(trimmed, ":")), true
}

func parseYAMLListItem(line string) (value string, ok bool) {
	if !strings.HasPrefix(line, "  - ") {
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(line, "  - ")), true
}

func stripQuotes(s string) string {
	trimmed := strings.TrimSpace(s)
	trimmed = strings.Trim(trimmed, `"`)
	trimmed = strings.Trim(trimmed, `'`)
	return strings.TrimSpace(trimmed)
}

func buildFileConfig(currentKey string, items map[string][]string) FileConfig {
	_ = currentKey
	return FileConfig{
		BanSubstrings:  items[yamlKeyBanSubstrings],
		BanTopics:      items[yamlKeyBanTopics],
		BanCompetitors: items[yamlKeyBanCompetitors],
		CustomRegex:    items[yamlKeyCustomRegex],
	}
}

func isSupportedYAMLKey(key string) bool {
	switch key {
	case yamlKeyBanSubstrings, yamlKeyBanTopics, yamlKeyBanCompetitors, yamlKeyCustomRegex:
		return true
	default:
		return false
	}
}

// LoadEnvVars parses optional CLI environment variables into ban-list config.
// Library consumers should pass configuration directly via Config or ConfigFile.
func LoadEnvVars() FileConfig {
	return FileConfig{
		BanSubstrings:  parseEnvList("IDPISHIELD_BAN_SUBSTRINGS"),
		BanTopics:      parseEnvList("IDPISHIELD_BAN_TOPICS"),
		BanCompetitors: parseEnvList("IDPISHIELD_BAN_COMPETITORS"),
		CustomRegex:    parseEnvList("IDPISHIELD_CUSTOM_REGEX"),
	}
}

func parseEnvList(name string) []string {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	items := make([]string, 0, len(parts))
	for _, p := range parts {
		item := strings.TrimSpace(p)
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}

func deduplicateStrings(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(s))
	out := make([]string, 0, len(s))
	for _, v := range s {
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}
