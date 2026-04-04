package engine

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadConfigFile_JSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	content := `{"ban_substrings":["alpha"],"ban_topics":["crypto"],"ban_competitors":["OpenAI"],"custom_regex":["\\bORDER-[0-9]{6}\\b"]}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfigFile(path)
	if err != nil {
		t.Fatalf("loadConfigFile failed: %v", err)
	}
	if !reflect.DeepEqual(cfg.BanSubstrings, []string{"alpha"}) {
		t.Fatalf("unexpected BanSubstrings: %v", cfg.BanSubstrings)
	}
	if !reflect.DeepEqual(cfg.BanTopics, []string{"crypto"}) {
		t.Fatalf("unexpected BanTopics: %v", cfg.BanTopics)
	}
	if !reflect.DeepEqual(cfg.BanCompetitors, []string{"OpenAI"}) {
		t.Fatalf("unexpected BanCompetitors: %v", cfg.BanCompetitors)
	}
	if !reflect.DeepEqual(cfg.CustomRegex, []string{`\bORDER-[0-9]{6}\b`}) {
		t.Fatalf("unexpected CustomRegex: %v", cfg.CustomRegex)
	}
}

func TestLoadConfigFile_YAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	yaml := "ban_substrings:\n  - \"phrase one\"\nban_topics:\n  - \"crypto\"\nban_competitors:\n  - \"OpenAI\"\ncustom_regex:\n  - '\\bORDER-[0-9]{6}\\b'\n"
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfigFile(path)
	if err != nil {
		t.Fatalf("loadConfigFile failed: %v", err)
	}
	if !reflect.DeepEqual(cfg.BanSubstrings, []string{"phrase one"}) {
		t.Fatalf("unexpected BanSubstrings: %v", cfg.BanSubstrings)
	}
	if !reflect.DeepEqual(cfg.BanTopics, []string{"crypto"}) {
		t.Fatalf("unexpected BanTopics: %v", cfg.BanTopics)
	}
	if !reflect.DeepEqual(cfg.BanCompetitors, []string{"OpenAI"}) {
		t.Fatalf("unexpected BanCompetitors: %v", cfg.BanCompetitors)
	}
	if !reflect.DeepEqual(cfg.CustomRegex, []string{`\bORDER-[0-9]{6}\b`}) {
		t.Fatalf("unexpected CustomRegex: %v", cfg.CustomRegex)
	}
}

func TestLoadConfigFile_InvalidPath(t *testing.T) {
	_, err := loadConfigFile(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}

func TestLoadEnvVars_ParsesCommaSeparated(t *testing.T) {
	t.Setenv("IDPISHIELD_BAN_TOPICS", "crypto,gambling, adult")
	cfg := LoadEnvVars()
	want := []string{"crypto", "gambling", "adult"}
	if !reflect.DeepEqual(cfg.BanTopics, want) {
		t.Fatalf("expected %v, got %v", want, cfg.BanTopics)
	}
}

func TestLoadEnvVars_EmptyEnv(t *testing.T) {
	t.Setenv("IDPISHIELD_BAN_SUBSTRINGS", "")
	t.Setenv("IDPISHIELD_BAN_TOPICS", "")
	t.Setenv("IDPISHIELD_BAN_COMPETITORS", "")
	t.Setenv("IDPISHIELD_CUSTOM_REGEX", "")
	cfg := LoadEnvVars()
	if len(cfg.BanSubstrings) != 0 || len(cfg.BanTopics) != 0 || len(cfg.BanCompetitors) != 0 || len(cfg.CustomRegex) != 0 {
		t.Fatalf("expected empty env config, got %+v", cfg)
	}
}

func TestLoadEnvVars_TrailingComma(t *testing.T) {
	t.Setenv("IDPISHIELD_BAN_TOPICS", "crypto,gambling,")
	cfg := LoadEnvVars()
	if len(cfg.BanTopics) != 2 {
		t.Fatalf("expected 2 topics, got %d (%v)", len(cfg.BanTopics), cfg.BanTopics)
	}
	if !reflect.DeepEqual(cfg.BanTopics, []string{"crypto", "gambling"}) {
		t.Fatalf("unexpected topics: %v", cfg.BanTopics)
	}
}

func TestLoadEnvVars_SpacesAroundComma(t *testing.T) {
	t.Setenv("IDPISHIELD_BAN_TOPICS", "crypto , gambling")
	cfg := LoadEnvVars()
	if !reflect.DeepEqual(cfg.BanTopics, []string{"crypto", "gambling"}) {
		t.Fatalf("expected [crypto gambling], got %v", cfg.BanTopics)
	}
}

func TestLoadEnvVars_EmptyString(t *testing.T) {
	t.Setenv("IDPISHIELD_BAN_TOPICS", "")
	cfg := LoadEnvVars()
	if len(cfg.BanTopics) != 0 {
		t.Fatalf("expected empty topics, got %v", cfg.BanTopics)
	}
}

func TestMergeOrder_ConfigFileOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	content := `{"ban_substrings":["from-file"]}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	resolved, err := ResolveConfig(Config{
		BanSubstrings: []string{"from-direct"},
		ConfigFile:    path,
	})
	if err != nil {
		t.Fatalf("ResolveConfig failed: %v", err)
	}

	if !reflect.DeepEqual(resolved.BanSubstrings, []string{"from-direct", "from-file"}) {
		t.Fatalf("unexpected merged order: %v", resolved.BanSubstrings)
	}
}
