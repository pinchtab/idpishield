package engine

// Built-in scanners are hardcoded for performance and security.
// They cannot be disabled via the plugin system.
// Custom scanners added via ExtraScanners run AFTER built-ins.
//
// To understand how to write a custom scanner, see the built-in
// scanners as reference implementations:
//   - scanner_secrets.go    (regex + entropy detection)
//   - scanner_toxicity.go   (tiered phrase detection)
//   - scanner_gibberish.go  (statistical text analysis)
//   - scanner_emotion.go    (category-based phrase detection)
//   - scanner_banlist.go    (user-configurable rules)
