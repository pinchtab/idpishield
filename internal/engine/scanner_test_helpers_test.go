package engine

// containsCategory reports whether target appears in categories.
func containsCategory(categories []string, target string) bool {
	for _, c := range categories {
		if c == target {
			return true
		}
	}
	return false
}
