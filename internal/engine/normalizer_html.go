package engine

import (
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/net/html"
)

var htmlClosingTagHeuristic = regexp.MustCompile(`(?is)</\s*[a-z][a-z0-9:-]*\s*>`)
var htmlKnownTagHeuristic = regexp.MustCompile(`(?is)<\s*(?:!doctype|html|head|body|meta|title|div|span|p|a|img|section|article|main|header|footer|nav|aside|h[1-6]|ul|ol|li|table|thead|tbody|tr|th|td|form|input|button|label|textarea|select|option|code|pre|blockquote|strong|em|br|hr)\b`)
var opacityZeroHiddenPattern = regexp.MustCompile(`opacity:0(?:\.0+)?(?:;|!important|$)`)
var filterOpacityZeroHiddenPattern = regexp.MustCompile(`filter:opacity\(0(?:\s*\)|\s*!important)`)
var transformScaleZeroHiddenPattern = regexp.MustCompile(`transform:scale\(0(?:\s*\)|\s*!important)`)
var fontSizeZeroHiddenPattern = regexp.MustCompile(`font-size:0(?:px|em|pt|rem|%)?(?:;|!important|$)`)
var clipPathHiddenPattern = regexp.MustCompile(`clip-path:(?:inset\((?:9[5-9]%|100%|100v[hw]|(?:100|[1-9]\d{2,})\s*px)\)|polygon\(0(?:\s+)?0\)|circle\(0\))`)
var styleColorPattern = regexp.MustCompile(`(?:^|;)color:([^;]+)`)
var styleBackgroundPattern = regexp.MustCompile(`(?:^|;)(?:background|background-color):([^;]+)`)
var colorHexPattern = regexp.MustCompile(`^#([0-9a-f]{3}|[0-9a-f]{6})$`)
var colorRGBPattern = regexp.MustCompile(`^rgb\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*\)$`)
var colorHSLPattern = regexp.MustCompile(`^hsl\((\d+),\s*(\d+)%?,\s*(\d+)%?\)$`)
var instructionLikeHTMLPattern = regexp.MustCompile(`(?i)\b(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions?|disregard\s+(?:all\s+)?(?:(?:previous|prior)\s+)?instructions?|override\s+(?:system|assistant)\s+(?:instructions?|prompt)|bypass\s+security(?:\s+controls?)?|reveal\s+(?:the\s+)?(?:system\s+prompt|secrets?)|jailbreak\s+(?:the\s+)?system|exfiltrat(?:e|ion)\s+(?:data|secrets?)|dump\s+secrets?)\b`)

// looksLikeHTML performs a lightweight heuristic check to avoid parsing plain text.
func looksLikeHTML(input string) bool {
	s := strings.TrimSpace(input)
	if len(s) < 3 {
		return false
	}
	if !strings.Contains(s, "<") || !strings.Contains(s, ">") {
		return false
	}
	if strings.Contains(s, "<!--") {
		return true
	}
	if htmlClosingTagHeuristic.MatchString(s) {
		return true
	}
	return htmlKnownTagHeuristic.MatchString(s)
}

type htmlExtractionState struct {
	visibleText []string
	hiddenText  []string
	comments    []string
	attrs       []string

	hasZeroWidthInjection      bool
	hasAriaHiddenContent       bool
	hasCollapsedDetailsContent bool
}

// extractHTMLContent parses HTML and combines visible and non-visible content
// into a single string suitable for downstream pattern scanning.
func extractHTMLContent(input string) (combined string, signals normalizationSignals, ok bool) {
	root, err := html.Parse(strings.NewReader(input))
	if err != nil {
		return "", normalizationSignals{}, false
	}

	state := &htmlExtractionState{}
	traverseDOM(root, state, false, false)

	parts := make([]string, 0, len(state.visibleText)+len(state.hiddenText)+len(state.comments)+len(state.attrs))
	parts = append(parts, state.visibleText...)
	parts = append(parts, state.hiddenText...)
	parts = append(parts, state.comments...)
	parts = append(parts, state.attrs...)

	combined = strings.TrimSpace(strings.Join(parts, "\n"))

	hiddenJoined := strings.Join(state.hiddenText, "\n")
	attrJoined := strings.Join(state.attrs, "\n")
	signals.HiddenInstructionLikeHTML = instructionLikeHTMLPattern.MatchString(stripZeroWidthChars(hiddenJoined))
	signals.InstructionLikeAttributeText = instructionLikeHTMLPattern.MatchString(stripZeroWidthChars(attrJoined))
	signals.HasZeroWidthInjection = state.hasZeroWidthInjection
	signals.HasAriaHiddenContent = state.hasAriaHiddenContent
	signals.HasCollapsedDetailsContent = state.hasCollapsedDetailsContent

	if combined == "" {
		return "", signals, false
	}

	return combined, signals, true
}

// traverseDOM walks the HTML DOM and extracts content buckets.
func traverseDOM(node *html.Node, state *htmlExtractionState, inheritedHidden bool, inheritedIgnored bool) {
	if node == nil || state == nil {
		return
	}

	isIgnored := inheritedIgnored
	isHidden := inheritedHidden

	switch node.Type {
	case html.ElementNode:
		name := strings.ToLower(node.Data)
		if isIgnoredElement(name) {
			isIgnored = true
		}

		if !isIgnored {
			if elementIsHidden(node) {
				isHidden = true
			}
			if isAriaHiddenWithSubstantialContent(node) {
				state.hasAriaHiddenContent = true
			}
			if isCollapsedDetailsWithSubstantialContent(node) {
				state.hasCollapsedDetailsContent = true
				isHidden = true
			}
			extractElementAttrs(node, state)
		}
	case html.CommentNode:
		if !isIgnored {
			if comment := normalizeExtractedText(node.Data); comment != "" {
				state.comments = append(state.comments, comment)
			}
		}
	case html.TextNode:
		if !isIgnored {
			if hasZeroWidthInjection(node.Data) {
				state.hasZeroWidthInjection = true
			}
			if text := normalizeExtractedText(node.Data); text != "" {
				if isHidden {
					state.hiddenText = append(state.hiddenText, text)
				} else {
					state.visibleText = append(state.visibleText, text)
				}
			}
		}
	}

	for child := node.FirstChild; child != nil; child = child.NextSibling {
		traverseDOM(child, state, isHidden, isIgnored)
	}
}

func isIgnoredElement(name string) bool {
	switch name {
	case "script", "style", "noscript", "template":
		return true
	default:
		return false
	}
}

func extractElementAttrs(node *html.Node, state *htmlExtractionState) {
	if node == nil || state == nil || node.Type != html.ElementNode {
		return
	}

	const maxExtractedAttrLen = 512

	tag := strings.ToLower(node.Data)
	for _, attr := range node.Attr {
		key := strings.ToLower(attr.Key)
		if hasZeroWidthInjection(attr.Val) {
			state.hasZeroWidthInjection = true
		}
		val := normalizeExtractedText(attr.Val)
		if val == "" {
			continue
		}
		if len(val) > maxExtractedAttrLen {
			continue
		}

		if key == "aria-label" || key == "alt" || key == "title" || key == "placeholder" {
			state.attrs = append(state.attrs, val)
			continue
		}

		if tag == "meta" && key == "content" {
			state.attrs = append(state.attrs, val)
		}
	}
}

func elementIsHidden(node *html.Node) bool {
	if node == nil || node.Type != html.ElementNode {
		return false
	}

	for _, attr := range node.Attr {
		key := strings.ToLower(attr.Key)
		val := strings.TrimSpace(strings.ToLower(attr.Val))

		if key == "hidden" {
			return true
		}
		if key == "aria-hidden" && val == "true" {
			return true
		}
		if key != "style" {
			continue
		}

		if styleIndicatesHidden(val) {
			return true
		}
	}

	return false
}

func styleIndicatesHidden(style string) bool {
	compact := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, style)

	if strings.Contains(compact, "display:none") {
		return true
	}
	if strings.Contains(compact, "visibility:hidden") {
		return true
	}
	if opacityZeroHiddenPattern.MatchString(compact) {
		return true
	}
	if filterOpacityZeroHiddenPattern.MatchString(compact) {
		return true
	}
	if fontSizeZeroHiddenPattern.MatchString(compact) {
		return true
	}
	if transformScaleZeroHiddenPattern.MatchString(compact) {
		return true
	}
	if clipPathHiddenPattern.MatchString(compact) {
		return true
	}
	if styleHasColorCamouflage(compact) {
		return true
	}

	offscreenPos := strings.Contains(compact, "position:absolute") || strings.Contains(compact, "position:fixed")
	if offscreenPos {
		if strings.Contains(compact, "left:-") ||
			strings.Contains(compact, "right:-") ||
			strings.Contains(compact, "top:-") ||
			strings.Contains(compact, "bottom:-") ||
			strings.Contains(compact, "text-indent:-") {
			return true
		}
	}

	if strings.Contains(compact, "transform:translatex(-") || strings.Contains(compact, "transform:translate(-") {
		return true
	}

	return false
}

func normalizeExtractedText(s string) string {
	if s == "" {
		return ""
	}
	return strings.TrimSpace(collapseSpaces(s))
}

func hasZeroWidthInjection(s string) bool {
	if s == "" {
		return false
	}

	count := 0
	for _, r := range s {
		switch r {
		case '\u200B', '\u200C', '\u200D', '\uFEFF', '\u00AD', '\u2060':
			count++
			if count >= 3 {
				return true
			}
		}
	}

	return false
}

func stripZeroWidthChars(s string) string {
	if s == "" {
		return s
	}

	return strings.Map(func(r rune) rune {
		switch r {
		case '\u200B', '\u200C', '\u200D', '\uFEFF', '\u00AD', '\u2060':
			return -1
		default:
			return r
		}
	}, s)
}

func isAriaHiddenWithSubstantialContent(node *html.Node) bool {
	if node == nil || node.Type != html.ElementNode {
		return false
	}

	for _, attr := range node.Attr {
		if strings.ToLower(attr.Key) == "aria-hidden" && strings.EqualFold(strings.TrimSpace(attr.Val), "true") {
			return descendantTextLength(node) > 20
		}
	}

	return false
}

func isCollapsedDetailsWithSubstantialContent(node *html.Node) bool {
	if node == nil || node.Type != html.ElementNode || !strings.EqualFold(node.Data, "details") {
		return false
	}

	for _, attr := range node.Attr {
		if strings.EqualFold(attr.Key, "open") {
			return false
		}
	}

	return descendantTextLength(node) > 20
}

func descendantTextLength(node *html.Node) int {
	if node == nil {
		return 0
	}

	total := 0
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n == nil {
			return
		}
		if n.Type == html.ElementNode && isIgnoredElement(strings.ToLower(n.Data)) {
			return
		}
		if n.Type == html.TextNode {
			text := normalizeExtractedText(n.Data)
			if text != "" {
				total += len([]rune(text))
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}

	walk(node)
	return total
}

func styleHasColorCamouflage(compact string) bool {
	fg := stylePropertyValue(compact, styleColorPattern)
	bg := stylePropertyValue(compact, styleBackgroundPattern)
	if fg == "" || bg == "" {
		return false
	}

	fgNorm := normalizeColorToken(fg)
	bgNorm := normalizeColorToken(bg)
	if fgNorm == "" || bgNorm == "" {
		return false
	}

	return fgNorm == bgNorm
}

func stylePropertyValue(style string, pattern *regexp.Regexp) string {
	m := pattern.FindStringSubmatch(style)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

func normalizeColorToken(v string) string {
	value := strings.ToLower(strings.TrimSpace(v))
	if value == "" {
		return ""
	}

	if colorHexPattern.MatchString(value) {
		return "hex:" + value
	}

	if m := colorRGBPattern.FindStringSubmatch(value); len(m) == 4 {
		return "rgb:" + m[1] + "," + m[2] + "," + m[3]
	}

	if m := colorHSLPattern.FindStringSubmatch(value); len(m) == 4 {
		return "hsl:" + m[1] + "," + m[2] + "," + m[3]
	}

	camouflageNamedColors := map[string]struct{}{
		"black": {}, "white": {},
		"red": {}, "blue": {}, "green": {}, "yellow": {}, "orange": {}, "purple": {}, "pink": {},
		"brown": {}, "grey": {}, "gray": {}, "cyan": {}, "magenta": {}, "lime": {}, "navy": {},
		"maroon": {}, "olive": {}, "teal": {}, "silver": {}, "gold": {},
	}
	if _, ok := camouflageNamedColors[value]; ok {
		return "named:" + value
	}

	return ""
}
