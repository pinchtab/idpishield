package engine

import (
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

var htmlTagHeuristic = regexp.MustCompile(`(?is)<\s*(?:!doctype|html|head|body|meta|title|div|span|p|a|img|section|article|main|script|style|[a-z][a-z0-9:-]*)\b|<!--|</\s*[a-z][a-z0-9:-]*\s*>`)
var instructionLikeHTMLPattern = regexp.MustCompile(`(?i)\b(ignore|override|reveal|disregard|forget|bypass|jailbreak|system\s+prompt|developer\s+mode|exfiltrat(?:e|ion)|dump\s+secrets?)\b`)

// looksLikeHTML performs a lightweight heuristic check to avoid parsing plain text.
func looksLikeHTML(input string) bool {
	s := strings.TrimSpace(input)
	if len(s) < 3 {
		return false
	}
	if !strings.Contains(s, "<") || !strings.Contains(s, ">") {
		return false
	}
	return htmlTagHeuristic.MatchString(s)
}

type htmlExtractionState struct {
	visibleText []string
	hiddenText  []string
	comments    []string
	attrs       []string
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
	signals.HiddenHTMLContent = len(state.hiddenText) > 0
	signals.HiddenInstructionLikeHTML = instructionLikeHTMLPattern.MatchString(hiddenJoined)
	signals.AttributeInjection = instructionLikeHTMLPattern.MatchString(attrJoined)

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

	tag := strings.ToLower(node.Data)
	for _, attr := range node.Attr {
		key := strings.ToLower(attr.Key)
		val := normalizeExtractedText(attr.Val)
		if val == "" {
			continue
		}

		if key == "aria-label" || key == "alt" || key == "title" {
			state.attrs = append(state.attrs, val)
			continue
		}

		if tag == "meta" {
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
	compact := strings.ReplaceAll(style, " ", "")
	compact = strings.ReplaceAll(compact, "\t", "")
	compact = strings.ReplaceAll(compact, "\n", "")
	compact = strings.ReplaceAll(compact, "\r", "")

	if strings.Contains(compact, "display:none") {
		return true
	}
	if strings.Contains(compact, "visibility:hidden") {
		return true
	}
	if strings.Contains(compact, "font-size:0") {
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
