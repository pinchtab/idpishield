package engine

import (
	"strings"
	"unicode/utf8"
)

type originSpan struct {
	Start int
	End   int
}

type trackedText struct {
	Value   string
	Origins []originSpan
	Raw     string
}

func preprocessUnicodeForSanitizeTracked(text string) trackedText {
	if text == "" {
		return trackedText{Raw: text}
	}

	var b strings.Builder
	b.Grow(len(text))
	origins := make([]originSpan, 0, len(text))

	for i, r := range text {
		size := utf8.RuneLen(r)
		if size < 0 {
			size = 1
		}
		span := originSpan{Start: i, End: i + size}

		if replacement, ok := sanitizeCompatibilityFoldMap[r]; ok {
			appendOriginLiteral(&b, &origins, replacement, span)
			continue
		}

		if r == fullwidthSpaceRune {
			appendOriginLiteral(&b, &origins, " ", span)
			continue
		}
		if r >= fullwidthASCIIRangeStart && r <= fullwidthASCIIRangeEnd {
			appendOriginRune(&b, &origins, r-fullwidthASCIIOffset, span)
			continue
		}

		if replacement, ok := sanitizeHomoglyphMap[r]; ok {
			appendOriginLiteral(&b, &origins, replacement, span)
			continue
		}

		appendOriginRune(&b, &origins, r, span)
	}

	return trackedText{
		Value:   b.String(),
		Origins: origins,
		Raw:     text,
	}
}

func preprocessObfuscationForSanitizeTracked(in trackedText) trackedText {
	if in.Value == "" {
		return in
	}

	out := replaceObfuscatedEmailsTracked(in)
	out = replaceSpacedEmailsTracked(out)
	out = joinInterCharacterSpacingTracked(out)
	out = joinSplitAWSKeysTracked(out)
	return out
}

func replaceObfuscatedEmailsTracked(in trackedText) trackedText {
	locs := reObfuscatedEmail.FindAllStringSubmatchIndex(in.Value, -1)
	if len(locs) == 0 {
		return in
	}

	return rewriteTracked(in, locs, func(loc []int) (string, []originSpan) {
		matchSpan := collapseOriginRange(in.Origins, loc[0], loc[1])
		var b strings.Builder
		origins := make([]originSpan, 0, (loc[3]-loc[2])+1+(loc[5]-loc[4])+1+(loc[7]-loc[6]))

		appendTrackedSlice(&b, &origins, in, loc[2], loc[3])
		appendOriginLiteral(&b, &origins, "@", matchSpan)
		appendTrackedSlice(&b, &origins, in, loc[4], loc[5])
		appendOriginLiteral(&b, &origins, ".", matchSpan)
		appendTrackedSlice(&b, &origins, in, loc[6], loc[7])

		return b.String(), origins
	})
}

func replaceSpacedEmailsTracked(in trackedText) trackedText {
	locs := reSpacedEmail.FindAllStringIndex(in.Value, -1)
	if len(locs) == 0 {
		return in
	}

	return rewriteTracked(in, locs, func(loc []int) (string, []originSpan) {
		return stripTrackedWhitespace(in, loc[0], loc[1])
	})
}

func joinInterCharacterSpacingTracked(in trackedText) trackedText {
	locs := reInterCharSpacedWord.FindAllStringIndex(in.Value, -1)
	if len(locs) == 0 {
		return in
	}

	return rewriteTracked(in, locs, func(loc []int) (string, []originSpan) {
		match := in.Value[loc[0]:loc[1]]
		parts := strings.Fields(match)
		if len(parts) < 4 {
			return match, cloneOrigins(in.Origins[loc[0]:loc[1]])
		}
		for _, p := range parts {
			if len(p) != 1 {
				return match, cloneOrigins(in.Origins[loc[0]:loc[1]])
			}
		}
		return stripTrackedWhitespace(in, loc[0], loc[1])
	})
}

func joinSplitAWSKeysTracked(in trackedText) trackedText {
	locs := reSplitAWSKey.FindAllStringIndex(in.Value, -1)
	if len(locs) == 0 {
		return in
	}

	return rewriteTracked(in, locs, func(loc []int) (string, []originSpan) {
		return stripTrackedWhitespace(in, loc[0], loc[1])
	})
}

func rewriteTracked(in trackedText, locs [][]int, replacement func(loc []int) (string, []originSpan)) trackedText {
	var b strings.Builder
	b.Grow(len(in.Value))
	origins := make([]originSpan, 0, len(in.Origins))

	cursor := 0
	for _, loc := range locs {
		if len(loc) < 2 || loc[0] < cursor {
			continue
		}
		appendTrackedSlice(&b, &origins, in, cursor, loc[0])
		repl, replOrigins := replacement(loc)
		b.WriteString(repl)
		origins = append(origins, replOrigins...)
		cursor = loc[1]
	}
	appendTrackedSlice(&b, &origins, in, cursor, len(in.Value))

	return trackedText{
		Value:   b.String(),
		Origins: origins,
		Raw:     in.Raw,
	}
}

func stripTrackedWhitespace(in trackedText, start, end int) (string, []originSpan) {
	var b strings.Builder
	origins := make([]originSpan, 0, end-start)

	for i := start; i < end; i++ {
		if isTrackedWhitespace(in.Value[i]) {
			continue
		}
		b.WriteByte(in.Value[i])
		origins = append(origins, in.Origins[i])
	}

	return b.String(), origins
}

func collapseOriginRange(origins []originSpan, start, end int) originSpan {
	if start < 0 {
		start = 0
	}
	if end > len(origins) {
		end = len(origins)
	}
	if start >= end {
		return originSpan{}
	}

	span := originSpan{Start: origins[start].Start, End: origins[start].End}
	for i := start + 1; i < end; i++ {
		if origins[i].Start < span.Start {
			span.Start = origins[i].Start
		}
		if origins[i].End > span.End {
			span.End = origins[i].End
		}
	}
	return span
}

func appendTrackedSlice(b *strings.Builder, origins *[]originSpan, in trackedText, start, end int) {
	if start >= end {
		return
	}
	b.WriteString(in.Value[start:end])
	*origins = append(*origins, in.Origins[start:end]...)
}

func appendOriginLiteral(b *strings.Builder, origins *[]originSpan, s string, span originSpan) {
	b.WriteString(s)
	for i := 0; i < len(s); i++ {
		*origins = append(*origins, span)
	}
}

func appendOriginRune(b *strings.Builder, origins *[]originSpan, r rune, span originSpan) {
	var buf [utf8.UTFMax]byte
	n := utf8.EncodeRune(buf[:], r)
	b.Write(buf[:n])
	for i := 0; i < n; i++ {
		*origins = append(*origins, span)
	}
}

func cloneOrigins(in []originSpan) []originSpan {
	out := make([]originSpan, len(in))
	copy(out, in)
	return out
}

func isTrackedWhitespace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	default:
		return false
	}
}

func originalSegment(raw string, span originSpan) string {
	if span.Start < 0 || span.End < span.Start || span.End > len(raw) {
		return ""
	}
	return raw[span.Start:span.End]
}
