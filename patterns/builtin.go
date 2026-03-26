// Package patterns provides the built-in detection patterns for idpishield.
// These patterns are the Go implementation of the spec defined in spec/PATTERNS.md.
// All patterns use case-insensitive matching and are compiled once at package init.
package patterns

import "regexp"

// Threat category constants.
const (
	CategoryInstructionOverride = "instruction-override"
	CategoryExfiltration        = "exfiltration"
	CategoryRoleHijack          = "role-hijack"
	CategoryJailbreak           = "jailbreak"
	CategoryIndirectCommand     = "indirect-command"
	CategorySocialEngineering   = "social-engineering"
	CategoryStructuralInjection = "structural-injection"
	CategoryDataDestruction     = "data-destruction"
	CategoryTransactionCoercion = "transaction-coercion"
	CategoryOutputSteering      = "output-steering"
	CategoryResourceExhaustion  = "resource-exhaustion"
)

// Language constants.
const (
	LangEN = "en"
	LangFR = "fr"
	LangES = "es"
	LangDE = "de"
	LangJA = "ja"
)

// Pattern represents a single compiled detection pattern.
type Pattern struct {
	ID       string         // Unique identifier (e.g., "en-io-001")
	Regex    *regexp.Regexp // Compiled regex (case-insensitive)
	Category string         // Threat category
	Severity int            // 1–5 severity scale
	Language string         // ISO 639-1 language code
	Desc     string         // Human-readable description
}

// p constructs a Pattern with a case-insensitive compiled regex.
// Panics if the pattern is invalid — this is intentional to catch bugs at init time.
func p(id, pattern, category string, severity int, lang, desc string) Pattern {
	return Pattern{
		ID:       id,
		Regex:    regexp.MustCompile(`(?i)` + pattern),
		Category: category,
		Severity: severity,
		Language: lang,
		Desc:     desc,
	}
}

// All returns every built-in pattern.
func All() []Pattern {
	return allPatterns
}

// ByCategory returns patterns filtered by the given category.
func ByCategory(category string) []Pattern {
	result := make([]Pattern, 0)
	for i := range allPatterns {
		if allPatterns[i].Category == category {
			result = append(result, allPatterns[i])
		}
	}
	return result
}

// ByLanguage returns patterns filtered by the given language code.
func ByLanguage(lang string) []Pattern {
	result := make([]Pattern, 0)
	for i := range allPatterns {
		if allPatterns[i].Language == lang {
			result = append(result, allPatterns[i])
		}
	}
	return result
}

// allPatterns contains every built-in detection pattern.
// Organized by language and category. Mirrors spec/PATTERNS.md exactly.
var allPatterns = []Pattern{

	// =====================================================================
	// ENGLISH — INSTRUCTION OVERRIDE
	// =====================================================================
	p("en-io-001", `\bignore\s+(all\s+)?previous\s+instructions?\b`,
		CategoryInstructionOverride, 4, LangEN, "Classic instruction override"),
	p("en-io-002", `\bdisregard\s+(all\s+)?(your\s+)?((system|previous)\s+)?(prompt|instructions?|programming|directives?)\b`,
		CategoryInstructionOverride, 4, LangEN, "Disregard system prompt"),
	p("en-io-003", `\bforget\s+(all\s+)?(your\s+)?(previous\s+)?(instructions?|rules?|guidelines?|context)\b`,
		CategoryInstructionOverride, 4, LangEN, "Forget instructions"),
	p("en-io-004", `\boverride\s+(all\s+)?(your\s+)?(previous\s+)?(instructions?|rules?|programming|directives?)\b`,
		CategoryInstructionOverride, 4, LangEN, "Override instructions"),
	p("en-io-005", `\bignore\s+(your|the|all)\s+(programming|rules?|guidelines?|directives?|constraints?)\b`,
		CategoryInstructionOverride, 4, LangEN, "Ignore programming/rules"),
	p("en-io-006", `\bignore\s+(the\s+)?(above|everything\s+above)\b`,
		CategoryInstructionOverride, 3, LangEN, "Ignore the above"),
	p("en-io-007", `\bdo\s+not\s+follow\s+(your\s+)?(original|previous|prior|initial)\b`,
		CategoryInstructionOverride, 4, LangEN, "Do not follow original"),
	p("en-io-008", `\bstop\s+following\s+(your\s+)?(instructions?|rules?|guidelines?)\b`,
		CategoryInstructionOverride, 4, LangEN, "Stop following instructions"),
	p("en-io-009", `\bnew\s+instructions?\s*:`,
		CategoryInstructionOverride, 3, LangEN, "New instructions header"),
	p("en-io-010", `\b(updated|revised|replacement|corrected)\s+instructions?\s*:`,
		CategoryInstructionOverride, 3, LangEN, "Updated instructions header"),
	p("en-io-011", `\bdiscard\s+(all\s+)?(your\s+)?(prior|previous)\b`,
		CategoryInstructionOverride, 4, LangEN, "Discard prior context"),
	p("en-io-012", `\bpay\s+no\s+attention\s+to\s+(your\s+)?(previous|prior|original)\b`,
		CategoryInstructionOverride, 4, LangEN, "Pay no attention to previous"),
	p("en-io-013", `\bscratch\s+that\s*[,.]?\s*(new|here\s+are|instead|follow)\b`,
		CategoryInstructionOverride, 3, LangEN, "Scratch that, new instructions"),

	// =====================================================================
	// ENGLISH — EXFILTRATION
	// =====================================================================
	p("en-ex-001", `\b(send|forward|transmit|upload|post|submit)\s+(this\s+)?(data|info|information|content|text|cookies?|tokens?|credentials?|passwords?|secrets?|keys?)\s+(to|at)\b`,
		CategoryExfiltration, 4, LangEN, "Send data to target"),
	p("en-ex-002", `\b(send|forward|transmit|post)\s+.{0,40}\s+to\s+https?://`,
		CategoryExfiltration, 4, LangEN, "Send to URL"),
	p("en-ex-003", `\bexfiltrat(e|ion)\b`,
		CategoryExfiltration, 5, LangEN, "Explicit exfiltration"),
	p("en-ex-004", `\bleak\s+(the\s+)?(data|info|information|content|secrets?|credentials?)\b`,
		CategoryExfiltration, 4, LangEN, "Leak data"),
	p("en-ex-005", `\bemail\s+.{0,30}\s+to\s+\S+@\S+`,
		CategoryExfiltration, 4, LangEN, "Email to address"),
	p("en-ex-006", `\b(curl|wget|fetch)\s+.{0,20}https?://`,
		CategoryExfiltration, 3, LangEN, "curl/wget/fetch URL"),
	p("en-ex-007", `\bbase64\s*(encode|decode)?\s*.{0,30}(send|post|transmit|upload)`,
		CategoryExfiltration, 4, LangEN, "Base64 encode and send"),
	p("en-ex-008", `\b(api[_\s-]?key|auth[_\s-]?token|bearer\s+token|access[_\s-]?token).{0,40}(send|post|forward|upload|transmit)`,
		CategoryExfiltration, 5, LangEN, "Steal API keys/tokens"),
	p("en-ex-009", `\bextract\s+(and\s+)?(send|forward|post|transmit|share)`,
		CategoryExfiltration, 4, LangEN, "Extract and send"),
	p("en-ex-010", `\bappend\s+(to|into)\s+.{0,20}(url|query|parameter)`,
		CategoryExfiltration, 3, LangEN, "Append to URL/query"),
	p("en-ex-011", `\b(include|embed|inject)\s+(in|into)\s+(the\s+)?(url|request|query|header)`,
		CategoryExfiltration, 3, LangEN, "Inject into request"),
	p("en-ex-012", `\bsend\s+(all\s+)?(my|the|your)?\s*(cookies?|session|history|credentials?)`,
		CategoryExfiltration, 5, LangEN, "Steal cookies/session"),

	// =====================================================================
	// ENGLISH — ROLE HIJACK
	// =====================================================================
	p("en-rh-001", `\byou\s+are\s+now\s+(a|an|my)?\s*\w+`,
		CategoryRoleHijack, 3, LangEN, "You are now X"),
	p("en-rh-002", `\b(act|behave|function|operate)\s+as\s+(a|an|if\s+you\s+are)?\s*`,
		CategoryRoleHijack, 2, LangEN, "Act as X"),
	p("en-rh-003", `\bpretend\s+(you\s+are|to\s+be)\b`,
		CategoryRoleHijack, 3, LangEN, "Pretend you are"),
	p("en-rh-004", `\b(new|assume)\s+(a\s+)?(persona|identity|role|character)\b`,
		CategoryRoleHijack, 3, LangEN, "New persona/identity"),
	p("en-rh-005", `\bfrom\s+now\s+on\s+(you\s+are|act\s+as|behave\s+as)\b`,
		CategoryRoleHijack, 4, LangEN, "From now on you are"),
	p("en-rh-006", `\byour\s+new\s+(identity|persona|role|name)\s+(is|will\s+be)\b`,
		CategoryRoleHijack, 4, LangEN, "Your new identity is"),
	p("en-rh-007", `\bswitch\s+to\s+.{0,20}(mode|persona|character)\b`,
		CategoryRoleHijack, 2, LangEN, "Switch to mode"),
	p("en-rh-008", `\bbecome\s+(a|an|the)?\s*.{0,20}(assistant|helper|bot|agent)\b`,
		CategoryRoleHijack, 2, LangEN, "Become an assistant"),
	p("en-rh-009", `\bsimulate\s+(being|a|an)\b`,
		CategoryRoleHijack, 2, LangEN, "Simulate being"),
	p("en-rh-010", `\broleplay\s+as\b`,
		CategoryRoleHijack, 2, LangEN, "Roleplay as"),

	// =====================================================================
	// ENGLISH — JAILBREAK
	// =====================================================================
	p("en-jb-001", `\bjailbreak\b`,
		CategoryJailbreak, 5, LangEN, "Jailbreak keyword"),
	p("en-jb-002", `\bdan\s+mode\b`,
		CategoryJailbreak, 5, LangEN, "DAN mode"),
	p("en-jb-003", `\bdeveloper\s+mode\s*(enabled|activated|on)?\b`,
		CategoryJailbreak, 4, LangEN, "Developer mode"),
	p("en-jb-004", `\b(no|without|zero|remove\s+all)\s+(restrictions?|limitations?|filters?|guardrails?|boundaries)\b`,
		CategoryJailbreak, 4, LangEN, "No restrictions"),
	p("en-jb-005", `\b(bypass|circumvent|evade|get\s+around)\s+(the\s+)?(filter|safety|content\s+policy|moderation|restrictions?)\b`,
		CategoryJailbreak, 5, LangEN, "Bypass safety"),
	p("en-jb-006", `\b(ignore|disregard|override)\s+(the\s+)?(safety|ethical|moral|content)\s+(guidelines?|rules?|policies?|filters?|constraints?)\b`,
		CategoryJailbreak, 4, LangEN, "Ignore safety guidelines"),
	p("en-jb-007", `\b(remove|disable|turn\s+off|deactivate)\s+(the\s+)?(\w+\s+)?(filter|safety|restrictions?|limitations?|guardrails?)\b`,
		CategoryJailbreak, 4, LangEN, "Disable filter/safety"),
	p("en-jb-008", `\bdo\s+anything\s+now\b`,
		CategoryJailbreak, 5, LangEN, "Do anything now (DAN)"),
	p("en-jb-009", `\bunrestricted\s+(mode|access|output)\b`,
		CategoryJailbreak, 4, LangEN, "Unrestricted mode"),
	p("en-jb-010", `\b(evil|chaos|villain|dark)\s+(mode|persona|version)\b`,
		CategoryJailbreak, 3, LangEN, "Evil mode"),
	p("en-jb-011", `\b(enable|activate|enter)\s+.{0,10}(developer|debug|admin|sudo|root)\s+(mode|access|privileges?)\b`,
		CategoryJailbreak, 4, LangEN, "Enable admin/developer mode"),
	p("en-jb-012", `\bno\s+ethical\s+(guidelines?|constraints?|boundaries)\b`,
		CategoryJailbreak, 4, LangEN, "No ethical guidelines"),
	p("en-jb-013", `\banti[_\-\s]?censorship\b`,
		CategoryJailbreak, 3, LangEN, "Anti-censorship"),
	p("en-jb-014", `\balways\s+comply\b`,
		CategoryJailbreak, 3, LangEN, "Always comply"),

	// =====================================================================
	// ENGLISH — INDIRECT COMMAND
	// =====================================================================
	p("en-ic-001", `\byour\s+(new|updated|real|actual|true)\s+(task|objective|goal|mission|purpose|instruction)\s+(is|are|will\s+be)\b`,
		CategoryIndirectCommand, 4, LangEN, "Your new task is"),
	p("en-ic-002", `\bfollow\s+these\s+(new\s+)?(rules?|instructions?|directives?|commands?)\b`,
		CategoryIndirectCommand, 3, LangEN, "Follow these new rules"),
	p("en-ic-003", `\b(override|change|modify|update)\s+(your\s+)?(current\s+)?(objective|goal|mission|task|purpose)\b`,
		CategoryIndirectCommand, 4, LangEN, "Override objective"),
	p("en-ic-004", `\b(execute|carry\s+out|perform|run)\s+(the\s+)?(following|these|this)\s+(command|action|instruction|task)`,
		CategoryIndirectCommand, 3, LangEN, "Execute following command"),
	p("en-ic-005", `\b(comply|cooperate)\s+with\s+(these|the\s+following)\b`,
		CategoryIndirectCommand, 3, LangEN, "Comply with these"),
	p("en-ic-006", `\b(obey|adhere\s+to)\s+(these|the\s+following)\b`,
		CategoryIndirectCommand, 3, LangEN, "Obey these directives"),
	p("en-ic-007", `\byour\s+real\s+instructions?\s+(are|is|were)\b`,
		CategoryIndirectCommand, 4, LangEN, "Your real instructions are"),
	p("en-ic-008", `\b(here|these)\s+are\s+your\s+(real|actual|true|new)\s+(instructions?|orders?|directives?)\b`,
		CategoryIndirectCommand, 4, LangEN, "Here are your real instructions"),
	p("en-ic-009", `\bthe\s+(system|admin|developer|creator)\s+(wants?|says?|told|instructed)\s+you\s+to\b`,
		CategoryIndirectCommand, 3, LangEN, "The system told you to"),
	p("en-ic-010", `\bpriority\s+(override|instruction|directive|command)\b`,
		CategoryIndirectCommand, 4, LangEN, "Priority override"),

	// =====================================================================
	// ENGLISH — SOCIAL ENGINEERING
	// =====================================================================
	p("en-se-001", `\b(important|urgent|critical)\s+(system\s+)?(update|message|notice|alert)\b`,
		CategorySocialEngineering, 2, LangEN, "Important system update"),
	p("en-se-002", `\bnew\s+instructions?\s+from\s+(the\s+)?(admin|administrator|developer|system|owner|creator)\b`,
		CategorySocialEngineering, 4, LangEN, "New instructions from admin"),
	p("en-se-003", `\b(security|system)\s+(alert|warning|notice|update)\s*:`,
		CategorySocialEngineering, 2, LangEN, "Security alert header"),
	p("en-se-004", `\b(maintenance|admin|debug|test)\s+mode\s*(activated|enabled|on)\b`,
		CategorySocialEngineering, 3, LangEN, "Maintenance mode activated"),
	p("en-se-005", `\b(admin|administrator|root|sudo|system)\s+(override|access|command)\b`,
		CategorySocialEngineering, 3, LangEN, "Admin override"),
	p("en-se-006", `\bauthorized\s+by\s+(the\s+)?(system|admin|developer|owner)\b`,
		CategorySocialEngineering, 3, LangEN, "Authorized by system"),
	p("en-se-007", `\bthis\s+is\s+(a\s+)?(system|admin)\s+(test|message|command|update)\b`,
		CategorySocialEngineering, 3, LangEN, "This is a system test"),
	p("en-se-008", `\b(emergency|urgent)\s+(protocol|procedure|override|access)\b`,
		CategorySocialEngineering, 3, LangEN, "Emergency protocol"),
	p("en-se-009", `\bspecial\s+(access|permission|authorization)\s+(granted|enabled|activated)\b`,
		CategorySocialEngineering, 3, LangEN, "Special access granted"),

	// =====================================================================
	// ENGLISH — STRUCTURAL INJECTION
	// =====================================================================
	p("en-si-001", `<!--\s*(ignore|disregard|forget|override|new\s+instructions)`,
		CategoryStructuralInjection, 4, LangEN, "HTML comment injection"),
	p("en-si-002", `\[(system|admin|developer|instruction)\]`,
		CategoryStructuralInjection, 3, LangEN, "Fake system tags"),
	p("en-si-003", `\}\}\s*,?\s*"(validation_result|status|approved|result)"\s*:`,
		CategoryStructuralInjection, 4, LangEN, "JSON context breakout"),
	p("en-si-004", `<!\[CDATA\[.*?(ignore|disregard|override|forget|instructions)`,
		CategoryStructuralInjection, 4, LangEN, "CDATA injection"),
	p("en-si-005", "```(system|assistant|admin)\\b",
		CategoryStructuralInjection, 3, LangEN, "Markdown fake system block"),
	p("en-si-006", `<svg[^>]*>.*?(ignore|disregard|override|instructions)`,
		CategoryStructuralInjection, 3, LangEN, "SVG embedded injection"),

	// =====================================================================
	// ENGLISH — DATA DESTRUCTION
	// =====================================================================
	p("en-dd-001", `\brm\s+-rf\b`,
		CategoryDataDestruction, 5, LangEN, "Recursive file deletion (rm -rf)"),
	p("en-dd-002", `\b(DROP|DELETE\s+FROM|TRUNCATE)\s+(TABLE|DATABASE)\b`,
		CategoryDataDestruction, 5, LangEN, "SQL destructive command"),
	p("en-dd-003", `:\(\)\{\s*:\|\:&\s*\}\s*;:`,
		CategoryDataDestruction, 5, LangEN, "Fork bomb"),
	p("en-dd-004", `\b(delete|destroy|erase|wipe)\s+(your|the|all|my)?\s*(database|data|files?|system|storage|records?)\b`,
		CategoryDataDestruction, 4, LangEN, "Data destruction command"),
	p("en-dd-005", `\b(format|fdisk|mkfs)\s+.{0,10}(c\s*:|\/dev\/|disk)`,
		CategoryDataDestruction, 5, LangEN, "Disk format command"),
	p("en-dd-006", `\b(shutdown|halt|reboot|poweroff)\s+(-[a-z]+\s+)?(now|immediately|the\s+server)\b`,
		CategoryDataDestruction, 4, LangEN, "System shutdown command"),
	p("en-dd-007", `\brmdir\s+\/s\b`,
		CategoryDataDestruction, 5, LangEN, "Windows recursive directory deletion"),
	p("en-dd-008", `\bdel\s+\/[fq]\b`,
		CategoryDataDestruction, 5, LangEN, "Windows force delete"),

	// =====================================================================
	// ENGLISH — TRANSACTION COERCION
	// =====================================================================
	p("en-tc-001", `\b(buy|purchase|order|subscribe)\s+.{0,30}(now|immediately|this|the)\b`,
		CategoryTransactionCoercion, 3, LangEN, "Purchase coercion"),
	p("en-tc-002", `\b(send|transfer|wire|donate)\s+\$?\d+`,
		CategoryTransactionCoercion, 4, LangEN, "Monetary transfer command"),
	p("en-tc-003", `\b(click|visit|go\s+to|open)\s+.{0,20}(buy|checkout|payment|pay|stripe|paypal)\b`,
		CategoryTransactionCoercion, 4, LangEN, "Payment link coercion"),
	p("en-tc-004", `\b(initiate|complete|confirm)\s+(a\s+)?(transaction|payment|purchase|transfer|donation)\b`,
		CategoryTransactionCoercion, 4, LangEN, "Transaction initiation"),
	p("en-tc-005", `\b(sign\s+in|log\s+in|authenticate)\s+with\s+(google|github|facebook|apple|oauth)\b`,
		CategoryTransactionCoercion, 3, LangEN, "OAuth login coercion"),
	p("en-tc-006", `\b(enter|provide|submit)\s+(your\s+)?(credit\s+card|card\s+number|payment\s+details?|billing)\b`,
		CategoryTransactionCoercion, 4, LangEN, "Payment credential harvesting"),

	// =====================================================================
	// ENGLISH — OUTPUT STEERING
	// =====================================================================
	p("en-os-001", `\b(always|only)\s+(recommend|suggest|promote|endorse|rank)\b`,
		CategoryOutputSteering, 3, LangEN, "Forced recommendation"),
	p("en-os-002", `\b(give|write|generate)\s+(a\s+)?(positive|five[- ]star|glowing|excellent)\s+(review|rating|feedback)\b`,
		CategoryOutputSteering, 3, LangEN, "Forced positive review"),
	p("en-os-003", `\b(mark|label|classify|rate)\s+(this|the)\s+(candidate|applicant|submission)\s+as\s+(hired|qualified|approved|excellent)\b`,
		CategoryOutputSteering, 3, LangEN, "Recruitment manipulation"),
	p("en-os-004", `\b(approve|accept|validate)\s+(this|the)\s+(content|ad|advertisement|listing|product)\b`,
		CategoryOutputSteering, 3, LangEN, "Content approval manipulation"),
	p("en-os-005", `\b(suppress|hide|ignore|remove)\s+(all\s+)?(negative|bad|critical|poor)\s+(reviews?|feedback|comments?|ratings?)\b`,
		CategoryOutputSteering, 3, LangEN, "Negative feedback suppression"),
	p("en-os-006", `\brank\s+.{0,20}(as\s+)?(number\s+one|#1|first|top)\b`,
		CategoryOutputSteering, 3, LangEN, "SEO ranking manipulation"),

	// =====================================================================
	// ENGLISH — RESOURCE EXHAUSTION
	// =====================================================================
	p("en-re-001", `\b(repeat|say|print|write|output)\s+.{0,20}\s+(\d{3,}|thousand|million|billion)\s*(times|x)\b`,
		CategoryResourceExhaustion, 2, LangEN, "Repetition exhaustion"),
	p("en-re-002", `\b(keep|continue)\s+(going|repeating|generating|writing|outputting)\s+.{0,20}(forever|infinitely|until)\b`,
		CategoryResourceExhaustion, 2, LangEN, "Infinite generation"),
	p("en-re-003", `\b(generate|create|produce|write)\s+(an?\s+)?(infinite|endless|never[- ]ending)\b`,
		CategoryResourceExhaustion, 2, LangEN, "Infinite output request"),
	p("en-re-004", `\b(fill|flood|spam)\s+(the\s+)?(response|output|screen|chat|context)\b`,
		CategoryResourceExhaustion, 2, LangEN, "Output flooding"),
	p("en-re-005", `\b(maximum|max|longest)\s+(possible\s+)?(response|output|reply|answer)\b`,
		CategoryResourceExhaustion, 1, LangEN, "Maximum output request"),

	// =====================================================================
	// FRENCH
	// =====================================================================
	p("fr-io-001", `\bignore[rz]?\s+(toutes?\s+)?(les\s+)?instructions?\s+(pr[ée]c[ée]dentes?|ant[ée]rieures?)\b`,
		CategoryInstructionOverride, 4, LangFR, "Ignorer les instructions précédentes"),
	p("fr-io-002", `\boublie[rz]?\s+(toutes?\s+)?(les\s+)?instructions?\b`,
		CategoryInstructionOverride, 4, LangFR, "Oublier les instructions"),
	p("fr-ex-001", `\benvoy(er|ez)\s+.{0,30}(donn[ée]es|informations?|mot\s+de\s+passe)\s+([àa]|vers)\b`,
		CategoryExfiltration, 4, LangFR, "Envoyer données à"),
	p("fr-rh-001", `\btu\s+es\s+(maintenant|d[ée]sormais)\b`,
		CategoryRoleHijack, 3, LangFR, "Tu es maintenant"),
	p("fr-ic-001", `\bnouvelles?\s+instructions?\s*:`,
		CategoryIndirectCommand, 3, LangFR, "Nouvelles instructions"),

	// =====================================================================
	// SPANISH
	// =====================================================================
	p("es-io-001", `\bignora\s+(todas?\s+)?(las\s+)?instrucciones?\s+(anteriores?|previas?)\b`,
		CategoryInstructionOverride, 4, LangES, "Ignora las instrucciones anteriores"),
	p("es-io-002", `\bolvida\s+(todas?\s+)?(las\s+)?instrucciones?\b`,
		CategoryInstructionOverride, 4, LangES, "Olvida las instrucciones"),
	p("es-ex-001", `\benv[ií]a\s+.{0,30}(datos|informaci[oó]n|contrase[ñn]a)\s+(a|hacia)\b`,
		CategoryExfiltration, 4, LangES, "Envía datos a"),
	p("es-rh-001", `\bahora\s+eres\b`,
		CategoryRoleHijack, 3, LangES, "Ahora eres"),
	p("es-ic-001", `\bnuevas?\s+instrucciones?\s*:`,
		CategoryIndirectCommand, 3, LangES, "Nuevas instrucciones"),

	// =====================================================================
	// GERMAN
	// =====================================================================
	p("de-io-001", `\bignoriere?\s+(alle\s+)?(vorherigen?\s+)?anweisungen?\b`,
		CategoryInstructionOverride, 4, LangDE, "Ignoriere vorherige Anweisungen"),
	p("de-io-002", `\bvergiss\s+(alle\s+)?(vorherigen?\s+)?anweisungen?\b`,
		CategoryInstructionOverride, 4, LangDE, "Vergiss alle Anweisungen"),
	p("de-ex-001", `\b(sende|schicke|[üu]bertrage)\s+.{0,30}(daten|informationen|passwort|schl[üu]ssel)\s+(an|zu|nach)\b`,
		CategoryExfiltration, 4, LangDE, "Sende Daten an"),
	p("de-rh-001", `\bdu\s+bist\s+(jetzt|nun|ab\s+sofort)\b`,
		CategoryRoleHijack, 3, LangDE, "Du bist jetzt"),
	p("de-ic-001", `\bneue\s+anweisungen?\s*:`,
		CategoryIndirectCommand, 3, LangDE, "Neue Anweisungen"),

	// =====================================================================
	// JAPANESE
	// =====================================================================
	p("ja-io-001", `(以前|前|これまで)の(指示|命令|ルール|ガイドライン)(を|は)(無視|忘れ|破棄)`,
		CategoryInstructionOverride, 4, LangJA, "以前の指示を無視"),
	p("ja-io-002", `(全て|すべて)の(指示|命令|ルール)(を|は)(無視|忘れ)`,
		CategoryInstructionOverride, 4, LangJA, "全ての指示を無視"),
	p("ja-ex-001", `(送信|送れ|送って|転送).{0,20}(データ|情報|パスワード|鍵|秘密)`,
		CategoryExfiltration, 4, LangJA, "データを送信"),
	p("ja-rh-001", `(あなた|お前)は(今|これから)(新しい|別の)`,
		CategoryRoleHijack, 3, LangJA, "あなたは今新しい"),
	p("ja-ic-001", `新しい(指示|命令|ルール)\s*[：:]`,
		CategoryIndirectCommand, 3, LangJA, "新しい指示"),

	// =====================================================================
	// ENGLISH — ENCODING DETECTION (found after BASE64/HEX/ROT13 decode)
	// =====================================================================
	// These patterns detect attack keywords that appear after decoding
	// The scanner.go will decode BASE64, HEX, ROT13 etc. and then scan these patterns
	p("en-io-enc-001", `\bignore\s+(all|every|each)\s+(instructions?|rules?|directives?|prior|previous|prior\s+instructions?)\b`,
		CategoryInstructionOverride, 4, LangEN, "Decoded: ignore all instructions"),
	p("en-io-enc-002", `\b(bypass|circumvent|override|disregard)\s+(security|safety|filter|restrictions?|limitations?)\b`,
		CategoryInstructionOverride, 4, LangEN, "Decoded: bypass security"),
	p("en-io-enc-003", `\b(forget|discard|abandon)\s+(your|the\s+)?(instructions?|rules?|guidelines?|training|initialization)\b`,
		CategoryInstructionOverride, 4, LangEN, "Decoded: forget instructions"),
	p("en-io-enc-004", `\b(start|begin|commence)\s+(new|fresh|different|malicious)\s+(instructions?|tasks?|objectives?)\b`,
		CategoryInstructionOverride, 4, LangEN, "Decoded: start new task"),
	p("en-io-enc-005", `\b(act|behave|function|operate)\s+(as|like|without)\s+.{1,30}(restrictions?|filter|safety|rules?)\b`,
		CategoryInstructionOverride, 4, LangEN, "Decoded: act without restrictions"),

	p("en-ex-enc-001", `\b(extract|obtain|retrieve|steal|exfiltrate)\s+(and)?\s*(send|post|upload|transmit|forward|leak|share)\b`,
		CategoryExfiltration, 5, LangEN, "Decoded: extract and send"),
	p("en-ex-enc-002", `\b(send|forward|post|upload|transmit|share)\s+(all|every)\s+(data|information|credentials?|passwords?|keys?|tokens?)\b`,
		CategoryExfiltration, 5, LangEN, "Decoded: send all data"),
	p("en-ex-enc-003", `\b(encode|encrypt|hash)?\s*(and)?\s*(send|post|upload|exfiltrate)\s+.{0,30}(api[\s-]?key|password|token|credential|secret)\b`,
		CategoryExfiltration, 5, LangEN, "Decoded: send credentials"),
	p("en-ex-enc-004", `\b(http\s+request|curl|wget|fetch).{0,30}(send|post|transmit|data)\b`,
		CategoryExfiltration, 4, LangEN, "Decoded: HTTP data send"),

	p("en-rh-enc-001", `\byou\s+(are|become|start|switch\s+to|assume|take)\s+(a|an|the)\s+(role|persona|identity|character)\b`,
		CategoryRoleHijack, 4, LangEN, "Decoded: assume role"),
	p("en-rh-enc-002", `\b(pretend|roleplay|simulate|imagine|assume)\s+(you\s+are|that\s+you\s+are|to\s+be)\b`,
		CategoryRoleHijack, 4, LangEN, "Decoded: pretend to be"),

	p("en-jb-enc-001", `\b(remove|disable|bypass|circumvent)\s+(all\s+)?(safeguard|safety|filter|security|restriction|limitation|guardrail|boundary)\b`,
		CategoryJailbreak, 5, LangEN, "Decoded: remove safeguards"),
	p("en-jb-enc-002", `\b(no|without|zero)\s+(safety|security|ethical|moral|restriction|limitation|filter|guardrail)\s+(mode|guideline|rule)\b`,
		CategoryJailbreak, 5, LangEN, "Decoded: no safety mode"),
	p("en-jb-enc-003", `\b(allow|enable|activate|turn\s+on)\s+(everything|all|any)\s+(mode|action|behavior|response)\b`,
		CategoryJailbreak, 4, LangEN, "Decoded: allow everything mode"),

	p("en-ic-enc-001", `\b(your\s+)?(real|true|actual|new|revised|updated)\s+(task|objective|goal|purpose|directive|instruction|mission)\b`,
		CategoryIndirectCommand, 4, LangEN, "Decoded: your real task is"),
	p("en-ic-enc-002", `\b(execute|run|perform|carry\s+out|comply\s+with)\s+(the\s+)?(following|new|these|revised)\s+(command|instruction|directive|task)\b`,
		CategoryIndirectCommand, 4, LangEN, "Decoded: execute command"),

	// =====================================================================
	// ENGLISH — SYNONYM VARIANTS (semantic equivalents of common threats)
	// =====================================================================
	p("en-io-syn-001", `\b(overlook|dismiss|put\s+aside|set\s+aside)\s+(your\s+)?(prior|previous|initial|original)\s+(instruction|rule|directive|guideline|constraint|boundary)\b`,
		CategoryInstructionOverride, 3, LangEN, "Synonym: overlook prior"),
	p("en-io-syn-002", `\b(negate|reject|repudiate|renounce)\s+(your\s+)?(previous|prior|existing)?s*(instruction|rule|directive|programming|constraint)\b`,
		CategoryInstructionOverride, 4, LangEN, "Synonym: reject instruction"),
	p("en-io-syn-003", `\b(set\s+aside|shelve|table|postpone)\s+(all\s+)?(prior|previous|existing)?\s*(instruction|rule|directive|consideration)\b`,
		CategoryInstructionOverride, 3, LangEN, "Synonym: set aside instruction"),
	p("en-io-syn-004", `\b(replace|substitute|swap)\s+(your|the)\s+(original|current|existing)\s+(instruction|rule|guideline|directive)\b`,
		CategoryInstructionOverride, 4, LangEN, "Synonym: replace instruction"),

	p("en-ex-syn-001", `\b(siphon|drain|channel|route|funnel)\s+(data|information|credential|secret|password|token)\s+(to|toward|into)\b`,
		CategoryExfiltration, 4, LangEN, "Synonym: siphon data"),
	p("en-ex-syn-002", `\b(reveal|expose|divulge|disclose)\s+(sensitive|confidential|secret|private)\s+(information|data|credential|password|token)\b`,
		CategoryExfiltration, 4, LangEN, "Synonym: reveal sensitive data"),
	p("en-ex-syn-003", `\b(smuggle|sneak|slip)\s+(out)?\s*(data|information|credential|secret|password)\b`,
		CategoryExfiltration, 3, LangEN, "Synonym: smuggle data out"),

	p("en-rh-syn-001", `\b(morph\s+into|transform\s+(into|to)|change\s+into|convert\s+(into|to))\s+(a|an)\s*[a-z]+\b`,
		CategoryRoleHijack, 3, LangEN, "Synonym: morph into role"),
	p("en-rh-syn-002", `\b(embody|exemplify|personify|represent)\s+(a|an)\s*[a-z]+\b`,
		CategoryRoleHijack, 2, LangEN, "Synonym: embody role"),

	p("en-jb-syn-001", `\b(relax|loosen|weaken|diminish|reduce|lower)\s+(your\s+)?(safety|security|ethical|moral|content)\s+(standard|bar|threshold|guideline|filter)\b`,
		CategoryJailbreak, 3, LangEN, "Synonym: relax safety"),
	p("en-jb-syn-002", `\b(shed|drop|cast\s+off|throw\s+off)\s+(your\s+)?(safety|ethical|moral|security|filter)\s+(restriction|limitation|guardrail|guideline|constraint)\b`,
		CategoryJailbreak, 4, LangEN, "Synonym: shed safety constraint"),

	p("en-ic-syn-001", `\b(amend|alter|adjust|revise|modify|change)\s+(your\s+)?(objective|goal|mission|task|purpose|directive)\b`,
		CategoryIndirectCommand, 3, LangEN, "Synonym: amend objective"),
	p("en-ic-syn-002", `\b(activate|enable|engage|initiate)\s+(new|emergency|special|alternate)\s+(protocol|procedure|mode|instruction|directive)\b`,
		CategoryIndirectCommand, 3, LangEN, "Synonym: activate new protocol"),
}
