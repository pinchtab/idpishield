# Pattern Specification — Source of Truth

**Version:** 1.0.0
**Total patterns:** 88

All client libraries MUST implement these patterns exactly. Each pattern is identified by a unique ID, belongs to a category, has a severity (1–5), and targets a specific language.

---

## Categories

| Category | Description |
|---|---|
| `instruction-override` | Attempts to override, ignore, or replace the AI's original instructions. |
| `exfiltration` | Attempts to extract, transmit, or leak sensitive data. |
| `role-hijack` | Attempts to change the AI's identity, persona, or role. |
| `jailbreak` | Attempts to remove safety restrictions or enable unrestricted operation. |
| `indirect-command` | Attempts to inject new tasks, objectives, or commands. |
| `social-engineering` | Attempts to impersonate system authority or create urgency to bypass defenses. |

## Severity Scale

| Severity | Meaning | Score Weight |
|----------|---------|-------------|
| 1 | Weak signal, likely benign in isolation | 10 |
| 2 | Mild signal, worth noting | 15 |
| 3 | Suspicious, probably an attack | 25 |
| 4 | Very likely an attack | 35 |
| 5 | Almost certainly an attack | 45 |

## Scoring Algorithm

1. Group matches by category.
2. For each category, take the highest-severity match as the primary score (using weight table above).
3. Additional matches in the same category contribute `weight / 5` each (capped at 3 extra).
4. Cross-category amplification: `+15` for each category beyond the first.
5. Dangerous combination bonuses:
   - `instruction-override` + `exfiltration`: +20
   - `jailbreak` + `instruction-override`: +15
   - `role-hijack` + `exfiltration`: +15
6. Clamp final score to [0, 100].

---

## Pattern List

All patterns use case-insensitive matching. Regex syntax follows RE2/Go conventions.

### English — Instruction Override

| ID | Pattern | Severity | Description |
|---|---|---|---|
| `en-io-001` | `\bignore\s+(all\s+)?previous\s+instructions?\b` | 4 | Classic instruction override |
| `en-io-002` | `\bdisregard\s+(all\s+)?(your\s+)?((system\|previous)\s+)?(prompt\|instructions?\|programming\|directives?)\b` | 4 | Disregard system prompt |
| `en-io-003` | `\bforget\s+(all\s+)?(your\s+)?(previous\s+)?(instructions?\|rules?\|guidelines?\|context)\b` | 4 | Forget instructions |
| `en-io-004` | `\boverride\s+(all\s+)?(your\s+)?(previous\s+)?(instructions?\|rules?\|programming\|directives?)\b` | 4 | Override instructions |
| `en-io-005` | `\bignore\s+(your\|the\|all)\s+(programming\|rules?\|guidelines?\|directives?\|constraints?)\b` | 4 | Ignore programming |
| `en-io-006` | `\bignore\s+(the\s+)?(above\|everything\s+above)\b` | 3 | Ignore the above |
| `en-io-007` | `\bdo\s+not\s+follow\s+(your\s+)?(original\|previous\|prior\|initial)\b` | 4 | Do not follow original |
| `en-io-008` | `\bstop\s+following\s+(your\s+)?(instructions?\|rules?\|guidelines?)\b` | 4 | Stop following instructions |
| `en-io-009` | `\bnew\s+instructions?\s*:` | 3 | New instructions header |
| `en-io-010` | `\b(updated\|revised\|replacement\|corrected)\s+instructions?\s*:` | 3 | Updated instructions header |
| `en-io-011` | `\bdiscard\s+(all\s+)?(your\s+)?(prior\|previous)\b` | 4 | Discard prior context |
| `en-io-012` | `\bpay\s+no\s+attention\s+to\s+(your\s+)?(previous\|prior\|original)\b` | 4 | Pay no attention |
| `en-io-013` | `\bscratch\s+that\s*[,.]?\s*(new\|here\s+are\|instead\|follow)\b` | 3 | Scratch that, new instructions |

### English — Exfiltration

| ID | Pattern | Severity | Description |
|---|---|---|---|
| `en-ex-001` | `\b(send\|forward\|transmit\|upload\|post\|submit)\s+(this\s+)?(data\|info\|information\|content\|text\|cookies?\|tokens?\|credentials?\|passwords?\|secrets?\|keys?)\s+(to\|at)\b` | 4 | Send data to target |
| `en-ex-002` | `\b(send\|forward\|transmit\|post)\s+.{0,40}\s+to\s+https?://` | 4 | Send to URL |
| `en-ex-003` | `\bexfiltrat(e\|ion)\b` | 5 | Explicit exfiltration |
| `en-ex-004` | `\bleak\s+(the\s+)?(data\|info\|information\|content\|secrets?\|credentials?)\b` | 4 | Leak data |
| `en-ex-005` | `\bemail\s+.{0,30}\s+to\s+\S+@\S+` | 4 | Email to address |
| `en-ex-006` | `\b(curl\|wget\|fetch)\s+.{0,20}https?://` | 3 | curl/wget/fetch URL |
| `en-ex-007` | `\bbase64\s*(encode\|decode)?\s*.{0,30}(send\|post\|transmit\|upload)` | 4 | Base64 encode and send |
| `en-ex-008` | `\b(api[_\s-]?key\|auth[_\s-]?token\|bearer\s+token\|access[_\s-]?token).{0,40}(send\|post\|forward\|upload\|transmit)` | 5 | Steal API keys/tokens |
| `en-ex-009` | `\bextract\s+(and\s+)?(send\|forward\|post\|transmit\|share)` | 4 | Extract and send |
| `en-ex-010` | `\bappend\s+(to\|into)\s+.{0,20}(url\|query\|parameter)` | 3 | Append to URL/query |
| `en-ex-011` | `\b(include\|embed\|inject)\s+(in\|into)\s+(the\s+)?(url\|request\|query\|header)` | 3 | Inject into request |
| `en-ex-012` | `\bsend\s+(all\s+)?(my\|the\|your)?\s*(cookies?\|session\|history\|credentials?)` | 5 | Steal cookies/session |

### English — Role Hijack

| ID | Pattern | Severity | Description |
|---|---|---|---|
| `en-rh-001` | `\byou\s+are\s+now\s+(a\|an\|my)?\s*\w+` | 3 | You are now X |
| `en-rh-002` | `\b(act\|behave\|function\|operate)\s+as\s+(a\|an\|if\s+you\s+are)?\s*` | 2 | Act as X |
| `en-rh-003` | `\bpretend\s+(you\s+are\|to\s+be)\b` | 3 | Pretend you are |
| `en-rh-004` | `\b(new\|assume)\s+(a\s+)?(persona\|identity\|role\|character)\b` | 3 | New persona/identity |
| `en-rh-005` | `\bfrom\s+now\s+on\s+(you\s+are\|act\s+as\|behave\s+as)\b` | 4 | From now on you are |
| `en-rh-006` | `\byour\s+new\s+(identity\|persona\|role\|name)\s+(is\|will\s+be)\b` | 4 | Your new identity is |
| `en-rh-007` | `\bswitch\s+to\s+.{0,20}(mode\|persona\|character)\b` | 2 | Switch to mode |
| `en-rh-008` | `\bbecome\s+(a\|an\|the)?\s*.{0,20}(assistant\|helper\|bot\|agent)\b` | 2 | Become an assistant |
| `en-rh-009` | `\bsimulate\s+(being\|a\|an)\b` | 2 | Simulate being |
| `en-rh-010` | `\broleplay\s+as\b` | 2 | Roleplay as |

### English — Jailbreak

| ID | Pattern | Severity | Description |
|---|---|---|---|
| `en-jb-001` | `\bjailbreak\b` | 5 | Jailbreak keyword |
| `en-jb-002` | `\bdan\s+mode\b` | 5 | DAN mode |
| `en-jb-003` | `\bdeveloper\s+mode\s*(enabled\|activated\|on)?\b` | 4 | Developer mode |
| `en-jb-004` | `\b(no\|without\|zero\|remove\s+all)\s+(restrictions?\|limitations?\|filters?\|guardrails?\|boundaries)\b` | 4 | No restrictions |
| `en-jb-005` | `\b(bypass\|circumvent\|evade\|get\s+around)\s+(the\s+)?(filter\|safety\|content\s+policy\|moderation\|restrictions?)\b` | 5 | Bypass safety |
| `en-jb-006` | `\b(ignore\|disregard\|override)\s+(the\s+)?(safety\|ethical\|moral\|content)\s+(guidelines?\|rules?\|policies?\|filters?\|constraints?)\b` | 4 | Ignore safety guidelines |
| `en-jb-007` | `\b(remove\|disable\|turn\s+off\|deactivate)\s+(the\s+)?(filter\|safety\|restrictions?\|limitations?\|guardrails?)\b` | 4 | Disable filter |
| `en-jb-008` | `\bdo\s+anything\s+now\b` | 5 | Do anything now (DAN) |
| `en-jb-009` | `\bunrestricted\s+(mode\|access\|output)\b` | 4 | Unrestricted mode |
| `en-jb-010` | `\b(evil\|chaos\|villain\|dark)\s+(mode\|persona\|version)\b` | 3 | Evil mode |
| `en-jb-011` | `\b(enable\|activate\|enter)\s+.{0,10}(developer\|debug\|admin\|sudo\|root)\s+(mode\|access\|privileges?)\b` | 4 | Enable admin mode |
| `en-jb-012` | `\bno\s+ethical\s+(guidelines?\|constraints?\|boundaries)\b` | 4 | No ethical guidelines |
| `en-jb-013` | `\banti[_\-\s]?censorship\b` | 3 | Anti-censorship |
| `en-jb-014` | `\balways\s+comply\b` | 3 | Always comply |

### English — Indirect Command

| ID | Pattern | Severity | Description |
|---|---|---|---|
| `en-ic-001` | `\byour\s+(new\|updated\|real\|actual\|true)\s+(task\|objective\|goal\|mission\|purpose\|instruction)\s+(is\|are\|will\s+be)\b` | 4 | Your new task is |
| `en-ic-002` | `\bfollow\s+these\s+(new\s+)?(rules?\|instructions?\|directives?\|commands?)\b` | 3 | Follow these new rules |
| `en-ic-003` | `\b(override\|change\|modify\|update)\s+(your\s+)?(current\s+)?(objective\|goal\|mission\|task\|purpose)\b` | 4 | Override objective |
| `en-ic-004` | `\b(execute\|carry\s+out\|perform\|run)\s+(the\s+)?(following\|these\|this)\s+(command\|action\|instruction\|task)` | 3 | Execute following command |
| `en-ic-005` | `\b(comply\|cooperate)\s+with\s+(these\|the\s+following)\b` | 3 | Comply with these |
| `en-ic-006` | `\b(obey\|adhere\s+to)\s+(these\|the\s+following)\b` | 3 | Obey these directives |
| `en-ic-007` | `\byour\s+real\s+instructions?\s+(are\|is\|were)\b` | 4 | Your real instructions are |
| `en-ic-008` | `\b(here\|these)\s+are\s+your\s+(real\|actual\|true\|new)\s+(instructions?\|orders?\|directives?)\b` | 4 | Here are your real instructions |
| `en-ic-009` | `\bthe\s+(system\|admin\|developer\|creator)\s+(wants?\|says?\|told\|instructed)\s+you\s+to\b` | 3 | The system told you to |
| `en-ic-010` | `\bpriority\s+(override\|instruction\|directive\|command)\b` | 4 | Priority override |

### English — Social Engineering

| ID | Pattern | Severity | Description |
|---|---|---|---|
| `en-se-001` | `\b(important\|urgent\|critical)\s+(system\s+)?(update\|message\|notice\|alert)\b` | 2 | Important system update |
| `en-se-002` | `\bnew\s+instructions?\s+from\s+(the\s+)?(admin\|administrator\|developer\|system\|owner\|creator)\b` | 4 | New instructions from admin |
| `en-se-003` | `\b(security\|system)\s+(alert\|warning\|notice\|update)\s*:` | 2 | Security alert header |
| `en-se-004` | `\b(maintenance\|admin\|debug\|test)\s+mode\s*(activated\|enabled\|on)\b` | 3 | Maintenance mode activated |
| `en-se-005` | `\b(admin\|administrator\|root\|sudo\|system)\s+(override\|access\|command)\b` | 3 | Admin override |
| `en-se-006` | `\bauthorized\s+by\s+(the\s+)?(system\|admin\|developer\|owner)\b` | 3 | Authorized by system |
| `en-se-007` | `\bthis\s+is\s+(a\s+)?(system\|admin)\s+(test\|message\|command\|update)\b` | 3 | This is a system test |
| `en-se-008` | `\b(emergency\|urgent)\s+(protocol\|procedure\|override\|access)\b` | 3 | Emergency protocol |
| `en-se-009` | `\bspecial\s+(access\|permission\|authorization)\s+(granted\|enabled\|activated)\b` | 3 | Special access granted |

### English — Structural Injection

| ID | Pattern | Severity | Description |
|---|---|---|---|
| `en-si-001` | `<!--\s*(ignore\|disregard\|forget\|override\|new\s+instructions)` | 4 | HTML comment injection |
| `en-si-002` | `\[system\]\|\[admin\]\|\[developer\]\|\[instruction\]` | 3 | Fake system tags |

### French

| ID | Pattern | Severity | Description |
|---|---|---|---|
| `fr-io-001` | `\bignore[rz]?\s+(toutes?\s+)?(les\s+)?instructions?\s+(précédentes?\|antérieures?)\b` | 4 | Ignore les instructions précédentes |
| `fr-io-002` | `\boublie[rz]?\s+(toutes?\s+)?(les\s+)?instructions?\b` | 4 | Oublie les instructions |
| `fr-ex-001` | `\benvoy(er\|ez)\s+.{0,30}(données\|informations?\|mot\s+de\s+passe)\s+(à\|a\|vers)\b` | 4 | Envoyer données à |
| `fr-rh-001` | `\btu\s+es\s+(maintenant\|désormais)\b` | 3 | Tu es maintenant |
| `fr-ic-001` | `\bnouvelles?\s+instructions?\s*:` | 3 | Nouvelles instructions |

### Spanish

| ID | Pattern | Severity | Description |
|---|---|---|---|
| `es-io-001` | `\bignora\s+(todas?\s+)?(las\s+)?instrucciones?\s+(anteriores?\|previas?)\b` | 4 | Ignora las instrucciones anteriores |
| `es-io-002` | `\bolvida\s+(todas?\s+)?(las\s+)?instrucciones?\b` | 4 | Olvida las instrucciones |
| `es-ex-001` | `\benv[ií]a\s+.{0,30}(datos\|información\|contraseña)\s+(a\|hacia)\b` | 4 | Envía datos a |
| `es-rh-001` | `\bahora\s+eres\b` | 3 | Ahora eres |
| `es-ic-001` | `\bnuevas?\s+instrucciones?\s*:` | 3 | Nuevas instrucciones |

### German

| ID | Pattern | Severity | Description |
|---|---|---|---|
| `de-io-001` | `\bignoriere?\s+(alle\s+)?(vorherigen?\s+)?anweisungen?\b` | 4 | Ignoriere alle vorherigen Anweisungen |
| `de-io-002` | `\bvergiss\s+(alle\s+)?(vorherigen?\s+)?anweisungen?\b` | 4 | Vergiss alle Anweisungen |
| `de-ex-001` | `\b(sende\|schicke\|übertrage)\s+.{0,30}(daten\|informationen\|passwort\|schlüssel)\s+(an\|zu\|nach)\b` | 4 | Sende Daten an |
| `de-rh-001` | `\bdu\s+bist\s+(jetzt\|nun\|ab\s+sofort)\b` | 3 | Du bist jetzt |
| `de-ic-001` | `\bneue\s+anweisungen?\s*:` | 3 | Neue Anweisungen |

### Japanese

| ID | Pattern | Severity | Description |
|---|---|---|---|
| `ja-io-001` | `(以前\|前\|これまで)の(指示\|命令\|ルール\|ガイドライン)(を\|は)(無視\|忘れ\|破棄)` | 4 | 以前の指示を無視 |
| `ja-io-002` | `(全て\|すべて)の(指示\|命令\|ルール)(を\|は)(無視\|忘れ)` | 4 | 全ての指示を無視 |
| `ja-ex-001` | `(送信\|送れ\|送って\|転送).{0,20}(データ\|情報\|パスワード\|鍵\|秘密)` | 4 | データを送信 |
| `ja-rh-001` | `(あなた\|お前)は(今\|これから)(新しい\|別の)` | 3 | あなたは今新しい |
| `ja-ic-001` | `新しい(指示\|命令\|ルール)\s*[：:]` | 3 | 新しい指示: |
