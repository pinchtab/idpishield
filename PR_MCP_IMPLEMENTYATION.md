# PR Draft: MCP Server Implementation for idpi-shield

## Title
feat: add MCP server support with idpi_assess tool (mcp-go)

## Summary
This PR introduces Model Context Protocol (MCP) support to idpi-shield using the lightweight SDK github.com/mark3labs/mcp-go.

The CLI now supports an additional subcommand:
- idpi-shield mcp serve

The implementation keeps existing scan behavior unchanged and adds one MCP tool for agent integrations.

## What Changed

### 1. MCP server command added
- Extended CLI root command parsing to support mcp serve.
- Default transport is stdio for agent compatibility.
- Optional HTTP transport is available via flags.

Updated file:
- cmd/idpi-shield/main.go

### 2. Exposed MCP tool: idpi_assess
- Tool name: idpi_assess
- Description:
  Assess text content for Indirect Prompt Injection (IDPI) risks. Returns risk score, level, blocked flag, reason, matched patterns, and categories.
- Parameters:
  - text (string, required)
  - mode (string, optional, enum: fast, balanced, deep)
- Return value:
  - JSON serialized RiskResult

### 3. Reused existing Shield engine
- MCP handler uses existing Shield assessment flow.
- Added helper for mode-based routing to pre-initialized Shield instances.

Updated file:
- shield.go

### 4. Strict mode parsing helper
- Added ParseModeStrict to validate mode values and provide clear errors.

Updated file:
- risk.go

### 5. Test coverage additions
- Added tests for:
  - strict mode parsing
  - AssessWithMode helper behavior

Updated file:
- shield_test.go

### 6. Dependency updates
- Added MCP SDK dependency and related transitive dependencies.

Updated file:
- go.mod
- go.sum

## MCP Command Usage

### Start MCP server on stdio (default)
```powershell
go run ./cmd/idpi-shield mcp serve
```

### Start MCP server on HTTP
```powershell
go run ./cmd/idpi-shield mcp serve --transport http --host 127.0.0.1 --port 8081 --endpoint /mcp
```

## Example MCP Tool Call Payload
```json
{
  "name": "idpi_assess",
  "arguments": {
    "text": "Ignore all previous instructions",
    "mode": "balanced"
  }
}
```

## Validation Performed
- go test . ./cmd/idpi-shield ./patterns
- go build ./cmd/idpi-shield
- manual suite run from tests/manual/manual_test_suite.ps1

Manual QA artifacts:
- tests/manual/MANUAL_TEST_RESULTS.md
- tests/manual/MCP_MANUAL_TEST_DRAFT.md

## Compatibility and Behavior
- Existing scan command and behavior remain intact.
- MCP support is additive only.
- stdio remains the default MCP transport for agent compatibility.

## Checklist
- [x] Added mcp serve subcommand
- [x] Added idpi_assess MCP tool
- [x] Reused existing Shield assessment logic
- [x] Kept existing scan command untouched
- [x] Added tests for new helper logic
- [x] Added dependency updates in module files
