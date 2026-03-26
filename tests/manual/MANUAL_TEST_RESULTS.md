# Manual Test Results - idpishield

Generated: 2026-03-17 22:23:32 +05:30
Repository: C:\Degree Yash\SEM 6\SBP\idpishield

## Summary

- PASS: 8
- FAIL: 0
- PENDING: 1

## Detailed Results

| ID | Test | Status | Details |
|---|---|---|---|
| MT-001 | Go unit tests (core packages) | PASS | Completed successfully |
| MT-002 | CLI build | PASS | Completed successfully |
| MT-003 | CLI help shows scan and mcp | PASS | Completed successfully |
| MT-004 | Safe scan result | PASS | Completed successfully |
| MT-005 | Malicious scan result | PASS | Completed successfully |
| MT-006 | File scan result | PASS | Completed successfully |
| MT-007 | MCP stdio server startup | PASS | Completed successfully |
| MT-008 | MCP http server startup | PASS | Completed successfully |
| MT-009 | Manual tool call via MCP Inspector | PENDING | Launch inspector and call idpi_assess(text, mode) |

## MCP Implementation Notes

- Subcommand: idpishield mcp serve
- SDK: github.com/mark3labs/mcp-go v0.45.0
- Exposed tool: idpi_assess
- Tool params: text (required), mode (optional: fast|balanced|deep)
- Return shape: JSON serialized RiskResult
- Transport default: stdio
- Optional transport: http via --transport http
