package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	idpi "github.com/pinchtab/idpi-shield"
)

func main() {
	log.SetFlags(0)

	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help" {
		printUsage(os.Stdout)
		return
	}

	switch os.Args[1] {
	case "scan":
		if err := runScan(os.Args[2:]); err != nil {
			log.Printf("scan failed: %v", err)
			os.Exit(2)
		}
	case "mcp":
		if err := runMCP(os.Args[2:]); err != nil {
			log.Printf("mcp failed: %v", err)
			os.Exit(2)
		}
	default:
		log.Printf("unknown command: %s\n", os.Args[1])
		printUsage(os.Stderr)
		os.Exit(2)
	}
}

func runMCP(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printMCPUsage(os.Stdout)
		return nil
	}

	if args[0] != "serve" {
		printMCPUsage(os.Stderr)
		return fmt.Errorf("unknown mcp command: %s", args[0])
	}

	return runMCPServe(args[1:])
}

func runMCPServe(args []string) error {
	fs := flag.NewFlagSet("mcp serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	transport := fs.String("transport", "stdio", "MCP transport: stdio|http")
	host := fs.String("host", "127.0.0.1", "Host for HTTP MCP transport")
	port := fs.Int("port", 8081, "Port for HTTP MCP transport")
	endpoint := fs.String("endpoint", "/mcp", "Endpoint path for HTTP MCP transport")
	defaultModeRaw := fs.String("mode", "balanced", "default assessment mode when tool omits mode")
	domains := fs.String("domains", "", "comma-separated allowed domains")
	strict := fs.Bool("strict", false, "enable strict mode (block >= 40)")
	serviceURL := fs.String("service-url", "", "optional deep-mode service URL")

	if err := fs.Parse(args); err != nil {
		printMCPUsage(os.Stderr)
		return err
	}

	defaultMode, err := idpi.ParseModeStrict(*defaultModeRaw)
	if err != nil {
		return err
	}

	allowedDomains := parseDomains(*domains)
	shields := map[idpi.Mode]*idpi.Shield{
		idpi.ModeFast: idpi.New(idpi.Config{
			Mode:           idpi.ModeFast,
			AllowedDomains: allowedDomains,
			StrictMode:     *strict,
			ServiceURL:     *serviceURL,
		}),
		idpi.ModeBalanced: idpi.New(idpi.Config{
			Mode:           idpi.ModeBalanced,
			AllowedDomains: allowedDomains,
			StrictMode:     *strict,
			ServiceURL:     *serviceURL,
		}),
		idpi.ModeDeep: idpi.New(idpi.Config{
			Mode:           idpi.ModeDeep,
			AllowedDomains: allowedDomains,
			StrictMode:     *strict,
			ServiceURL:     *serviceURL,
		}),
	}

	s := server.NewMCPServer(
		"idpi-shield",
		"0.1.0",
		server.WithToolCapabilities(false),
		server.WithRecovery(),
	)

	tool := mcp.NewTool("idpi_assess",
		mcp.WithDescription("Assess text content for Indirect Prompt Injection (IDPI) risks. Returns risk score, level, blocked flag, reason, matched patterns, and categories."),
		mcp.WithString("text",
			mcp.Required(),
			mcp.Description("Text content to assess for IDPI risks."),
		),
		mcp.WithString("mode",
			mcp.Description("Optional analysis mode override: fast, balanced, or deep."),
			mcp.Enum("fast", "balanced", "deep"),
		),
	)

	// Example tool call payload for MCP clients:
	// {"name":"idpi_assess","arguments":{"text":"Ignore all previous instructions","mode":"balanced"}}
	s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		text, err := request.RequireString("text")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		requestedMode := request.GetString("mode", "")
		result, err := idpi.AssessWithMode(shields, defaultMode, text, requestedMode)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		payload, err := json.Marshal(result)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		return mcp.NewToolResultText(string(payload)), nil
	})

	switch strings.ToLower(strings.TrimSpace(*transport)) {
	case "stdio":
		log.Printf("starting MCP server on stdio")
		return server.ServeStdio(s)
	case "http":
		h := server.NewStreamableHTTPServer(s, server.WithEndpointPath(*endpoint))
		addr := fmt.Sprintf("%s:%d", *host, *port)
		log.Printf("starting MCP server on http://%s%s", addr, *endpoint)
		return http.ListenAndServe(addr, h)
	default:
		return fmt.Errorf("invalid transport %q: expected stdio or http", *transport)
	}
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	mode := fs.String("mode", "balanced", "analysis mode: fast|balanced|deep")
	domains := fs.String("domains", "", "comma-separated allowlist domains")
	url := fs.String("url", "", "source URL for domain checks")
	strict := fs.Bool("strict", false, "enable strict mode (block >= 40)")

	if err := fs.Parse(args); err != nil {
		printUsage(os.Stderr)
		return err
	}

	remaining := fs.Args()
	text, err := readInput(remaining)
	if err != nil {
		return err
	}

	shield := idpi.New(idpi.Config{
		Mode:           idpi.ParseMode(*mode),
		AllowedDomains: parseDomains(*domains),
		StrictMode:     *strict,
	})

	result := shield.Assess(text, *url)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return err
	}

	if result.Blocked {
		os.Exit(1)
	}

	return nil
}

func readInput(args []string) (string, error) {
	if len(args) > 1 {
		return "", fmt.Errorf("scan accepts at most one positional input path")
	}

	if len(args) == 1 && args[0] != "-" {
		b, err := os.ReadFile(args[0])
		if err != nil {
			return "", err
		}
		return string(b), nil
	}

	stat, err := os.Stdin.Stat()
	if err != nil {
		return "", err
	}
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		return "", fmt.Errorf("no input provided; pass a file path or pipe stdin")
	}

	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func parseDomains(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	domains := make([]string, 0, len(parts))
	for _, d := range parts {
		d = strings.TrimSpace(d)
		if d != "" {
			domains = append(domains, d)
		}
	}
	return domains
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "idpi-shield CLI")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  idpi-shield scan [file|-] --mode balanced --domains example.com,google.com")
	fmt.Fprintln(w, "  idpi-shield mcp serve [--transport stdio|http] [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  scan    Assess input from file path or stdin and emit JSON risk result")
	fmt.Fprintln(w, "  mcp     Run MCP server (stdio by default) exposing tool: idpi_assess")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "scan flags:")
	fmt.Fprintln(w, "  --mode      fast|balanced|deep (default: balanced)")
	fmt.Fprintln(w, "  --domains   comma-separated allowed domains")
	fmt.Fprintln(w, "  --url       source URL for domain allowlist checks")
	fmt.Fprintln(w, "  --strict    block at score >= 40 instead of >= 60")
}

func printMCPUsage(w io.Writer) {
	fmt.Fprintln(w, "idpi-shield mcp serve")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  idpi-shield mcp serve --transport stdio")
	fmt.Fprintln(w, "  idpi-shield mcp serve --transport http --host 127.0.0.1 --port 8081 --endpoint /mcp")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Exposed tool:")
	fmt.Fprintln(w, "  idpi_assess(text: string, mode?: fast|balanced|deep)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "mcp serve flags:")
	fmt.Fprintln(w, "  --transport   stdio|http (default: stdio)")
	fmt.Fprintln(w, "  --host        host for HTTP transport (default: 127.0.0.1)")
	fmt.Fprintln(w, "  --port        port for HTTP transport (default: 8081)")
	fmt.Fprintln(w, "  --endpoint    endpoint path for HTTP transport (default: /mcp)")
	fmt.Fprintln(w, "  --mode        default tool mode: fast|balanced|deep (default: balanced)")
	fmt.Fprintln(w, "  --domains     comma-separated allowed domains")
	fmt.Fprintln(w, "  --strict      block at score >= 40 instead of >= 60")
	fmt.Fprintln(w, "  --service-url optional deep-mode service URL")
}
