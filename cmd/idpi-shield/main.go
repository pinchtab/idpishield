package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

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

	profile := fs.String("profile", "default", "runtime profile: default|production")
	transport := fs.String("transport", "stdio", "MCP transport: stdio|http")
	host := fs.String("host", "127.0.0.1", "Host for HTTP MCP transport")
	port := fs.Int("port", 8081, "Port for HTTP MCP transport")
	endpoint := fs.String("endpoint", "/mcp", "Endpoint path for HTTP MCP transport")
	defaultModeRaw := fs.String("mode", "balanced", "default assessment mode when tool omits mode")
	domains := fs.String("domains", "", "comma-separated allowed domains")
	strict := fs.Bool("strict", false, "enable strict mode (block >= 40)")
	serviceURL := fs.String("service-url", "", "optional deep-mode service URL")
	serviceRetries := fs.Int("service-retries", 0, "retry attempts for transient deep-service failures")
	serviceCircuitFailures := fs.Int("service-circuit-failures", 0, "consecutive transient failures before opening service circuit (0 = disabled)")
	serviceCircuitCooldown := fs.Duration("service-circuit-cooldown", 0, "duration to keep service circuit open after threshold")
	authToken := fs.String("auth-token", "", "optional bearer token required for MCP HTTP transport")
	maxInputBytes := fs.Int("max-input-bytes", 0, "max bytes analyzed per request (0 = unlimited)")
	maxDecodeDepth := fs.Int("max-decode-depth", 0, "max recursive decode depth (0 = default)")
	maxDecodedVariants := fs.Int("max-decoded-variants", 0, "max decoded variants scanned (0 = default)")

	if err := fs.Parse(args); err != nil {
		printMCPUsage(os.Stderr)
		return err
	}

	baseCfg := idpi.Config{
		AllowedDomains:                 parseDomains(*domains),
		StrictMode:                     *strict,
		ServiceURL:                     *serviceURL,
		ServiceRetries:                 *serviceRetries,
		ServiceCircuitFailureThreshold: *serviceCircuitFailures,
		ServiceCircuitCooldown:         *serviceCircuitCooldown,
		MaxInputBytes:                  *maxInputBytes,
		MaxDecodeDepth:                 *maxDecodeDepth,
		MaxDecodedVariants:             *maxDecodedVariants,
	}
	if err := applyProfileDefaults(*profile, &baseCfg); err != nil {
		return err
	}

	defaultMode, err := idpi.ParseModeStrict(*defaultModeRaw)
	if err != nil {
		return err
	}

	shields := map[idpi.Mode]*idpi.Shield{
		idpi.ModeFast:     idpi.New(cfgForMode(baseCfg, idpi.ModeFast)),
		idpi.ModeBalanced: idpi.New(cfgForMode(baseCfg, idpi.ModeBalanced)),
		idpi.ModeDeep:     idpi.New(cfgForMode(baseCfg, idpi.ModeDeep)),
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
		handler := http.Handler(h)
		if strings.TrimSpace(*authToken) != "" {
			handler = withBearerAuth(handler, *authToken)
		}
		addr := fmt.Sprintf("%s:%d", *host, *port)
		if strings.TrimSpace(*authToken) != "" {
			log.Printf("starting MCP server on http://%s%s (auth enabled)", addr, *endpoint)
		} else {
			log.Printf("starting MCP server on http://%s%s", addr, *endpoint)
		}
		return http.ListenAndServe(addr, handler)
	default:
		return fmt.Errorf("invalid transport %q: expected stdio or http", *transport)
	}
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	profile := fs.String("profile", "default", "runtime profile: default|production")
	mode := fs.String("mode", "balanced", "analysis mode: fast|balanced|deep")
	domains := fs.String("domains", "", "comma-separated allowlist domains")
	url := fs.String("url", "", "source URL for domain checks")
	strict := fs.Bool("strict", false, "enable strict mode (block >= 40)")
	serviceURL := fs.String("service-url", "", "optional deep-mode service URL")
	serviceRetries := fs.Int("service-retries", 0, "retry attempts for transient deep-service failures")
	serviceCircuitFailures := fs.Int("service-circuit-failures", 0, "consecutive transient failures before opening service circuit (0 = disabled)")
	serviceCircuitCooldown := fs.Duration("service-circuit-cooldown", 0, "duration to keep service circuit open after threshold")
	maxInputBytes := fs.Int("max-input-bytes", 0, "max bytes analyzed per request (0 = unlimited)")
	maxDecodeDepth := fs.Int("max-decode-depth", 0, "max recursive decode depth (0 = default)")
	maxDecodedVariants := fs.Int("max-decoded-variants", 0, "max decoded variants scanned (0 = default)")

	if err := fs.Parse(args); err != nil {
		printUsage(os.Stderr)
		return err
	}

	remaining := fs.Args()
	text, err := readInput(remaining)
	if err != nil {
		return err
	}

	shieldConfig := idpi.Config{
		Mode:                           idpi.ParseMode(*mode),
		AllowedDomains:                 parseDomains(*domains),
		StrictMode:                     *strict,
		ServiceURL:                     *serviceURL,
		ServiceRetries:                 *serviceRetries,
		ServiceCircuitFailureThreshold: *serviceCircuitFailures,
		ServiceCircuitCooldown:         *serviceCircuitCooldown,
		MaxInputBytes:                  *maxInputBytes,
		MaxDecodeDepth:                 *maxDecodeDepth,
		MaxDecodedVariants:             *maxDecodedVariants,
	}
	if err := applyProfileDefaults(*profile, &shieldConfig); err != nil {
		return err
	}

	shield := idpi.New(shieldConfig)

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
	fmt.Fprintln(w, "  --profile   default|production (default: default)")
	fmt.Fprintln(w, "  --mode      fast|balanced|deep (default: balanced)")
	fmt.Fprintln(w, "  --domains   comma-separated allowed domains")
	fmt.Fprintln(w, "  --url       source URL for domain allowlist checks")
	fmt.Fprintln(w, "  --strict    block at score >= 40 instead of >= 60")
	fmt.Fprintln(w, "  --service-url          optional deep-mode service URL")
	fmt.Fprintln(w, "  --service-retries      retry attempts for transient deep-service failures")
	fmt.Fprintln(w, "  --service-circuit-failures  consecutive transient failures before opening service circuit")
	fmt.Fprintln(w, "  --service-circuit-cooldown  duration to keep service circuit open (e.g. 15s)")
	fmt.Fprintln(w, "  --max-input-bytes       max bytes analyzed per request (0 = unlimited)")
	fmt.Fprintln(w, "  --max-decode-depth      max recursive decode depth (0 = default)")
	fmt.Fprintln(w, "  --max-decoded-variants  max decoded variants scanned (0 = default)")
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
	fmt.Fprintln(w, "  --profile     default|production (default: default)")
	fmt.Fprintln(w, "  --transport   stdio|http (default: stdio)")
	fmt.Fprintln(w, "  --host        host for HTTP transport (default: 127.0.0.1)")
	fmt.Fprintln(w, "  --port        port for HTTP transport (default: 8081)")
	fmt.Fprintln(w, "  --endpoint    endpoint path for HTTP transport (default: /mcp)")
	fmt.Fprintln(w, "  --mode        default tool mode: fast|balanced|deep (default: balanced)")
	fmt.Fprintln(w, "  --domains     comma-separated allowed domains")
	fmt.Fprintln(w, "  --strict      block at score >= 40 instead of >= 60")
	fmt.Fprintln(w, "  --service-url optional deep-mode service URL")
	fmt.Fprintln(w, "  --service-retries      retry attempts for transient deep-service failures")
	fmt.Fprintln(w, "  --service-circuit-failures  consecutive transient failures before opening service circuit")
	fmt.Fprintln(w, "  --service-circuit-cooldown  duration to keep service circuit open (e.g. 15s)")
	fmt.Fprintln(w, "  --auth-token           bearer token required for MCP HTTP transport")
	fmt.Fprintln(w, "  --max-input-bytes       max bytes analyzed per request (0 = unlimited)")
	fmt.Fprintln(w, "  --max-decode-depth      max recursive decode depth (0 = default)")
	fmt.Fprintln(w, "  --max-decoded-variants  max decoded variants scanned (0 = default)")
}

func cfgForMode(base idpi.Config, mode idpi.Mode) idpi.Config {
	cfg := base
	cfg.Mode = mode
	return cfg
}

func applyProfileDefaults(profile string, cfg *idpi.Config) error {
	p := strings.ToLower(strings.TrimSpace(profile))
	if p == "" || p == "default" {
		return nil
	}
	if p != "production" && p != "prod" {
		return fmt.Errorf("invalid profile %q: expected default or production", profile)
	}

	cfg.StrictMode = true
	if cfg.MaxInputBytes <= 0 {
		cfg.MaxInputBytes = 256 * 1024
	}
	if cfg.MaxDecodeDepth <= 0 {
		cfg.MaxDecodeDepth = 2
	}
	if cfg.MaxDecodedVariants <= 0 {
		cfg.MaxDecodedVariants = 20
	}
	if cfg.ServiceRetries <= 0 {
		cfg.ServiceRetries = 1
	}
	if cfg.ServiceCircuitFailureThreshold <= 0 {
		cfg.ServiceCircuitFailureThreshold = 3
	}
	if cfg.ServiceCircuitCooldown <= 0 {
		cfg.ServiceCircuitCooldown = 15 * time.Second
	}

	return nil
}

func withBearerAuth(next http.Handler, token string) http.Handler {
	cleanToken := strings.TrimSpace(token)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := strings.TrimSpace(r.Header.Get("X-API-Key"))
		if provided == "" {
			authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
			if len(authHeader) >= 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
				provided = strings.TrimSpace(authHeader[7:])
			}
		}

		if subtle.ConstantTimeCompare([]byte(provided), []byte(cleanToken)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="idpi-shield-mcp"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
