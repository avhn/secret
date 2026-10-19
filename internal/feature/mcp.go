package feature

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"

	"github.com/avhn/secret/internal/store"
)

const (
	MaxMCPInputBytes  = 64 << 10
	MaxMCPOutputBytes = 4 << 20
	mcpVersion        = "2025-06-18"
)

var (
	ErrMCPDisabled = errors.New("metadata MCP is not configured")
	ErrMCPConfig   = errors.New("invalid metadata MCP configuration")
	ErrMCPProtocol = errors.New("invalid or oversized metadata MCP input")
	ErrMCPIO       = errors.New("metadata MCP transport failed")
)

// MCPConfig explicitly enables stdio metadata access to exact store references.
// File stores require absolute file: paths. Provider records come exclusively from
// manifests in Directory, never provider Get or ambient discovery. No default
// allowlist, wildcard, resource, prompt, mutation or value capability is exposed.
type MCPConfig struct {
	Enabled   bool
	Stores    []string
	Directory string
}

// MCPServer holds an owned, immutable allowlist. Each Serve invocation has its own
// protocol session. There are no network listeners or subprocess transports.
type MCPServer struct {
	references []string
	allowed    map[string]bool
	directory  string
	read       func(string, string) (store.Metadata, error)
}

// MCPHealth describes this configured names-only service, not host protection or
// provider availability. Health never opens stores or contacts value providers.
type MCPHealth struct {
	Version int    `json:"version"`
	Status  string `json:"status"`
	Stores  int    `json:"stores"`
}

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *mcpError       `json:"error,omitempty"`
}

type mcpTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations struct {
		ReadOnlyHint    bool `json:"readOnlyHint"`
		DestructiveHint bool `json:"destructiveHint"`
		OpenWorldHint   bool `json:"openWorldHint"`
	} `json:"annotations"`
}

type mcpArguments struct {
	Reference      string          `json:"reference,omitempty"`
	Selectors      store.Selectors `json:"selectors,omitempty"`
	Left           string          `json:"left,omitempty"`
	Right          string          `json:"right,omitempty"`
	LeftSelectors  store.Selectors `json:"left_selectors,omitempty"`
	RightSelectors store.Selectors `json:"right_selectors,omitempty"`
}

// NewMCPServer validates configuration without opening stores. Exact request
// reference matching is performed before metadata reads, including diff's two
// sides. Aliases and alternate spellings do not expand the configured scope.
func NewMCPServer(config MCPConfig) (*MCPServer, error) {
	if !config.Enabled {
		return nil, ErrMCPDisabled
	}
	if len(config.Stores) == 0 || len(config.Stores) > 64 {
		return nil, ErrMCPConfig
	}
	server := &MCPServer{references: make([]string, 0, len(config.Stores)), allowed: make(map[string]bool), directory: config.Directory, read: ReadMetadata}
	for _, reference := range config.Stores {
		if !explicitMetadataReference(reference) || server.allowed[reference] {
			return nil, ErrMCPConfig
		}
		if reference[:5] != "file:" && (!absoluteMetadataPath(config.Directory) || !safeMetadataText(config.Directory, 4096, false)) {
			return nil, ErrMCPConfig
		}
		server.references = append(server.references, reference)
		server.allowed[reference] = true
	}
	return server, nil
}

// Serve implements newline-delimited MCP JSON-RPC over caller-owned stdio. Frames
// are bounded to 64 KiB (excluding LF); responses to 4 MiB. Batches and duplicate
// JSON keys are rejected. IDs are nonnegative safe JSON integers or short ASCII
// opaque strings, never arbitrary request text. Error messages never echo input,
// parser diagnostics, store errors, argv or provider stderr. EOF ends the session;
// the caller owns transport cancellation and must close a blocked input to stop it.
func (server *MCPServer) Serve(input io.Reader, output io.Writer) error {
	if server == nil || len(server.allowed) == 0 {
		return ErrMCPDisabled
	}
	reader := bufio.NewReaderSize(input, MaxMCPInputBytes+2)
	initialized, ready := false, false
	for {
		frame, err := reader.ReadSlice('\n')
		if err == io.EOF && len(frame) == 0 {
			return nil
		}
		if err != nil && err != io.EOF && err != bufio.ErrBufferFull {
			return ErrMCPIO
		}
		frame = bytes.TrimSuffix(frame, []byte{'\n'})
		if err == bufio.ErrBufferFull || len(frame) > MaxMCPInputBytes {
			if server.writeResponse(output, mcpFailure(nil, -32700, "Invalid metadata protocol input")) != nil {
				return ErrMCPIO
			}
			return ErrMCPProtocol
		}
		var request mcpRequest
		if decodeNamesJSON(frame, &request) != nil || request.JSONRPC != "2.0" || request.Method == "" || (len(request.ID) != 0 && !validMCPID(request.ID)) {
			if server.writeResponse(output, mcpFailure(nil, -32600, "Invalid metadata protocol request")) != nil {
				return ErrMCPIO
			}
			continue
		}
		// Notifications never produce responses. Only initialization changes state.
		if len(request.ID) == 0 {
			if request.Method == "notifications/initialized" && initialized && emptyMCPParams(request.Params) {
				ready = true
			}
			continue
		}
		response := mcpResponse{JSONRPC: "2.0", ID: request.ID}
		switch request.Method {
		case "initialize":
			var params struct {
				ProtocolVersion string          `json:"protocolVersion"`
				Capabilities    json.RawMessage `json:"capabilities"`
				ClientInfo      struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Title   string `json:"title,omitempty"`
				} `json:"clientInfo"`
			}
			if initialized || decodeNamesJSON(request.Params, &params) != nil || params.ProtocolVersion == "" || params.ClientInfo.Name == "" {
				response = mcpFailure(request.ID, -32602, "Invalid metadata protocol parameters")
			} else {
				initialized = true
				version := mcpVersion
				if params.ProtocolVersion == "2024-11-05" || params.ProtocolVersion == "2025-03-26" {
					version = params.ProtocolVersion
				}
				response.Result = struct {
					ProtocolVersion string `json:"protocolVersion"`
					Capabilities    struct {
						Tools struct{} `json:"tools"`
					} `json:"capabilities"`
					ServerInfo struct {
						Name    string `json:"name"`
						Version string `json:"version"`
					} `json:"serverInfo"`
				}{ProtocolVersion: version, ServerInfo: struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				}{"secret-metadata", "1"}}
			}
		case "ping":
			if !emptyMCPParams(request.Params) {
				response = mcpFailure(request.ID, -32602, "Invalid metadata protocol parameters")
			} else {
				response.Result = struct{}{}
			}
		case "tools/list":
			if !ready {
				response = mcpFailure(request.ID, -32600, "Metadata protocol is not initialized")
			} else if !emptyMCPParams(request.Params) {
				response = mcpFailure(request.ID, -32602, "Invalid metadata protocol parameters")
			} else {
				response.Result = struct {
					Tools []mcpTool `json:"tools"`
				}{metadataTools()}
			}
		case "tools/call":
			if !ready {
				response = mcpFailure(request.ID, -32600, "Metadata protocol is not initialized")
			} else {
				response = server.call(request)
			}
		default:
			response = mcpFailure(request.ID, -32601, "Metadata method is not available")
		}
		if server.writeResponse(output, response) != nil {
			return ErrMCPIO
		}
	}
}

func emptyMCPParams(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	var params struct{}
	return decodeNamesJSON(data, &params) == nil
}

func (server *MCPServer) call(request mcpRequest) mcpResponse {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments,omitempty"`
	}
	if decodeNamesJSON(request.Params, &params) != nil {
		return mcpFailure(request.ID, -32602, "Invalid metadata tool parameters")
	}
	// Reject unsupported capabilities before parsing arguments or reading any store.
	if params.Name != "list" && params.Name != "show" && params.Name != "diff" && params.Name != "health" {
		return mcpFailure(request.ID, -32602, "Metadata tool is not available")
	}
	if len(params.Arguments) == 0 {
		params.Arguments = json.RawMessage("{}")
	}
	var arguments mcpArguments
	if decodeNamesJSON(params.Arguments, &arguments) != nil || validateMetadataSelectors(arguments.Selectors) != nil || validateMetadataSelectors(arguments.LeftSelectors) != nil || validateMetadataSelectors(arguments.RightSelectors) != nil {
		return mcpFailure(request.ID, -32602, "Invalid metadata tool parameters")
	}
	// Check exact fields too: ignored fields must not accidentally imply scoping.
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(params.Arguments, &fields)
	for field := range fields {
		allowed := (params.Name == "show" && (field == "reference" || field == "selectors")) || (params.Name == "diff" && (field == "left" || field == "right" || field == "left_selectors" || field == "right_selectors"))
		if !allowed {
			return mcpFailure(request.ID, -32602, "Invalid metadata tool parameters")
		}
	}
	var result any
	var err error
	switch params.Name {
	case "health":
		result = MCPHealth{Version: store.MetadataVersion, Status: "ready", Stores: len(server.references)}
	case "list":
		result, err = server.inventory(server.references, nil)
	case "show":
		if !server.allowed[arguments.Reference] {
			return mcpFailure(request.ID, -32602, "Store is not allowlisted")
		}
		result, err = server.inventory([]string{arguments.Reference}, arguments.Selectors)
	case "diff":
		if !server.allowed[arguments.Left] || !server.allowed[arguments.Right] {
			return mcpFailure(request.ID, -32602, "Store is not allowlisted")
		}
		var left, right store.Metadata
		left, err = server.metadata(arguments.Left)
		if err == nil {
			right, err = server.metadata(arguments.Right)
		}
		if err == nil {
			result, err = DiffMetadata(left, right, arguments.LeftSelectors, arguments.RightSelectors)
		}
	}
	if err != nil {
		return mcpFailure(request.ID, -32603, "Store metadata is unavailable")
	}
	data, err := json.Marshal(result)
	if err != nil || len(data) > MaxMCPOutputBytes/2 {
		return mcpFailure(request.ID, -32603, "Metadata response exceeds limit")
	}
	return mcpResponse{JSONRPC: "2.0", ID: request.ID, Result: struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}{Content: []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}{{"text", string(data)}}}}
}

func (server *MCPServer) metadata(reference string) (store.Metadata, error) {
	if !server.allowed[reference] {
		return store.Metadata{}, ErrMCPConfig
	}
	metadata, err := server.read(reference, server.directory)
	if err != nil || metadata.Reference != reference || validateMetadata(metadata) != nil {
		return store.Metadata{}, ErrMetadataRead
	}
	return metadata, nil
}

func (server *MCPServer) inventory(references []string, selectors store.Selectors) (Inventory, error) {
	metadata := make([]store.Metadata, 0, len(references))
	for _, reference := range references {
		item, err := server.metadata(reference)
		if err != nil {
			return Inventory{}, err
		}
		metadata = append(metadata, item)
	}
	return BuildInventory(metadata, selectors)
}

func metadataTools() []mcpTool {
	labels := `{"type":"object","additionalProperties":{"type":"string"}}`
	specs := []struct{ name, description, schema string }{
		{"list", "List names and labels in explicitly allowlisted stores", `{"type":"object","properties":{},"additionalProperties":false}`},
		{"show", "Show names-only metadata for one allowlisted store", `{"type":"object","properties":{"reference":{"type":"string"},"selectors":` + labels + `},"required":["reference"],"additionalProperties":false}`},
		{"diff", "Compare selected names, labels, presence and backend only", `{"type":"object","properties":{"left":{"type":"string"},"right":{"type":"string"},"left_selectors":` + labels + `,"right_selectors":` + labels + `},"required":["left","right"],"additionalProperties":false}`},
		{"health", "Report configured metadata service readiness, not host protection", `{"type":"object","properties":{},"additionalProperties":false}`},
	}
	tools := make([]mcpTool, 0, len(specs))
	for _, spec := range specs {
		tool := mcpTool{Name: spec.name, Description: spec.description, InputSchema: json.RawMessage(spec.schema)}
		tool.Annotations.ReadOnlyHint = true
		tools = append(tools, tool)
	}
	return tools
}

func mcpFailure(id json.RawMessage, code int, message string) mcpResponse {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return mcpResponse{JSONRPC: "2.0", ID: id, Error: &mcpError{Code: code, Message: message}}
}

func (server *MCPServer) writeResponse(output io.Writer, response mcpResponse) error {
	data, err := json.Marshal(response)
	if err != nil {
		return ErrMCPIO
	}
	if len(data)+1 > MaxMCPOutputBytes {
		data, _ = json.Marshal(mcpFailure(response.ID, -32603, "Metadata response exceeds limit"))
	}
	data = append(data, '\n')
	if n, err := output.Write(data); err != nil || n != len(data) {
		return ErrMCPIO
	}
	return nil
}

func validMCPID(data []byte) bool {
	if len(data) > 66 {
		return false
	}
	if len(data) > 0 && data[0] == '"' {
		var id string
		if json.Unmarshal(data, &id) != nil || id == "" || len(id) > 64 {
			return false
		}
		for _, r := range id {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
				return false
			}
		}
		return true
	}
	id, err := strconv.ParseUint(string(data), 10, 53)
	return err == nil && id <= 1<<53-1 && strconv.FormatUint(id, 10) == string(data)
}

// decodeNamesJSON rejects duplicate keys, excessive nesting, invalid UTF-8,
// unknown typed fields and trailing JSON. It returns only a fixed error category.
func decodeNamesJSON(data []byte, result any) error {
	if len(data) == 0 || !utf8.Valid(data) {
		return ErrMCPProtocol
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	keys := 0
	if validateNamesJSON(decoder, 0, &keys) != nil {
		return ErrMCPProtocol
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrMCPProtocol
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(result) != nil || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return ErrMCPProtocol
	}
	return nil
}

func validateNamesJSON(decoder *json.Decoder, depth int, keys *int) error {
	if depth > 32 {
		return ErrMCPProtocol
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrMCPProtocol
	}
	delim, container := token.(json.Delim)
	if !container {
		return nil
	}
	seen := make(map[string]bool)
	for decoder.More() {
		if delim == '{' {
			token, err := decoder.Token()
			name, ok := token.(string)
			if err != nil || !ok || seen[name] || *keys >= 4096 {
				return ErrMCPProtocol
			}
			seen[name] = true
			*keys++
		}
		if validateNamesJSON(decoder, depth+1, keys) != nil {
			return ErrMCPProtocol
		}
	}
	end, err := decoder.Token()
	if err != nil || (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
		return ErrMCPProtocol
	}
	return nil
}
