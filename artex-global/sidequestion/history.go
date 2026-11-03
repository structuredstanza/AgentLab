package sidequestion

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/norma/llm"
)

func formatReadableToolInput(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "{}"
	}
	var compact bytes.Buffer
	if json.Compact(&compact, raw) == nil {
		return compact.String()
	}
	return string(raw)
}

func renderReadableContentBlock(b llm.ContentBlock) (string, error) {
	switch b.Type {
	case llm.BlockText:
		return "[UNTRUSTED prior transcript text]\n" + b.Text, nil
	case llm.BlockToolUse:
		return fmt.Sprintf("[UNTRUSTED Prior Model Tool Call: %s (id: %s)\nArguments: %s]", b.Name, b.ID, formatReadableToolInput(b.Input)), nil
	case llm.BlockToolResult:
		status := "success"
		if b.IsError {
			status = "error"
		}
		var content strings.Builder
		for _, child := range b.Content {
			if child.Type != llm.BlockText {
				return "", fmt.Errorf("native input: uninspectable attachment block %q in tool result", child.Type)
			}
			content.WriteString(child.Text)
		}
		return fmt.Sprintf("[UNTRUSTED Prior Model Tool Result (call_id: %s, status: %s):\n%s]", b.ToolUseID, status, content.String()), nil
	default:
		return "", fmt.Errorf("native input: uninspectable attachment block %q in converted prefix", b.Type)
	}
}

// ReadableHistoryMessage copies history without granting replay or tool-execution authority.
func ReadableHistoryMessage(message llm.Message) (llm.Message, error) {
	var blocks []llm.ContentBlock
	for _, block := range message.Content {
		if block.Type == "provider_state" || block.Type == llm.BlockThinking {
			continue
		}
		text, err := renderReadableContentBlock(block)
		if err != nil {
			return llm.Message{}, err
		}
		if text != "" {
			blocks = append(blocks, llm.ContentBlock{Type: llm.BlockText, Text: text})
		}
	}
	return llm.Message{Role: message.Role, Content: blocks}, nil
}
