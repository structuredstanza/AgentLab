package execbox

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// Some callers can only start a process (the MCP stdio client takes a command
// and arguments). The bridge is how such a caller still gets an isolated
// program: the command it spawns is our own binary, which reads the session the
// trusted backend handed it, asks the supervisor to start the real program in a
// session, and shuttles bytes. The program never sees the session, and a tool
// process cannot use the bridge because it can neither reach the supervisor nor
// pass the peer check.
const (
	bridgeSessionEnv = "M1NERVAC0NSOLE_EXECBOX_SESSION"
	bridgeProgramEnv = "M1NERVAC0NSOLE_EXECBOX_ENV"
)

// BridgeCommand builds the command, arguments and environment that run argv
// inside a session. The returned environment entries are the only ones the
// bridge needs; the child's environment is passed separately so the backend's
// own environment is not inherited by the program.
func BridgeCommand(sess netpolicy.Session, argv []string, env []string) (string, []string, map[string]string, error) {
	if len(argv) == 0 {
		return "", nil, nil, fmt.Errorf("execbox: bridge: no program")
	}
	sessJSON, err := json.Marshal(sess)
	if err != nil {
		return "", nil, nil, err
	}
	envJSON, err := json.Marshal(env)
	if err != nil {
		return "", nil, nil, err
	}
	self, err := os.Executable()
	if err != nil {
		return "", nil, nil, err
	}
	return self, append([]string{"execbox", "bridge", "--"}, argv...), map[string]string{
		bridgeSessionEnv: base64.StdEncoding.EncodeToString(sessJSON),
		bridgeProgramEnv: base64.StdEncoding.EncodeToString(envJSON),
	}, nil
}

// BridgeSession decodes the session the backend handed the bridge.
func BridgeSession() (netpolicy.Session, error) {
	var sess netpolicy.Session
	raw, err := base64.StdEncoding.DecodeString(os.Getenv(bridgeSessionEnv))
	if err != nil {
		return sess, fmt.Errorf("execbox bridge: session: %w", err)
	}
	if err := json.Unmarshal(raw, &sess); err != nil {
		return sess, fmt.Errorf("execbox bridge: session: %w", err)
	}
	return sess, nil
}

// BridgeProgramEnv decodes the child environment the backend handed the bridge.
func BridgeProgramEnv() ([]string, error) {
	v := os.Getenv(bridgeProgramEnv)
	if v == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("execbox bridge: env: %w", err)
	}
	var env []string
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("execbox bridge: env: %w", err)
	}
	return env, nil
}
