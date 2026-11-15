package execbox

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// publishTestSupervisor is a supervisor with only the configuration publishing
// reads: no namespaces, no cgroup, no listener.
func publishTestSupervisor(t *testing.T) *Supervisor {
	t.Helper()
	root := t.TempDir()
	cfg := Config{
		WritableRoots: []string{t.TempDir()},
		ToolboxRoot:   filepath.Join(root, "toolbox"),
		Logf:          func(string, ...any) {},
	}
	if err := os.MkdirAll(filepath.Join(cfg.ToolboxRoot, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.ToolboxRoot, "staging"), 0o700); err != nil {
		t.Fatal(err)
	}
	return &Supervisor{cfg: cfg, sessions: map[string]*session{}}
}

// stage writes a fixture artifact into an install session's staging prefix.
func stage(t *testing.T, sup *Supervisor, id, name, content string) string {
	t.Helper()
	dir, err := sup.stagingDir(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareStaging(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bin", name)
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A staged artifact is published atomically: the destination holds the whole
// file, owner root and mode 0755, and no temp file is left behind.
func TestPublishArtifactMovesAStagedFile(t *testing.T) {
	sup := publishTestSupervisor(t)
	dir := stage(t, sup, "install-1", "fixture", "#!/bin/sh\necho fixture 1.0\n")
	binDir := sup.cfg.BinDir()
	// A previous publication of the same name is replaced, not appended to.
	if err := os.WriteFile(filepath.Join(binDir, "fixture"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	pub, err := publishArtifact(dir, binDir, "fixture")
	if err != nil {
		t.Fatalf("publishArtifact: %v", err)
	}
	want := filepath.Join(binDir, "fixture")
	if pub.Path != want || pub.Name != "fixture" {
		t.Fatalf("published %+v, want %s", pub, want)
	}
	body, err := os.ReadFile(want)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "#!/bin/sh\necho fixture 1.0\n" {
		t.Fatalf("published body = %q", body)
	}
	if pub.Size != int64(len(body)) {
		t.Errorf("size = %d, want %d", pub.Size, len(body))
	}
	if wantDigest := fmt.Sprintf("%x", sha256.Sum256(body)); pub.SHA256 != wantDigest {
		t.Errorf("digest = %s, want %s", pub.SHA256, wantDigest)
	}
	fi, err := os.Stat(want)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("mode = %v, want 0755", fi.Mode().Perm())
	}
	// The published file is the supervisor's, not the session's: the session uid
	// must not be able to change what later sessions run.
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 && st.Uid != 0 {
		t.Errorf("published owner = %d, want root", st.Uid)
	}
	entries, err := os.ReadDir(binDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("bin dir holds %d entries, want the published file alone", len(entries))
	}
}

// Nothing that is not a regular file inside the staging root is published: a
// symlink, a directory, a name that escapes the root, and a bin directory
// replaced by a symlink are all refused.
func TestPublishRefusesAnythingButAStagedRegularFile(t *testing.T) {
	sup := publishTestSupervisor(t)
	binDir := sup.cfg.BinDir()
	dir := stage(t, sup, "install-1", "good", "good")

	t.Run("symlink", func(t *testing.T) {
		if err := os.Symlink(filepath.Join(dir, "bin", "good"), filepath.Join(dir, "bin", "link")); err != nil {
			t.Fatal(err)
		}
		if _, err := publishArtifact(dir, binDir, "link"); err == nil {
			t.Fatal("a symlink was published")
		}
	})
	t.Run("directory", func(t *testing.T) {
		if err := os.Mkdir(filepath.Join(dir, "bin", "subdir"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := publishArtifact(dir, binDir, "subdir"); err == nil {
			t.Fatal("a directory was published")
		}
	})
	t.Run("path outside staging", func(t *testing.T) {
		outside := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(outside, []byte("outside"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := publishArtifact(dir, binDir, "../../outside"); err == nil {
			t.Fatal("a path outside the staging root was published")
		}
	})
	t.Run("bin replaced by a symlink", func(t *testing.T) {
		evil := t.TempDir()
		if err := os.WriteFile(filepath.Join(evil, "evil"), []byte("evil"), 0o755); err != nil {
			t.Fatal(err)
		}
		escape := stage(t, sup, "install-2", "evil", "evil")
		if err := os.RemoveAll(filepath.Join(escape, "bin")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(evil, filepath.Join(escape, "bin")); err != nil {
			t.Fatal(err)
		}
		if _, err := publishArtifact(escape, binDir, "evil"); err == nil {
			t.Fatal("a bin directory that resolves outside the staging root was published")
		}
	})
	t.Run("nothing staged", func(t *testing.T) {
		if _, err := publishArtifact(dir, binDir, "absent"); !errors.Is(err, ErrNotStaged) {
			t.Fatalf("publish of an absent artifact = %v, want ErrNotStaged", err)
		}
	})
	if _, err := os.Stat(filepath.Join(binDir, "good")); err == nil {
		t.Fatal("a refused publish still wrote into the bin directory")
	}
}

// The protocol path: only an install session may publish, and a successful
// publish removes the staging prefix it came from.
func TestSupervisorPublishOnlyForInstallSessions(t *testing.T) {
	sup := publishTestSupervisor(t)
	dir := stage(t, sup, "install-1", "fixture", "#!/bin/sh\necho ok\n")

	clientConn, serverConn := unixSocketPair(t)
	go sup.publish(newWireConn(serverConn), request{
		Op:      opPublish,
		Session: &sessionWire{ID: "install-1", Purpose: string(netpolicy.PurposeTesting)},
		Publish: &publishRequest{Name: "fixture"},
	})
	var f frame
	if err := newWireConn(clientConn).read(&f); err != nil {
		t.Fatalf("read: %v", err)
	}
	if f.Type != frameError || !strings.Contains(f.Message, "only an install session") {
		t.Fatalf("a testing session published: %+v", f)
	}

	clientConn, serverConn = unixSocketPair(t)
	go sup.publish(newWireConn(serverConn), request{
		Op:      opPublish,
		Session: &sessionWire{ID: "install-1", Purpose: string(netpolicy.PurposeInstall)},
		Publish: &publishRequest{Name: "fixture"},
	})
	if err := newWireConn(clientConn).read(&f); err != nil {
		t.Fatalf("read: %v", err)
	}
	if f.Type != framePublished || f.Published == nil || f.Published.Name != "fixture" {
		t.Fatalf("install publish = %+v", f)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the staging prefix survived a successful publish: %v", err)
	}
}

// The client maps the supervisor's answer: a publication, a missing staged
// artifact, and a refusal are three different outcomes.
func TestClientPublishOutcomes(t *testing.T) {
	install := netpolicy.Session{ID: "install-1", Purpose: netpolicy.PurposeInstall}

	t.Run("published", func(t *testing.T) {
		f := newFakeSupervisor(t, Report{Isolation: true})
		f.publish = &frame{Type: framePublished, Published: &Published{Name: "fixture", Path: "/state/bin/fixture", SHA256: "abc", Size: 3}}
		pub, err := PublishArtifact(NewClient(f.path), context.Background(), install, "fixture")
		if err != nil {
			t.Fatalf("PublishArtifact: %v", err)
		}
		if pub.Path != "/state/bin/fixture" || pub.SHA256 != "abc" || pub.Size != 3 {
			t.Fatalf("published = %+v", pub)
		}
		req := <-f.gotReqs
		if req.Op != opPublish || req.Publish == nil || req.Publish.Name != "fixture" {
			t.Fatalf("publish request = %+v", req)
		}
		if req.Session == nil || req.Session.Purpose != string(netpolicy.PurposeInstall) {
			t.Fatalf("publish session = %+v", req.Session)
		}
	})
	t.Run("not staged", func(t *testing.T) {
		f := newFakeSupervisor(t, Report{Isolation: true})
		f.publish = &frame{Type: frameNotStaged, Message: "nothing at /state/staging/install-1/bin/fixture"}
		_, err := PublishArtifact(NewClient(f.path), context.Background(), install, "fixture")
		if !errors.Is(err, ErrNotStaged) {
			t.Fatalf("PublishArtifact = %v, want ErrNotStaged", err)
		}
	})
	t.Run("refused", func(t *testing.T) {
		f := newFakeSupervisor(t, Report{Isolation: true})
		f.publish = &frame{Type: frameError, Message: "execbox: publish refused: not a regular file"}
		_, err := PublishArtifact(NewClient(f.path), context.Background(), install, "fixture")
		if err == nil || errors.Is(err, ErrNotStaged) {
			t.Fatalf("PublishArtifact = %v, want a refusal", err)
		}
	})
	t.Run("client cannot publish", func(t *testing.T) {
		_, err := PublishArtifact(runOnlyClient{}, context.Background(), install, "fixture")
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("PublishArtifact = %v, want a capability error", err)
		}
	})
}

// runOnlyClient is a Client that cannot publish, the shape of a client from
// before the toolbox existed.
type runOnlyClient struct{}

func (runOnlyClient) Run(context.Context, netpolicy.Session, Spec) (io.ReadWriteCloser, error) {
	return nil, ErrUnavailable
}

func (runOnlyClient) RunOnce(context.Context, netpolicy.Session, Spec) (Result, error) {
	return Result{}, ErrUnavailable
}

func (runOnlyClient) Capabilities(context.Context) (Report, error) {
	return Report{}, ErrUnavailable
}

// An install session gets a writable staging prefix and an environment that
// points at it; every other session gets the published bin directory read-only
// on PATH and no staging path at all.
func TestInstallSessionStagingAndPath(t *testing.T) {
	sup := publishTestSupervisor(t)
	ws := sup.cfg.WritableRoots[0]
	binDir := sup.cfg.BinDir()

	sess, err := sup.newSession(request{
		Session: &sessionWire{ID: "install-1", Purpose: string(netpolicy.PurposeInstall)},
		Spec:    &Spec{Argv: []string{"true"}, Dir: ws},
	})
	if err != nil {
		t.Fatalf("newSession: %v", err)
	}
	staging := sess.staging
	if staging == "" || !strings.HasPrefix(staging, sup.cfg.StagingRoot()) {
		t.Fatalf("install staging = %q, want a prefix under %s", staging, sup.cfg.StagingRoot())
	}
	for _, sub := range []string{"bin", "home", "tmp"} {
		if fi, err := os.Stat(filepath.Join(staging, sub)); err != nil || !fi.IsDir() {
			t.Errorf("staging %s: %v", sub, err)
		}
	}
	if !contains(sess.spec.Writable, staging) {
		t.Errorf("staging %q is not writable in the session: %v", staging, sess.spec.Writable)
	}

	env := withEnvDefaults(nil, staging, binDir)
	for _, want := range []string{
		"PREFIX=" + staging,
		"HOME=" + filepath.Join(staging, "home"),
		"TMPDIR=" + filepath.Join(staging, "tmp"),
	} {
		if !contains(env, want) {
			t.Errorf("install env lacks %q: %v", want, env)
		}
	}
	path := envValue(env, "PATH")
	if !strings.HasPrefix(path, filepath.Join(staging, "bin")+":"+binDir+":") {
		t.Errorf("install PATH = %q, want the staged prefix and the published bin dir first", path)
	}

	normal, err := sup.newSession(request{
		Session: &sessionWire{ID: "task-1", Purpose: string(netpolicy.PurposeTesting)},
		Spec:    &Spec{Argv: []string{"true"}, Dir: ws},
	})
	if err != nil {
		t.Fatalf("newSession: %v", err)
	}
	if normal.staging != "" {
		t.Errorf("a testing session got a staging prefix %q", normal.staging)
	}
	env = withEnvDefaults(nil, normal.staging, binDir)
	if envValue(env, "PREFIX") != "" {
		t.Errorf("a testing session exported PREFIX: %v", env)
	}
	if path := envValue(env, "PATH"); !strings.HasPrefix(path, binDir+":") {
		t.Errorf("testing PATH = %q, want the published bin dir first", path)
	}
	// A caller's own PATH keeps its order, after the toolbox directories.
	env = withEnvDefaults([]string{"PATH=/opt/bin"}, "", binDir)
	if got := envValue(env, "PATH"); got != binDir+":/opt/bin" {
		t.Errorf("caller PATH = %q, want %s:/opt/bin", got, binDir)
	}
}

// A program named without a path is resolved against the session's PATH, which
// is where a published tool lives, not against the supervisor child's.
func TestLookPathInUsesTheSessionPath(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "fixture")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notexec"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := []string{"PATH=/usr/bin:" + dir}
	if got, ok := lookPathIn(env, "fixture"); !ok || got != tool {
		t.Fatalf("lookPathIn(fixture) = %q (ok=%v), want %s", got, ok, tool)
	}
	if _, ok := lookPathIn(env, "notexec"); ok {
		t.Error("a non-executable file was resolved as a program")
	}
	if got, ok := lookPathIn(env, "/bin/sh"); ok || got != "/bin/sh" {
		t.Errorf("an absolute path was rewritten: %q (ok=%v)", got, ok)
	}
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func envValue(env []string, key string) string {
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, key+"="); ok {
			return v
		}
	}
	return ""
}
