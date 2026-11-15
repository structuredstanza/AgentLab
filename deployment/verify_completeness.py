#!/usr/bin/env python3
"""Prove the recorder loses no bytes, without a borrowed credential or a policy change.

Tier 1, byte completeness. A real gateway.New and traffic.OpenWithTransport run on
a temporary store, in memory only: the harness mints the session credential itself,
grants 127.0.0.1/32 on the fixture's own ports through an in-memory netpolicy.Source,
and produces four shapes through the recorder -- plain HTTP, SSE, a 6 MiB body, and a
duplex WebSocket with text and binary frames in both directions. Each shape is then
measured at four stages, each a different artifact:

  collected  the recorder stored the exchange (the index row and its resp_len)
  retained   the body reads back from the live store, complete
  exported   ExportTask's archive carries the body
  consumed   ImportArchive into an empty store gives the same bytes back

A shape is verified only when collected == retained == exported == consumed, byte for
byte, against what the origin sent. Anything else exits non-zero naming the shape and
the stage that lost the bytes. For the WebSocket shape the stored body is the JSONL
transcript, so the check compares the transcript's data lines with the frames the
peers exchanged: same direction, type, length and payload hash, in order.

The harness writes no scope rule, no certificate exception and no policy-audit row.
The gateway it configures is its own, the credential is minted inside the fixture
process and never printed, and every temporary directory is removed before exit.

Keylog: the real recorder and gateway run against a local TLS origin with
SSLKEYLOGFILE set, the origin flow is recorded, and tshark must recover the plaintext
nonce with that keylog and not without it.

Tier 2, live guest, is verify_capture.py: it covers credential-free guest execution,
the recorded refusal and the export, so this script does not repeat it and adds no
authority to reach a live origin.

Exit: 0 verified, 1 a check failed, 2 a prerequisite was missing.
"""
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import uuid

ROOT = Path(__file__).resolve().parents[1]
TIER = 'tier 1: isolated recorder harness'
SHAPES = ('plain', 'sse', 'big', 'ws')
STAGES = ('collected', 'retained', 'exported', 'consumed')

# The producer: a real gateway and recorder over a temporary store, with a
# credential it mints itself. It prints one JSON report and exits 0; the verifier
# decides the verdict. Its only arguments are three directories, so no credential
# and no proxy address can reach its command line.
COMPLETENESS_FIXTURE = r'''package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/gateway"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/traffic"
)

const (
	taskID   = 1
	bigBytes = 6 * 1024 * 1024
	// captureMark is the header family the recorder appends to a stored response
	// head when it did not keep the whole body.
	captureMark = "X-M1nervac0nsole-Capture: body not captured"
	recordWait  = 30 * time.Second
)

// stage is one measurement of one body: its length and its SHA-256.
type stage struct {
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// frameLine is one WebSocket message as the peers exchanged it, or as the
// transcript recorded it.
type frameLine struct {
	Dir    string `json:"dir"`
	Type   string `json:"type"`
	Len    int    `json:"len"`
	SHA256 string `json:"sha256"`
}

type shape struct {
	Path       string      `json:"path"`
	Nonce      string      `json:"nonce"`
	Status     int         `json:"status"`
	Sent       stage       `json:"sent"`
	Collected  stage       `json:"collected"`
	Retained   stage       `json:"retained"`
	Exported   stage       `json:"exported"`
	Consumed   stage       `json:"consumed"`
	Frames     []frameLine `json:"frames,omitempty"`
	Transcript []frameLine `json:"transcript,omitempty"`
	Closes     []string    `json:"closes,omitempty"`
	Partial    bool        `json:"partial"`
	Error      string      `json:"error,omitempty"`

	// id is the exchange this shape was recorded as; not part of the report.
	id string
}

// refusal is the check that the grant is narrow: a loopback port outside the
// granted set must be refused at the policy stage, before the gateway dials.
type refusal struct {
	Port       int    `json:"port"`
	Status     int    `json:"status"`
	Stage      string `json:"stage"`
	OriginHits int64  `json:"origin_hits"`
}

type report struct {
	TaskID   int64    `json:"task_id"`
	Shapes   []shape  `json:"shapes"`
	Refused  *refusal `json:"refused,omitempty"`
	Imported int64    `json:"imported"`
	Error    string   `json:"error,omitempty"`
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: fixture <store> <second-store> <export-dir>")
		os.Exit(2)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(run(os.Args[1], os.Args[2], os.Args[3])); err != nil {
		fmt.Fprintln(os.Stderr, "fixture:", err)
		os.Exit(1)
	}
}

func run(store, second, exportDir string) *report {
	out := &report{TaskID: taskID}
	failed := func(err error) *report {
		out.Error = err.Error()
		return out
	}
	credential, err := newCredential()
	if err != nil {
		return failed(err)
	}
	base, err := newCredential()
	if err != nil {
		return failed(err)
	}
	plainOrigin, plainPort, err := serve(plainHandler())
	if err != nil {
		return failed(err)
	}
	defer plainOrigin.Close()
	certificate, err := selfSigned()
	if err != nil {
		return failed(err)
	}
	// The WebSocket origin is TLS: the recorder upgrades a socket only inside a
	// CONNECT tunnel.
	secureOrigin, securePort, err := serveTLS(wsHandler(), certificate)
	if err != nil {
		return failed(err)
	}
	defer secureOrigin.Close()
	// A listener the policy does not grant. The gateway must refuse before it
	// dials, so this listener must never see a connection.
	ungranted, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return failed(err)
	}
	defer ungranted.Close()
	var hits atomic.Int64
	go func() {
		for {
			conn, err := ungranted.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			conn.Close()
		}
	}()
	ungrantedPort := ungranted.Addr().(*net.TCPAddr).Port

	listenPort, err := freePort()
	if err != nil {
		return failed(err)
	}
	listen := fmt.Sprintf("127.0.0.1:%d", listenPort)
	session := netpolicy.Session{ID: "completeness-fixture", TaskID: taskID,
		Purpose: netpolicy.PurposeTesting, Revision: 1, Credential: credential}
	transport := gateway.New(gateway.Config{
		Authorizer: netpolicy.NewAuthorizer(fixturePolicy{ports: []int{plainPort, securePort}}),
		SessionFor: func(req *http.Request) (netpolicy.Session, bool) {
			if credentialOf(req) != credential {
				return netpolicy.Session{}, false
			}
			return session, true
		},
		// The fixture's own origin is self-signed and a bare address sends no
		// SNI. This exception lives in the harness's throwaway gateway only: no
		// policy row and no certificate exception is written anywhere.
		CertException: func(_ netpolicy.Session, serverName string) bool {
			return serverName == "" || serverName == "127.0.0.1"
		},
	})
	recorder, err := traffic.OpenWithTransport(store, listen, transport)
	if err != nil {
		return failed(err)
	}
	defer recorder.Close()
	go func() { _ = recorder.Start() }()
	if err := waitFor(listen); err != nil {
		return failed(err)
	}
	// The empty password is deliberate: gorilla sends Proxy-Authorization only
	// when the proxy URL carries one, and the gateway resolves the session from it.
	proxy := &url.URL{Scheme: "http", User: url.UserPassword(credential, ""), Host: listen}
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(proxy),
		// The recorder's leaf carries no IP SAN for a bare address, so the
		// fixture client trusts the recorder it just started instead of its CA.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	for _, name := range []string{"plain", "sse", "big"} {
		nonce := base + "-" + name
		target := fmt.Sprintf("http://127.0.0.1:%d/%s/%s", plainPort, name, nonce)
		out.Shapes = append(out.Shapes, measureHTTP(recorder, client, name, target, nonce))
	}
	wsNonce := base + "-ws"
	wsTarget := fmt.Sprintf("wss://127.0.0.1:%d/ws/%s", securePort, wsNonce)
	out.Shapes = append(out.Shapes, measureWS(recorder, proxy, wsTarget, wsNonce))
	out.Refused, err = refused(client, ungrantedPort, base+"-refused", &hits)
	if err != nil {
		return failed(err)
	}
	if _, _, err := recorder.ExportTask(taskID, exportDir); err != nil {
		return failed(err)
	}
	snapshot, err := readExport(exportDir)
	if err != nil {
		return failed(err)
	}
	secondStore, err := traffic.OpenWithTransport(second, "127.0.0.1:0", transport)
	if err != nil {
		return failed(err)
	}
	defer secondStore.Close()
	imported, err := secondStore.ImportArchive(exportDir)
	if err != nil {
		return failed(err)
	}
	out.Imported = imported
	for index := range out.Shapes {
		entry := &out.Shapes[index]
		if entry.Error != "" || entry.id == "" {
			continue
		}
		if err := fillStages(entry, snapshot, exportDir, secondStore); err != nil {
			entry.Error = err.Error()
		}
	}
	return out
}

// fixturePolicy is the harness's own policy source: one authorized include for
// loopback on the fixture's ports and nothing else.
type fixturePolicy struct{ ports []int }

func (p fixturePolicy) PolicyState(context.Context, netpolicy.Session) (netpolicy.State, error) {
	return netpolicy.State{Revision: 1, Rules: []netpolicy.Rule{{
		ID: 1, Effect: "include", Pattern: "127.0.0.1/32", Protocol: "any",
		Ports: p.ports, Authorized: true,
	}}}, nil
}

// credentialOf reads the session credential the way the server does: the proxy
// URL's user part arrives as Basic auth, and a client may send a bearer token.
func credentialOf(req *http.Request) string {
	if req == nil {
		return ""
	}
	value := strings.TrimSpace(req.Header.Get("Proxy-Authorization"))
	scheme, rest, _ := strings.Cut(value, " ")
	rest = strings.TrimSpace(rest)
	switch {
	case strings.EqualFold(scheme, "basic"):
		raw, err := base64.StdEncoding.DecodeString(rest)
		if err != nil {
			return ""
		}
		user, _, _ := strings.Cut(string(raw), ":")
		return user
	case strings.EqualFold(scheme, "bearer"):
		return rest
	}
	return ""
}

func measureHTTP(rec *traffic.Traffic, client *http.Client, name, target, nonce string) shape {
	sent := expectedBody(name, nonce)
	entry := shape{Path: name, Nonce: nonce, Sent: stageOf(sent)}
	body, status, err := fetch(client, target)
	if err != nil {
		entry.Error = err.Error()
		return entry
	}
	entry.Status = status
	if !bytes.Equal(body, sent) {
		entry.Error = fmt.Sprintf("the client received %d bytes with status %d, the origin sent %d",
			len(body), status, len(sent))
		return entry
	}
	row, err := rowFor(rec, nonce)
	if err != nil {
		entry.Error = err.Error()
		return entry
	}
	entry.id = row.ID
	entry.Collected = stage{Bytes: int64(row.RespLen)}
	retained, head, err := bodyOf(rec, row.ID)
	if err != nil {
		entry.Error = err.Error()
		return entry
	}
	entry.Retained = stageOf(retained)
	entry.Partial = strings.Contains(head, captureMark)
	return entry
}

func measureWS(rec *traffic.Traffic, proxy *url.URL, target, nonce string) shape {
	entry := shape{Path: "ws", Nonce: nonce}
	frames, err := exchangeWS(proxy, target, nonce)
	entry.Frames = frames
	if err != nil {
		entry.Error = err.Error()
		return entry
	}
	row, err := rowFor(rec, nonce)
	if err != nil {
		entry.Error = err.Error()
		return entry
	}
	entry.id = row.ID
	entry.Status = row.Status
	entry.Collected = stage{Bytes: int64(row.RespLen)}
	transcript, head, err := bodyOf(rec, row.ID)
	if err != nil {
		entry.Error = err.Error()
		return entry
	}
	entry.Retained = stageOf(transcript)
	entry.Partial = strings.Contains(head, captureMark)
	entry.Transcript, entry.Closes, err = parseTranscript(transcript)
	if err != nil {
		entry.Error = err.Error()
	}
	return entry
}

// fillStages measures the two stages that leave the live store: the archive
// ExportTask wrote, and the second store ImportArchive restored into.
func fillStages(entry *shape, snapshot traffic.ArchiveSnapshot, exportDir string, second *traffic.Traffic) error {
	found := false
	for _, item := range snapshot.Exchanges {
		if !strings.Contains(item.URL, entry.Nonce) {
			continue
		}
		body, err := exportedBody(exportDir, item)
		if err != nil {
			return err
		}
		if int64(len(body)) != int64(item.RespLen) {
			return fmt.Errorf("the archive says %d bytes for %s and holds %d", item.RespLen, entry.Nonce, len(body))
		}
		entry.Exported = stageOf(body)
		found = true
		break
	}
	if !found {
		return fmt.Errorf("the export holds no exchange for %s", entry.Nonce)
	}
	body, head, err := bodyOf(second, entry.id)
	if err != nil {
		return err
	}
	entry.Consumed = stageOf(body)
	if strings.Contains(head, captureMark) {
		entry.Partial = true
	}
	return nil
}

// parseTranscript decodes the stored JSONL transcript: one header line, then one
// data line per forwarded message and one close line per direction.
func parseTranscript(raw []byte) ([]frameLine, []string, error) {
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return nil, nil, errors.New("the transcript is empty")
	}
	var header struct {
		V    int    `json:"v"`
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
		return nil, nil, fmt.Errorf("the transcript header %q: %w", lines[0], err)
	}
	if header.V != 1 || header.Kind != "ws-transcript" {
		return nil, nil, fmt.Errorf("the transcript header is %q, not a v1 ws-transcript", lines[0])
	}
	var frames []frameLine
	var closes []string
	for _, line := range lines[1:] {
		var decoded struct {
			Dir   string          `json:"dir"`
			Type  string          `json:"type"`
			Len   int             `json:"len"`
			Data  []byte          `json:"data"`
			Close json.RawMessage `json:"close"`
		}
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			return nil, nil, fmt.Errorf("the transcript line %q: %w", line, err)
		}
		if len(decoded.Close) > 0 && string(decoded.Close) != "null" {
			closes = append(closes, decoded.Dir)
			continue
		}
		if decoded.Len != len(decoded.Data) {
			return nil, nil, fmt.Errorf("the transcript line %q says %d bytes and carries %d",
				line, decoded.Len, len(decoded.Data))
		}
		sum := sha256.Sum256(decoded.Data)
		frames = append(frames, frameLine{Dir: decoded.Dir, Type: decoded.Type,
			Len: decoded.Len, SHA256: hex.EncodeToString(sum[:])})
	}
	return frames, closes, nil
}

// exchangeWS sends one text and one binary message and reads each echo, so both
// directions carry both types, then closes the session by agreement.
func exchangeWS(proxy *url.URL, target, nonce string) ([]frameLine, error) {
	dialer := &websocket.Dialer{
		Proxy:            http.ProxyURL(proxy),
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
		HandshakeTimeout: 30 * time.Second,
	}
	conn, _, err := dialer.Dial(target, nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var frames []frameLine
	for _, message := range []struct {
		kind    int
		payload []byte
	}{
		{websocket.TextMessage, []byte("AGENTLAB_WS_TEXT:" + nonce)},
		// Invalid UTF-8 on purpose: a binary frame must survive byte for byte.
		{websocket.BinaryMessage, append([]byte{0x00, 0xff, 0xfe, 0x80}, nonce...)},
	} {
		if err := conn.WriteMessage(message.kind, message.payload); err != nil {
			return frames, err
		}
		frames = append(frames, frameOf("c2s", message.kind, message.payload))
		kind, payload, err := conn.ReadMessage()
		if err != nil {
			return frames, err
		}
		if kind != message.kind || !bytes.Equal(payload, message.payload) {
			return frames, fmt.Errorf("the origin echoed %d bytes of type %d, the client sent %d of type %d",
				len(payload), kind, len(message.payload), message.kind)
		}
		frames = append(frames, frameOf("s2c", kind, payload))
	}
	if err := conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")); err != nil {
		return frames, err
	}
	// Wait for the origin's close reply, so both directions end with a close
	// frame instead of a teardown.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, _ = conn.ReadMessage()
	return frames, nil
}

// refused asks for a loopback port the policy does not grant and reports what the
// gateway answered and whether the listener was reached.
func refused(client *http.Client, port int, nonce string, hits *atomic.Int64) (*refusal, error) {
	response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/refused/%s", port, nonce))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	// A dial would have completed before the refusal was written, but the accept
	// runs in another goroutine: give it a moment before reading the count.
	time.Sleep(100 * time.Millisecond)
	return &refusal{Port: port, Status: response.StatusCode,
		Stage: response.Header.Get(gateway.HeaderStage), OriginHits: hits.Load()}, nil
}

// rowFor waits for the recorder to index an exchange whose URL carries the nonce.
func rowFor(rec *traffic.Traffic, nonce string) (traffic.ExchangeMeta, error) {
	deadline := time.Now().Add(recordWait)
	for {
		rows, _, err := rec.Page(traffic.PageQuery{Query: nonce}, 0, 10)
		if err != nil {
			return traffic.ExchangeMeta{}, err
		}
		for _, row := range rows {
			if strings.Contains(row.URL, nonce) {
				return row, nil
			}
		}
		if time.Now().After(deadline) {
			return traffic.ExchangeMeta{}, fmt.Errorf("no exchange was recorded for %s within %s", nonce, recordWait)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// bodyOf reads one exchange's complete response body and stored head back.
func bodyOf(rec *traffic.Traffic, id string) ([]byte, string, error) {
	var body []byte
	var head string
	err := rec.ReadEvidence(context.Background(), []string{id}, func(e traffic.EvidenceExchange) error {
		data, err := io.ReadAll(e.Response)
		body, head = data, e.RespHead
		return err
	})
	return body, head, err
}

func readExport(dir string) (traffic.ArchiveSnapshot, error) {
	var snapshot traffic.ArchiveSnapshot
	raw, err := os.ReadFile(filepath.Join(dir, "traffic.json"))
	if err != nil {
		return snapshot, err
	}
	return snapshot, json.Unmarshal(raw, &snapshot)
}

func exportedBody(dir string, item traffic.ArchiveExchange) ([]byte, error) {
	if item.RespBlob != "" {
		return os.ReadFile(filepath.Join(dir, "blobs", item.RespBlob+".bin"))
	}
	return item.RespBody, nil
}

func fetch(client *http.Client, target string) ([]byte, int, error) {
	response, err := client.Get(target)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, response.StatusCode, err
	}
	return body, response.StatusCode, nil
}

func plainHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		name, nonce := parts[0], parts[1]
		switch name {
		case "plain", "big":
			body := expectedBody(name, nonce)
			contentType := "text/plain"
			if name == "big" {
				contentType = "application/octet-stream"
			}
			w.Header().Set("Content-Type", contentType)
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			_, _ = w.Write(body)
		case "sse":
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "close")
			flusher, _ := w.(http.Flusher)
			for _, event := range sseEvents(nonce) {
				_, _ = io.WriteString(w, event)
				if flusher != nil {
					flusher.Flush()
				}
			}
		default:
			http.NotFound(w, r)
		}
	})
}

func wsHandler() http.Handler {
	upgrader := websocket.Upgrader{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			kind, payload, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if err := conn.WriteMessage(kind, payload); err != nil {
				return
			}
		}
	})
}

func sseEvents(nonce string) []string {
	return []string{
		"data: 0 keepalive\n\n",
		"data: 1 " + nonce + "\n\n",
		"data: 2 keepalive\n\n",
	}
}

// expectedBody is what the origin serves for one shape, and so what the client
// must receive and the recorder must keep.
func expectedBody(name, nonce string) []byte {
	switch name {
	case "plain":
		return []byte("AGENTLAB_PLAIN:" + nonce + "\n")
	case "sse":
		return []byte(strings.Join(sseEvents(nonce), ""))
	case "big":
		tail := []byte("\nAGENTLAB_BIG:" + nonce + "\n")
		return append(bytes.Repeat([]byte("B"), bigBytes-len(tail)), tail...)
	}
	return nil
}

func stageOf(body []byte) stage {
	sum := sha256.Sum256(body)
	return stage{Bytes: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}
}

func frameOf(dir string, kind int, payload []byte) frameLine {
	name := "binary"
	if kind == websocket.TextMessage {
		name = "text"
	}
	sum := sha256.Sum256(payload)
	return frameLine{Dir: dir, Type: name, Len: len(payload), SHA256: hex.EncodeToString(sum[:])}
}

func serve(handler http.Handler) (*http.Server, int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, 0, err
	}
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()
	return server, listener.Addr().(*net.TCPAddr).Port, nil
}

func serveTLS(handler http.Handler, certificate tls.Certificate) (*http.Server, int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, 0, err
	}
	server := &http.Server{Handler: handler,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}}}
	go func() { _ = server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
	return server, listener.Addr().(*net.TCPAddr).Port, nil
}

func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func newCredential() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func waitFor(address string) error {
	deadline := time.Now().Add(20 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the recorder did not listen on %s: %w", address, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
'''

# The fixture recorder+gateway: the real origin transport, no guest, so the
# keylog it writes can be proven against a captured flow.
KEYLOG_FIXTURE = r'''package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/gateway"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/traffic"
)

type source struct{ state netpolicy.State }

func (s source) PolicyState(context.Context, netpolicy.Session) (netpolicy.State, error) {
	return s.state, nil
}

func main() {
	origin, listen, dir, credential, path := os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5]
	_, rawPort, err := net.SplitHostPort(origin)
	if err != nil {
		fail(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		fail(err)
	}
	session := netpolicy.Session{ID: "keylog-fixture", TaskID: 1, Purpose: netpolicy.PurposeTesting,
		Revision: 1, Credential: credential}
	transport := gateway.New(gateway.Config{
		Authorizer: netpolicy.NewAuthorizer(source{state: netpolicy.State{Revision: 1, Rules: []netpolicy.Rule{
			{ID: 1, Effect: "include", Pattern: "127.0.0.1/32", Protocol: "any", Ports: []int{port}, Authorized: true},
		}}}),
		SessionFor: func(*http.Request) (netpolicy.Session, bool) { return session, true },
		// The fixture origin is self-signed: the same operator exception a real
		// engagement uses for a target with a broken chain.
		CertException: func(netpolicy.Session, string) bool { return true },
	})
	recorder, err := traffic.OpenWithTransport(dir, listen, transport)
	if err != nil {
		fail(err)
	}
	defer recorder.Close()
	go func() { _ = recorder.Start() }()
	waitFor(listen)
	proxy, err := url.Parse("http://" + credential + "@" + listen)
	if err != nil {
		fail(err)
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(proxy),
		// go-mitmproxy's leaf carries no IP SAN for a bare address, so the
		// fixture client trusts the recorder it just started instead of its CA.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	response, err := client.Get("https://" + origin + path)
	if err != nil {
		fail(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		fail(err)
	}
	fmt.Printf("status=%d body=%q\n", response.StatusCode, string(body))
}

func waitFor(address string) {
	deadline := time.Now().Add(20 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		if time.Now().After(deadline) {
			fail(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "keylog fixture:", err)
	os.Exit(1)
}
'''


class Harness:
    """The tier-1 producer: a real gateway and recorder on a temporary store.

    The fixture is a Go program in the module, because it uses the module's own
    gateway, netpolicy and traffic packages. It is written under a unique name,
    run, and removed again whatever happens.
    """

    def __init__(self, root=ROOT):
        self.root = root
        self.module = Path(root) / 'm1nervac0nsole'

    def produce(self, work):
        """Run the fixture over work/{store,store2,export} and return its report."""
        source = self.module / ('.verify-completeness-' + uuid.uuid4().hex[:8])
        try:
            source.mkdir()
            (source / 'main.go').write_text(COMPLETENESS_FIXTURE)
            result = subprocess.run(
                ['go', 'run', './' + source.name, str(Path(work) / 'store'),
                 str(Path(work) / 'store2'), str(Path(work) / 'export')],
                cwd=self.module, capture_output=True, text=True, timeout=900)
        finally:
            shutil.rmtree(source, ignore_errors=True)
        if result.returncode != 0:
            raise ValueError('the harness fixture failed: ' + result.stderr.strip()[-800:])
        lines = [line for line in result.stdout.splitlines() if line.startswith('{')]
        if not lines:
            raise ValueError('the harness fixture printed no report: ' + result.stdout.strip()[-400:])
        measured = json.loads(lines[-1])
        if not isinstance(measured, dict):
            raise ValueError('the harness fixture printed %s, not a report' % type(measured).__name__)
        return measured


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def checksum(header):
    total = sum(struct.unpack('>%dH' % (len(header) // 2), header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def frame(source, destination, seq, ack, flags, payload=b''):
    """One Ethernet/IPv4/TCP frame between the fixture's two loopback ports."""
    tcp = struct.pack('>HHIIBBHHH', source, destination, seq, ack, 5 << 4, flags, 65535, 0, 0)
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 0, 0x4000, 64, 6, 0,
                     socket.inet_aton('127.0.0.1'), socket.inet_aton('127.0.0.1'))
    ip = ip[:10] + struct.pack('>H', checksum(ip)) + ip[12:]
    return b'\x02\x00\x00\x00\x00\x01' + b'\x02\x00\x00\x00\x00\x02' + b'\x08\x00' + ip + tcp + payload


def record_flow(listen_port, origin_port, pcap_path, finished):
    """Relay the gateway's origin connection and record both directions as a pcap.

    This host cannot sniff loopback (dumpcap needs the wireshark group), so the
    fixture records the flow it relays: the same TLS records tshark is asked to
    decrypt, in a pcap it can read.
    """
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', listen_port))
    listener.listen(1)
    client = upstream = None
    try:
        client, _ = listener.accept()
        upstream = socket.create_connection(('127.0.0.1', origin_port))
        with pcap_path.open('wb') as capture:
            capture.write(struct.pack('>IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            seq = {'client': 0, 'origin': 0}
            lock = threading.Lock()

            def packet(from_client, payload=b'', flags=0x18):
                with lock:
                    if from_client:
                        source, destination = listen_port, origin_port
                        number, ack = seq['client'], seq['origin']
                        seq['client'] += len(payload)
                    else:
                        source, destination = origin_port, listen_port
                        number, ack = seq['origin'], seq['client']
                        seq['origin'] += len(payload)
                    data = frame(source, destination, number, ack, flags, payload)
                    capture.write(struct.pack('>IIII', 1, 0, len(data), len(data)) + data)

            packet(True, flags=0x02)   # SYN
            seq['client'] += 1
            packet(False, flags=0x12)  # SYN, ACK
            seq['origin'] += 1
            packet(True, flags=0x10)   # ACK

            def pump(source, sink, from_client):
                while True:
                    try:
                        data = source.recv(65536)
                    except OSError:
                        break
                    if not data:
                        break
                    packet(from_client, data)
                    try:
                        sink.sendall(data)
                    except OSError:
                        break
                try:
                    sink.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

            thread = threading.Thread(target=pump, args=(client, upstream, True), daemon=True)
            thread.start()
            pump(upstream, client, False)
            thread.join(5)
    finally:
        for sock in (client, upstream, listener):
            if sock is not None:
                sock.close()
        finished.set()


class Origin(http.server.BaseHTTPRequestHandler):
    """Local TLS origin: the plaintext nonce is what decryption must recover."""

    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        body = ('AGENTLAB_KEYLOG_PLAINTEXT:' + self.server.nonce + '\n').encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def start_origin(cert, key, nonce):
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    server.nonce = nonce
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def decrypt(pcap, nonce, keylog=None):
    """Frame numbers whose decrypted HTTP carries the nonce."""
    command = ['tshark', '-r', str(pcap), '-o', 'tcp.check_checksum:FALSE']
    if keylog is not None:
        command += ['-o', 'tls.keylog_file:' + str(keylog)]
    command += ['-Y', 'http contains "%s"' % nonce, '-T', 'fields', '-e', 'frame.number']
    result = subprocess.run(command, capture_output=True, text=True)
    return [line for line in result.stdout.split() if line]


def keylog_fixture():
    """Run the recorder+gateway against a TLS origin and prove the keylog decrypts it."""
    missing = [tool for tool in ('openssl', 'go', 'tshark') if shutil.which(tool) is None]
    if missing:
        return {'status': 'skipped', 'reason': 'not installed: ' + ', '.join(missing)}
    module = ROOT / 'm1nervac0nsole'
    for stale in module.glob('.verify-keylog-*'):
        shutil.rmtree(stale, ignore_errors=True)
    work = Path(tempfile.mkdtemp(prefix='agentlab-keylog-'))
    fixture = module / ('.verify-keylog-' + uuid.uuid4().hex[:8])
    nonce = uuid.uuid4().hex
    origin = None
    try:
        cert, key = work / 'origin.crt', work / 'origin.key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=127.0.0.1', '-keyout', str(key), '-out', str(cert)],
                       check=True, capture_output=True)
        origin = start_origin(cert, key, nonce)
        pcap = work / 'origin-flow.pcap'
        finished = threading.Event()
        relay_port = free_port()
        threading.Thread(target=record_flow,
                         args=(relay_port, origin.server_port, pcap, finished), daemon=True).start()
        fixture.mkdir()
        (fixture / 'main.go').write_text(KEYLOG_FIXTURE)
        keylog = work / 'tls.keys'
        env = dict(os.environ, SSLKEYLOGFILE=str(keylog))
        result = subprocess.run(['go', 'run', './' + fixture.name, '127.0.0.1:%d' % relay_port,
                                 '127.0.0.1:%d' % free_port(), str(work / 'store'),
                                 'keylog-fixture', '/nonce-' + nonce],
                                cwd=module, env=env, capture_output=True, text=True, timeout=600)
        finished.wait(15)
        report = {'status': 'failed', 'nonce': nonce, 'pcap': str(pcap), 'keylog': str(keylog)}
        if result.returncode != 0:
            report['reason'] = 'the gateway fixture failed: ' + result.stderr.strip()[-800:]
            return report
        if nonce not in result.stdout:
            report['reason'] = 'the client did not receive the plaintext nonce: ' + result.stdout.strip()[-400:]
            return report
        secrets = keylog.read_text() if keylog.exists() else ''
        report['keylog_lines'] = len(secrets.splitlines())
        report['pcap_bytes'] = pcap.stat().st_size if pcap.exists() else 0
        if 'HANDSHAKE_TRAFFIC_SECRET' not in secrets:
            report['reason'] = 'SSLKEYLOGFILE holds no origin handshake secret'
            return report
        with_keylog = decrypt(pcap, nonce, keylog)
        without_keylog = decrypt(pcap, nonce)
        report['frames_with_keylog'] = len(with_keylog)
        report['frames_without_keylog'] = len(without_keylog)
        if not with_keylog:
            report['reason'] = 'tshark did not recover the nonce with the gateway keylog'
            return report
        if without_keylog:
            report['reason'] = 'the flow decrypted without a keylog, so the capture is not encrypted'
            return report
        if nonce.encode() in pcap.read_bytes():
            report['reason'] = 'the nonce is in the capture in plaintext'
            return report
        report['status'] = 'verified'
        report.pop('reason', None)
        return report
    except (OSError, subprocess.SubprocessError) as error:
        return {'status': 'failed', 'nonce': nonce, 'reason': 'keylog fixture: %s' % error}
    finally:
        if origin is not None:
            origin.shutdown()
            origin.server_close()
        shutil.rmtree(fixture, ignore_errors=True)
        shutil.rmtree(work, ignore_errors=True)


def describe(stage, got, want, label):
    return '%s holds %d bytes (sha256 %s), %s %d bytes (sha256 %s)' % (
        stage, got.get('bytes', 0), got.get('sha256') or '-',
        label, want.get('bytes', 0), want.get('sha256') or '-')


def check_frames(entry):
    """The transcript must reproduce the frames the peers exchanged."""
    sent = entry.get('frames') or []
    got = entry.get('transcript') or []
    if not sent:
        return 'sent', 'the fixture sent no WebSocket frames'
    if len(got) != len(sent):
        return 'transcript', 'the transcript holds %d data lines, the peers exchanged %d frames' % (
            len(got), len(sent))
    for direction in ('c2s', 's2c'):
        want = [(f.get('type'), f.get('len'), f.get('sha256')) for f in sent if f.get('dir') == direction]
        have = [(f.get('type'), f.get('len'), f.get('sha256')) for f in got if f.get('dir') == direction]
        if want != have:
            return 'transcript', ('the %s data lines do not reproduce the %d sent frames: type, length '
                                  'or payload hash differs' % (direction, len(want)))
    if not {'c2s', 's2c'} <= set(entry.get('closes') or []):
        return 'transcript', 'the transcript has no close line for both directions'
    return '', ''


def check(entry):
    """The first stage that does not hold for one shape, or ('', '')."""
    if entry.get('error'):
        return 'error', entry['error']
    if entry.get('partial'):
        return 'retained', 'the recorder labelled the capture partial, so the body is not whole'
    expected = 101 if entry.get('path') == 'ws' else 200
    if entry.get('status') != expected:
        return 'collected', 'the recorded status is %r, not %d' % (entry.get('status'), expected)
    stages = [entry.get(name) or {} for name in STAGES]
    if entry.get('path') == 'ws':
        # The stored body is the transcript, not the payload the frames carried,
        # so the chain starts at the recorder's own length and the frame list is
        # what the sent side is compared against.
        if not stages[0].get('bytes'):
            return 'collected', 'the recorder stored no transcript'
        if stages[1].get('bytes') != stages[0].get('bytes'):
            return 'retained', describe('retained', stages[1], stages[0], 'the recorder stored')
        for name, got in zip(STAGES[2:], stages[2:]):
            if got != stages[1]:
                return name, describe(name, got, stages[1], 'the retained transcript holds')
        return check_frames(entry)
    sent = entry.get('sent') or {}
    if not sent.get('bytes'):
        return 'sent', 'the origin sent no bytes'
    if stages[0].get('bytes') != sent['bytes']:
        return 'collected', describe('collected', stages[0], sent, 'the origin sent')
    for name, got in zip(STAGES[1:], stages[1:]):
        if got != sent:
            return name, describe(name, got, sent, 'the origin sent')
    return '', ''


def table(entries):
    header = ('shape', 'sent', 'collected', 'retained', 'exported', 'consumed', 'verdict')
    rows = [header]
    for entry in entries:
        stage, _ = check(entry)
        rows.append((
            entry.get('path') or '?',
            '-' if entry.get('path') == 'ws' else str((entry.get('sent') or {}).get('bytes', 0)),
            str((entry.get('collected') or {}).get('bytes', 0)),
            str((entry.get('retained') or {}).get('bytes', 0)),
            str((entry.get('exported') or {}).get('bytes', 0)),
            str((entry.get('consumed') or {}).get('bytes', 0)),
            'ok' if not stage else stage,
        ))
    widths = [len(cell) for cell in header]
    for row in rows:
        widths = [max(width, len(cell)) for width, cell in zip(widths, row)]
    lines = ['  '.join(cell.ljust(width) for cell, width in zip(header, widths)),
             '  '.join('-' * width for width in widths)]
    lines += ['  '.join(cell.ljust(width) for cell, width in zip(row, widths)) for row in rows[1:]]
    return '\n'.join(lines)


def stop(report, code, result, detail):
    report['result'] = result
    report['detail'] = detail
    return code, report


def verify(harness):
    """Run tier 1 and the keylog check, and return (exit code, report)."""
    report = {'tier': TIER, 'result': 'failed', 'proven': [], 'not_proven': [
        'an allowed live-guest round trip to a synthetic origin: it needs an operator-authorized '
        'task, which is the policy model, not a defect of this check (verify_capture.py)',
        'live guest capture, export and host-event correlation (verify_capture.py)',
    ]}
    missing = [tool for tool in ('go', 'openssl', 'tshark') if shutil.which(tool) is None]
    if missing:
        return stop(report, 2, 'prerequisite missing', 'not installed: ' + ', '.join(missing))
    report['keylog'] = keylog_fixture()
    with tempfile.TemporaryDirectory(prefix='agentlab-completeness-') as work:
        try:
            measured = harness.produce(work)
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            return stop(report, 1, 'failed', 'the harness did not run: %s' % error)
    report['shapes'] = measured.get('shapes') or []
    report['refused'] = measured.get('refused')
    report['imported'] = measured.get('imported')
    failures = []
    if measured.get('error'):
        failures.append(('harness', 'error', measured['error']))
    refused = measured.get('refused') or {}
    if refused.get('status') != 403 or refused.get('stage') != 'policy':
        failures.append(('refused', 'policy', 'a request to the ungranted port %r got status %r and '
                         'stage %r, not a policy 403' % (refused.get('port'), refused.get('status'),
                                                         refused.get('stage'))))
    if refused.get('origin_hits'):
        failures.append(('refused', 'dial', 'the gateway dialed the ungranted port %d time(s), so the '
                         'grant is not narrow' % refused['origin_hits']))
    seen = {entry.get('path'): entry for entry in report['shapes']}
    for path in SHAPES:
        entry = seen.get(path)
        if entry is None:
            failures.append((path, 'missing', 'the harness measured no such shape'))
            continue
        stage, detail = check(entry)
        if stage:
            failures.append((path, stage, detail))
    if report['keylog'].get('status') == 'failed':
        failures.append(('keylog', 'decrypt', report['keylog'].get('reason', 'the keylog check failed')))
    report['failures'] = [{'shape': shape, 'stage': stage, 'detail': detail}
                          for shape, stage, detail in failures]
    if failures:
        report['detail'] = '; '.join('%s at %s: %s' % (shape, stage, detail)
                                     for shape, stage, detail in failures)
        return 1, report
    if report['keylog'].get('status') == 'skipped':
        return stop(report, 2, 'prerequisite missing', report['keylog'].get('reason', ''))
    report['result'] = 'verified'
    report['proven'] = [
        'a real gateway.New and traffic.OpenWithTransport recorded four shapes on a temporary store',
        'the harness minted its own session credential and wrote no scope rule, certificate '
        'exception or policy row',
        'plain HTTP, SSE and a 6 MiB body: collected == retained == exported == consumed bytes',
        'a duplex WebSocket: the exported transcript reproduces every sent frame, both directions, '
        'text and binary',
        'a loopback port outside the granted set was refused at the policy stage and never dialed',
        'the gateway keylog decrypts a recorded TLS flow with tshark, and not without it',
    ]
    return 0, report


def main(harness=None):
    try:
        code, report = verify(harness or Harness())
    except (OSError, ValueError) as error:
        code, report = 1, {'tier': TIER, 'result': 'failed',
                           'detail': '%s: %s' % (type(error).__name__, error)}
    print(table(report.get('shapes') or []))
    print(json.dumps(report, indent=2))
    return code


if __name__ == '__main__':
    sys.exit(main())
