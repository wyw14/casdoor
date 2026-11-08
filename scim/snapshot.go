// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package scim

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/casdoor/casdoor/conf"
	"github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
)

// SnapshotSchemaVersion is bound into every token. It must be bumped whenever the
// sealed envelope or the projected resource layout changes, so old tokens can never
// be interpreted against a newer schema.
const SnapshotSchemaVersion = "casdoor-scim-snapshot-v1"

const (
	snapshotHeaderMagic = "CSCIMSNP"
	snapshotFooterMagic = "PNPMSCIC"
	snapshotVersion     = byte(1)
	snapshotNonceSize   = 12
	snapshotFooterSize  = 8 + sha256.Size + sha256.Size + len(snapshotFooterMagic)
	snapshotFileSuffix  = ".snap"
)

// Sentinel failures keep the security relevant rejections explicit instead of
// surfacing generic 500s. Every value is a SCIM error the library can serialize.
var (
	ErrSnapshotExpired = scimerrors.ScimError{
		ScimType: scimerrors.ScimTypeInvalidValue,
		Detail:   "The SCIM list snapshot token has expired.",
		Status:   http.StatusBadRequest,
	}
	ErrSnapshotCorrupted = scimerrors.ScimError{
		ScimType: scimerrors.ScimTypeInvalidValue,
		Detail:   "The SCIM list snapshot artifact is corrupted or has a broken integrity footer.",
		Status:   http.StatusBadRequest,
	}
	ErrSnapshotTokenInvalid = scimerrors.ScimError{
		Detail: "The SCIM list snapshot token is unknown or no longer valid.",
		Status: http.StatusForbidden,
	}
	ErrSnapshotBindingMismatch = scimerrors.ScimError{
		Detail: "The SCIM list snapshot token does not bind to the caller, organization or query parameters of this request.",
		Status: http.StatusForbidden,
	}
	ErrSnapshotTooMany = scimerrors.ScimError{
		ScimType: scimerrors.ScimTypeTooMany,
		Detail:   "The SCIM list snapshot exceeds the resource, byte or concurrency bounds of the service provider.",
		Status:   http.StatusBadRequest,
	}
)

type snapshotConfig struct {
	enabled       bool
	dir           string
	maxResources  int
	maxBytes      int
	ttl           time.Duration
	maxPerOrg     int
	sweepInterval time.Duration
	masterKey     []byte
}

// snapshotEnvelope is the only payload written into a sealed artifact. It carries
// the frozen query bindings alongside the already projected resources, so a leaked
// file never exposes attributes the client was not allowed to receive.
type snapshotEnvelope struct {
	SchemaVersion      string          `json:"schemaVersion"`
	ResourceType       string          `json:"resourceType"`
	Organization       string          `json:"organization"`
	Subject            string          `json:"subject"`
	PermissionGen      string          `json:"permissionGen"`
	Filter             string          `json:"filter"`
	SortBy             string          `json:"sortBy"`
	SortOrder          string          `json:"sortOrder"`
	Attributes         []string        `json:"attributes"`
	ExcludedAttributes []string        `json:"excludedAttributes"`
	CreatedAt          time.Time       `json:"createdAt"`
	ExpiresAt          time.Time       `json:"expiresAt"`
	TotalResults       int             `json:"totalResults"`
	Resources          []scim.Resource `json:"resources"`
}

// snapshotEntry is the in-memory ownership record. The sealed file is the durable
// artifact; the entry tracks readers and deletion rights while the token is alive.
type snapshotEntry struct {
	mu           sync.RWMutex
	token        string
	path         string
	organization string
	subject      string
	resourceType string
	createdAt    time.Time
	expiresAt    time.Time
	deleted      bool
}

type snapshotManager struct {
	cfg     snapshotConfig
	aeadKey []byte
	hmacKey []byte

	mu      sync.Mutex
	entries map[string]*snapshotEntry

	stopOnce sync.Once
	stopCh   chan struct{}
}

func snapshotConfigInt(key string, fallback int) int {
	raw := strings.TrimSpace(conf.GetConfigString(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func loadSnapshotConfig() snapshotConfig {
	cfg := snapshotConfig{
		enabled:      conf.GetConfigBool("scimSnapshotEnabled"),
		maxResources: snapshotConfigInt("scimSnapshotMaxResources", 5000),
		maxBytes:     snapshotConfigInt("scimSnapshotMaxBytes", 16*1024*1024),
		ttl:          time.Duration(snapshotConfigInt("scimSnapshotTTLSeconds", 300)) * time.Second,
		maxPerOrg:    snapshotConfigInt("scimSnapshotMaxPerOrg", 8),
		sweepInterval: time.Duration(
			snapshotConfigInt("scimSnapshotSweepSeconds", 60),
		) * time.Second,
	}
	cfg.dir = strings.TrimSpace(conf.GetConfigString("scimSnapshotDir"))
	if cfg.dir == "" {
		cfg.dir = filepath.Join(os.TempDir(), "casdoor-scim-snapshots")
	}
	if key := strings.TrimSpace(conf.GetConfigString("scimSnapshotKey")); key != "" {
		sum := sha256.Sum256([]byte(key))
		cfg.masterKey = sum[:]
	}
	return cfg
}

func newSnapshotManager(cfg snapshotConfig) (*snapshotManager, error) {
	if len(cfg.masterKey) == 0 {
		cfg.masterKey = make([]byte, sha256.Size)
		if _, err := rand.Read(cfg.masterKey); err != nil {
			return nil, err
		}
	}
	aeadSum := sha256.Sum256(append([]byte("casdoor-scim-snapshot-aead:"), cfg.masterKey...))
	hmacSum := sha256.Sum256(append([]byte("casdoor-scim-snapshot-hmac:"), cfg.masterKey...))
	if err := os.MkdirAll(cfg.dir, 0o700); err != nil {
		return nil, err
	}
	m := &snapshotManager{
		cfg:     cfg,
		aeadKey: aeadSum[:],
		hmacKey: hmacSum[:],
		entries: make(map[string]*snapshotEntry),
		stopCh:  make(chan struct{}),
	}
	go m.sweepLoop()
	return m, nil
}

var (
	defaultSnapshotManager     *snapshotManager
	defaultSnapshotManagerLock sync.Mutex
)

// getSnapshotManager returns nil when the extension is disabled, so the ordinary
// SCIM list path keeps its original behavior.
func getSnapshotManager() *snapshotManager {
	cfg := loadSnapshotConfig()
	if !cfg.enabled {
		return nil
	}
	defaultSnapshotManagerLock.Lock()
	defer defaultSnapshotManagerLock.Unlock()
	if defaultSnapshotManager != nil {
		return defaultSnapshotManager
	}
	m, err := newSnapshotManager(cfg)
	if err != nil {
		return nil
	}
	defaultSnapshotManager = m
	return m
}

func (m *snapshotManager) sweepLoop() {
	ticker := time.NewTicker(m.cfg.sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.sweep()
		}
	}
}

// Close stops the janitor and removes every artifact still owned by the manager.
// It is used by tests and by process shutdown.
func (m *snapshotManager) Close() {
	m.stopOnce.Do(func() { close(m.stopCh) })

	m.mu.Lock()
	entries := make([]*snapshotEntry, 0, len(m.entries))
	for _, entry := range m.entries {
		entries = append(entries, entry)
	}
	m.entries = make(map[string]*snapshotEntry)
	m.mu.Unlock()

	for _, entry := range entries {
		entry.mu.Lock()
		entry.deleted = true
		_ = os.Remove(entry.path)
		entry.mu.Unlock()
	}
}

func (m *snapshotManager) snapshotCountForOrg(organization string) int {
	count := 0
	for _, entry := range m.entries {
		if entry.organization == organization && !entry.deleted {
			count++
		}
	}
	return count
}

// create seals the envelope into a temp file and atomically publishes it. Any
// failure before publication removes the temp file, so aborted requests never
// leave partial artifacts behind.
func (m *snapshotManager) create(env *snapshotEnvelope) (string, error) {
	if len(env.Resources) > m.cfg.maxResources {
		return "", ErrSnapshotTooMany
	}

	raw, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	if len(raw) > m.cfg.maxBytes {
		return "", ErrSnapshotTooMany
	}
	sealed, err := m.seal(raw)
	if err != nil {
		return "", err
	}
	if len(sealed) > m.cfg.maxBytes {
		return "", ErrSnapshotTooMany
	}

	tokenBytes := make([]byte, 24)
	if _, err = rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := encodeSnapshotToken(tokenBytes)

	m.mu.Lock()
	if m.snapshotCountForOrg(env.Organization) >= m.cfg.maxPerOrg {
		m.mu.Unlock()
		return "", ErrSnapshotTooMany
	}
	m.mu.Unlock()

	tmpPath := filepath.Join(m.cfg.dir, "."+token+".tmp")
	finalPath := filepath.Join(m.cfg.dir, token+snapshotFileSuffix)
	file, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	if _, err = file.Write(sealed); err != nil {
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err = file.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err = os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}

	entry := &snapshotEntry{
		token:        token,
		path:         finalPath,
		organization: env.Organization,
		subject:      env.Subject,
		resourceType: env.ResourceType,
		createdAt:    env.CreatedAt,
		expiresAt:    env.ExpiresAt,
	}
	m.mu.Lock()
	m.entries[token] = entry
	m.mu.Unlock()
	return token, nil
}

// acquire reserves a read slot. The returned release function must be called once
// the page has been served; deletion waits for every acquired slot to drain.
func (m *snapshotManager) acquire(token string) (*snapshotEntry, func(), error) {
	m.mu.Lock()
	entry := m.entries[token]
	m.mu.Unlock()
	if entry == nil {
		return nil, nil, ErrSnapshotTokenInvalid
	}

	entry.mu.RLock()
	if entry.deleted {
		entry.mu.RUnlock()
		return nil, nil, ErrSnapshotTokenInvalid
	}
	if time.Now().After(entry.expiresAt) {
		entry.mu.RUnlock()
		return nil, nil, ErrSnapshotExpired
	}
	return entry, func() { entry.mu.RUnlock() }, nil
}

func (m *snapshotManager) read(entry *snapshotEntry) (*snapshotEnvelope, error) {
	data, err := os.ReadFile(entry.path)
	if err != nil {
		return nil, ErrSnapshotCorrupted
	}
	env, err := m.openSealed(data)
	if err != nil {
		return nil, err
	}
	if time.Now().After(env.ExpiresAt) {
		return nil, ErrSnapshotExpired
	}
	return env, nil
}

// release revokes a token. Only the subject that created the snapshot may release
// it; active readers make the call fail explicitly instead of deleting underneath them.
func (m *snapshotManager) release(token, subject string) error {
	m.mu.Lock()
	entry := m.entries[token]
	m.mu.Unlock()
	if entry == nil {
		return ErrSnapshotTokenInvalid
	}
	if entry.subject != subject {
		return ErrSnapshotBindingMismatch
	}
	if !entry.mu.TryLock() {
		return scimerrors.ScimError{
			Detail: "The SCIM list snapshot still has active readers and cannot be released yet.",
			Status: http.StatusConflict,
		}
	}
	defer entry.mu.Unlock()

	if entry.deleted {
		return ErrSnapshotTokenInvalid
	}
	entry.deleted = true
	m.mu.Lock()
	delete(m.entries, token)
	m.mu.Unlock()
	if err := os.Remove(entry.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (m *snapshotManager) sweep() {
	now := time.Now()

	m.mu.Lock()
	expired := make([]*snapshotEntry, 0)
	activeTokens := make(map[string]struct{}, len(m.entries))
	for token, entry := range m.entries {
		activeTokens[token] = struct{}{}
		if now.After(entry.expiresAt) {
			expired = append(expired, entry)
		}
	}
	m.mu.Unlock()

	for _, entry := range expired {
		// A busy entry is revisited on the next sweep instead of blocking the janitor.
		if !entry.mu.TryLock() {
			continue
		}
		if !entry.deleted {
			entry.deleted = true
			_ = os.Remove(entry.path)
		}
		entry.mu.Unlock()

		m.mu.Lock()
		delete(m.entries, entry.token)
		m.mu.Unlock()
	}

	// Reclaim orphan artifacts and aborted temp files left by a crashed process.
	dirEntries, err := os.ReadDir(m.cfg.dir)
	if err != nil {
		return
	}
	for _, dirEntry := range dirEntries {
		name := dirEntry.Name()
		if strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".tmp") {
			_ = os.Remove(filepath.Join(m.cfg.dir, name))
			continue
		}
		if !strings.HasSuffix(name, snapshotFileSuffix) {
			continue
		}
		token := strings.TrimSuffix(name, snapshotFileSuffix)
		if _, ok := activeTokens[token]; !ok {
			_ = os.Remove(filepath.Join(m.cfg.dir, name))
		}
	}
}

// seal lays out header || AEAD body || integrity footer. The HMAC footer covers the
// header and body, so truncation or byte flipping fails verification before AES-GCM
// is even touched.
func (m *snapshotManager) seal(plaintext []byte) ([]byte, error) {
	compressed, err := gzipBytes(plaintext)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(m.aeadKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, snapshotNonceSize)
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	body := aead.Seal(nil, nonce, compressed, nil)

	header := make([]byte, 0, len(snapshotHeaderMagic)+2+snapshotNonceSize)
	header = append(header, []byte(snapshotHeaderMagic)...)
	header = append(header, snapshotVersion, 0)
	header = append(header, nonce...)

	plaintextSum := sha256.Sum256(plaintext)
	mac := hmac.New(sha256.New, m.hmacKey)
	mac.Write(header)
	mac.Write(body)
	bodyMac := mac.Sum(nil)

	footer := make([]byte, 0, snapshotFooterSize)
	lengthBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(lengthBytes, uint64(len(body)))
	footer = append(footer, lengthBytes...)
	footer = append(footer, plaintextSum[:]...)
	footer = append(footer, bodyMac...)
	footer = append(footer, []byte(snapshotFooterMagic)...)

	sealed := make([]byte, 0, len(header)+len(body)+len(footer))
	sealed = append(sealed, header...)
	sealed = append(sealed, body...)
	sealed = append(sealed, footer...)
	return sealed, nil
}

func (m *snapshotManager) openSealed(data []byte) (*snapshotEnvelope, error) {
	headerSize := len(snapshotHeaderMagic) + 2 + snapshotNonceSize
	if len(data) < headerSize+snapshotFooterSize {
		return nil, ErrSnapshotCorrupted
	}
	header, body, footer := data[:headerSize], data[headerSize:len(data)-snapshotFooterSize], data[len(data)-snapshotFooterSize:]

	if string(header[:len(snapshotHeaderMagic)]) != snapshotHeaderMagic ||
		header[len(snapshotHeaderMagic)] != snapshotVersion ||
		string(footer[len(footer)-len(snapshotFooterMagic):]) != snapshotFooterMagic {
		return nil, ErrSnapshotCorrupted
	}
	bodyLength := binary.BigEndian.Uint64(footer[:8])
	if int(bodyLength) != len(body) {
		return nil, ErrSnapshotCorrupted
	}

	expectedMac := footer[8+sha256.Size : 8+2*sha256.Size]
	mac := hmac.New(sha256.New, m.hmacKey)
	mac.Write(header)
	mac.Write(body)
	if !hmac.Equal(mac.Sum(nil), expectedMac) {
		return nil, ErrSnapshotCorrupted
	}

	nonce := header[len(snapshotHeaderMagic)+2:]
	block, err := aes.NewCipher(m.aeadKey)
	if err != nil {
		return nil, ErrSnapshotCorrupted
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrSnapshotCorrupted
	}
	compressed, err := aead.Open(nil, nonce, body, nil)
	if err != nil {
		return nil, ErrSnapshotCorrupted
	}
	plaintext, err := gunzipBytes(compressed)
	if err != nil {
		return nil, ErrSnapshotCorrupted
	}
	plaintextSum := sha256.Sum256(plaintext)
	if !hmac.Equal(plaintextSum[:], footer[8:8+sha256.Size]) {
		return nil, ErrSnapshotCorrupted
	}

	env := &snapshotEnvelope{}
	if err = json.Unmarshal(plaintext, env); err != nil {
		return nil, ErrSnapshotCorrupted
	}
	if env.SchemaVersion != SnapshotSchemaVersion {
		return nil, ErrSnapshotCorrupted
	}
	return env, nil
}

func gzipBytes(raw []byte) ([]byte, error) {
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(raw); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func gunzipBytes(raw []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// encodeSnapshotToken renders the random snapshot id as an opaque, URL safe string.
// It deliberately carries no offset, query or claim: those only live in the sealed
// envelope and are re-validated on every page request.
func encodeSnapshotToken(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}
