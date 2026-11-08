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

package auditsnapshot

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// Signer is the dedicated snapshot signing key. It is intentionally separate
// from TLS, JWT and session keys: compromising one usage never signs snapshots.
type Signer interface {
	KeyID() string
	PublicKey() ed25519.PublicKey
	Sign(message []byte) ([]byte, error)
}

// KeyIDOf derives the stable key identity from the SubjectPublicKeyInfo
// encoding of the public key.
func KeyIDOf(public ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return "ed25519-" + hex.EncodeToString(sum[:16]), nil
}

// GeneratePrivateKey creates a new Ed25519 private key with the standard
// library crypto/rand generator.
func GeneratePrivateKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// MarshalPrivateKeyPEM encodes a private key as PKCS#8 PEM.
func MarshalPrivateKeyPEM(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// MarshalPublicKeyPEM encodes a public key as SubjectPublicKeyInfo PEM.
func MarshalPublicKeyPEM(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParsePrivateKeyPEM reads an Ed25519 PKCS#8 PEM private key.
func ParsePrivateKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("snapshot signer: private key is not PEM encoded")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("snapshot signer: failed to parse PKCS#8 key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("snapshot signer: key is not Ed25519")
	}
	return priv, nil
}

// ParsePublicKeyPEM reads an Ed25519 SubjectPublicKeyInfo PEM public key.
func ParsePublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("snapshot anchor: public key is not PEM encoded")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("snapshot anchor: failed to parse public key: %w", err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("snapshot anchor: key is not Ed25519")
	}
	return pub, nil
}

// WriteKeyFile stores a PKCS#8 PEM private key at an explicitly chosen path
// with owner-only permissions. The export path never calls this: provisioning
// a key is an out-of-band operator action.
func WriteKeyFile(path string, priv ed25519.PrivateKey) error {
	data, err := MarshalPrivateKeyPEM(priv)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// FileSigner loads the dedicated snapshot key from a PEM file the operator
// configured explicitly. No default or fallback key exists.
type FileSigner struct {
	priv  ed25519.PrivateKey
	keyID string
}

func NewFileSigner(path string) (*FileSigner, error) {
	if path == "" {
		return nil, errors.New("snapshot signer: key file path is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("snapshot signer: failed to read key file: %w", err)
	}
	priv, err := ParsePrivateKeyPEM(data)
	if err != nil {
		return nil, err
	}
	keyID, err := KeyIDOf(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	return &FileSigner{priv: priv, keyID: keyID}, nil
}

func (s *FileSigner) KeyID() string { return s.keyID }

func (s *FileSigner) PublicKey() ed25519.PublicKey {
	pub := s.priv.Public().(ed25519.PublicKey)
	return pub
}

func (s *FileSigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, message), nil
}

// StaticSigner adapts an in-memory Ed25519 private key, mainly for tests and
// for key providers backed by an external secret store.
type StaticSigner struct {
	Priv ed25519.PrivateKey
}

func (s StaticSigner) KeyID() string {
	id, _ := KeyIDOf(s.Priv.Public().(ed25519.PublicKey))
	return id
}

func (s StaticSigner) PublicKey() ed25519.PublicKey {
	return s.Priv.Public().(ed25519.PublicKey)
}

func (s StaticSigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.Priv, message), nil
}
