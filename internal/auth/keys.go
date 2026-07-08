// Package auth implements API-key authentication for the HTTP ingress.
// Keys are random bearer tokens of the form "sk-steiner-<hex>".
// Only their SHA-256 digests are stored, in a YAML keys file managed by `steiner keygen`.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const tokenPrefix = "sk-steiner-"

// KeysFile is the on-disk format of the keys file.
type KeysFile struct {
	Keys []Key `yaml:"keys"`
}

// Key associates a token digest with a principal name.
type Key struct {
	Name   string `yaml:"name"`
	SHA256 string `yaml:"sha256"`
}

// Generate creates a new token for the principal and appends its digest to the keys file.
// The plaintext token is returned exactly once.
func Generate(keysPath, principal string) (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := tokenPrefix + hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))

	kf, err := loadKeys(keysPath)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	kf.Keys = append(kf.Keys, Key{Name: principal, SHA256: hex.EncodeToString(sum[:])})
	data, err := yaml.Marshal(kf)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(keysPath, data, 0o600); err != nil {
		return "", err
	}
	return token, nil
}

func loadKeys(path string) (KeysFile, error) {
	var kf KeysFile
	data, err := os.ReadFile(path)
	if err != nil {
		return kf, err
	}
	if err := yaml.Unmarshal(data, &kf); err != nil {
		return kf, fmt.Errorf("parsing %s: %w", path, err)
	}
	return kf, nil
}

// Verifier authenticates bearer tokens against the keys file
type Verifier struct {
	keys []Key
}

// NewVerifier loads the keys file. A missing file yields a verifier that rejects everything (HTTP ingress requires keys; stdio ingress does not).
func NewVerifier(keysPath string) (*Verifier, error) {
	kf, err := loadKeys(keysPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return &Verifier{keys: kf.Keys}, nil
}

// Lookup returns the principal name for a plaintext token.
func (v *Verifier) Lookup(token string) (string, bool) {
	sum := sha256.Sum256([]byte(token))
	digest := []byte(hex.EncodeToString(sum[:]))
	for _, k := range v.keys {
		if subtle.ConstantTimeCompare(digest, []byte(k.SHA256)) == 1 {
			return k.Name, true
		}
	}
	return "", false
}

type ctxKey struct{}

// Middleware enforces bearer auth and stores the principal in the context.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			http.Error(w, `{"error":"missing Authorization: Bearer <key>"}`, http.StatusUnauthorized)
			return
		}
		principal, ok := v.Lookup(strings.TrimSpace(token))
		if !ok {
			http.Error(w, `{"error":"invalid API key"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), principal)))
	})
}

// WithPrincipal returns a context carrying the authenticated principal name.
func WithPrincipal(ctx context.Context, principal string) context.Context {
	return context.WithValue(ctx, ctxKey{}, principal)
}

// PrincipalFrom extracts the authenticated principal name, if there even is one lmao.
func PrincipalFrom(ctx context.Context) (string, bool) {
	p, ok := ctx.Value(ctxKey{}).(string)
	return p, ok
}
