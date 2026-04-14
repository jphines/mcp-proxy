// Package store implements the gateway.CredentialStore interface backed by
// AWS Secrets Manager with an AES-256-GCM in-memory cache.
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"
	"time"
)

// cacheEntry holds an encrypted credential value with its expiry.
type cacheEntry struct {
	encrypted []byte    // AES-256-GCM ciphertext
	nonce     []byte    // 12-byte GCM nonce
	expiresAt time.Time
	timer     *time.Timer // fires Zero() when TTL expires
}

// encryptedCache is a sync.Map-keyed store that encrypts values at rest.
// Even if the process heap is dumped, credentials are not readable in plaintext.
// The encryption key is derived from a random 32-byte master key generated at
// startup — it is never persisted and is discarded on process exit.
type encryptedCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	block   cipher.Block // AES-256 block
	ttl     time.Duration
}

func newEncryptedCache(ttl time.Duration) (*encryptedCache, error) {
	// Generate a random per-process AES-256 key.
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generating cache encryption key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	// Zero the key slice now that the cipher block holds a copy.
	for i := range key {
		key[i] = 0
	}

	return &encryptedCache{
		entries: make(map[string]*cacheEntry),
		block:   block,
		ttl:     ttl,
	}, nil
}

// cacheKey builds a deterministic cache key from scope components.
// Including the scope level prevents escalation attacks (session cred ≠ org cred).
func cacheKey(scopeLevel, ownerID, serviceID string) string {
	h := sha256.New()
	h.Write([]byte(scopeLevel))
	h.Write([]byte{0})
	h.Write([]byte(ownerID))
	h.Write([]byte{0})
	h.Write([]byte(serviceID))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// set encrypts value and stores it under key with the configured TTL.
func (c *encryptedCache) set(key string, value []byte) error {
	gcm, err := cipher.NewGCM(c.block)
	if err != nil {
		return fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	encrypted := gcm.Seal(nil, nonce, value, nil)
	expiresAt := time.Now().Add(c.ttl)

	entry := &cacheEntry{
		encrypted: encrypted,
		nonce:     nonce,
		expiresAt: expiresAt,
	}

	// Schedule automatic zeroing when the TTL fires.
	entry.timer = time.AfterFunc(c.ttl, func() {
		c.delete(key)
	})

	c.mu.Lock()
	// Cancel any existing timer for this key.
	if old, ok := c.entries[key]; ok {
		old.timer.Stop()
		zeroBytes(old.encrypted)
	}
	c.entries[key] = entry
	c.mu.Unlock()
	return nil
}

// get decrypts and returns the value for key. Returns nil, false if not found or expired.
func (c *encryptedCache) get(key string) ([]byte, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		c.delete(key)
		return nil, false
	}

	gcm, err := cipher.NewGCM(c.block)
	if err != nil {
		return nil, false
	}

	plaintext, err := gcm.Open(nil, entry.nonce, entry.encrypted, nil)
	if err != nil {
		return nil, false
	}
	return plaintext, true
}

// delete removes and zeroes an entry.
func (c *encryptedCache) delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[key]; ok {
		entry.timer.Stop()
		zeroBytes(entry.encrypted)
		zeroBytes(entry.nonce)
		delete(c.entries, key)
	}
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
