package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// PathCache stores the AI generated response for each request path, so a given path only ever costs
// one LLM call: the first request generates it, every later request to the same path is served from
// the cache (persisted under <dataDir>/cache). This both cuts cost and makes the honeypot consistent,
// a real server returns the same page for the same URL.
type PathCache struct {
	dir string
	max int

	mu    sync.Mutex
	mem   map[string]*CachedResponse
	count int // approximate number of persisted entries (bounds disk growth)
}

// CachedResponse is a stored HTTP answer.
type CachedResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Model   string            `json:"model"`
	Created time.Time         `json:"created"`
}

const (
	cacheMemMax  = 2048   // in-memory hot entries
	cacheDiskMax = 50_000 // hard cap on persisted entries (scanners probe endless unique paths)
)

func NewPathCache(dataDir string) *PathCache {
	dir := filepath.Join(dataDir, "cache")
	_ = os.MkdirAll(dir, 0o700)
	c := &PathCache{dir: dir, max: cacheDiskMax, mem: map[string]*CachedResponse{}}
	if entries, err := os.ReadDir(dir); err == nil {
		c.count = len(entries)
	}
	return c
}

// cacheKey normalizes a request into a cache key. HEAD shares GET's entry.
func cacheKey(method, requestURI string) string {
	if method == "HEAD" {
		method = "GET"
	}
	return method + " " + requestURI
}

func (c *PathCache) file(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(c.dir, hex.EncodeToString(sum[:])+".json")
}

// Get returns a cached response for key, from memory or disk.
func (c *PathCache) Get(key string) (*CachedResponse, bool) {
	c.mu.Lock()
	if v, ok := c.mem[key]; ok {
		c.mu.Unlock()
		return v, true
	}
	c.mu.Unlock()

	data, err := os.ReadFile(c.file(key))
	if err != nil {
		return nil, false
	}
	var v CachedResponse
	if json.Unmarshal(data, &v) != nil {
		return nil, false
	}
	c.remember(key, &v)
	return &v, true
}

// Put stores a response for key (memory + disk), bounded by cacheDiskMax.
func (c *PathCache) Put(key string, v *CachedResponse) {
	path := c.file(key)
	c.mu.Lock()
	_, inMem := c.mem[key]
	if !inMem && c.count >= c.max {
		c.mu.Unlock()
		return // disk cap reached: serve fresh from the LLM instead of growing unboundedly
	}
	c.mu.Unlock()

	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	isNew := true
	if _, err := os.Stat(path); err == nil {
		isNew = false
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return
	}
	c.mu.Lock()
	if isNew {
		c.count++
	}
	c.rememberLocked(key, v)
	c.mu.Unlock()
}

// remember adds to the in-memory layer under its own lock (called from Get, which holds no lock).
func (c *PathCache) remember(key string, v *CachedResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rememberLocked(key, v)
}

// rememberLocked adds to the in-memory layer, evicting arbitrarily when full. Caller holds c.mu.
func (c *PathCache) rememberLocked(key string, v *CachedResponse) {
	if _, ok := c.mem[key]; !ok && len(c.mem) >= cacheMemMax {
		for k := range c.mem { // drop an arbitrary hot entry
			delete(c.mem, k)
			break
		}
	}
	c.mem[key] = v
}

// Clear wipes the whole cache (used on "clear data" and world regenerate).
func (c *PathCache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mem = map[string]*CachedResponse{}
	c.count = 0
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		_ = os.Remove(filepath.Join(c.dir, e.Name()))
	}
	return nil
}
