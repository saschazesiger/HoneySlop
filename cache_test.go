package main

import (
	"testing"
	"time"
)

func TestPathCache(t *testing.T) {
	dir := t.TempDir()
	c := NewPathCache(dir)
	key := cacheKey("GET", "/wp-login.php?x=1")
	if _, ok := c.Get(key); ok {
		t.Fatal("empty cache should miss")
	}
	cr := &CachedResponse{Status: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: "<html>hi</html>", Model: "m", Created: time.Now()}
	c.Put(key, cr)
	got, ok := c.Get(key)
	if !ok || got.Body != "<html>hi</html>" || got.Status != 200 {
		t.Fatalf("cache hit expected: %+v %v", got, ok)
	}
	// HEAD shares the GET entry
	if _, ok := c.Get(cacheKey("HEAD", "/wp-login.php?x=1")); !ok {
		t.Fatal("HEAD should reuse the GET cache entry")
	}
	// survives a reload from disk (new in-memory layer)
	c2 := NewPathCache(dir)
	if got, ok := c2.Get(key); !ok || got.Body != "<html>hi</html>" {
		t.Fatal("cache should persist to disk and reload")
	}
	// clear wipes it
	if err := c2.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, ok := NewPathCache(dir).Get(key); ok {
		t.Fatal("cleared cache should miss")
	}
}
