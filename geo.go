package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// GeoResolver looks up country/city/ASN for attacker IPs (ipwho.is, fallback ip-api.com).
type GeoResolver struct {
	store  *Store
	hub    *Hub
	client *http.Client
	sem    chan struct{}
	mu     sync.Mutex
	busy   map[string]bool
}

func NewGeoResolver(store *Store, hub *Hub) *GeoResolver {
	return &GeoResolver{
		store:  store,
		hub:    hub,
		client: &http.Client{Timeout: 8 * time.Second},
		sem:    make(chan struct{}, 4),
		busy:   map[string]bool{},
	}
}

func isPrivateIP(ip string) bool {
	p := net.ParseIP(ip)
	return p == nil || p.IsLoopback() || p.IsPrivate() || p.IsLinkLocalUnicast() || p.IsUnspecified() || p.IsLinkLocalMulticast()
}

// Resolve runs asynchronously if the IP has not been resolved yet.
func (g *GeoResolver) Resolve(ip string) {
	g.mu.Lock()
	if g.busy[ip] || len(g.busy) >= 256 { // bounded queue; skipped IPs are retried on their next hit
		g.mu.Unlock()
		return
	}
	g.busy[ip] = true
	g.mu.Unlock()

	go func() {
		defer func() {
			g.mu.Lock()
			delete(g.busy, ip)
			g.mu.Unlock()
		}()
		var info IPInfo
		if isPrivateIP(ip) {
			info = IPInfo{Geo: "private", Country: "Private network", Org: "LAN / loopback"}
		} else {
			g.sem <- struct{}{}
			var err error
			info, err = g.lookupIPWho(ip)
			if err != nil {
				info, err = g.lookupIPAPI(ip)
			}
			<-g.sem
			if err != nil {
				log.Printf("geo: %s: %v", ip, err)
				info = IPInfo{Geo: "failed"}
			}
		}
		updated, err := g.store.SetGeo(ip, info)
		if err == nil {
			g.hub.Publish("ip", updated)
		}
	}()
}

func (g *GeoResolver) getJSON(url string, v any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "honeyslop-geo/1.0")
	resp, err := g.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func (g *GeoResolver) lookupIPWho(ip string) (IPInfo, error) {
	var r struct {
		Success     bool   `json:"success"`
		Message     string `json:"message"`
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
		Region      string `json:"region"`
		City        string `json:"city"`
		Connection  struct {
			ASN int    `json:"asn"`
			Org string `json:"org"`
			ISP string `json:"isp"`
		} `json:"connection"`
	}
	if err := g.getJSON("https://ipwho.is/"+ip, &r); err != nil {
		return IPInfo{}, err
	}
	if !r.Success {
		return IPInfo{}, fmt.Errorf("ipwho.is: %s", r.Message)
	}
	info := IPInfo{Geo: "ok", Country: r.Country, CountryCode: r.CountryCode, Region: r.Region, City: r.City,
		Org: r.Connection.Org, ISP: r.Connection.ISP}
	if r.Connection.ASN > 0 {
		info.ASN = fmt.Sprintf("AS%d", r.Connection.ASN)
	}
	return info, nil
}

func (g *GeoResolver) lookupIPAPI(ip string) (IPInfo, error) {
	var r struct {
		Status      string `json:"status"`
		Message     string `json:"message"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		RegionName  string `json:"regionName"`
		City        string `json:"city"`
		ISP         string `json:"isp"`
		Org         string `json:"org"`
		AS          string `json:"as"`
	}
	if err := g.getJSON("http://ip-api.com/json/"+ip+"?fields=status,message,country,countryCode,regionName,city,isp,org,as", &r); err != nil {
		return IPInfo{}, err
	}
	if r.Status != "success" {
		return IPInfo{}, fmt.Errorf("ip-api: %s", r.Message)
	}
	asn := r.AS
	if i := indexByte(asn, ' '); i > 0 {
		asn = asn[:i]
	}
	org := r.Org
	if org == "" {
		org = r.ISP
	}
	return IPInfo{Geo: "ok", Country: r.Country, CountryCode: r.CountryCode, Region: r.RegionName, City: r.City,
		Org: org, ISP: r.ISP, ASN: asn}, nil
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
