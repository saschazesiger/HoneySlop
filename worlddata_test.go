package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	wdTestOnce  sync.Once
	wdTestW     *World
	wdTestWErr  error
	wdTrackRe   = regexp.MustCompile(`^VLT\d{10}$`)
	wdBadWordRe = regexp.MustCompile(`(?i)\b(test|lorem|ipsum|john doe|jane doe|foo|example)\b`)
)

func wdWorldForTest(t *testing.T) *World {
	t.Helper()
	wdTestOnce.Do(func() { wdTestW, wdTestWErr = GenerateWorld() })
	if wdTestWErr != nil {
		t.Fatal(wdTestWErr)
	}
	return wdTestW
}

func wdFindTable(t *testing.T, dbs []Database, db, name string) Table {
	t.Helper()
	for _, d := range dbs {
		if d.Name != db {
			continue
		}
		for _, tb := range d.Tables {
			if tb.Name == name {
				return tb
			}
		}
	}
	t.Fatalf("table %s.%s missing", db, name)
	return Table{}
}

func wdCol(t *testing.T, tb Table, name string) int {
	t.Helper()
	for i, c := range tb.Columns {
		if c.Name == name {
			return i
		}
	}
	t.Fatalf("%s.%s missing", tb.Name, name)
	return -1
}

func wdIDSet(t *testing.T, tb Table, col string) map[int64]bool {
	set := map[int64]bool{}
	i := wdCol(t, tb, col)
	for _, r := range tb.Rows {
		set[r[i].(int64)] = true
	}
	return set
}

func TestWorldDataDeterministic(t *testing.T) {
	w := wdWorldForTest(t)
	a, b := buildDatabases(w), buildDatabases(w)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("buildDatabases is not deterministic")
	}
	// simulated restart: world.json round trip
	data, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	var w2 World
	if err := json.Unmarshal(data, &w2); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, buildDatabases(&w2)) {
		t.Fatal("databases differ after world.json round trip")
	}
	if s1, s2 := trackingSamples(w, 6), trackingSamples(&w2, 6); !reflect.DeepEqual(s1, s2) {
		t.Fatalf("trackingSamples differ: %v vs %v", s1, s2)
	}
	other := w2
	other.Seed++
	if reflect.DeepEqual(a, buildDatabases(&other)) {
		t.Fatal("different seed produced identical data")
	}
}

func TestWorldDataShapeAndTypes(t *testing.T) {
	w := wdWorldForTest(t)
	start := time.Now()
	dbs := buildDatabases(w)
	t.Logf("buildDatabases took %v", time.Since(start))
	size := 0
	for _, db := range dbs {
		for _, tb := range db.Tables {
			if len(tb.Columns) == 0 {
				t.Errorf("%s.%s has no columns", db.Name, tb.Name)
			}
			for ri, row := range tb.Rows {
				if len(row) != len(tb.Columns) {
					t.Fatalf("%s.%s row %d: %d values for %d columns", db.Name, tb.Name, ri, len(row), len(tb.Columns))
				}
				for ci, v := range row {
					switch x := v.(type) {
					case nil:
						if !tb.Columns[ci].Nullable {
							t.Errorf("%s.%s.%s row %d: NULL in NOT NULL column", db.Name, tb.Name, tb.Columns[ci].Name, ri)
						}
					case int64:
						size += 8
					case float64:
						size += 8
					case string:
						size += len(x)
						if wdBadWordRe.MatchString(x) {
							t.Errorf("%s.%s.%s contains placeholder text: %q", db.Name, tb.Name, tb.Columns[ci].Name, x)
						}
					default:
						t.Fatalf("%s.%s.%s: unsupported value type %T", db.Name, tb.Name, tb.Columns[ci].Name, v)
					}
				}
			}
			t.Logf("%-18s %-24s %4d rows", db.Name, tb.Name, len(tb.Rows))
		}
	}
	t.Logf("approx. data size %d bytes", size)
	if size > 1500*1024 {
		t.Errorf("data too large: %d bytes", size)
	}
}

func TestWorldDataNoFuture(t *testing.T) {
	w := wdWorldForTest(t)
	now := w.Created.UTC().Format(wdTS)
	for _, db := range buildDatabases(w) {
		for _, tb := range db.Tables {
			for ci, c := range tb.Columns {
				if c.Type != "timestamp" && c.Type != "datetime" {
					continue
				}
				for _, row := range tb.Rows {
					if s, ok := row[ci].(string); ok && s > now {
						t.Errorf("%s.%s.%s in the future: %s > %s", db.Name, tb.Name, c.Name, s, now)
					}
				}
			}
		}
	}
	sh := wdFindTable(t, buildDatabases(w), worldAppDB, "shipments")
	ei, si := wdCol(t, sh, "eta"), wdCol(t, sh, "status")
	for _, r := range sh.Rows {
		if r[ei].(string) > now[:10] && r[si] == "delivered" {
			t.Errorf("delivered shipment with future ETA: %v", r)
		}
	}
}

func TestWorldDataForeignKeys(t *testing.T) {
	w := wdWorldForTest(t)
	dbs := buildDatabases(w)
	customers := wdFindTable(t, dbs, worldAppDB, "customers")
	custIDs := wdIDSet(t, customers, "id")
	for id := int64(100); id <= 159; id++ {
		if !custIDs[id] {
			t.Errorf("customer %d missing", id)
		}
	}
	if len(custIDs) != 60 {
		t.Errorf("want 60 customers, got %d", len(custIDs))
	}

	// users == w.AppUsers
	users := wdFindTable(t, dbs, worldAppDB, "users")
	if len(users.Rows) != len(w.AppUsers) {
		t.Fatalf("users: %d rows, want %d", len(users.Rows), len(w.AppUsers))
	}
	userRole := map[int64]string{}
	for i, u := range w.AppUsers {
		r := users.Rows[i]
		if r[wdCol(t, users, "id")] != int64(u.ID) || r[wdCol(t, users, "email")] != u.Email ||
			r[wdCol(t, users, "password")] != u.Hash || r[wdCol(t, users, "role")] != u.Role || r[wdCol(t, users, "name")] != u.Name {
			t.Errorf("user row %v does not match %+v", r, u)
		}
		cid := r[wdCol(t, users, "customer_id")]
		if u.Role == "customer" {
			if cid != int64(u.CustomerID) || !custIDs[int64(u.CustomerID)] {
				t.Errorf("user %d customer_id %v, want existing %d", u.ID, cid, u.CustomerID)
			}
		} else if cid != nil {
			t.Errorf("staff user %d has customer_id %v", u.ID, cid)
		}
		userRole[int64(u.ID)] = u.Role
	}
	// customer domain matches the portal user's e-mail domain
	emailCol := wdCol(t, customers, "contact_email")
	for _, u := range w.AppUsers {
		if u.Role != "customer" {
			continue
		}
		for _, r := range customers.Rows {
			if r[0] == int64(u.CustomerID) && r[emailCol] != u.Email {
				t.Errorf("customer %d contact %v, want %s", u.CustomerID, r[emailCol], u.Email)
			}
		}
	}
	mi := wdCol(t, customers, "account_manager_id")
	for _, r := range customers.Rows {
		if m, ok := r[mi].(int64); ok && userRole[m] == "customer" || r[mi] != nil && userRole[r[mi].(int64)] == "" {
			t.Errorf("customer %v: bad account manager %v", r[0], r[mi])
		}
	}

	shipments := wdFindTable(t, dbs, worldAppDB, "shipments")
	if n := len(shipments.Rows); n < 200 || n > 300 {
		t.Errorf("unexpected shipment count %d", n)
	}
	shipIDs := wdIDSet(t, shipments, "id")
	drivers := wdIDSet(t, wdFindTable(t, dbs, worldAppDB, "drivers"), "id")
	whs := wdIDSet(t, wdFindTable(t, dbs, worldAppDB, "warehouses"), "id")
	shipCust := map[int64]int64{}
	seenTN := map[string]bool{}
	ci, di, wi, ti, cbi := wdCol(t, shipments, "customer_id"), wdCol(t, shipments, "driver_id"), wdCol(t, shipments, "warehouse_id"),
		wdCol(t, shipments, "tracking_no"), wdCol(t, shipments, "created_by")
	coni := wdCol(t, shipments, "container_no")
	for _, r := range shipments.Rows {
		cid := r[ci].(int64)
		if !custIDs[cid] {
			t.Errorf("shipment %v: unknown customer %d", r[0], cid)
		}
		shipCust[r[0].(int64)] = cid
		if d, ok := r[di].(int64); ok && !drivers[d] {
			t.Errorf("shipment %v: unknown driver %d", r[0], d)
		}
		if x, ok := r[wi].(int64); ok && !whs[x] {
			t.Errorf("shipment %v: unknown warehouse %d", r[0], x)
		}
		if x, ok := r[cbi].(int64); ok && userRole[x] == "" {
			t.Errorf("shipment %v: unknown creator %d", r[0], x)
		}
		tn := r[ti].(string)
		if !wdTrackRe.MatchString(tn) || seenTN[tn] {
			t.Errorf("bad or duplicate tracking number %q", tn)
		}
		seenTN[tn] = true
		if c, ok := r[coni].(string); ok && (len(c) != 11 || fmt.Sprint(wd6346Check(c[:10])) != c[10:]) {
			t.Errorf("bad container number %q", c)
		}
	}

	events := wdFindTable(t, dbs, worldAppDB, "shipment_events")
	if n := len(events.Rows); n < 300 || n > 1200 {
		t.Errorf("unexpected event count %d", n)
	}
	esi := wdCol(t, events, "shipment_id")
	for _, r := range events.Rows {
		if !shipIDs[r[esi].(int64)] {
			t.Errorf("event %v: unknown shipment", r[0])
		}
	}

	invoices := wdFindTable(t, dbs, worldAppDB, "invoices")
	if n := len(invoices.Rows); n < 100 || n > 200 {
		t.Errorf("unexpected invoice count %d", n)
	}
	ici, isi := wdCol(t, invoices, "customer_id"), wdCol(t, invoices, "shipment_id")
	ni, vi, toti, ri := wdCol(t, invoices, "net_amount"), wdCol(t, invoices, "vat_amount"), wdCol(t, invoices, "total_amount"), wdCol(t, invoices, "vat_rate")
	noRe := regexp.MustCompile(`^INV-\d{4}-\d{6}$`)
	for _, r := range invoices.Rows {
		sid := r[isi].(int64)
		if !shipIDs[sid] || shipCust[sid] != r[ici].(int64) {
			t.Errorf("invoice %v: shipment/customer mismatch", r[1])
		}
		net, vat, tot, rate := r[ni].(float64), r[vi].(float64), r[toti].(float64), r[ri].(float64)
		if c := int64(net*100+0.5) + int64(vat*100+0.5) - int64(tot*100+0.5); c != 0 {
			t.Errorf("invoice %v: %.2f + %.2f != %.2f", r[1], net, vat, tot)
		}
		if d := net*rate/100 - vat; d > 0.006 || d < -0.006 {
			t.Errorf("invoice %v: vat %.2f != %.2f%% of %.2f", r[1], vat, rate, net)
		}
		if !noRe.MatchString(r[1].(string)) {
			t.Errorf("bad invoice number %v", r[1])
		}
	}

	pat := wdFindTable(t, dbs, worldAppDB, "personal_access_tokens")
	for _, r := range pat.Rows {
		if userRole[r[wdCol(t, pat, "tokenable_id")].(int64)] == "" {
			t.Errorf("token %v: unknown user", r[0])
		}
	}
	audit := wdFindTable(t, dbs, worldAppDB, "audit_log")
	for _, r := range audit.Rows {
		if u, ok := r[wdCol(t, audit, "user_id")].(int64); ok && userRole[u] == "" {
			t.Errorf("audit %v: unknown user %d", r[0], u)
		}
	}
}

func TestWorldDataIBANAndIDs(t *testing.T) {
	if !wdIBANValid("CH9300762011623852957") || !wdIBANValid("DE89370400440532013000") || wdIBANValid("DE89370400440532013001") {
		t.Fatal("IBAN validator broken")
	}
	if wd6346Check("CSQU305438") != 3 {
		t.Fatal("ISO 6346 check broken")
	}
	w := wdWorldForTest(t)
	customers := wdFindTable(t, buildDatabases(w), worldAppDB, "customers")
	lens := map[string]int{"CH": 21, "DE": 22, "IT": 27, "NL": 18, "PL": 28, "AT": 20}
	vatRe := map[string]*regexp.Regexp{
		"CH": regexp.MustCompile(`^CHE-\d{3}\.\d{3}\.\d{3} (MWST|IVA)$`), "DE": regexp.MustCompile(`^DE\d{9}$`),
		"IT": regexp.MustCompile(`^IT\d{11}$`), "NL": regexp.MustCompile(`^NL\d{9}B0\d$`), "PL": regexp.MustCompile(`^PL\d{10}$`),
		"AT": regexp.MustCompile(`^ATU\d{8}$`)}
	ii, ci, vi := wdCol(t, customers, "iban"), wdCol(t, customers, "country"), wdCol(t, customers, "vat_id")
	for _, r := range customers.Rows {
		iban, cc, vat := r[ii].(string), r[ci].(string), r[vi].(string)
		if !wdIBANValid(iban) || !strings.HasPrefix(iban, cc) || len(iban) != lens[cc] {
			t.Errorf("customer %v: invalid IBAN %s (%s)", r[0], iban, cc)
		}
		if !vatRe[cc].MatchString(vat) {
			t.Errorf("customer %v: bad VAT id %q for %s", r[0], vat, cc)
		}
		if cc == "CH" { // UID mod 11
			d := strings.NewReplacer("CHE-", "", ".", "").Replace(vat[:15])
			sum := 0
			for i, wgt := range []int{5, 4, 3, 2, 7, 6, 5, 4} {
				sum += int(d[i]-'0') * wgt
			}
			if c := (11 - sum%11) % 11; c != int(d[8]-'0') {
				t.Errorf("customer %v: CH UID check digit wrong in %s", r[0], vat)
			}
		}
	}
}

func TestWorldDataWordPressAndMySQL(t *testing.T) {
	w := wdWorldForTest(t)
	dbs := buildDatabases(w)
	wpu := wdFindTable(t, dbs, worldWPDB, "wp_users")
	if len(wpu.Rows) != len(w.WPUsers) {
		t.Fatalf("wp_users: %d rows, want %d", len(wpu.Rows), len(w.WPUsers))
	}
	for i, u := range w.WPUsers {
		r := wpu.Rows[i]
		if r[0] != int64(u.ID) || r[1] != u.Login || r[2] != u.Hash || r[4] != u.Email || r[9] != u.Display {
			t.Errorf("wp_users row %v does not match %+v", r, u)
		}
	}
	um := wdFindTable(t, dbs, worldWPDB, "wp_usermeta")
	caps := 0
	for _, r := range um.Rows {
		if r[2] == "wp_capabilities" {
			caps++
		}
	}
	if caps != len(w.WPUsers) {
		t.Errorf("wp_capabilities rows %d, want %d", caps, len(w.WPUsers))
	}
	opts := wdFindTable(t, dbs, worldWPDB, "wp_options")
	found := map[string]string{}
	for _, r := range opts.Rows {
		found[r[1].(string)] = r[2].(string)
	}
	if found["db_version"] != "49752" || found["siteurl"] != "https://www.veltrona-group.com/blog" ||
		!strings.Contains(found["active_plugins"], "wp-file-manager/file_folder_manager.php") {
		t.Errorf("wp_options incomplete: %v", found["active_plugins"])
	}
	if !strings.HasPrefix(found["wp_user_roles"], "a:7:{s:13:\"administrator\";a:2:{") {
		t.Errorf("wp_user_roles malformed: %.60s", found["wp_user_roles"])
	}

	mu := wdFindTable(t, dbs, "mysql", "user")
	hi, ui, ai, sel, gr := wdCol(t, mu, "Host"), wdCol(t, mu, "User"), wdCol(t, mu, "authentication_string"),
		wdCol(t, mu, "Select_priv"), wdCol(t, mu, "Grant_priv")
	got := map[string][]any{}
	for _, r := range mu.Rows {
		got[r[ui].(string)+"@"+r[hi].(string)] = r
	}
	for _, a := range w.MySQL {
		r := got[a.User+"@"+a.Host]
		if r == nil || r[ai] != a.Hash {
			t.Errorf("mysql.user missing/mismatch for %s@%s", a.User, a.Host)
			continue
		}
		switch a.User {
		case "root":
			if r[sel] != "Y" || r[gr] != "Y" {
				t.Errorf("root privileges wrong: %v", r)
			}
		case "connect_app", "wp_blog":
			if r[sel] != "N" {
				t.Errorf("%s must not have global SELECT", a.User)
			}
		case "backup":
			if r[sel] != "Y" || r[gr] != "N" {
				t.Errorf("backup privileges wrong")
			}
		}
	}
	for _, k := range []string{"mysql.session@localhost", "mysql.sys@localhost", "debian-sys-maint@localhost"} {
		if got[k] == nil {
			t.Errorf("%s missing", k)
		}
	}
	if r := got["mysql.sys@localhost"]; r != nil && (r[ai] != "*THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE" || r[len(r)-1] != "Y") {
		t.Errorf("mysql.sys row wrong")
	}
}

func TestTrackingSamples(t *testing.T) {
	w := wdWorldForTest(t)
	sh := wdFindTable(t, buildDatabases(w), worldAppDB, "shipments")
	status := map[string]string{}
	for _, r := range sh.Rows {
		status[r[wdCol(t, sh, "tracking_no")].(string)] = r[wdCol(t, sh, "status")].(string)
	}
	s := trackingSamples(w, 8)
	if len(s) != 8 {
		t.Fatalf("got %d samples", len(s))
	}
	seen := map[string]bool{}
	for _, tn := range s {
		if st := status[tn]; (st != "in_transit" && st != "delivered") || seen[tn] || !wdTrackRe.MatchString(tn) {
			t.Errorf("bad sample %q (status %q)", tn, st)
		}
		seen[tn] = true
	}
	t.Logf("samples: %v", s)
}
