package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Deterministic business data of the world: the MySQL schemas veltrona_connect (Laravel portal),
// veltrona_wp (legacy WordPress blog) and mysql (grant tables). Everything derives from w.Seed and
// w.Created, so the same world yields byte-identical databases on every start. Never call bcrypt here.

const (
	wdTS   = "2006-01-02 15:04:05"
	wdDate = "2006-01-02"
)

// ---------- random helpers (seeded, deterministic) ----------

type wdRand struct{ *rand.Rand }

func newWDRand(w *World, stream uint64) wdRand {
	return wdRand{rand.New(rand.NewPCG(w.Seed, 0x76656c74726f6e61^(stream*0x9e3779b97f4a7c15)))}
}

func (r wdRand) between(a, b int) int {
	if b <= a {
		return a
	}
	return a + r.IntN(b-a+1)
}

func (r wdRand) chance(p float64) bool { return r.Float64() < p }

func (r wdRand) str(alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.IntN(len(alphabet))]
	}
	return string(b)
}

func (r wdRand) digits(n int) string { return r.str("0123456789", n) }
func (r wdRand) hex(n int) string    { return r.str("0123456789abcdef", n) }

func (r wdRand) dur(a, b time.Duration) time.Duration {
	if b <= a {
		return a
	}
	return a + time.Duration(r.Int64N(int64(b-a)))
}

func (r wdRand) timeIn(a, b time.Time) time.Time { return a.Add(r.dur(0, b.Sub(a))) }

// work moves t to a working day between 06:00 and 16:30 UTC (office hours in Zug).
func (r wdRand) work(t time.Time) time.Time {
	d := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	switch d.Weekday() {
	case time.Saturday:
		d = d.AddDate(0, 0, 2)
	case time.Sunday:
		d = d.AddDate(0, 0, 1)
	}
	return d.Add(time.Duration(6*3600+r.IntN(10*3600+1800)) * time.Second)
}

func (r wdRand) uuid() string {
	h := r.hex(32)
	return h[0:8] + "-" + h[8:12] + "-4" + h[13:16] + "-" + string("89ab"[r.IntN(4)]) + h[17:20] + "-" + h[20:32]
}

const wdBcryptAlpha = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// fakeBcrypt returns a well-formed $2y$10$ hash (correct padding bits) of an unknown secret.
func (r wdRand) fakeBcrypt() string {
	salt := r.str(wdBcryptAlpha, 21) + string(".Oeu"[r.IntN(4)])
	sum := r.str(wdBcryptAlpha, 30) + string(wdBcryptAlpha[4*r.IntN(16)])
	return "$2y$10$" + salt + sum
}

func wdOne[T any](r wdRand, xs []T) T { return xs[r.IntN(len(xs))] }

func wdWeighted(r wdRand, ws []float64) int {
	var tot float64
	for _, w := range ws {
		tot += w
	}
	x := r.Float64() * tot
	for i, w := range ws {
		if x -= w; x < 0 {
			return i
		}
	}
	return len(ws) - 1
}

// ---------- value / column helpers ----------

func wdT(t time.Time) string { return t.UTC().Format(wdTS) }
func wdD(t time.Time) string { return t.UTC().Format(wdDate) }
func wdI(x int) any          { return int64(x) }
func wdF(x float64) any      { return math.Round(x*100) / 100 }
func wdBool(b bool) any {
	if b {
		return int64(1)
	}
	return int64(0)
}

func wdNS(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func wdNT(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return wdT(t)
}

func wdNI(x int64) any {
	if x == 0 {
		return nil
	}
	return x
}

func wdSha256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func wdRound2(x float64) float64 { return math.Round(x*100) / 100 }

// wdc builds a column; spec is "|"-separated: null, ai, pk, uni, mul, upd, def=<value>.
func wdc(name, typ, spec string) Column {
	c := Column{Name: name, Type: typ}
	for _, f := range strings.Split(spec, "|") {
		switch {
		case f == "null":
			c.Nullable = true
		case f == "pk":
			c.Key = "PRI"
		case f == "ai":
			c.Key, c.Extra = "PRI", "auto_increment"
		case f == "uni":
			c.Key = "UNI"
		case f == "mul":
			c.Key = "MUL"
		case f == "upd":
			c.Extra = "on update CURRENT_TIMESTAMP"
		case strings.HasPrefix(f, "def="):
			v := f[4:]
			c.Default = &v
		}
	}
	return c
}

func wdLaravelTS() []Column {
	return []Column{wdc("created_at", "timestamp", "null"), wdc("updated_at", "timestamp", "null")}
}

func wdTable(name string, cols []Column, rows [][]any) Table {
	t := Table{Name: name, Engine: "InnoDB", Columns: cols, Rows: rows}
	if len(cols) > 0 && cols[0].Extra == "auto_increment" {
		t.AutoIncrement = 1
		for _, row := range rows {
			if id, ok := row[0].(int64); ok && id >= t.AutoIncrement {
				t.AutoIncrement = id + 1
			}
		}
	}
	return t
}

func wdEnum(vals ...string) string { return "enum('" + strings.Join(vals, "','") + "')" }

// wdFold turns names into ASCII for e-mail addresses and domains.
var wdFoldRepl = strings.NewReplacer("ä", "ae", "ö", "oe", "ü", "ue", "ß", "ss", "é", "e", "è", "e", "ê", "e", "à", "a",
	"á", "a", "ò", "o", "ó", "o", "ù", "u", "ú", "u", "ì", "i", "í", "i", "ł", "l", "ą", "a", "ę", "e", "ś", "s", "ć", "c",
	"ź", "z", "ż", "z", "ń", "n", "ø", "o", "å", "a", "'", "", " ", "", ".", "", "&", "")

func wdFold(s string) string { return wdFoldRepl.Replace(strings.ToLower(s)) }

func wdUpperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ---------- check digit algorithms ----------

// wdIBAN computes ISO 13616 check digits for a BBAN.
func wdIBAN(cc, bban string) string {
	return fmt.Sprintf("%s%02d%s", cc, 98-wdMod97(bban+cc+"00"), bban)
}

func wdMod97(s string) int {
	rem := 0
	for _, ch := range s {
		switch {
		case ch >= '0' && ch <= '9':
			rem = (rem*10 + int(ch-'0')) % 97
		case ch >= 'A' && ch <= 'Z':
			rem = (rem*100 + int(ch-'A') + 10) % 97
		}
	}
	return rem
}

func wdIBANValid(iban string) bool {
	return len(iban) > 4 && wdMod97(iban[4:]+iban[:4]) == 1
}

func wdLuhnDigit(s string) int { // check digit to append to s
	sum := 0
	for i := len(s) - 1; i >= 0; i-- {
		d := int(s[i] - '0')
		if (len(s)-1-i)%2 == 0 {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return (10 - sum%10) % 10
}

// ISO 6346 letter values (multiples of 11 skipped), also used for MRN check characters.
func wd6346Val(ch byte) int {
	if ch >= '0' && ch <= '9' {
		return int(ch - '0')
	}
	v := 10 + int(ch-'A')
	v += (v - 1) / 10 // skip 11, 22, 33
	return v
}

func wd6346Check(s string) int {
	sum := 0
	for i := 0; i < len(s); i++ {
		sum += wd6346Val(s[i]) << i
	}
	return sum % 11
}

func (r wdRand) container(owner string) string {
	for {
		s := owner + r.digits(6)
		if c := wd6346Check(s); c < 10 {
			return s + strconv.Itoa(c)
		}
	}
}

func (r wdRand) mrn(year int, cc string) string {
	for {
		s := fmt.Sprintf("%02d%s%s", year%100, cc, r.str("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 13))
		if c := wd6346Check(s); c < 10 {
			return s + strconv.Itoa(c)
		}
	}
}

func (r wdRand) awb(prefix string) string {
	serial := r.IntN(9000000) + 1000000
	return fmt.Sprintf("%s-%07d%d", prefix, serial, serial%7)
}

// national VAT / company identifiers with valid check digits
func (r wdRand) vatID(cc, city string) string {
	for {
		switch cc {
		case "CH":
			d := strconv.Itoa(r.between(1, 9)) + r.digits(7)
			w := []int{5, 4, 3, 2, 7, 6, 5, 4}
			sum := 0
			for i := range w {
				sum += int(d[i]-'0') * w[i]
			}
			c := 11 - sum%11
			if c == 10 {
				continue
			}
			if c == 11 {
				c = 0
			}
			d += strconv.Itoa(c)
			suffix := "MWST"
			if city == "Lugano" {
				suffix = "IVA"
			}
			return fmt.Sprintf("CHE-%s.%s.%s %s", d[0:3], d[3:6], d[6:9], suffix)
		case "DE":
			d := strconv.Itoa(r.between(1, 9)) + r.digits(7)
			p := 10
			for i := 0; i < 8; i++ {
				s := (int(d[i]-'0') + p) % 10
				if s == 0 {
					s = 10
				}
				p = (2 * s) % 11
			}
			c := 11 - p
			if c == 10 {
				c = 0
			}
			return "DE" + d + strconv.Itoa(c)
		case "IT":
			d := strconv.Itoa(r.between(0, 9)) + r.digits(6) + fmt.Sprintf("%03d", r.between(1, 100))
			return "IT" + d + strconv.Itoa(wdLuhnDigit(d))
		case "NL":
			d := strconv.Itoa(r.between(1, 9)) + r.digits(7)
			sum := 0
			for i := 0; i < 8; i++ {
				sum += int(d[i]-'0') * (9 - i)
			}
			if sum%11 == 10 {
				continue
			}
			return "NL" + d + strconv.Itoa(sum%11) + "B01"
		case "PL":
			d := strconv.Itoa(r.between(1, 9)) + r.digits(8)
			w := []int{6, 5, 7, 2, 3, 4, 5, 6, 7}
			sum := 0
			for i := range w {
				sum += int(d[i]-'0') * w[i]
			}
			if sum%11 == 10 {
				continue
			}
			return "PL" + d + strconv.Itoa(sum%11)
		case "AT":
			d := r.digits(7)
			s := 0
			for i := 0; i < 7; i++ {
				x := int(d[i] - '0')
				if i%2 == 1 {
					x = x/5 + (x*2)%10
				}
				s += x
			}
			return "ATU" + d + strconv.Itoa((10-(s+4)%10)%10)
		default:
			return ""
		}
	}
}

type wdBank struct{ Code, BIC string }

var wdBanks = map[string][]wdBank{
	"CH": {{"00700", "ZKBKCHZZ80A"}, {"00230", "UBSWCHZH80A"}, {"04835", "CRESCHZZ80A"}, {"09000", "POFICHBEXXX"},
		{"00787", "KBZGCH22XXX"}, {"00778", "LUKBCH2260A"}, {"00770", "BKBBCHBBXXX"}, {"80808", "RAIFCH22XXX"}},
	"DE": {{"50070010", "DEUTDEFFXXX"}, {"50040000", "COBADEFFXXX"}, {"70020270", "HYVEDEMMXXX"}, {"70150000", "SSKMDEMMXXX"},
		{"20050550", "HASPDEHHXXX"}, {"60050101", "SOLADEST600"}, {"37050198", "COLSDE33XXX"}},
	"IT": {{"03069", "BCITITMMXXX"}, {"02008", "UNCRITMMXXX"}, {"05034", "BAPPIT21XXX"}, {"03032", "BACRIT22XXX"}, {"05696", "POSOIT22XXX"}},
	"NL": {{"ABNA", "ABNANL2A"}, {"RABO", "RABONL2U"}, {"INGB", "INGBNL2A"}},
	"PL": {{"102", "BPKOPLPW"}, {"114", "BREXPLPW"}, {"124", "PKOPPLPW"}, {"105", "INGBPLPW"}, {"109", "WBKPPLPP"}},
	"AT": {{"20111", "GIBAATWWXXX"}, {"34000", "RZOOAT2L"}, {"12000", "BKAUATWWXXX"}, {"15000", "OBKLAT2L"}, {"32000", "RLNWATWW"}},
}

// iban returns a valid IBAN of the country plus the BIC of the bank.
func (r wdRand) iban(cc string) (string, string) {
	b := wdOne(r, wdBanks[cc])
	switch cc {
	case "CH":
		return wdIBAN(cc, b.Code+"0"+r.digits(11)), b.BIC
	case "DE":
		return wdIBAN(cc, b.Code+"0"+r.digits(9)), b.BIC
	case "AT":
		return wdIBAN(cc, b.Code+"00"+r.digits(9)), b.BIC
	case "IT":
		bban := b.Code + r.digits(5) + "0000" + r.digits(8)
		odd := []int{1, 0, 5, 7, 9, 13, 15, 17, 19, 21}
		sum := 0
		for i := 0; i < len(bban); i++ {
			d := int(bban[i] - '0')
			if i%2 == 0 {
				sum += odd[d]
			} else {
				sum += d
			}
		}
		return wdIBAN(cc, string(rune('A'+sum%26))+bban), b.BIC
	case "NL":
		if b.Code == "INGB" {
			return wdIBAN(cc, b.Code+"000"+r.digits(7)), b.BIC
		}
		for {
			acc := strconv.Itoa(r.between(1, 5)) + r.digits(9)
			if b.Code == "RABO" {
				acc = "3" + acc[1:]
			}
			sum := 0
			for i := 0; i < 10; i++ {
				sum += int(acc[i]-'0') * (10 - i)
			}
			if sum%11 == 0 {
				return wdIBAN(cc, b.Code+acc), b.BIC
			}
		}
	case "PL":
		sort7 := b.Code + r.digits(4)
		w := []int{3, 9, 7, 1, 3, 9, 7}
		sum := 0
		for i := range w {
			sum += int(sort7[i]-'0') * w[i]
		}
		return wdIBAN(cc, sort7+strconv.Itoa((10-sum%10)%10)+"0000"+r.digits(12)), b.BIC
	}
	return "", ""
}

// ---------- PHP serialize ----------

type wdKV struct {
	K any
	V any
}
type wdArr []wdKV
type wdObj struct {
	Class string
	Props wdArr
}

func wdList(xs ...string) wdArr {
	a := make(wdArr, len(xs))
	for i, x := range xs {
		a[i] = wdKV{i, x}
	}
	return a
}

func wdPHP(v any) string {
	switch x := v.(type) {
	case nil:
		return "N;"
	case bool:
		if x {
			return "b:1;"
		}
		return "b:0;"
	case int:
		return fmt.Sprintf("i:%d;", x)
	case int64:
		return fmt.Sprintf("i:%d;", x)
	case string:
		return fmt.Sprintf("s:%d:\"%s\";", len(x), x)
	case wdArr:
		var b strings.Builder
		fmt.Fprintf(&b, "a:%d:{", len(x))
		for _, kv := range x {
			b.WriteString(wdPHP(kv.K))
			b.WriteString(wdPHP(kv.V))
		}
		b.WriteString("}")
		return b.String()
	case wdObj:
		inner := wdPHP(x.Props)
		inner = inner[strings.Index(inner, ":{"):] // reuse array body
		return fmt.Sprintf("O:%d:\"%s\":%d%s", len(x.Class), x.Class, len(x.Props), inner)
	}
	panic(fmt.Sprintf("wdPHP: unsupported %T", v))
}

// wdPHPJSON encodes like PHP json_encode (escaped slashes, unescaped unicode).
func wdPHPJSON(v any) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return strings.ReplaceAll(strings.TrimSuffix(b.String(), "\n"), "/", `\/`)
}

// ---------- reference data ----------

var wdFirst = map[string][2][]string{ // [male, female]
	"de": {{"Thomas", "Andreas", "Michael", "Stefan", "Markus", "Christian", "Martin", "Reto", "Urs", "Beat", "Patrick", "Roman",
		"Simon", "Matthias", "Jürg", "Adrian", "Fabian", "Philipp", "Florian", "Ralf", "Jörg", "Oliver", "Dominik", "Severin"},
		{"Sabine", "Claudia", "Nicole", "Andrea", "Monika", "Barbara", "Karin", "Corinne", "Melanie", "Franziska", "Katharina",
			"Laura", "Sarah", "Ursula", "Esther", "Martina", "Daniela", "Jasmin", "Simone", "Regula", "Anja", "Bettina"}},
	"it": {{"Luca", "Marco", "Alessandro", "Matteo", "Davide", "Francesco", "Stefano", "Giorgio", "Paolo", "Roberto", "Fabio", "Simone"},
		{"Giulia", "Francesca", "Chiara", "Sara", "Valentina", "Federica", "Elisa", "Silvia", "Martina", "Roberta", "Paola", "Alessia"}},
	"nl": {{"Jan", "Pieter", "Daan", "Sander", "Bram", "Thijs", "Ruben", "Joost", "Maarten", "Wouter", "Erik", "Bas"},
		{"Sanne", "Lotte", "Femke", "Anouk", "Marieke", "Esther", "Inge", "Ilse", "Noor", "Eva", "Linda", "Mirjam"}},
	"pl": {{"Piotr", "Krzysztof", "Andrzej", "Tomasz", "Paweł", "Marcin", "Michał", "Grzegorz", "Łukasz", "Jakub", "Wojciech", "Adam"},
		{"Anna", "Katarzyna", "Agnieszka", "Magdalena", "Joanna", "Monika", "Ewa", "Barbara", "Aleksandra", "Karolina", "Natalia", "Beata"}},
}

var wdSurnames = map[string][]string{
	"de": {"Müller", "Meier", "Schmid", "Keller", "Weber", "Schneider", "Steiner", "Fischer", "Gerber", "Frei", "Zimmermann",
		"Moser", "Widmer", "Graf", "Roth", "Suter", "Kunz", "Lüthi", "Bühler", "Bachmann", "Zbinden", "Ammann", "Hofer", "Egli",
		"Kälin", "Imhof", "Schnyder", "Becker", "Hoffmann", "Schulz", "Koch", "Richter", "Wolf", "Schröder", "Neumann", "Braun",
		"Hartmann", "Krüger", "Lang", "Pichler", "Gruber", "Leitner", "Eder", "Mayr", "Lehner", "Fuchs", "Wallner", "Odermatt",
		"Achermann", "Vogt", "Bosshard", "Studer", "Reichmuth", "Kaufmann", "Dietrich", "Seiler", "Haas", "Brandl"},
	"it": {"Russo", "Ferrari", "Esposito", "Romano", "Colombo", "Ricci", "Marino", "Greco", "Bruno", "Gallo", "Conti",
		"De Luca", "Costa", "Giordano", "Mancini", "Rizzo", "Lombardi", "Moretti", "Barbieri", "Fontana", "Santoro", "Mariani",
		"Rinaldi", "Caruso", "Galli", "Martini", "Leone", "Longo", "Gentile", "Vitale", "Pellegrini", "Brambilla", "Fumagalli",
		"Sala", "Villa", "Bonetti", "Cattaneo"},
	"nl": {"de Jong", "Jansen", "van den Berg", "van Dijk", "Bakker", "Janssen", "Visser", "Smit", "Meijer", "de Boer",
		"Mulder", "de Groot", "Bos", "Vos", "Peters", "Hendriks", "van Leeuwen", "Dekker", "Brouwer", "de Wit", "Dijkstra",
		"Smits", "de Graaf", "van der Meer", "Kok", "Verhoeven", "van Beek"},
	"pl": {"Nowak", "Wójcik", "Kowalczyk", "Woźniak", "Mazur", "Krawczyk", "Kaczmarek", "Zając", "Król", "Wieczorek",
		"Pawlak", "Walczak", "Michalak", "Sikora", "Baran", "Duda", "Szewczyk", "Kowalski", "Lewandowski", "Zieliński",
		"Szymański", "Dąbrowski", "Kozłowski", "Jankowski", "Wiśniewski"},
}

func wdLang(cc string) string {
	switch cc {
	case "IT":
		return "it"
	case "NL":
		return "nl"
	case "PL":
		return "pl"
	}
	return "de"
}

// person returns a realistic first and last name for a country.
func (r wdRand) person(cc string) (string, string) {
	lang := wdLang(cc)
	g := r.IntN(2)
	first := wdOne(r, wdFirst[lang][g])
	last := wdOne(r, wdSurnames[lang])
	if lang == "pl" && g == 1 {
		for _, suf := range []string{"ski", "cki", "dzki"} {
			if strings.HasSuffix(last, suf) {
				last = strings.TrimSuffix(last, "i") + "a"
				break
			}
		}
	}
	return first, last
}

type wdCity struct{ Postal, City, Area string }

type wdCountry struct {
	Code, Currency, TLD string
	Cities              []wdCity
	Streets             []string
	Weight              float64
}

var wdCountries = []wdCountry{
	{"CH", "CHF", "ch", []wdCity{{"8005", "Zürich", "44"}, {"8048", "Zürich", "44"}, {"4057", "Basel", "61"}, {"4133", "Pratteln", "61"},
		{"6300", "Zug", "41"}, {"6340", "Baar", "41"}, {"6003", "Luzern", "41"}, {"3011", "Bern", "31"}, {"9000", "St. Gallen", "71"},
		{"8404", "Winterthur", "52"}, {"6900", "Lugano", "91"}, {"5000", "Aarau", "62"}, {"4600", "Olten", "62"}, {"8952", "Schlieren", "44"},
		{"2502", "Biel/Bienne", "32"}, {"8957", "Spreitenbach", "56"}, {"6210", "Sursee", "41"}, {"8590", "Romanshorn", "71"}},
		[]string{"Industriestrasse", "Bahnhofstrasse", "Gewerbestrasse", "Hardturmstrasse", "Riedstrasse", "Hinterbergstrasse",
			"Allmendstrasse", "Grabenstrasse", "Chamerstrasse", "Pilatusstrasse", "Neuhofstrasse", "Zürcherstrasse", "Werkstrasse",
			"Bernstrasse", "Hauptstrasse", "Lagerstrasse"}, 0.30},
	{"DE", "EUR", "de", []wdCity{{"60327", "Frankfurt am Main", "69"}, {"70565", "Stuttgart", "711"}, {"80939", "München", "89"},
		{"20457", "Hamburg", "40"}, {"50829", "Köln", "221"}, {"90411", "Nürnberg", "911"}, {"68219", "Mannheim", "621"},
		{"79108", "Freiburg im Breisgau", "761"}, {"44147", "Dortmund", "231"}, {"04129", "Leipzig", "341"}, {"86156", "Augsburg", "821"},
		{"33602", "Bielefeld", "521"}, {"73037", "Göppingen", "7161"}, {"88214", "Ravensburg", "751"}},
		[]string{"Industriestraße", "Robert-Bosch-Straße", "Carl-Benz-Straße", "Gutenbergstraße", "Daimlerstraße", "Max-Planck-Straße",
			"Siemensstraße", "Im Gewerbepark", "Otto-Hahn-Straße", "Raiffeisenstraße", "Benzstraße", "Rudolf-Diesel-Straße"}, 0.25},
	{"IT", "EUR", "it", []wdCity{{"20138", "Milano", "02"}, {"20090", "Segrate", "02"}, {"10156", "Torino", "011"}, {"40138", "Bologna", "051"},
		{"37135", "Verona", "045"}, {"35127", "Padova", "049"}, {"25125", "Brescia", "030"}, {"41122", "Modena", "059"},
		{"50127", "Firenze", "055"}, {"22100", "Como", "031"}, {"24126", "Bergamo", "035"}},
		[]string{"Via dell'Industria", "Via Enrico Fermi", "Via Guglielmo Marconi", "Via Alessandro Volta", "Viale Lombardia",
			"Via dei Mestieri", "Via Galileo Galilei", "Via dell'Artigianato", "Via Leonardo da Vinci", "Via del Lavoro"}, 0.15},
	{"NL", "EUR", "nl", []wdCity{{"3089", "Rotterdam", "10"}, {"5928", "Venlo", "77"}, {"5048", "Tilburg", "13"}, {"5651", "Eindhoven", "40"},
		{"3542", "Utrecht", "30"}, {"1043", "Amsterdam", "20"}, {"4823", "Breda", "76"}, {"8041", "Zwolle", "38"}, {"2665", "Bleiswijk", "10"}},
		[]string{"Industrieweg", "Transportweg", "Edisonstraat", "Marconistraat", "Columbusweg", "Nijverheidsweg", "Energieweg",
			"Handelsweg", "Distributieweg"}, 0.10},
	{"PL", "EUR", "pl", []wdCity{{"02-672", "Warszawa", "22"}, {"05-850", "Ożarów Mazowiecki", "22"}, {"30-347", "Kraków", "12"},
		{"50-512", "Wrocław", "71"}, {"61-131", "Poznań", "61"}, {"80-309", "Gdańsk", "58"}, {"90-361", "Łódź", "42"},
		{"40-203", "Katowice", "32"}, {"62-080", "Tarnowo Podgórne", "61"}},
		[]string{"ul. Przemysłowa", "ul. Fabryczna", "ul. Logistyczna", "ul. Składowa", "ul. Towarowa", "ul. Domaniewska",
			"ul. Poznańska", "ul. Magazynowa"}, 0.10},
	{"AT", "EUR", "at", []wdCity{{"1230", "Wien", "1"}, {"1110", "Wien", "1"}, {"4020", "Linz", "732"}, {"8020", "Graz", "316"},
		{"5020", "Salzburg", "662"}, {"6020", "Innsbruck", "512"}, {"4600", "Wels", "7242"}, {"6850", "Dornbirn", "5572"},
		{"9020", "Klagenfurt", "463"}, {"2351", "Wiener Neudorf", "2236"}},
		[]string{"Industriestraße", "Gewerbepark", "Wiener Straße", "Salzburger Straße", "Lastenstraße", "Hafenstraße",
			"Industriezeile", "Gewerbestraße", "Welser Straße"}, 0.10},
}

func wdCountryByCode(cc string) *wdCountry {
	for i := range wdCountries {
		if wdCountries[i].Code == cc {
			return &wdCountries[i]
		}
	}
	return &wdCountries[1]
}

var wdDial = map[string]string{"CH": "41", "DE": "49", "IT": "39", "NL": "31", "PL": "48", "AT": "43"}

func (r wdRand) phone(cc, area string) string {
	p := "+" + wdDial[cc] + " " + area + " "
	switch cc {
	case "CH", "PL":
		return p + strconv.Itoa(r.between(2, 9)) + r.digits(2) + " " + r.digits(2) + " " + r.digits(2)
	case "NL":
		return p + strconv.Itoa(r.between(2, 8)) + r.digits(2) + " " + r.digits(4)
	case "AT":
		return p + strconv.Itoa(r.between(2, 9)) + r.digits(max(4, 8-len(area)))
	default: // DE, IT
		n := 10 - len(area)
		if cc == "DE" {
			n = 11 - len(area)
		}
		return p + strconv.Itoa(r.between(2, 9)) + r.digits(n-1)
	}
}

func (r wdRand) mobile(cc string) string {
	switch cc {
	case "CH":
		return "+41 " + wdOne(r, []string{"76", "77", "78", "79"}) + " " + r.digits(3) + " " + r.digits(2) + " " + r.digits(2)
	case "DE":
		return "+49 " + wdOne(r, []string{"151", "152", "160", "170", "171", "172", "175", "176"}) + " " + strconv.Itoa(r.between(1, 9)) + r.digits(7)
	case "PL":
		return "+48 " + wdOne(r, []string{"501", "502", "600", "601", "691", "721", "781"}) + " " + r.digits(3) + " " + r.digits(3)
	case "IT":
		return "+39 " + wdOne(r, []string{"333", "335", "340", "347", "348"}) + " " + r.digits(3) + " " + r.digits(4)
	case "AT":
		return "+43 " + wdOne(r, []string{"664", "676", "699", "650"}) + " " + r.digits(7)
	}
	return "+31 6 " + r.digits(8)
}

func (r wdRand) address(c *wdCountry) (street, postal string, city wdCity) {
	city = wdOne(r, c.Cities)
	st := wdOne(r, c.Streets)
	no := strconv.Itoa(r.between(1, 90))
	if r.chance(0.1) && c.Code != "IT" {
		no += string("abc"[r.IntN(3)])
	}
	switch c.Code {
	case "IT":
		street = st + ", " + no
	default:
		street = st + " " + no
	}
	postal = city.Postal
	if c.Code == "NL" {
		postal += " " + r.str("ABCEGHJKLMNPRTVWXZ", 2)
	}
	return
}

// industries and their typical goods
const (
	indMachinery = iota
	indPharma
	indTextile
	indPlastics
	indElectronics
	indFurniture
	indFood
	indAgri
	indWine
	indChemicals
	indPrecision
)

type wdGoods struct {
	Desc, HS string
	PerKg    float64 // declared value per kg
}

type wdIndustry struct {
	DE, IT, NL, PL string
	Goods          []wdGoods
}

var wdIndustries = []wdIndustry{
	indMachinery: {"Maschinenbau", "Meccanica", "Machinebouw", "Maszyny", []wdGoods{{"Maschinenteile, palettiert", "84879090", 28},
		{"Hydraulikzylinder", "84122180", 35}, {"Getriebe und Wälzlager", "84834023", 42}, {"Werkzeugmaschine, demontiert in Kisten", "84581120", 55}}},
	indPharma: {"Pharma", "Farmaceutici", "Farma", "Farmacja", []wdGoods{{"Arzneimittel, temperaturgeführt 2-8 °C", "30049000", 210},
		{"Wirkstoffe (API), kein Gefahrgut", "29420000", 160}, {"Medizinprodukte, steril verpackt", "90189084", 120}}},
	indTextile: {"Textil", "Tessile", "Textiel", "Tekstylia", []wdGoods{{"Herrenanzüge aus Wolle", "62031100", 60},
		{"Baumwollgewebe auf Rollen", "52083100", 14}, {"Damenblusen aus Seide", "62064000", 85}}},
	indPlastics: {"Kunststofftechnik", "Plastica", "Kunststoffen", "Tworzywa", []wdGoods{{"Polyethylen-Granulat in Big Bags", "39011010", 2.1},
		{"Kunststoffprofile", "39162000", 6}, {"Spritzgussteile aus Polyamid", "39269097", 11}}},
	indElectronics: {"Elektrotechnik", "Elettronica", "Elektronica", "Elektronika", []wdGoods{{"Elektronische Steuergeräte", "85371098", 95},
		{"Leiterplatten, bestückt", "85340011", 140}, {"Schaltschränke, verkabelt", "85371091", 38}}},
	indFurniture: {"Möbelwerke", "Arredamenti", "Meubelen", "Meble", []wdGoods{{"Büromöbel, zerlegt", "94033011", 9},
		{"Polstersessel", "94016100", 16}, {"Küchenmöbel, montagefertig", "94034090", 11}}},
	indFood: {"Lebensmittel", "Alimentari", "Voeding", "Żywność", []wdGoods{{"Tiefkühlbackwaren -18 °C", "19059080", 4.5},
		{"Hartkäse in Laiben", "04069021", 19}, {"Schokolade und Pralinen", "18063100", 14}, {"Teigwaren, getrocknet", "19021990", 2.8}}},
	indAgri: {"Agrartechnik", "Agricola", "Agro", "Agro", []wdGoods{{"Ersatzteile Landmaschinen", "84339000", 24},
		{"Saatgut in Säcken", "12099180", 7}, {"Bewässerungstechnik", "84248210", 18}}},
	indWine: {"Weinkellerei", "Vini", "Wijnimport", "Napoje", []wdGoods{{"Wein in Flaschen, palettiert", "22042109", 11},
		{"Spirituosen", "22083071", 26}, {"Olivenöl extra vergine", "15092000", 8}}},
	indChemicals: {"Chemie", "Chimica", "Chemie", "Chemia", []wdGoods{{"Industriechemikalien, kein Gefahrgut", "38249996", 4},
		{"Lacke und Farben (UN 1263)", "32081090", 7}, {"Klebstoffe in IBC", "35069190", 6}}},
	indPrecision: {"Präzisionsteile", "Meccanica di Precisione", "Precisietechniek", "Metal", []wdGoods{{"Präzisionsdrehteile", "73181595", 70},
		{"Uhrenbestandteile", "91149000", 900}, {"Messinstrumente", "90318038", 260}}},
}

// relative frequency of the industries among the shippers
var wdIndustryWeights = []float64{indMachinery: 3, indPharma: 1.1, indTextile: 1, indPlastics: 1.5, indElectronics: 1.6,
	indFurniture: 1, indFood: 1.6, indAgri: 0.9, indWine: 0.8, indChemicals: 1.2, indPrecision: 1.6}

// ---------- context ----------

type wdCustomer struct {
	ID                                     int64
	No, SAP, Name, Legal, Country, Street  string
	Postal, City, Phone, Contact, Email    string
	InvoiceEmail, VAT, IBAN, BIC, Currency string
	Domain, Notes                          string
	Industry, Terms                        int
	Credit, Weight                         float64
	Manager                                int64
	Created, Updated, Deleted              time.Time
	RefStyle                               int
}

func (cu *wdCustomer) alive(t time.Time) bool {
	return cu.Created.Before(t) && (cu.Deleted.IsZero() || t.Before(cu.Deleted))
}

type wdWarehouse struct {
	ID                                                 int64
	Code, Name, Street, Postal, City, Country, Manager string
	Phone, Hours                                       string
	Capacity                                           int
	Temp, Bonded                                       bool
}

type wdDriver struct {
	ID                                        int64
	EmpNo, First, Last, Phone, Email, Licence string
	LicCountry, Classes, Plate, Status        string
	LicExpires, CPC, Hired                    time.Time
	ADR                                       bool
	Home                                      int64
	Created, Updated                          time.Time
}

type wdEvent struct {
	Status, Location, Hub, Desc, Source string
	At                                  time.Time
}

type wdShipment struct {
	ID                                                  int64
	Tracking, Ref, Status, Mode, Incoterm               string
	OCountry, OCity, DCountry, DCity, Consignee         string
	Goods, HS, Container, AWB, Plate, Customs, Currency string
	Pieces                                              int
	Weight, Volume, Value                               float64
	DG                                                  bool
	Cust                                                *wdCustomer
	Driver                                              *wdDriver
	WH                                                  *wdWarehouse
	Created, Pickup, ETA, Delivered, Updated            time.Time
	CreatedBy                                           int64
	Events                                              []wdEvent
}

type wdInvoice struct {
	ID                                 int64
	No, SAP, Currency, Status, PDF     string
	Cust                               *wdCustomer
	Ship                               *wdShipment
	Issue, Due, Paid, Created, Updated time.Time
	Net, Rate, VAT, Total              float64
	Reminder                           int
}

type wdAudit struct {
	UserID                 int64
	Action, Type, Old, New string
	Auditable              int64
	IP, UA                 string
	At                     time.Time
}

type wdCtx struct {
	w                  *World
	now, start, goLive time.Time
	customers          []*wdCustomer
	custByID           map[int64]*wdCustomer
	staff, admins      []int64
	userCreated        map[int]time.Time
	userIP             map[int]string
	userUA             map[int]int
	warehouses         []*wdWarehouse
	drivers            []*wdDriver
	shipments          []*wdShipment
	invoices           []*wdInvoice
	audit              []wdAudit
}

func buildDatabases(w *World) []Database {
	now := w.Created.UTC()
	if now.IsZero() {
		now = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	start := time.Date(now.Year()-4, now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	c := &wdCtx{w: w, now: now, start: start, custByID: map[int64]*wdCustomer{}}
	c.goLive = start.AddDate(0, 0, 2).Add(5*time.Hour + 12*time.Minute)
	for _, u := range w.AppUsers {
		switch u.Role {
		case "staff":
			c.staff = append(c.staff, int64(u.ID))
		case "admin":
			c.admins = append(c.admins, int64(u.ID))
		}
	}
	c.genCustomers()
	c.genUserMeta()
	c.genWarehouses()
	c.genDrivers()
	c.genShipments()
	c.genInvoices()
	c.genAudit()
	return []Database{c.connectDB(), c.wpDB(), c.mysqlDB()}
}

// trackingSamples returns n tracking numbers of existing in-transit or delivered shipments.
func trackingSamples(w *World, n int) []string {
	dbs := w.dbs
	if dbs == nil {
		dbs = buildDatabases(w)
	}
	var transit, delivered []string
	for _, db := range dbs {
		if db.Name != worldAppDB {
			continue
		}
		for _, t := range db.Tables {
			if t.Name != "shipments" {
				continue
			}
			ti, si := -1, -1
			for i, col := range t.Columns {
				switch col.Name {
				case "tracking_no":
					ti = i
				case "status":
					si = i
				}
			}
			for i := len(t.Rows) - 1; i >= 0; i-- { // newest first
				row := t.Rows[i]
				switch row[si] {
				case "in_transit":
					transit = append(transit, row[ti].(string))
				case "delivered":
					if len(delivered) < 40 {
						delivered = append(delivered, row[ti].(string))
					}
				}
			}
		}
	}
	r := newWDRand(w, 99)
	r.Shuffle(len(delivered), func(i, j int) { delivered[i], delivered[j] = delivered[j], delivered[i] })
	var out []string
	for i := 0; len(out) < n && (i < len(transit) || i < len(delivered)); i++ {
		if i < len(transit) && len(out) < n {
			out = append(out, transit[i])
		}
		if i < len(delivered) && len(out) < n {
			out = append(out, delivered[i])
		}
	}
	return out
}

func (c *wdCtx) capNow(r wdRand, t time.Time) time.Time {
	if t.After(c.now.Add(-5 * time.Minute)) {
		return c.now.Add(-r.dur(10*time.Minute, 3*time.Hour))
	}
	return t
}

// ---------- customers ----------

type wdKnown struct {
	Name, Legal string
	Industry    int
}

var wdKnownCustomers = map[string]wdKnown{
	"alpenfrost":          {"Alpenfrost AG", "AG", indFood},
	"rossi-import":        {"Rossi Import S.r.l.", "S.r.l.", indWine},
	"wagner-maschinenbau": {"Wagner Maschinenbau GmbH", "GmbH", indMachinery},
	"novak-trade":         {"Novak Trade Sp. z o.o.", "Sp. z o.o.", indElectronics},
	"devries-agro":        {"De Vries Agro B.V.", "B.V.", indAgri},
	"huber-pharma":        {"Huber Pharma AG", "AG", indPharma},
	"baumann-moebel":      {"Baumann Möbel GmbH", "GmbH", indFurniture},
	"ferri-tessile":       {"Ferri Tessile S.p.A.", "S.p.A.", indTextile},
}

func wdCountryOfTLD(tld string) string {
	for _, c := range wdCountries {
		if c.TLD == tld {
			return c.Code
		}
	}
	return "DE"
}

func (r wdRand) company(cc string, ind int) (name, legal, domain string) {
	lang := wdLang(cc)
	sur := wdOne(r, wdSurnames[lang])
	in := wdIndustries[ind]
	switch cc {
	case "CH":
		legal = wdOne(r, []string{"AG", "AG", "AG", "GmbH"})
		name = sur + " " + in.DE + " " + legal
		domain = wdFold(sur) + "-" + wdFold(in.DE)
	case "DE":
		legal = wdOne(r, []string{"GmbH", "GmbH", "GmbH & Co. KG", "AG"})
		name = sur + " " + in.DE + " " + legal
		domain = wdFold(sur) + "-" + wdFold(in.DE)
	case "AT":
		legal = wdOne(r, []string{"GmbH", "GmbH", "Ges.m.b.H.", "AG"})
		name = sur + " " + in.DE + " " + legal
		domain = wdFold(sur) + "-" + wdFold(in.DE)
	case "IT":
		legal = wdOne(r, []string{"S.r.l.", "S.r.l.", "S.p.A."})
		w := strings.Fields(in.IT)[0]
		if r.IntN(2) == 0 {
			name = in.IT + " " + sur + " " + legal
			domain = wdFold(w) + wdFold(sur)
		} else {
			name = sur + " " + in.IT + " " + legal
			domain = wdFold(sur) + "-" + wdFold(w)
		}
	case "NL":
		legal = "B.V."
		name = wdUpperFirst(sur) + " " + in.NL + " B.V."
		domain = wdFold(sur) + "-" + wdFold(in.NL)
	case "PL":
		legal = "Sp. z o.o."
		if r.IntN(2) == 0 {
			name = in.PL + " " + sur + " Sp. z o.o."
		} else {
			name = sur + " " + in.PL + " Sp. z o.o."
		}
		domain = wdFold(sur) + "-" + wdFold(in.PL)
	}
	return name, legal, domain + "." + wdCountryByCode(cc).TLD
}

func (c *wdCtx) genCustomers() {
	r := newWDRand(c.w, 1)
	special := map[int64]AppUser{}
	used := map[string]bool{}
	for _, u := range c.w.AppUsers {
		if u.Role == "customer" && u.CustomerID >= 100 && u.CustomerID < 160 {
			special[int64(u.CustomerID)] = u
			_, d, _ := strings.Cut(u.Email, "@")
			used[d] = true
		}
	}
	const n = 60
	times := make([]time.Time, n)
	later := make([]time.Time, 0, n)
	for i := 0; i < n; i++ {
		if i < 28 {
			times[i] = c.goLive.Add(time.Duration(i*2+r.IntN(2)) * time.Second)
		} else {
			later = append(later, r.work(r.timeIn(c.start.AddDate(0, 0, 30), c.now.AddDate(0, 0, -75))))
		}
	}
	sort.Slice(later, func(i, j int) bool { return later[i].Before(later[j]) })
	copy(times[28:], later)

	weights := make([]float64, len(wdCountries))
	for i, cn := range wdCountries {
		weights[i] = cn.Weight
	}
	termsBy := map[string][]int{"IT": {60, 60, 90, 30}, "PL": {30, 45, 14}, "default": {30, 30, 30, 45, 60, 20, 10}}
	deleted := map[int64]bool{int64(100 + 9 + r.IntN(8)): true, int64(100 + 19 + r.IntN(8)): true}

	for i := 0; i < n; i++ {
		id := int64(100 + i)
		cu := &wdCustomer{ID: id, Created: times[i], RefStyle: r.IntN(4)}
		var cn *wdCountry
		if u, ok := special[id]; ok {
			_, domain, _ := strings.Cut(u.Email, "@")
			label, tld, _ := strings.Cut(domain, ".")
			cn = wdCountryByCode(wdCountryOfTLD(tld))
			if k, ok := wdKnownCustomers[label]; ok {
				cu.Name, cu.Legal, cu.Industry = k.Name, k.Legal, k.Industry
			} else {
				parts := strings.Split(label, "-")
				for j := range parts {
					parts[j] = wdUpperFirst(parts[j])
				}
				cu.Legal = map[string]string{"CH": "AG", "IT": "S.r.l.", "NL": "B.V.", "PL": "Sp. z o.o."}[cn.Code]
				if cu.Legal == "" {
					cu.Legal = "GmbH"
				}
				cu.Name = strings.Join(parts, " ") + " " + cu.Legal
				cu.Industry = indMachinery
			}
			cu.Domain = domain
			cu.Contact, cu.Email = u.Name, u.Email
			cu.Weight = 2.2 + r.Float64()*2
		} else {
			cn = &wdCountries[wdWeighted(r, weights)]
			cu.Industry = wdWeighted(r, wdIndustryWeights)
			for {
				cu.Name, cu.Legal, cu.Domain = r.company(cn.Code, cu.Industry)
				if !used[cu.Domain] {
					used[cu.Domain] = true
					break
				}
			}
			first, last := r.person(cn.Code)
			cu.Contact = first + " " + last
			if r.IntN(3) == 0 {
				cu.Email = wdFold(first)[:1] + "." + wdFold(last) + "@" + cu.Domain
			} else {
				cu.Email = wdFold(first) + "." + wdFold(last) + "@" + cu.Domain
			}
			cu.Weight = 0.25 + r.ExpFloat64()
		}
		var city wdCity
		cu.Street, cu.Postal, city = r.address(cn)
		cu.City, cu.Country, cu.Currency = city.City, cn.Code, cn.Currency
		cu.Phone = r.phone(cn.Code, city.Area)
		cu.InvoiceEmail = wdOne(r, map[string][]string{
			"de": {"buchhaltung", "kreditoren", "rechnungen", "finanzen"}, "it": {"amministrazione", "contabilita", "fatture"},
			"nl": {"crediteuren", "administratie", "facturen"}, "pl": {"ksiegowosc", "faktury"}}[wdLang(cn.Code)]) + "@" + cu.Domain
		cu.VAT = r.vatID(cn.Code, cu.City)
		cu.IBAN, cu.BIC = r.iban(cn.Code)
		cu.No = fmt.Sprintf("K-%d", 20000+i*13+r.IntN(12))
		cu.SAP = fmt.Sprintf("%010d", 300100+i*7+r.IntN(6))
		terms := termsBy[cn.Code]
		if terms == nil {
			terms = termsBy["default"]
		}
		cu.Terms = wdOne(r, terms)
		cu.Credit = float64(wdOne(r, []int{25000, 50000, 50000, 75000, 100000, 100000, 150000, 250000, 500000}))
		switch {
		case len(c.staff) > 0:
			cu.Manager = wdOne(r, c.staff)
		case len(c.admins) > 0:
			cu.Manager = wdOne(r, c.admins)
		}
		if r.chance(0.25) {
			cu.Notes = wdOne(r, []string{"Avisierung 24h vor Anlieferung erforderlich (Rampe 3).",
				"Anlieferung nur Mo-Fr 07:00-15:30, keine Zustellung samstags.", "Zollvollmacht liegt vor (gültig bis auf Widerruf).",
				"Rechnungsversand ausschliesslich per E-Mail an die Kreditorenabteilung.", "Rahmenvertrag Seefracht Asien, Raten siehe SAP.",
				"Palettentausch Euro-Paletten vereinbart.", "Bonität geprüft, Kreditlimit durch CFO freigegeben.",
				"Hebebühne erforderlich, keine Rampe vorhanden.", "Ansprechpartner Disposition wechselt, siehe CRM."})
			if cu.Industry == indPharma {
				cu.Notes = "GDP-Kunde: Kühlkette 2-8 °C, Temperaturlogger bei jeder Sendung beilegen."
			}
		}
		cu.Updated = r.work(r.timeIn(cu.Created, c.now.AddDate(0, 0, -3)))
		if _, isSpecial := special[id]; deleted[id] && !isSpecial {
			cu.Deleted = r.work(r.timeIn(c.start.AddDate(0, 0, 400), c.start.AddDate(0, 0, 900)))
			cu.Updated = cu.Deleted
		}
		c.customers = append(c.customers, cu)
		c.custByID[id] = cu
	}
}

// user creation times, usual IPs and browsers of the portal users
var wdPublicPrefixes = map[string][]string{
	"CH": {"85.2", "178.197", "213.55", "83.77", "62.202"}, "DE": {"87.123", "91.64", "217.229", "84.150", "93.199"},
	"IT": {"79.31", "93.40", "151.38", "87.18"}, "NL": {"145.53", "77.163", "84.104", "86.88"},
	"PL": {"83.24", "89.64", "31.183", "178.36"}, "AT": {"62.178", "84.112", "91.114", "213.162"},
}

func (c *wdCtx) genUserMeta() {
	r := newWDRand(c.w, 2)
	c.userCreated, c.userIP, c.userUA = map[int]time.Time{}, map[int]string{}, map[int]int{}
	prev := c.start.AddDate(0, 0, -21).Add(9 * time.Hour)
	for i, u := range c.w.AppUsers {
		var t time.Time
		if u.Role != "customer" {
			if i == 0 {
				t = prev
			} else {
				t = r.work(prev.AddDate(0, 0, r.between(0, 12)))
			}
			if r.IntN(3) == 0 {
				c.userIP[u.ID] = fmt.Sprintf("10.20.8.%d", r.between(20, 230)) // VPN
			} else {
				c.userIP[u.ID] = fmt.Sprintf("10.20.10.%d", r.between(30, 199)) // office Zug
			}
		} else {
			t = r.work(prev.AddDate(0, 0, r.between(8, 120)))
			if cu := c.custByID[int64(u.CustomerID)]; cu != nil {
				if lo := cu.Created.Add(26 * time.Hour); t.Before(lo) {
					t = r.work(lo)
				}
				pre := wdPublicPrefixes[cu.Country]
				if pre == nil {
					pre = wdPublicPrefixes["DE"]
				}
				c.userIP[u.ID] = fmt.Sprintf("%s.%d.%d", wdOne(r, pre), r.between(1, 254), r.between(2, 253))
			}
		}
		if lim := c.now.AddDate(0, 0, -(len(c.w.AppUsers)-i)*3); t.After(lim) {
			t = lim
		}
		if t.Before(prev) {
			t = prev.Add(r.dur(time.Hour, 48*time.Hour))
		}
		c.userCreated[u.ID] = t
		c.userUA[u.ID] = r.IntN(len(wdUAFamilies))
		prev = t
	}
}

// ---------- warehouses & drivers ----------

func (c *wdCtx) genWarehouses() {
	r := newWDRand(c.w, 3)
	type wh struct {
		code, name, street, postal, city, cc, area, hours string
		cap                                               int
		temp, bonded                                      bool
	}
	list := []wh{
		{"ZRH1", "Hub Zürich Rümlang", "Hofwisenstrasse 50", "8153", "Rümlang", "CH", "44", "Mo-Fr 05:30-22:00, Sa 06:00-12:00", 6400, true, true},
		{"BSL1", "Rheinhafen Basel Kleinhüningen", "Westquaistrasse 24", "4057", "Basel", "CH", "61", "Mo-Fr 06:00-20:00", 9800, false, true},
		{"FRA1", "Frankfurt Cargo City Süd", "Cargo City Süd, Gebäude 558", "60549", "Frankfurt am Main", "DE", "69", "24/7", 5200, true, true},
		{"MXP1", "Milano Peschiera Borromeo", "Via Fratelli Bandiera 9", "20068", "Peschiera Borromeo", "IT", "02", "Lun-Ven 06:00-19:00", 4100, false, false},
		{"RTM1", "Rotterdam Waalhaven", "Waalhaven Oostzijde 81", "3087 BM", "Rotterdam", "NL", "10", "Ma-Vr 06:00-22:00", 12000, true, true},
		{"WAW1", "Warszawa Okęcie", "ul. Poleczki 35", "02-822", "Warszawa", "PL", "22", "Pn-Pt 06:00-20:00", 3800, false, false},
	}
	for i, x := range list {
		first, last := r.person(x.cc)
		c.warehouses = append(c.warehouses, &wdWarehouse{ID: int64(i + 1), Code: x.code, Name: x.name, Street: x.street,
			Postal: x.postal, City: x.city, Country: x.cc, Manager: first + " " + last, Phone: r.phone(x.cc, x.area),
			Hours: x.hours, Capacity: x.cap, Temp: x.temp, Bonded: x.bonded})
	}
}

func (c *wdCtx) whByCode(code string) *wdWarehouse {
	for _, w := range c.warehouses {
		if w.Code == code {
			return w
		}
	}
	return nil
}

// hub returns the warehouse handling goods of a country (nil for overseas).
func (c *wdCtx) hub(cc, mode string) *wdWarehouse {
	switch cc {
	case "CH":
		if mode == "sea" || mode == "rail" {
			return c.whByCode("BSL1")
		}
		return c.whByCode("ZRH1")
	case "DE", "AT", "FR":
		return c.whByCode("FRA1")
	case "IT", "ES":
		return c.whByCode("MXP1")
	case "NL", "BE", "DK", "SE":
		return c.whByCode("RTM1")
	case "PL", "CZ":
		return c.whByCode("WAW1")
	}
	return nil
}

func (r wdRand) deLicence() string {
	s := string(rune('A'+r.IntN(26))) + r.digits(3) + r.str("ABCDEFGHJKLMNPRSTUVWXYZ0123456789", 5)
	sum := 0
	for i := 0; i < 9; i++ {
		v := 0
		if s[i] >= '0' && s[i] <= '9' {
			v = int(s[i] - '0')
		} else {
			v = int(s[i]-'A') + 10
		}
		sum += v * (9 - i)
	}
	chk := "X"
	if sum%11 < 10 {
		chk = strconv.Itoa(sum % 11)
	}
	return s + chk + strconv.Itoa(r.between(1, 3))
}

func (c *wdCtx) genDrivers() {
	r := newWDRand(c.w, 4)
	plan := []string{}
	for _, x := range []struct {
		cc string
		n  int
	}{{"CH", 11}, {"DE", 7}, {"PL", 5}, {"IT", 2}} {
		for i := 0; i < x.n; i++ {
			plan = append(plan, x.cc)
		}
	}
	r.Shuffle(len(plan), func(i, j int) { plan[i], plan[j] = plan[j], plan[i] })
	created := make([]time.Time, len(plan))
	hired := make([]time.Time, len(plan))
	for i := range plan {
		if i < 14 {
			created[i] = c.goLive.Add(time.Duration(40+i) * time.Minute)
			hired[i] = c.start.AddDate(0, 0, -r.between(60, 3600))
		} else {
			hired[i] = r.work(r.timeIn(c.start.AddDate(0, 0, 20), c.now.AddDate(0, 0, -45)))
		}
	}
	sort.Slice(hired[14:], func(i, j int) bool { return hired[14+i].Before(hired[14+j]) })
	usedPlate := map[string]bool{}
	for i, cc := range plan {
		d := &wdDriver{ID: int64(i + 1), LicCountry: cc, Hired: hired[i], Status: "active"}
		if i >= 14 {
			created[i] = r.work(hired[i].AddDate(0, 0, -r.between(1, 10)))
			if created[i].Before(created[i-1]) {
				created[i] = created[i-1].Add(r.dur(time.Hour, 72*time.Hour))
			}
		}
		d.Created = created[i]
		d.First, d.Last = r.person(cc)
		d.EmpNo = fmt.Sprintf("P%05d", 10200+r.IntN(7800))
		d.Phone = r.mobile(cc)
		if cc == "CH" && r.chance(0.4) {
			d.Email = wdFold(d.First) + "." + wdFold(d.Last) + "@" + worldDomain
		}
		for {
			switch cc {
			case "CH":
				d.Licence = r.digits(9) + "001"
				d.Plate = "ZG " + strconv.Itoa(r.between(10000, 199999))
				d.Home = wdOne(r, []int64{1, 1, 2})
			case "DE":
				d.Licence = r.deLicence()
				d.Plate = "F-VL " + strconv.Itoa(r.between(100, 9999))
				d.Home = 3
			case "PL":
				d.Licence = fmt.Sprintf("%05d/%02d/%04d", r.IntN(100000), r.between(5, 22), r.between(1001, 1465))
				d.Plate = "WE " + r.digits(1) + string(rune('A'+r.IntN(26))) + r.digits(3)
				d.Home = 6
			case "IT":
				d.Licence = "U1" + r.str("ABCDEFGHJKLMNPRSTUVWXYZ0123456789", 7) + string(rune('A'+r.IntN(26)))
				d.Plate = r.str("ABCDEFGHJKLMNPRSTVWXYZ", 2) + " " + r.digits(3) + " " + r.str("ABCDEFGHJKLMNPRSTVWXYZ", 2)
				d.Home = 4
			}
			if !usedPlate[d.Plate] {
				usedPlate[d.Plate] = true
				break
			}
		}
		d.Classes = wdOne(r, []string{"C, CE", "C, CE", "C, CE, D1", "C1, C1E", "B, C, CE"})
		d.ADR = r.chance(0.4)
		day := time.Date(c.now.Year(), c.now.Month(), c.now.Day(), 0, 0, 0, 0, time.UTC)
		d.LicExpires = day.AddDate(0, 0, r.between(200, 3600))
		d.CPC = day.AddDate(0, 0, r.between(25, 1800))
		d.Updated = c.capNow(r, r.work(r.timeIn(d.Created, c.now.AddDate(0, 0, -2))))
		c.drivers = append(c.drivers, d)
	}
	for _, i := range r.Perm(len(c.drivers))[:4] {
		if i < 2 {
			c.drivers[i].Status = "inactive"
		} else {
			c.drivers[i].Status = "on_leave"
		}
	}
}

// ---------- shipments ----------

type wdPlace struct{ City, CC string }

var (
	wdEuroCities = []wdPlace{{"Zürich", "CH"}, {"Basel", "CH"}, {"Bern", "CH"}, {"Lausanne", "CH"}, {"Genève", "CH"}, {"Lugano", "CH"},
		{"St. Gallen", "CH"}, {"München", "DE"}, {"Stuttgart", "DE"}, {"Frankfurt am Main", "DE"}, {"Hamburg", "DE"}, {"Duisburg", "DE"},
		{"Berlin", "DE"}, {"Milano", "IT"}, {"Torino", "IT"}, {"Verona", "IT"}, {"Bologna", "IT"}, {"Rotterdam", "NL"}, {"Venlo", "NL"},
		{"Amsterdam", "NL"}, {"Warszawa", "PL"}, {"Poznań", "PL"}, {"Wrocław", "PL"}, {"Wien", "AT"}, {"Linz", "AT"}, {"Graz", "AT"},
		{"Lyon", "FR"}, {"Paris", "FR"}, {"Strasbourg", "FR"}, {"Antwerpen", "BE"}, {"Bruxelles", "BE"}, {"Praha", "CZ"}, {"Brno", "CZ"},
		{"Barcelona", "ES"}, {"Madrid", "ES"}, {"Aarhus", "DK"}, {"Göteborg", "SE"}}
	wdSeaPorts = []wdPlace{{"Shanghai", "CN"}, {"Ningbo", "CN"}, {"Shenzhen", "CN"}, {"Qingdao", "CN"}, {"Singapore", "SG"},
		{"Busan", "KR"}, {"Nhava Sheva", "IN"}, {"Jebel Ali", "AE"}, {"New York", "US"}, {"Savannah", "US"}, {"Houston", "US"},
		{"Santos", "BR"}, {"Montreal", "CA"}, {"Yokohama", "JP"}, {"Hong Kong", "HK"}}
	wdAirports = []wdPlace{{"Chicago", "US"}, {"New York", "US"}, {"Atlanta", "US"}, {"Dubai", "AE"}, {"Singapore", "SG"},
		{"Hong Kong", "HK"}, {"Shanghai", "CN"}, {"Tokyo", "JP"}, {"Mumbai", "IN"}, {"São Paulo", "BR"}, {"Toronto", "CA"}, {"Seoul", "KR"}}
	wdRailChina = []wdPlace{{"Xi'an", "CN"}, {"Chongqing", "CN"}, {"Chengdu", "CN"}}
	wdEU        = map[string]bool{"DE": true, "IT": true, "NL": true, "PL": true, "AT": true, "FR": true, "BE": true, "CZ": true,
		"ES": true, "DK": true, "SE": true}
	wdForeignConsignees = map[string][]string{
		"FR": {"Transmeca Lyon SAS", "Groupe Bréval Distribution SA", "Atelier Morvan Industrie SARL"},
		"BE": {"Van Hecke Logistics NV", "Delcour Industrie SA"}, "CZ": {"Strojírny Vysočina s.r.o.", "Novotný Elektro a.s."},
		"ES": {"Industrias Garrido S.L.", "Distribuciones Ebro S.A."}, "DK": {"Nørgaard Maskinfabrik A/S", "Holm & Søn ApS"},
		"SE": {"Lindqvist Verkstad AB", "Bergström Livsmedel AB"},
		"CN": {"Ningbo Haitong Machinery Co., Ltd.", "Shanghai Jinqiao Precision Co., Ltd.", "Shenzhen Hualong Electronics Co., Ltd."},
		"SG": {"Tanjong Ridge Trading Pte. Ltd.", "Straits Medical Supplies Pte. Ltd."},
		"KR": {"Hanbit Precision Co., Ltd.", "Daesung Industrial Co., Ltd."},
		"IN": {"Shree Ganesh Engineering Pvt. Ltd.", "Mehta Pharma Distributors Pvt. Ltd."},
		"AE": {"Al Noor Trading LLC", "Gulf Crest Industrial Supplies FZE"},
		"US": {"Great Lakes Industrial Supply Inc.", "Brennan Medical Distribution LLC", "Harbor Point Foods Inc."},
		"BR": {"Comercial Paulista de Máquinas Ltda.", "Agro Cerrado Insumos Ltda."},
		"CA": {"Northshore Equipment Ltd.", "Laurentian Specialty Foods Inc."},
		"JP": {"Kaneda Precision Co., Ltd.", "Tokai Medical Trading K.K."},
		"HK": {"Victoria Harbour Trading Ltd.", "Kowloon Precision Parts Ltd."},
	}
	wdAirportCode = map[string]string{"CH": "ZRH", "DE": "FRA", "IT": "MXP", "NL": "AMS", "PL": "WAW", "AT": "VIE"}
	wdAirportCity = map[string]string{"ZRH": "Zürich Flughafen", "FRA": "Frankfurt am Main", "MXP": "Milano Malpensa",
		"AMS": "Amsterdam Schiphol", "WAW": "Warszawa", "VIE": "Wien-Schwechat"}
)

func (c *wdCtx) consignee(r wdRand, cc string) string {
	if names := wdForeignConsignees[cc]; names != nil {
		return wdOne(r, names)
	}
	name, _, _ := r.company(cc, r.IntN(len(wdIndustries)))
	return name
}

func wdLoc(city, cc string) string { return city + ", " + cc }

func (c *wdCtx) genShipments() {
	r := newWDRand(c.w, 5)
	const n = 250
	created := make([]time.Time, n)
	span := c.now.Sub(c.start.AddDate(0, 0, 4)).Hours() / 24
	for i := range created {
		var age float64
		if i < n-26 {
			age = 13 + (span-13)*math.Pow(r.Float64(), 1.35)
		} else {
			age = r.Float64() * 13
		}
		t := r.work(c.now.Add(-time.Duration(age * 24 * float64(time.Hour))))
		created[i] = c.capNow(r, t)
	}
	sort.Slice(created, func(i, j int) bool { return created[i].Before(created[j]) })

	portalUser := map[int64][]AppUser{}
	for _, u := range c.w.AppUsers {
		if u.Role == "customer" {
			portalUser[int64(u.CustomerID)] = append(portalUser[int64(u.CustomerID)], u)
		}
	}
	staffAll := append(append([]int64{}, c.staff...), c.admins...)
	usedTN := map[string]bool{}
	id := int64(0)
	for _, t0 := range created {
		id++
		if r.chance(0.04) {
			id += int64(r.between(1, 3)) // deleted test bookings
		}
		s := &wdShipment{ID: id, Created: t0}
		cu := c.pickCustomer(r, t0)
		s.Cust, s.Currency = cu, cu.Currency
		for {
			body := fmt.Sprintf("%d%08d", r.between(1, 9), r.IntN(100000000))
			s.Tracking = "VLT" + body + strconv.Itoa(wdLuhnDigit(body))
			if !usedTN[s.Tracking] {
				usedTN[s.Tracking] = true
				break
			}
		}
		switch cu.RefStyle {
		case 0:
			s.Ref = "4500" + r.digits(6)
		case 1:
			s.Ref = "PO-" + strconv.Itoa(t0.Year()) + "-" + r.digits(5)
		case 2:
			s.Ref = "AUF" + r.digits(7)
		default:
			s.Ref = ""
			if r.chance(0.6) {
				s.Ref = "BE " + r.digits(6)
			}
		}
		s.Mode = []string{"road", "sea", "air", "rail"}[wdWeighted(r, []float64{0.55, 0.2, 0.12, 0.13})]
		home := wdPlace{cu.City, cu.Country}
		export := r.chance(0.7)
		var far wdPlace
		var transit int
		switch s.Mode {
		case "road":
			for far = wdOne(r, wdEuroCities); far.City == home.City; far = wdOne(r, wdEuroCities) {
			}
			transit = r.between(1, 4)
		case "sea":
			far = wdOne(r, wdSeaPorts)
			transit = r.between(24, 42)
		case "air":
			far = wdOne(r, wdAirports)
			transit = r.between(2, 5)
		case "rail":
			if r.chance(0.25) {
				far = wdOne(r, wdRailChina)
				transit = r.between(16, 23)
			} else {
				for far = wdOne(r, wdEuroCities); far.City == home.City; far = wdOne(r, wdEuroCities) {
				}
				transit = r.between(3, 7)
			}
		}
		if export {
			s.OCity, s.OCountry, s.DCity, s.DCountry = home.City, home.CC, far.City, far.CC
			s.Consignee = c.consignee(r, far.CC)
			s.WH = c.hub(home.CC, s.Mode)
		} else {
			s.OCity, s.OCountry, s.DCity, s.DCountry = far.City, far.CC, home.City, home.CC
			s.Consignee = cu.Name
			s.WH = c.hub(home.CC, s.Mode)
		}
		s.Incoterm = wdOne(r, map[string][]string{"road": {"DAP", "DAP", "DDP", "FCA", "EXW", "CPT"},
			"sea": {"FOB", "FOB", "CIF", "CFR", "FCA", "DAP"}, "air": {"FCA", "CPT", "CIP", "DAP", "EXW"},
			"rail": {"FCA", "DAP", "CPT"}}[s.Mode])
		g := wdOne(r, wdIndustries[cu.Industry].Goods)
		s.Goods, s.HS = g.Desc, g.HS
		s.DG = strings.Contains(g.Desc, "UN ") || (cu.Industry == indChemicals && r.chance(0.3))
		switch s.Mode {
		case "road":
			s.Pieces = r.between(1, 33)
			s.Weight = float64(s.Pieces) * (120 + r.Float64()*560)
			s.Volume = float64(s.Pieces) * (0.9 + r.Float64()*1.1)
		case "sea":
			s.Pieces = r.between(8, 40)
			s.Weight = 3800 + r.Float64()*20000
			s.Volume = wdOne(r, []float64{28, 33.2, 58, 67.7, 76.3})
			s.Container = r.container(wdOne(r, []string{"MSCU", "MAEU", "CMAU", "HLXU", "TGHU", "TCNU", "OOLU", "EGHU", "CSNU"}))
		case "air":
			s.Pieces = r.between(1, 12)
			s.Weight = float64(s.Pieces) * (6 + r.Float64()*140)
			s.Volume = s.Weight / (120 + r.Float64()*160)
			s.AWB = r.awb(wdOne(r, []string{"724", "724", "020", "176", "157", "618", "016"}))
		case "rail":
			s.Pieces = r.between(10, 36)
			s.Weight = 7500 + r.Float64()*16000
			s.Volume = wdOne(r, []float64{33.2, 67.7, 76.3})
			s.Container = r.container(wdOne(r, []string{"TGHU", "CAIU", "TCNU", "BMOU", "CSNU"}))
		}
		s.Weight, s.Volume = wdRound2(s.Weight), math.Round(s.Volume*1000)/1000
		s.Value = wdRound2(s.Weight * g.PerKg * (0.6 + r.Float64()*0.9))
		if s.OCountry != s.DCountry && (!wdEU[s.OCountry] || !wdEU[s.DCountry]) {
			cc := s.DCountry // declaration in the customer's country
			if export {
				cc = s.OCountry
			}
			s.Customs = r.mrn(t0.Year(), cc)
		}
		if s.Mode == "road" {
			var cand []*wdDriver
			for _, d := range c.drivers {
				if d.Hired.Before(t0) && d.Status != "inactive" {
					cand = append(cand, d)
				}
			}
			if len(cand) > 0 {
				s.Driver = wdOne(r, cand)
				s.Plate = s.Driver.Plate
			}
		}
		// who entered the booking
		s.CreatedBy = 0
		for _, u := range portalUser[cu.ID] {
			if c.userCreated[u.ID].Before(t0) && r.chance(0.65) {
				s.CreatedBy = int64(u.ID)
			}
		}
		if s.CreatedBy == 0 {
			if cu.Manager != 0 && r.chance(0.6) {
				s.CreatedBy = cu.Manager
			} else if len(staffAll) > 0 {
				s.CreatedBy = wdOne(r, staffAll)
			}
		}
		c.timeline(r, s, transit, export)
		c.shipments = append(c.shipments, s)
	}
}

func (c *wdCtx) pickCustomer(r wdRand, t time.Time) *wdCustomer {
	var tot float64
	for _, cu := range c.customers {
		if cu.alive(t) {
			tot += cu.Weight
		}
	}
	x := r.Float64() * tot
	var last *wdCustomer
	for _, cu := range c.customers {
		if cu.alive(t) {
			last = cu
			if x -= cu.Weight; x < 0 {
				return cu
			}
		}
	}
	if last == nil {
		return c.customers[0]
	}
	return last
}

// timeline plans the status events of a shipment and derives status, ETA and delivery from them.
func (c *wdCtx) timeline(r wdRand, s *wdShipment, transit int, export bool) {
	var ev []wdEvent
	add := func(at time.Time, status, loc, hub, desc, src string) time.Time {
		if n := len(ev); n > 0 && !at.After(ev[n-1].At) {
			at = ev[n-1].At.Add(r.dur(12*time.Minute, 95*time.Minute))
		}
		ev = append(ev, wdEvent{status, loc, hub, desc, src, at})
		return at
	}
	customs := func(at time.Time, loc string) time.Time {
		if s.Customs == "" {
			return at
		}
		if r.chance(0.3) {
			at = add(at, "customs_hold", loc, "", wdOne(r, []string{"Zollkontrolle: Unterlagen angefordert (Handelsrechnung)",
				"Zollbeschau angeordnet", "Zollanmeldung in Prüfung, MRN " + s.Customs,
				"Ursprungsnachweis fehlt, Rückfrage beim Versender"}), "customs")
			at = at.Add(r.dur(5*time.Hour, 52*time.Hour))
		}
		return add(at, "in_transit", loc, "", "Zollfreigabe erteilt (MRN "+s.Customs+")", "customs")
	}
	src := "sap"
	switch {
	case s.CreatedBy != 0 && c.isCustomerUser(s.CreatedBy):
		src = "portal"
	case r.chance(0.35):
		src = "edi"
	}
	origin, dest := wdLoc(s.OCity, s.OCountry), wdLoc(s.DCity, s.DCountry)
	add(s.Created, "booked", origin, "", "Sendung erfasst", src)
	pickup := r.work(s.Created.Add(r.dur(4*time.Hour, 60*time.Hour)))
	s.Pickup = pickup
	eta := time.Date(pickup.Year(), pickup.Month(), pickup.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, transit)
	switch eta.Weekday() {
	case time.Saturday:
		eta = eta.AddDate(0, 0, 2)
	case time.Sunday:
		eta = eta.AddDate(0, 0, 1)
	}
	s.ETA = eta

	if export {
		t := add(pickup, "picked_up", origin, "", "Sendung beim Versender abgeholt", "driver_app")
		if s.WH != nil {
			t = add(t.Add(r.dur(2*time.Hour, 9*time.Hour)), "in_transit", wdLoc(s.WH.City, s.WH.Country), s.WH.Code,
				"Eingang Umschlaglager "+s.WH.Name, "scanner")
		}
		t = customs(t.Add(r.dur(2*time.Hour, 8*time.Hour)), origin) // export declaration
		depart, hub := origin, ""
		if s.WH != nil {
			depart, hub = wdLoc(s.WH.City, s.WH.Country), s.WH.Code
		}
		switch s.Mode {
		case "road":
			add(t.Add(r.dur(2*time.Hour, 12*time.Hour)), "in_transit", depart, hub, "Abfahrt Richtung "+s.DCity, "driver_app")
		case "rail":
			add(t.Add(r.dur(6*time.Hour, 30*time.Hour)), "in_transit", depart, hub, "Container auf Zug verladen ("+s.Container+")", "carrier")
		case "sea":
			port, pcc := "Rotterdam", "NL"
			switch s.OCountry {
			case "IT":
				port, pcc = "Genova", "IT"
			case "DE", "PL":
				port, pcc = "Hamburg", "DE"
			}
			add(t.Add(r.dur(30*time.Hour, 96*time.Hour)), "in_transit", wdLoc(port, pcc), "", "Container verladen, Schiff ausgelaufen ("+s.Container+")", "carrier")
			add(eta.Add(-time.Duration(r.between(30, 60))*time.Hour), "in_transit", dest, "", "Ankunft Zielhafen "+s.DCity, "carrier")
		case "air":
			ap := wdAirportCode[s.OCountry]
			add(t.Add(r.dur(8*time.Hour, 30*time.Hour)), "in_transit", wdLoc(wdAirportCity[ap], s.OCountry), "", "Abflug ab "+ap+", AWB "+s.AWB, "carrier")
			add(eta.Add(-time.Duration(r.between(10, 22))*time.Hour), "in_transit", dest, "", "Ankunft Zielflughafen "+s.DCity, "carrier")
		}
	} else {
		var t time.Time
		switch s.Mode {
		case "sea":
			t = add(pickup, "picked_up", origin, "", "Container im Abgangshafen übernommen", "carrier")
			add(t.Add(r.dur(20*time.Hour, 80*time.Hour)), "in_transit", origin, "", "Container verladen, Schiff ausgelaufen ("+s.Container+")", "carrier")
			t = add(eta.Add(-time.Duration(r.between(100, 150))*time.Hour), "in_transit", "Rotterdam, NL", "", "Ankunft Hafen Rotterdam, Container entladen", "carrier")
		case "air":
			t = add(pickup, "picked_up", origin, "", "Sendung vom Agenten übernommen", "carrier")
			add(t.Add(r.dur(6*time.Hour, 20*time.Hour)), "in_transit", origin, "", "Abflug ab "+s.OCity+", AWB "+s.AWB, "carrier")
			ap := wdAirportCode[s.DCountry]
			t = add(eta.Add(-time.Duration(r.between(26, 40))*time.Hour), "in_transit", wdLoc(wdAirportCity[ap], s.DCountry), "", "Ankunft "+ap+", Übergabe Handling", "carrier")
		default:
			t = add(pickup, "picked_up", origin, "", "Sendung beim Versender abgeholt", "carrier")
			desc := "Abfahrt Richtung " + s.DCity
			if s.Mode == "rail" {
				desc = "Container auf Zug verladen (" + s.Container + ")"
			}
			add(t.Add(r.dur(3*time.Hour, 14*time.Hour)), "in_transit", origin, "", desc, "carrier")
			t = t.Add(time.Duration(float64(eta.Sub(t)) * (0.45 + r.Float64()*0.2)))
		}
		border := dest
		if s.DCountry == "CH" && s.Mode != "air" {
			border = "Basel, CH"
		}
		t = customs(t.Add(r.dur(2*time.Hour, 18*time.Hour)), border)
		if s.WH != nil {
			add(wdMaxTime(t.Add(r.dur(2*time.Hour, 10*time.Hour)), eta.Add(-time.Duration(r.between(14, 30))*time.Hour)),
				"in_transit", wdLoc(s.WH.City, s.WH.Country), s.WH.Code, "Eingang Umschlaglager "+s.WH.Name, "scanner")
		}
	}
	ofd := eta.Add(time.Duration(r.between(5*60+30, 8*60+30)) * time.Minute)
	if r.chance(0.12) {
		ofd = ofd.AddDate(0, 0, r.between(1, 3)) // delayed
	}
	end := add(ofd, "out_for_delivery", dest, "", "In Zustellung", "driver_app").Add(r.dur(50*time.Minute, 6*time.Hour))
	if r.chance(0.03) {
		add(end, "exception", dest, "", wdOne(r, []string{"Zustellung fehlgeschlagen: Annahme verweigert",
			"Transportschaden festgestellt, Schadensprotokoll erstellt", "Empfängeradresse unvollständig, Rückfrage beim Versender"}), "driver_app")
	} else {
		_, sign := r.person(s.DCountry)
		add(end, "delivered", dest, "", "Zugestellt, Empfang quittiert durch "+strings.ToUpper(wdFold(sign)), "driver_app")
	}
	// current state = last event that already happened
	s.Status, s.Updated = "booked", s.Created
	for _, e := range ev {
		if e.At.After(c.now) {
			break
		}
		s.Events = append(s.Events, e)
		s.Status, s.Updated = e.Status, e.At
		if e.Status == "delivered" {
			s.Delivered = e.At
		}
	}
}

func wdMaxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func (c *wdCtx) isCustomerUser(id int64) bool {
	for _, u := range c.w.AppUsers {
		if int64(u.ID) == id {
			return u.Role == "customer"
		}
	}
	return false
}

// ---------- invoices ----------

func wdSwissVAT(t time.Time) float64 {
	switch {
	case t.Before(time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)):
		return 8.0
	case t.Before(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)):
		return 7.7
	}
	return 8.1
}

func (c *wdCtx) genInvoices() {
	r := newWDRand(c.w, 6)
	var cand []*wdShipment
	for _, s := range c.shipments {
		if s.Status == "delivered" {
			cand = append(cand, s)
		}
	}
	type pick struct {
		s     *wdShipment
		issue time.Time
	}
	var picks []pick
	keep := 150.0 / float64(max(1, len(cand)))
	for _, s := range cand {
		if !r.chance(keep) {
			continue
		}
		issue := r.work(s.Delivered.AddDate(0, 0, r.between(1, 4)))
		if issue.After(c.now.Add(-time.Hour)) {
			continue
		}
		picks = append(picks, pick{s, issue})
	}
	sort.SliceStable(picks, func(i, j int) bool { return picks[i].issue.Before(picks[j].issue) })
	lastNo := map[int]int{}
	sapNo := 90010000 + r.IntN(5000)
	for i, p := range picks {
		s := p.s
		inv := &wdInvoice{ID: int64(i + 1), Cust: s.Cust, Ship: s, Currency: s.Currency, Issue: p.issue}
		y := p.issue.Year()
		no := p.issue.YearDay()*16 + r.IntN(16)
		if no <= lastNo[y] {
			no = lastNo[y] + 1 + r.IntN(4)
		}
		lastNo[y] = no
		inv.No = fmt.Sprintf("INV-%d-%06d", y, no)
		inv.PDF = fmt.Sprintf("invoices/%d/%s.pdf", y, inv.No)
		sapNo += r.between(3, 160)
		inv.SAP = strconv.Itoa(sapNo)
		var net float64
		switch s.Mode {
		case "road":
			net = 165 + s.Weight*(0.09+r.Float64()*0.06)
		case "sea":
			net = 1350 + r.Float64()*2900
		case "air":
			net = 95 + s.Weight*(3.9+r.Float64()*2.2)
		case "rail":
			net = 880 + s.Weight*(0.05+r.Float64()*0.05)
		}
		if s.Customs != "" {
			net += float64(r.between(65, 145))
		}
		if s.Currency == "EUR" {
			net *= 0.96
		}
		cents := int64(math.Round(net * 100))
		var rate float64
		if s.Cust.Country == "CH" {
			rate = wdSwissVAT(p.issue)
		}
		vat := int64(math.Round(float64(cents) * rate / 100))
		inv.Net, inv.Rate, inv.VAT, inv.Total = float64(cents)/100, rate, float64(vat)/100, float64(cents+vat)/100
		inv.Due = p.issue.AddDate(0, 0, s.Cust.Terms)
		inv.Created = p.issue
		inv.Status, inv.Updated = "sent", p.issue
		switch x := r.Float64(); {
		case x < 0.003 && inv.Due.Before(c.now): // collection case, never paid
			inv.Status, inv.Reminder = "overdue", 3
			inv.Updated = c.capNow(r, r.work(inv.Due.AddDate(0, 0, 42)))
		case x < 0.015:
			inv.Status = "cancelled"
			inv.Updated = c.capNow(r, p.issue.Add(r.dur(2*time.Hour, 72*time.Hour)))
		case x < 0.25 && inv.Due.Before(c.now) && inv.Due.After(c.now.AddDate(0, 0, -100)):
			inv.Status = "overdue"
			inv.Reminder = min(3, int(c.now.Sub(inv.Due).Hours()/24/14)+1)
			inv.Updated = c.capNow(r, r.work(inv.Due.AddDate(0, 0, 7)))
		default:
			paid := r.work(p.issue.Add(time.Duration(float64(inv.Due.Sub(p.issue)) * (0.4 + r.Float64()*0.9))))
			if paid.Before(c.now.Add(-time.Hour)) {
				inv.Status, inv.Paid, inv.Updated = "paid", paid, paid
			} else if inv.Due.Before(c.now) {
				inv.Status, inv.Reminder = "overdue", 1
				inv.Updated = c.capNow(r, r.work(inv.Due.AddDate(0, 0, 7)))
			}
		}
		if inv.Updated.Before(inv.Created) {
			inv.Updated = inv.Created
		}
		c.invoices = append(c.invoices, inv)
	}
}

// ---------- audit log ----------

var wdUAFamilies = []string{"chrome-win", "edge-win", "chrome-win", "firefox-win", "safari-mac", "chrome-mac"}

func wdUA(fam int, t time.Time) string {
	chrome := 100 + int(t.Sub(time.Date(2022, 3, 29, 0, 0, 0, 0, time.UTC)).Hours()/24/28)
	ff := 100 + int(t.Sub(time.Date(2022, 5, 3, 0, 0, 0, 0, time.UTC)).Hours()/24/28)
	safari := t.Year() - 2007
	if t.Month() >= 9 {
		safari++
	}
	if safari >= 19 {
		safari = t.Year() - 2000
		if t.Month() >= 9 {
			safari++
		}
	}
	switch wdUAFamilies[fam%len(wdUAFamilies)] {
	case "edge-win":
		return fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36 Edg/%d.0.0.0", chrome, chrome)
	case "firefox-win":
		return fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:%d.0) Gecko/20100101 Firefox/%d.0", ff, ff)
	case "safari-mac":
		return fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%d.1 Safari/605.1.15", safari)
	case "chrome-mac":
		return fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36", chrome)
	}
	return fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36", chrome)
}

func (c *wdCtx) genAudit() {
	r := newWDRand(c.w, 7)
	from := c.now.AddDate(0, 0, -120)
	var staffUsers, custUsers []AppUser
	for _, u := range c.w.AppUsers {
		if c.userCreated[u.ID].After(from) {
			continue
		}
		if u.Role == "customer" {
			custUsers = append(custUsers, u)
		} else {
			staffUsers = append(staffUsers, u)
		}
	}
	if len(staffUsers) == 0 && len(custUsers) == 0 {
		return
	}
	attackers := []string{"185.220.101." + strconv.Itoa(r.between(2, 250)), "45.142.120." + strconv.Itoa(r.between(2, 250)),
		"193.32.162." + strconv.Itoa(r.between(2, 250)), "103.145.13." + strconv.Itoa(r.between(2, 250))}
	attackUA := []string{"python-requests/2.31.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
		"Go-http-client/1.1", "curl/7.88.1"}
	guess := []string{"admin@" + worldDomain, "it@" + worldDomain, "info@" + worldDomain, "it-support@" + worldDomain, "support@" + worldDomain}
	ua := func(u AppUser, t time.Time) string { return wdUA(c.userUA[u.ID], t) }
	custShip := func(cid int64) []*wdShipment {
		var out []*wdShipment
		for _, s := range c.shipments {
			if s.Cust.ID == cid {
				out = append(out, s)
			}
		}
		return out
	}
	custInv := func(cid int64) []*wdInvoice {
		var out []*wdInvoice
		for _, inv := range c.invoices {
			if inv.Cust.ID == cid {
				out = append(out, inv)
			}
		}
		return out
	}
	statuses := []string{"booked", "picked_up", "in_transit", "customs_hold", "out_for_delivery", "delivered"}
	for len(c.audit) < 118 {
		var a wdAudit
		staffTurn := len(custUsers) == 0 || (len(staffUsers) > 0 && r.chance(0.55))
		if staffTurn {
			u := wdOne(r, staffUsers)
			a.At = c.capNow(r, r.work(r.timeIn(from, c.now)))
			a.UserID, a.IP, a.UA = int64(u.ID), c.userIP[u.ID], ua(u, a.At)
			switch x := r.IntN(100); {
			case x < 45:
				a.Action = "auth.login"
			case x < 70 && len(c.shipments) > 0:
				s := wdOne(r, c.shipments)
				old := wdOne(r, statuses)
				a.Action, a.Type, a.Auditable = "shipment.updated", `App\Models\Shipment`, s.ID
				a.Old = wdPHPJSON(map[string]string{"status": old})
				a.New = wdPHPJSON(map[string]string{"status": s.Status})
				if old == s.Status {
					a.Old = wdPHPJSON(map[string]string{"eta": wdD(s.ETA.AddDate(0, 0, -1))})
					a.New = wdPHPJSON(map[string]string{"eta": wdD(s.ETA)})
				}
			case x < 80:
				cu := wdOne(r, c.customers)
				a.Action, a.Type, a.Auditable = "customer.updated", `App\Models\Customer`, cu.ID
				a.Old = wdPHPJSON(map[string]string{"credit_limit": fmt.Sprintf("%.2f", cu.Credit/2)})
				a.New = wdPHPJSON(map[string]string{"credit_limit": fmt.Sprintf("%.2f", cu.Credit)})
			case x < 90:
				a.Action = "export.shipments"
				a.New = wdPHPJSON(map[string]any{"format": wdOne(r, []string{"xlsx", "csv"}), "rows": r.between(40, 2400)})
			case x < 94 && u.Role == "admin":
				a.Action, a.Type = "settings.updated", `App\Models\Setting`
				a.Auditable = 12 // sap.sync_interval_minutes
				a.Old, a.New = `{"value":"15"}`, `{"value":"30"}`
			default:
				a.Action = "auth.logout"
			}
		} else {
			u := wdOne(r, custUsers)
			a.At = c.capNow(r, r.work(r.timeIn(from, c.now)).Add(time.Duration(r.IntN(3))*time.Hour))
			a.UserID, a.IP, a.UA = int64(u.ID), c.userIP[u.ID], ua(u, a.At)
			cid := int64(u.CustomerID)
			switch x := r.IntN(100); {
			case x < 45:
				a.Action = "auth.login"
			case x < 70:
				invs := custInv(cid)
				if len(invs) == 0 {
					a.Action = "auth.login"
					break
				}
				inv := wdOne(r, invs)
				if inv.Issue.After(a.At) {
					a.At = c.capNow(r, inv.Issue.Add(r.dur(time.Hour, 96*time.Hour)))
				}
				a.Action, a.Type, a.Auditable = "invoice.downloaded", `App\Models\Invoice`, inv.ID
			case x < 85:
				ships := custShip(cid)
				if len(ships) == 0 {
					a.Action = "auth.login"
					break
				}
				s := wdOne(r, ships)
				a.Action, a.Type, a.Auditable = "shipment.viewed", `App\Models\Shipment`, s.ID
				if s.Created.After(a.At) {
					a.At = c.capNow(r, s.Created.Add(r.dur(time.Hour, 72*time.Hour)))
				}
			case x < 90:
				a.Action = "user.password_changed"
			default:
				a.Action = "auth.login_failed"
				a.New = wdPHPJSON(map[string]string{"email": u.Email})
				a.UserID = 0
			}
		}
		c.audit = append(c.audit, a)
		if r.chance(0.04) { // credential stuffing
			t := c.capNow(r, r.timeIn(from, c.now))
			ip, agent := wdOne(r, attackers), wdOne(r, attackUA)
			for k := r.between(2, 4); k > 0; k-- {
				c.audit = append(c.audit, wdAudit{Action: "auth.login_failed", IP: ip, UA: agent, At: t,
					New: wdPHPJSON(map[string]string{"email": wdOne(r, guess)})})
				t = t.Add(time.Duration(r.between(1, 9)) * time.Second)
			}
		}
	}
	sort.SliceStable(c.audit, func(i, j int) bool { return c.audit[i].At.Before(c.audit[j].At) })
}

// ---------- veltrona_connect ----------

func (c *wdCtx) connectDB() Database {
	r := newWDRand(c.w, 10)
	ts := wdLaravelTS()
	var tables []Table
	add := func(t Table) { tables = append(tables, t) }

	// migrations
	dev := c.start.AddDate(0, 0, -45)
	mig := func(day time.Time, n int, name string) string {
		t := day.Add(time.Duration(8*3600+n*1500+r.IntN(1200)) * time.Second)
		return t.Format("2006_01_02_150405") + "_" + name
	}
	type m struct {
		name  string
		batch int
	}
	migs := []m{{"2014_10_12_000000_create_users_table", 1}, {"2014_10_12_100000_create_password_resets_table", 1},
		{"2014_10_12_200000_add_two_factor_columns_to_users_table", 1}, {"2019_08_19_000000_create_failed_jobs_table", 1},
		{"2019_12_14_000001_create_personal_access_tokens_table", 1}}
	for i, name := range []string{"create_customers_table", "create_warehouses_table", "create_drivers_table",
		"create_shipments_table", "create_shipment_events_table", "create_invoices_table", "create_settings_table",
		"create_jobs_table", "create_sessions_table", "add_role_and_customer_id_to_users_table"} {
		migs = append(migs, m{mig(dev.AddDate(0, 0, i/3), i%3, name), 1})
	}
	for _, x := range []struct {
		day   int
		names []string
	}{{18, []string{"add_container_no_to_shipments_table"}},
		{160, []string{"add_customs_ref_to_shipments_table", "create_api_clients_table"}},
		{410, []string{"create_audit_log_table", "add_last_login_columns_to_users_table"}},
		{690, []string{"add_sap_debtor_no_to_customers_table", "add_deleted_at_to_customers_table"}},
		{1010, []string{"add_reminder_level_to_invoices_table", "add_adr_certified_to_drivers_table"}},
		{1250, []string{"add_dangerous_goods_to_shipments_table"}}} {
		d := c.start.AddDate(0, 0, x.day)
		if d.After(c.now) {
			break
		}
		batch := migs[len(migs)-1].batch + 1
		for i, name := range x.names {
			migs = append(migs, m{mig(d, i+1, name), batch})
		}
	}
	var rows [][]any
	for i, x := range migs {
		rows = append(rows, []any{wdI(i + 1), x.name, wdI(x.batch)})
	}
	add(wdTable("migrations", []Column{wdc("id", "int(10) unsigned", "ai"), wdc("migration", "varchar(255)", ""), wdc("batch", "int(11)", "")}, rows))

	// users (exactly the world's portal accounts) + login data from the audit log
	lastLogin := map[int64]wdAudit{}
	for _, a := range c.audit {
		if a.Action == "auth.login" && a.UserID != 0 {
			lastLogin[a.UserID] = a
		}
	}
	rows = nil
	for i, u := range c.w.AppUsers {
		created := c.userCreated[u.ID]
		verified := created.Add(r.dur(2*time.Minute, 40*time.Hour))
		if u.Role == "customer" && i%5 == 4 {
			verified = time.Time{}
		}
		if verified.After(c.now) {
			verified = created
		}
		var remember any
		if r.chance(0.55) {
			remember = r.str(alnum, 60)
		}
		var custID any
		if u.Role == "customer" && u.CustomerID != 0 {
			custID = int64(u.CustomerID)
		}
		var ip, at any
		updated := created
		if a, ok := lastLogin[int64(u.ID)]; ok {
			ip, at, updated = a.IP, wdT(a.At), a.At
		} else if u.Role != "customer" || r.chance(0.7) {
			t := r.timeIn(created, c.now.AddDate(0, 0, -121))
			if t.After(created) {
				ip, at, updated = c.userIP[u.ID], wdT(t), t
			}
		}
		if verified.After(updated) {
			updated = verified
		}
		rows = append(rows, []any{wdI(u.ID), u.Name, u.Email, wdNT(verified), u.Hash, u.Role, custID, nil, nil,
			remember, ip, at, wdT(created), wdT(updated)})
	}
	add(wdTable("users", append([]Column{wdc("id", "bigint(20) unsigned", "ai"), wdc("name", "varchar(255)", ""),
		wdc("email", "varchar(255)", "uni"), wdc("email_verified_at", "timestamp", "null"), wdc("password", "varchar(255)", ""),
		wdc("role", wdEnum("admin", "staff", "customer"), "def=customer"), wdc("customer_id", "bigint(20) unsigned", "null|mul"),
		wdc("two_factor_secret", "text", "null"), wdc("two_factor_recovery_codes", "text", "null"),
		wdc("remember_token", "varchar(100)", "null"), wdc("last_login_ip", "varchar(45)", "null"),
		wdc("last_login_at", "timestamp", "null")}, ts...), rows))

	// password_resets
	rows = nil
	var cust []AppUser
	for _, u := range c.w.AppUsers {
		if u.Role == "customer" {
			cust = append(cust, u)
		}
	}
	if len(cust) > 0 {
		for _, k := range []int{2, 11, 47} {
			u := cust[(k*7)%len(cust)]
			rows = append(rows, []any{u.Email, r.fakeBcrypt(), wdT(c.capNow(r, r.work(c.now.AddDate(0, 0, -k))))})
		}
		sort.SliceStable(rows, func(i, j int) bool { return rows[i][2].(string) < rows[j][2].(string) })
	}
	add(wdTable("password_resets", []Column{wdc("email", "varchar(255)", "mul"), wdc("token", "varchar(255)", ""),
		wdc("created_at", "timestamp", "null")}, rows))

	add(wdTable("failed_jobs", []Column{wdc("id", "bigint(20) unsigned", "ai"), wdc("uuid", "varchar(255)", "uni"),
		wdc("connection", "text", ""), wdc("queue", "text", ""), wdc("payload", "longtext", ""), wdc("exception", "longtext", ""),
		wdc("failed_at", "timestamp", "def=CURRENT_TIMESTAMP")}, c.failedJobs(r)))

	// personal_access_tokens (Sanctum)
	rows = nil
	type tok struct {
		user        int64
		name, abil  string
		age, recent int
	}
	var toks []tok
	if len(c.admins) > 0 {
		toks = append(toks, tok{c.admins[0], "sap-bridge-prod", `["*"]`, 1100, 0}, tok{c.admins[0], "postman-debug", `["*"]`, 640, 200})
	}
	if len(c.staff) > 0 {
		toks = append(toks, tok{c.staff[0], "powerbi-export", `["shipments:read","invoices:read"]`, 420, 1})
	}
	n := 0
	for _, u := range cust {
		if n < 3 && c.userCreated[u.ID].Before(c.now.AddDate(0, 0, -200)) && r.chance(0.6) {
			toks = append(toks, tok{int64(u.ID), wdOne(r, []string{"ERP-Anbindung", "SAP Business One", "Tracking-Integration", "abacus-sync"}),
				`["shipments:read","shipments:create","tracking:read"]`, r.between(60, 190), r.between(0, 3)})
			n++
		}
	}
	type tokRow struct {
		t   tok
		at  time.Time
		use time.Time
	}
	var trs []tokRow
	for _, t := range toks {
		at := r.work(c.now.AddDate(0, 0, -t.age))
		if uc := c.userCreated[int(t.user)]; at.Before(uc) {
			at = uc.Add(r.dur(time.Hour, 200*time.Hour))
		}
		use := c.capNow(r, c.now.AddDate(0, 0, -t.recent).Add(-r.dur(0, 10*time.Hour)))
		if use.Before(at) {
			use = at
		}
		trs = append(trs, tokRow{t, at, use})
	}
	sort.SliceStable(trs, func(i, j int) bool { return trs[i].at.Before(trs[j].at) })
	for i, x := range trs {
		rows = append(rows, []any{wdI(i + 1), `App\Models\User`, x.t.user, x.t.name, wdSha256(r.str(alnum, 40)), x.t.abil,
			wdT(x.use), wdT(x.at), wdT(x.use)})
	}
	add(wdTable("personal_access_tokens", append([]Column{wdc("id", "bigint(20) unsigned", "ai"),
		wdc("tokenable_type", "varchar(255)", "mul"), wdc("tokenable_id", "bigint(20) unsigned", ""), wdc("name", "varchar(255)", ""),
		wdc("token", "varchar(64)", "uni"), wdc("abilities", "text", "null"), wdc("last_used_at", "timestamp", "null")}, ts...), rows))

	// customers
	rows = nil
	for _, cu := range c.customers {
		rows = append(rows, []any{cu.ID, cu.No, cu.SAP, cu.Name, cu.Legal, cu.VAT, cu.Street, cu.Postal, cu.City, cu.Country,
			cu.Phone, cu.Contact, cu.Email, cu.InvoiceEmail, cu.IBAN, cu.BIC, cu.Currency, wdF(cu.Credit), wdI(cu.Terms),
			wdNI(cu.Manager), wdBool(cu.Deleted.IsZero()), wdNS(cu.Notes), wdT(cu.Created), wdT(cu.Updated), wdNT(cu.Deleted)})
	}
	add(wdTable("customers", append(append([]Column{wdc("id", "bigint(20) unsigned", "ai"), wdc("customer_no", "varchar(20)", "uni"),
		wdc("sap_debtor_no", "varchar(10)", "null|mul"), wdc("company_name", "varchar(255)", ""), wdc("legal_form", "varchar(30)", "null"),
		wdc("vat_id", "varchar(30)", "null"), wdc("street", "varchar(255)", ""), wdc("postal_code", "varchar(12)", ""),
		wdc("city", "varchar(100)", ""), wdc("country", "char(2)", "def=CH"), wdc("phone", "varchar(40)", "null"),
		wdc("contact_name", "varchar(255)", "null"), wdc("contact_email", "varchar(255)", "null"),
		wdc("invoice_email", "varchar(255)", "null"), wdc("iban", "varchar(34)", "null"), wdc("bic", "varchar(11)", "null"),
		wdc("currency", "char(3)", "def=CHF"), wdc("credit_limit", "decimal(12,2)", "def=0.00"),
		wdc("payment_terms", "smallint(5) unsigned", "def=30"), wdc("account_manager_id", "bigint(20) unsigned", "null|mul"),
		wdc("is_active", "tinyint(1)", "def=1"), wdc("notes", "text", "null")}, ts...),
		wdc("deleted_at", "timestamp", "null")), rows))

	// warehouses
	rows = nil
	for _, w := range c.warehouses {
		rows = append(rows, []any{w.ID, w.Code, w.Name, w.Street, w.Postal, w.City, w.Country, w.Manager, w.Phone, w.Hours,
			wdI(w.Capacity), wdBool(w.Temp), wdBool(w.Bonded), int64(1), wdT(c.goLive.Add(-20 * time.Minute)),
			wdT(r.work(r.timeIn(c.goLive, c.now.AddDate(0, 0, -30))))})
	}
	add(wdTable("warehouses", append([]Column{wdc("id", "int(10) unsigned", "ai"), wdc("code", "varchar(10)", "uni"),
		wdc("name", "varchar(255)", ""), wdc("street", "varchar(255)", ""), wdc("postal_code", "varchar(12)", ""),
		wdc("city", "varchar(100)", ""), wdc("country", "char(2)", ""), wdc("manager_name", "varchar(255)", "null"),
		wdc("phone", "varchar(40)", "null"), wdc("opening_hours", "varchar(100)", "null"),
		wdc("capacity_pallets", "int(10) unsigned", "def=0"), wdc("temperature_controlled", "tinyint(1)", "def=0"),
		wdc("bonded", "tinyint(1)", "def=0"), wdc("is_active", "tinyint(1)", "def=1")}, ts...), rows))

	// drivers
	rows = nil
	for _, d := range c.drivers {
		rows = append(rows, []any{d.ID, d.EmpNo, d.First, d.Last, d.Phone, wdNS(d.Email), d.Licence, d.LicCountry, d.Classes,
			wdD(d.LicExpires), wdD(d.CPC), wdBool(d.ADR), d.Plate, d.Home, d.Status, wdD(d.Hired), wdT(d.Created), wdT(d.Updated)})
	}
	add(wdTable("drivers", append([]Column{wdc("id", "bigint(20) unsigned", "ai"), wdc("employee_no", "varchar(20)", "uni"),
		wdc("first_name", "varchar(100)", ""), wdc("last_name", "varchar(100)", ""), wdc("phone", "varchar(40)", "null"),
		wdc("email", "varchar(255)", "null"), wdc("licence_no", "varchar(30)", ""), wdc("licence_country", "char(2)", ""),
		wdc("licence_classes", "varchar(50)", ""), wdc("licence_expires_at", "date", "null"), wdc("cpc_valid_until", "date", "null"),
		wdc("adr_certified", "tinyint(1)", "def=0"), wdc("vehicle_plate", "varchar(20)", "null"),
		wdc("home_warehouse_id", "int(10) unsigned", "null|mul"),
		wdc("status", wdEnum("active", "on_leave", "inactive"), "def=active"), wdc("hired_at", "date", "null")}, ts...), rows))

	// shipments
	rows = nil
	for _, s := range c.shipments {
		var drv, wh any
		if s.Driver != nil {
			drv = s.Driver.ID
		}
		if s.WH != nil {
			wh = s.WH.ID
		}
		rows = append(rows, []any{s.ID, s.Tracking, s.Cust.ID, wdNS(s.Ref), s.Status, s.Mode, s.Incoterm, s.OCountry, s.OCity,
			s.DCountry, s.DCity, s.Consignee, wdI(s.Pieces), wdF(s.Weight), s.Volume, s.Goods, s.HS, wdBool(s.DG),
			wdNS(s.Container), wdNS(s.AWB), drv, wdNS(s.Plate), wh, wdNS(s.Customs), wdF(s.Value), s.Currency,
			wdD(s.Pickup), wdD(s.ETA), wdNT(s.Delivered), wdNI(s.CreatedBy), wdT(s.Created), wdT(s.Updated)})
	}
	add(wdTable("shipments", append([]Column{wdc("id", "bigint(20) unsigned", "ai"), wdc("tracking_no", "varchar(20)", "uni"),
		wdc("customer_id", "bigint(20) unsigned", "mul"), wdc("customer_reference", "varchar(50)", "null"),
		wdc("status", wdEnum("booked", "picked_up", "in_transit", "customs_hold", "out_for_delivery", "delivered", "exception"), "def=booked|mul"),
		wdc("mode", wdEnum("road", "sea", "air", "rail"), "def=road"), wdc("incoterm", "char(3)", "null"),
		wdc("origin_country", "char(2)", ""), wdc("origin_city", "varchar(100)", ""), wdc("destination_country", "char(2)", ""),
		wdc("destination_city", "varchar(100)", ""), wdc("consignee_name", "varchar(255)", "null"),
		wdc("pieces", "int(10) unsigned", "def=1"), wdc("weight_kg", "decimal(10,2)", "def=0.00"),
		wdc("volume_m3", "decimal(8,3)", "null"), wdc("goods_description", "varchar(255)", "null"), wdc("hs_code", "varchar(10)", "null"),
		wdc("dangerous_goods", "tinyint(1)", "def=0"), wdc("container_no", "varchar(11)", "null"), wdc("awb_no", "varchar(12)", "null"),
		wdc("driver_id", "bigint(20) unsigned", "null|mul"), wdc("vehicle_plate", "varchar(20)", "null"),
		wdc("warehouse_id", "int(10) unsigned", "null|mul"), wdc("customs_ref", "varchar(30)", "null"),
		wdc("declared_value", "decimal(12,2)", "null"), wdc("currency", "char(3)", "def=CHF"), wdc("pickup_date", "date", "null"),
		wdc("eta", "date", "null"), wdc("delivered_at", "timestamp", "null"), wdc("created_by", "bigint(20) unsigned", "null|mul")}, ts...), rows))

	// shipment_events (older events are archived to cold storage, see settings)
	type evRow struct {
		s *wdShipment
		e wdEvent
	}
	var evs []evRow
	keepFrom := c.now.AddDate(0, 0, -365)
	for _, s := range c.shipments {
		if s.Created.Before(keepFrom) {
			continue
		}
		for _, e := range s.Events {
			evs = append(evs, evRow{s, e})
		}
	}
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].e.At.Before(evs[j].e.At) })
	rows = nil
	evID := int64(18000 + r.IntN(4000))
	for _, x := range evs {
		evID++
		logged := x.e.At.Add(time.Duration(r.between(1, 240)) * time.Second)
		if logged.After(c.now) {
			logged = x.e.At
		}
		var hub any
		if x.e.Hub != "" {
			hub = x.e.Hub
		}
		rows = append(rows, []any{evID, x.s.ID, x.e.Status, x.e.Location, hub, x.e.Desc, x.e.Source, wdT(x.e.At), wdT(logged), wdT(logged)})
	}
	add(wdTable("shipment_events", append([]Column{wdc("id", "bigint(20) unsigned", "ai"),
		wdc("shipment_id", "bigint(20) unsigned", "mul"),
		wdc("status", wdEnum("booked", "picked_up", "in_transit", "customs_hold", "out_for_delivery", "delivered", "exception"), ""),
		wdc("location", "varchar(120)", "null"), wdc("hub_code", "varchar(10)", "null"), wdc("description", "varchar(255)", "null"),
		wdc("source", wdEnum("portal", "sap", "edi", "driver_app", "scanner", "carrier", "customs", "system"), "def=system"),
		wdc("occurred_at", "timestamp", "null")}, ts...), rows))

	// invoices
	rows = nil
	for _, inv := range c.invoices {
		rows = append(rows, []any{inv.ID, inv.No, inv.Cust.ID, inv.Ship.ID, inv.SAP, wdD(inv.Issue), wdD(inv.Due), inv.Currency,
			inv.Net, inv.Rate, inv.VAT, inv.Total, inv.Status, wdNT(inv.Paid), wdI(inv.Reminder), inv.PDF,
			wdT(inv.Created), wdT(inv.Updated)})
	}
	add(wdTable("invoices", append([]Column{wdc("id", "bigint(20) unsigned", "ai"), wdc("invoice_no", "varchar(20)", "uni"),
		wdc("customer_id", "bigint(20) unsigned", "mul"), wdc("shipment_id", "bigint(20) unsigned", "null|mul"),
		wdc("sap_document_no", "varchar(10)", "null"), wdc("issue_date", "date", ""), wdc("due_date", "date", ""),
		wdc("currency", "char(3)", "def=CHF"), wdc("net_amount", "decimal(12,2)", ""), wdc("vat_rate", "decimal(4,2)", "def=0.00"),
		wdc("vat_amount", "decimal(12,2)", "def=0.00"), wdc("total_amount", "decimal(12,2)", ""),
		wdc("status", wdEnum("draft", "sent", "paid", "overdue", "cancelled"), "def=draft|mul"), wdc("paid_at", "timestamp", "null"),
		wdc("reminder_level", "tinyint(3) unsigned", "def=0"), wdc("pdf_path", "varchar(255)", "null")}, ts...), rows))

	add(c.apiClients(r))
	add(c.settings(r))

	// audit_log
	rows = nil
	auditID := int64(r.between(4000, 9000))
	for _, a := range c.audit {
		auditID += int64(1 + r.IntN(3))
		var aType, aID any
		if a.Type != "" {
			aType, aID = a.Type, a.Auditable
		}
		rows = append(rows, []any{auditID, wdNI(a.UserID), a.Action, aType, aID, wdNS(a.Old), wdNS(a.New), a.IP, a.UA, wdT(a.At)})
	}
	add(wdTable("audit_log", []Column{wdc("id", "bigint(20) unsigned", "ai"), wdc("user_id", "bigint(20) unsigned", "null|mul"),
		wdc("action", "varchar(64)", "mul"), wdc("auditable_type", "varchar(255)", "null"), wdc("auditable_id", "bigint(20) unsigned", "null"),
		wdc("old_values", "text", "null"), wdc("new_values", "text", "null"), wdc("ip_address", "varchar(45)", "null"),
		wdc("user_agent", "varchar(255)", "null"), wdc("created_at", "timestamp", "null")}, rows))

	jobs := wdTable("jobs", []Column{wdc("id", "bigint(20) unsigned", "ai"), wdc("queue", "varchar(255)", "mul"),
		wdc("payload", "longtext", ""), wdc("attempts", "tinyint(3) unsigned", ""), wdc("reserved_at", "int(10) unsigned", "null"),
		wdc("available_at", "int(10) unsigned", ""), wdc("created_at", "int(10) unsigned", "")}, nil)
	jobs.AutoIncrement = int64(48000 + r.IntN(30000))
	add(jobs)
	add(wdTable("sessions", []Column{wdc("id", "varchar(255)", "pk"), wdc("user_id", "bigint(20) unsigned", "null|mul"),
		wdc("ip_address", "varchar(45)", "null"), wdc("user_agent", "text", "null"), wdc("payload", "text", ""),
		wdc("last_activity", "int(11)", "mul")}, nil))

	sort.SliceStable(tables, func(i, j int) bool { return tables[i].Name < tables[j].Name })
	return Database{Name: worldAppDB, Tables: tables}
}

func (c *wdCtx) failedJobs(r wdRand) [][]any {
	if len(c.shipments) == 0 {
		return nil
	}
	model := func(class string, id int64) wdObj {
		return wdObj{`Illuminate\Contracts\Database\ModelIdentifier`, wdArr{{"class", class}, {"id", id},
			{"relations", wdArr{}}, {"connection", "mysql"}, {"collectionClass", nil}}}
	}
	queueable := func(queue string) wdArr {
		return wdArr{{"connection", nil}, {"queue", queue}, {"chainConnection", nil}, {"chainQueue", nil},
			{"chainCatchCallbacks", nil}, {"delay", nil}, {"afterCommit", nil}, {"middleware", wdArr{}}, {"chained", wdArr{}}}
	}
	type payload struct {
		UUID          string `json:"uuid"`
		DisplayName   string `json:"displayName"`
		Job           string `json:"job"`
		MaxTries      any    `json:"maxTries"`
		MaxExceptions any    `json:"maxExceptions"`
		FailOnTimeout bool   `json:"failOnTimeout"`
		Backoff       any    `json:"backoff"`
		Timeout       any    `json:"timeout"`
		RetryUntil    any    `json:"retryUntil"`
		Data          struct {
			CommandName string `json:"commandName"`
			Command     string `json:"command"`
		} `json:"data"`
	}
	trace := func(frames ...string) string {
		var b strings.Builder
		b.WriteString("Stack trace:\n")
		all := append(frames,
			`/var/www/connect/vendor/laravel/framework/src/Illuminate/Container/BoundMethod.php(36): App\Jobs\%s->handle()`,
			`/var/www/connect/vendor/laravel/framework/src/Illuminate/Container/Util.php(40): Illuminate\Container\BoundMethod::Illuminate\Container\{closure}()`,
			`/var/www/connect/vendor/laravel/framework/src/Illuminate/Container/BoundMethod.php(93): Illuminate\Container\Util::unwrapIfClosure(Object(Closure))`,
			`/var/www/connect/vendor/laravel/framework/src/Illuminate/Container/Container.php(653): Illuminate\Container\BoundMethod::call(Object(Illuminate\Foundation\Application), Array, Array, NULL)`,
			`/var/www/connect/vendor/laravel/framework/src/Illuminate/Bus/Dispatcher.php(128): Illuminate\Container\Container->call(Array)`,
			`/var/www/connect/vendor/laravel/framework/src/Illuminate/Pipeline/Pipeline.php(128): Illuminate\Bus\Dispatcher->Illuminate\Bus\{closure}(Object(App\Jobs\%s))`,
			`/var/www/connect/vendor/laravel/framework/src/Illuminate/Queue/CallQueuedHandler.php(120): Illuminate\Pipeline\Pipeline->then(Object(Closure))`,
			`/var/www/connect/vendor/laravel/framework/src/Illuminate/Queue/Jobs/Job.php(98): Illuminate\Queue\CallQueuedHandler->call(Object(Illuminate\Queue\Jobs\RedisJob), Array)`,
			`/var/www/connect/vendor/laravel/framework/src/Illuminate/Queue/Worker.php(428): Illuminate\Queue\Jobs\Job->fire()`,
			`/var/www/connect/vendor/laravel/framework/src/Illuminate/Queue/Console/WorkCommand.php(117): Illuminate\Queue\Worker->daemon('redis', 'default', Object(Illuminate\Queue\WorkerOptions))`,
			`/var/www/connect/artisan(37): Illuminate\Foundation\Console\Kernel->handle(Object(Symfony\Component\Console\Input\ArgvInput), Object(Symfony\Component\Console\Output\ConsoleOutput))`)
		for i, f := range all {
			fmt.Fprintf(&b, "#%d %s\n", i, f)
		}
		fmt.Fprintf(&b, "#%d {main}", len(all))
		return b.String()
	}
	sapURL := "https://sap-bridge.internal.veltrona-group.com:8443/sap/opu/odata/sap/ZVLT_SHIPMENT_SRV/ShipmentSet"
	type fj struct {
		job, queue string
		prop       string
		model      string
		id         int64
		tries      int
		exc        string
		at         time.Time
	}
	var jobs []fj
	pickShip := func(back int) *wdShipment {
		t := c.now.AddDate(0, 0, -back)
		var best *wdShipment
		for _, s := range c.shipments {
			if s.Created.Before(t) {
				best = s
			}
		}
		if best == nil {
			best = c.shipments[0]
		}
		return best
	}
	s1, s2, s3 := pickShip(r.between(200, 330)), pickShip(r.between(40, 90)), pickShip(r.between(3, 12))
	jobs = append(jobs, fj{"SyncShipmentToSap", "sap", "shipment", `App\Models\Shipment`, s1.ID, 3,
		"GuzzleHttp\\Exception\\ConnectException: cURL error 28: Operation timed out after 30001 milliseconds with 0 bytes received (see https://curl.haxx.se/libcurl/c/libcurl-errors.html) for " + sapURL + " in /var/www/connect/vendor/guzzlehttp/guzzle/src/Handler/CurlFactory.php:210\n" +
			strings.ReplaceAll(trace(
				`/var/www/connect/vendor/guzzlehttp/guzzle/src/Handler/CurlFactory.php(158): GuzzleHttp\Handler\CurlFactory::createRejection(Object(GuzzleHttp\Handler\EasyHandle), Array)`,
				`/var/www/connect/vendor/guzzlehttp/guzzle/src/Handler/CurlFactory.php(110): GuzzleHttp\Handler\CurlFactory::finishError(Object(GuzzleHttp\Handler\CurlHandler), Object(GuzzleHttp\Handler\EasyHandle), Object(GuzzleHttp\Handler\CurlFactory))`,
				`/var/www/connect/vendor/guzzlehttp/guzzle/src/Handler/CurlHandler.php(47): GuzzleHttp\Handler\CurlFactory::finish(Object(GuzzleHttp\Handler\CurlHandler), Object(GuzzleHttp\Handler\EasyHandle), Object(GuzzleHttp\Handler\CurlFactory))`,
				`/var/www/connect/vendor/guzzlehttp/guzzle/src/Client.php(333): GuzzleHttp\Handler\CurlHandler->__invoke(Object(GuzzleHttp\Psr7\Request), Array)`,
				`/var/www/connect/app/Services/Sap/SapBridgeClient.php(84): GuzzleHttp\Client->request('POST', 'ShipmentSet', Array)`,
				`/var/www/connect/app/Jobs/SyncShipmentToSap.php(52): App\Services\Sap\SapBridgeClient->pushShipment(Object(App\Models\Shipment))`), "%s", "SyncShipmentToSap"),
		r.work(s1.Created.Add(2 * time.Hour))})
	jobs = append(jobs, fj{"SyncShipmentToSap", "sap", "shipment", `App\Models\Shipment`, s2.ID, 3,
		"GuzzleHttp\\Exception\\ClientException: Client error: `POST " + sapURL + "` resulted in a `401 Unauthorized` response:\n<html><head><title>Logon Error Message</title></head><body>Logon failed for user SVC_CONNECT_RFC (truncated...)\n in /var/www/connect/vendor/guzzlehttp/guzzle/src/Exception/RequestException.php:113\n" +
			strings.ReplaceAll(trace(
				`/var/www/connect/vendor/guzzlehttp/guzzle/src/Middleware.php(69): GuzzleHttp\Exception\RequestException::create(Object(GuzzleHttp\Psr7\Request), Object(GuzzleHttp\Psr7\Response), NULL, Array, NULL)`,
				`/var/www/connect/vendor/guzzlehttp/promises/src/Promise.php(204): GuzzleHttp\Middleware::GuzzleHttp\{closure}(Object(GuzzleHttp\Psr7\Response))`,
				`/var/www/connect/vendor/guzzlehttp/guzzle/src/Client.php(187): GuzzleHttp\Promise\Promise->wait()`,
				`/var/www/connect/app/Services/Sap/SapBridgeClient.php(84): GuzzleHttp\Client->request('POST', 'ShipmentSet', Array)`,
				`/var/www/connect/app/Jobs/SyncShipmentToSap.php(52): App\Services\Sap\SapBridgeClient->pushShipment(Object(App\Models\Shipment))`), "%s", "SyncShipmentToSap"),
		r.work(s2.Created.Add(time.Hour))})
	if len(c.invoices) > 0 {
		inv := c.invoices[len(c.invoices)*2/3]
		jobs = append(jobs, fj{"SendInvoiceMail", "mail", "invoice", `App\Models\Invoice`, inv.ID, 5,
			"Swift_TransportException: Expected response code 250 but got code \"554\", with message \"554 5.2.0 STOREDRV.Submission.Exception:SendAsDeniedException.MapiExceptionSendAsDenied; Failed to process message due to a permanent exception with message Cannot submit message. 0.35250:0A008E84, 1.36674:0A000000, 1.61250:00000000\"\n in /var/www/connect/vendor/swiftmailer/swiftmailer/lib/classes/Swift/Transport/AbstractSmtpTransport.php:457\n" +
				strings.ReplaceAll(trace(
					`/var/www/connect/vendor/swiftmailer/swiftmailer/lib/classes/Swift/Transport/AbstractSmtpTransport.php(341): Swift_Transport_AbstractSmtpTransport->assertResponseCode('554 5.2.0 STORE...', Array)`,
					`/var/www/connect/vendor/swiftmailer/swiftmailer/lib/classes/Swift/Transport/EsmtpTransport.php(305): Swift_Transport_AbstractSmtpTransport->executeCommand('\r\n.\r\n', Array, Array, false, NULL)`,
					`/var/www/connect/vendor/swiftmailer/swiftmailer/lib/classes/Swift/Mailer.php(71): Swift_Transport_AbstractSmtpTransport->send(Object(Swift_Message), Array)`,
					`/var/www/connect/vendor/laravel/framework/src/Illuminate/Mail/Mailer.php(521): Swift_Mailer->send(Object(Swift_Message), Array)`,
					`/var/www/connect/app/Jobs/SendInvoiceMail.php(41): Illuminate\Mail\Mailer->send(Object(App\Mail\InvoiceIssued))`), "%s", "SendInvoiceMail"),
			r.work(inv.Issue.Add(30 * time.Minute))})
		inv2 := c.invoices[len(c.invoices)-1]
		jobs = append(jobs, fj{"GenerateInvoicePdf", "default", "invoice", `App\Models\Invoice`, inv2.ID, 3,
			"Aws\\S3\\Exception\\S3Exception: Error executing \"PutObject\" on \"https://veltrona-connect-docs.s3.eu-central-1.amazonaws.com/" + inv2.PDF + "\"; AWS HTTP error: Client error: `PUT https://veltrona-connect-docs.s3.eu-central-1.amazonaws.com/" + inv2.PDF + "` resulted in a `403 Forbidden` response:\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>RequestTimeTooSkewed</Code><Message>The difference between the request time and the current time is too large.</Message> (truncated...)\n RequestTimeTooSkewed (client): The difference between the request time and the current time is too large. in /var/www/connect/vendor/aws/aws-sdk-php/src/WrappedHttpHandler.php:195\n" +
				strings.ReplaceAll(trace(
					`/var/www/connect/vendor/aws/aws-sdk-php/src/WrappedHttpHandler.php(97): Aws\WrappedHttpHandler->parseError(Array, Object(GuzzleHttp\Psr7\Request), Object(Aws\Command), Array)`,
					`/var/www/connect/vendor/guzzlehttp/promises/src/Promise.php(204): Aws\WrappedHttpHandler->Aws\{closure}(Array)`,
					`/var/www/connect/vendor/league/flysystem-aws-s3-v3/src/AwsS3Adapter.php(629): Aws\S3\S3Client->putObject(Array)`,
					`/var/www/connect/vendor/league/flysystem/src/Filesystem.php(43): League\Flysystem\AwsS3v3\AwsS3Adapter->write('`+inv2.PDF[:15]+`...', '%PDF-1.7\n%\xE2\xE3...', Object(League\Flysystem\Config))`,
					`/var/www/connect/app/Jobs/GenerateInvoicePdf.php(63): Illuminate\Filesystem\FilesystemAdapter->put('`+inv2.PDF[:15]+`...', '%PDF-1.7\n%\xE2\xE3...')`), "%s", "GenerateInvoicePdf"),
			c.capNow(r, inv2.Issue.Add(4*time.Minute))})
	}
	jobs = append(jobs, fj{"ImportEdiStatus", "edi", "shipment", `App\Models\Shipment`, s3.ID, 1,
		"ErrorException: Undefined index: NAD+CN in /var/www/connect/app/Services/Edi/IftstaParser.php:118\n" +
			strings.ReplaceAll(trace(
				`/var/www/connect/app/Services/Edi/IftstaParser.php(118): Illuminate\Foundation\Bootstrap\HandleExceptions->handleError(8, 'Undefined index...', '/var/www/connec...', 118, Array)`,
				`/var/www/connect/app/Services/Edi/IftstaParser.php(57): App\Services\Edi\IftstaParser->consignee(Array)`,
				`/var/www/connect/app/Jobs/ImportEdiStatus.php(45): App\Services\Edi\IftstaParser->parse('UNA:+.? \'UNB+UN...')`), "%s", "ImportEdiStatus"),
		c.capNow(r, s3.Created.Add(5*time.Hour))})
	sort.SliceStable(jobs, func(i, j int) bool { return jobs[i].at.Before(jobs[j].at) })
	var rows [][]any
	id := int64(r.between(30, 140))
	for _, j := range jobs {
		id += int64(r.between(1, 40))
		class := `App\Jobs\` + j.job
		props := append(wdArr{{j.prop, model(j.model, j.id)}, {"tries", j.tries}}, queueable(j.queue)...)
		p := payload{UUID: r.uuid(), DisplayName: class, Job: `Illuminate\Queue\CallQueuedHandler@call`, MaxTries: j.tries,
			Backoff: 60, Timeout: 120}
		p.Data.CommandName, p.Data.Command = class, wdPHP(wdObj{class, props})
		rows = append(rows, []any{id, p.UUID, "redis", j.queue, wdPHPJSON(p), j.exc, wdT(j.at)})
	}
	return rows
}

func (c *wdCtx) apiClients(r wdRand) Table {
	type cl struct {
		name, scopes, ips, contact string
		day                        int
		plain, active              bool
		lastUsed                   time.Duration
	}
	custDomain := func(i int) string {
		if i < len(c.customers) {
			return c.customers[i].Domain
		}
		return worldDomain
	}
	custName := func(i int) string {
		if i < len(c.customers) {
			return c.customers[i].Name
		}
		return "Partner"
	}
	list := []cl{
		{"SAP S/4HANA Bridge (PRD 100)", `["shipments:*","invoices:*","customers:*"]`, `["10.20.6.21","10.20.6.22"]`, "sap-basis@" + worldDomain, 160, false, true, 3 * time.Minute},
		{"Legacy Tracking Widget (www)", `["tracking:read"]`, `[]`, "webmaster@" + worldDomain, 161, true, true, 40 * time.Minute},
		{"EDI Gateway IFTSTA/IFTMIN", `["shipments:read","shipments:create","events:create"]`, `["10.20.6.40"]`, "edi@" + worldDomain, 230, false, true, 12 * time.Minute},
		{"Customs Gateway (Passar/ATLAS)", `["shipments:read","customs:write"]`, `["10.20.6.45"]`, "zoll@" + worldDomain, 410, false, true, 2 * time.Hour},
		{"Driver App Android", `["events:create","shipments:read"]`, `[]`, "mobile@" + worldDomain, 520, false, true, 9 * time.Minute},
		{"Power BI Reporting", `["shipments:read","invoices:read"]`, `["10.20.6.60"]`, "bi@" + worldDomain, 700, false, true, 26 * time.Hour},
		{"EDI " + custName(3), `["tracking:read"]`, `[]`, "it@" + custDomain(3), 880, false, false, 190 * 24 * time.Hour},
	}
	var rows [][]any
	for i, x := range list {
		created := r.work(c.start.AddDate(0, 0, x.day))
		if created.After(c.now) {
			continue
		}
		secret := r.fakeBcrypt()
		if x.plain {
			secret = r.str(alnum, 40)
		}
		used := c.capNow(r, c.now.Add(-x.lastUsed-r.dur(0, x.lastUsed/3+time.Minute)))
		if used.Before(created) {
			used = created
		}
		rows = append(rows, []any{wdI(i + 1), x.name, r.uuid(), secret, x.scopes, x.ips, x.contact, wdT(used), wdBool(x.active),
			wdT(created), wdT(used)})
	}
	return wdTable("api_clients", append([]Column{wdc("id", "bigint(20) unsigned", "ai"), wdc("name", "varchar(255)", ""),
		wdc("client_id", "char(36)", "uni"), wdc("client_secret", "varchar(255)", ""), wdc("scopes", "text", "null"),
		wdc("allowed_ips", "text", "null"), wdc("contact_email", "varchar(255)", "null"), wdc("last_used_at", "timestamp", "null"),
		wdc("is_active", "tinyint(1)", "def=1")}, wdLaravelTS()...), rows)
}

func (c *wdCtx) settings(r wdRand) Table {
	admin := any(nil)
	if len(c.admins) > 0 {
		admin = c.admins[0]
	}
	kv := []struct{ key, value, typ, group string }{
		{"app.name", "Veltrona Connect", "string", "general"},
		{"app.maintenance", "0", "bool", "general"},
		{"app.maintenance_message", "Wegen Wartungsarbeiten ist Veltrona Connect am Samstag zwischen 22:00 und 02:00 Uhr nicht erreichbar.", "string", "general"},
		{"app.default_locale", "de_CH", "string", "general"},
		{"mail.from_address", "noreply-connect@" + worldDomain, "string", "mail"},
		{"mail.from_name", "Veltrona Connect", "string", "mail"},
		{"mail.support_address", "connect-support@" + worldDomain, "string", "mail"},
		{"mail.invoice_bcc", "debitoren@" + worldDomain, "string", "mail"},
		{"sap.bridge_url", "https://sap-bridge.internal.veltrona-group.com:8443/sap/opu/odata/sap/ZVLT_SHIPMENT_SRV", "string", "sap"},
		{"sap.client", "100", "string", "sap"},
		{"sap.username", "SVC_CONNECT_RFC", "string", "sap"},
		{"sap.sync_interval_minutes", "15", "int", "sap"},
		{"sap.sync_enabled", "1", "bool", "sap"},
		{"edi.sftp_host", "edi.veltrona-group.com", "string", "edi"},
		{"edi.sftp_user", "edi_inbound", "string", "edi"},
		{"edi.inbound_path", "/data/edi/inbound", "string", "edi"},
		{"tracking.public_enabled", "1", "bool", "tracking"},
		{"tracking.event_retention_days", "365", "int", "tracking"},
		{"tracking.archive_disk", "s3-archive", "string", "tracking"},
		{"invoices.storage_disk", "s3", "string", "invoices"},
		{"invoices.s3_bucket", "veltrona-connect-docs", "string", "invoices"},
		{"invoices.vat_rate_ch", fmt.Sprintf("%.1f", wdSwissVAT(c.now)), "string", "invoices"},
		{"invoices.number_prefix", "INV-", "string", "invoices"},
		{"invoices.reminder_days", "[14,28,42]", "json", "invoices"},
		{"security.password_min_length", "8", "int", "security"},
		{"security.login_throttle_attempts", "5", "int", "security"},
		{"security.2fa_enforced_for_admins", "0", "bool", "security"},
		{"security.session_lifetime_minutes", "480", "int", "security"},
		{"features.driver_app_beta", "1", "bool", "features"},
		{"features.customs_self_service", "0", "bool", "features"},
		{"portal.announcement", "Hinweis: Wegen der Feiertage gelten angepasste Abhol- und Zustellzeiten. Details erhalten Sie von Ihrer Kundenberatung.", "string", "portal"},
	}
	var rows [][]any
	created := c.goLive.Add(-3 * time.Hour)
	for i, x := range kv {
		upd := created
		var by any
		if r.chance(0.35) {
			upd = r.work(r.timeIn(created, c.now.AddDate(0, 0, -10)))
			by = admin
		}
		rows = append(rows, []any{wdI(i + 1), x.key, x.value, x.typ, x.group, by, wdT(created), wdT(upd)})
	}
	return wdTable("settings", append([]Column{wdc("id", "bigint(20) unsigned", "ai"), wdc("key", "varchar(191)", "uni"),
		wdc("value", "text", "null"), wdc("type", "varchar(20)", "def=string"), wdc("group", "varchar(50)", "def=general|mul"),
		wdc("updated_by", "bigint(20) unsigned", "null")}, wdLaravelTS()...), rows)
}

// ---------- veltrona_wp (WordPress 5.8.3) ----------

// wdZurich converts UTC to Europe/Zurich local time (EU DST rules, no tzdata needed).
func wdZurich(t time.Time) time.Time {
	t = t.UTC()
	lastSun := func(m time.Month) time.Time {
		d := time.Date(t.Year(), m+1, 1, 1, 0, 0, 0, time.UTC).AddDate(0, 0, -1)
		return d.AddDate(0, 0, -int(d.Weekday()))
	}
	if !t.Before(lastSun(time.March)) && t.Before(lastSun(time.October)) {
		return t.Add(2 * time.Hour)
	}
	return t.Add(time.Hour)
}

type wdPost struct {
	ID                                    int64
	Author                                int64
	Date, Modified                        time.Time
	Content, Title, Excerpt, Status, Name string
	CommentStatus, Type, Mime, GUID       string
	Parent                                int64
	CommentCount                          int
}

func wdBlocks(paras ...string) string {
	var b []string
	for _, p := range paras {
		b = append(b, "<!-- wp:paragraph -->\n<p>"+p+"</p>\n<!-- /wp:paragraph -->")
	}
	return strings.Join(b, "\n\n")
}

func (c *wdCtx) wpDB() Database {
	r := newWDRand(c.w, 20)
	const site = "https://www." + worldDomain + "/blog"
	blogStart := c.start.AddDate(0, 0, 1).Add(8*time.Hour + 14*time.Minute)
	var tables []Table

	// users
	users := append([]WPUser(nil), c.w.WPUsers...)
	sort.SliceStable(users, func(i, j int) bool { return users[i].ID < users[j].ID })
	byRole := map[string]int64{}
	reg := map[int]time.Time{}
	prev := blogStart.Add(-30 * time.Minute)
	var rows [][]any
	for i, u := range users {
		t := prev
		if i > 0 {
			t = r.work(prev.AddDate(0, 0, r.between(25, 330)))
			if lim := c.now.AddDate(0, 0, -(len(users)-i)*30); t.After(lim) {
				t = lim
			}
		}
		reg[u.ID] = t
		prev = t
		if byRole[u.Role] == 0 {
			byRole[u.Role] = int64(u.ID)
		}
		url := ""
		if _, d, _ := strings.Cut(u.Email, "@"); d != worldDomain {
			url = "https://www." + d
		}
		nice := strings.NewReplacer(".", "-", "_", "-", "@", "").Replace(strings.ToLower(u.Login))
		rows = append(rows, []any{wdI(u.ID), u.Login, u.Hash, nice, u.Email, url, wdT(t), "", int64(0), u.Display})
	}
	wpUsers := wdTable("wp_users", []Column{wdc("ID", "bigint(20) unsigned", "ai"), wdc("user_login", "varchar(60)", "mul|def="),
		wdc("user_pass", "varchar(255)", "def="), wdc("user_nicename", "varchar(50)", "mul|def="), wdc("user_email", "varchar(100)", "mul|def="),
		wdc("user_url", "varchar(100)", "def="), wdc("user_registered", "datetime", "def=0000-00-00 00:00:00"),
		wdc("user_activation_key", "varchar(255)", "def="), wdc("user_status", "int(11)", "def=0"),
		wdc("display_name", "varchar(250)", "def=")}, rows)
	if len(users) > 0 {
		wpUsers.AutoIncrement = int64(users[len(users)-1].ID) + 1
	}
	tables = append(tables, wpUsers)
	authorFor := func(roles ...string) int64 {
		for _, ro := range roles {
			if id := byRole[ro]; id != 0 {
				return id
			}
		}
		if len(users) > 0 {
			return int64(users[0].ID)
		}
		return 1
	}
	admin := authorFor("administrator")
	editor := authorFor("editor", "administrator")
	author := authorFor("author", "editor", "administrator")
	agency := admin
	for _, u := range users {
		if u.Role == "administrator" && int64(u.ID) != admin {
			agency = int64(u.ID)
		}
	}

	// posts
	var posts []*wdPost
	nextID := int64(1)
	newPost := func(t time.Time, authorID int64, typ, status, title, name, content string) *wdPost {
		p := &wdPost{ID: nextID, Author: authorID, Date: t, Modified: t, Content: content, Title: title, Status: status, Name: name,
			CommentStatus: "open", Type: typ}
		if typ == "page" {
			p.CommentStatus = "closed"
			p.GUID = fmt.Sprintf("%s/?page_id=%d", site, p.ID)
		} else {
			p.GUID = fmt.Sprintf("%s/?p=%d", site, p.ID)
		}
		nextID += 1 + int64(r.IntN(3))
		posts = append(posts, p)
		return p
	}
	t := blogStart
	newPost(t, admin, "post", "trash", "Hallo Welt!", "hallo-welt__trashed", wdBlocks("Willkommen bei WordPress. Dies ist dein erster Beitrag. Bearbeite oder lösche ihn und beginne mit dem Schreiben!"))
	nextID = 3
	priv := newPost(t, admin, "page", "publish", "Datenschutzerklärung", "datenschutzerklaerung", "<!-- wp:heading -->\n<h2>Verantwortliche Stelle</h2>\n<!-- /wp:heading -->\n\n"+
		wdBlocks("Verantwortlich für die Bearbeitung von Personendaten auf dieser Website ist die Veltrona Logistics AG, Baarerstrasse 78, 6300 Zug, Schweiz. Kontakt: datenschutz@"+worldDomain+".",
			"Wir bearbeiten Personendaten gemäss dem schweizerischen Datenschutzgesetz (DSG) und, soweit anwendbar, der DSGVO. Beim Besuch dieser Website werden IP-Adresse, Datum und Uhrzeit des Zugriffs sowie der verwendete Browser in Logfiles gespeichert und nach 90 Tagen gelöscht."))
	nextID = 6
	t = blogStart.AddDate(0, 0, 2)
	newPost(t, agency, "page", "publish", "Über uns", "ueber-uns", wdBlocks(
		"Die Veltrona Logistics AG mit Sitz in Zug ist ein unabhängiges Speditions- und Kontraktlogistikunternehmen. Rund 1450 Mitarbeitende an Standorten in Zürich, Basel, Frankfurt am Main, Mailand, Rotterdam und Warschau organisieren Transporte auf Strasse, Schiene, See und in der Luft.",
		"Unsere Kunden aus Industrie, Pharma und Handel vertrauen uns seit über 30 Jahren. Mit Veltrona Connect behalten sie ihre Sendungen, Zolldokumente und Rechnungen jederzeit im Blick."))
	cf7 := newPost(t.Add(25*time.Minute), agency, "wpcf7_contact_form", "publish", "Kontaktformular 1", "kontaktformular-1",
		"<label> Ihr Name (Pflichtfeld)\n    [text* your-name] </label>\n\n<label> Firma\n    [text your-company] </label>\n\n<label> Ihre E-Mail-Adresse (Pflichtfeld)\n    [email* your-email] </label>\n\n<label> Betreff\n    [text your-subject] </label>\n\n<label> Ihre Nachricht\n    [textarea your-message] </label>\n\n[submit \"Senden\"]")
	cf7.CommentStatus = "closed"
	newPost(t.Add(40*time.Minute), agency, "page", "publish", "Kontakt", "kontakt", "<!-- wp:paragraph -->\n<p>Veltrona Logistics AG, Baarerstrasse 78, 6300 Zug, Telefon +41 41 768 20 00</p>\n<!-- /wp:paragraph -->\n\n<!-- wp:shortcode -->\n"+
		fmt.Sprintf(`[contact-form-7 id="%d" title="Kontaktformular 1"]`, cf7.ID)+"\n<!-- /wp:shortcode -->")
	newPost(t.Add(70*time.Minute), agency, "page", "publish", "Karriere", "karriere", wdBlocks(
		"Wir suchen laufend Disponentinnen und Disponenten, Zolldeklarantinnen und Zolldeklaranten sowie Berufsfahrer (Kat. C/CE) für unsere Standorte in der Schweiz und in Deutschland.",
		"Offene Stellen und Lehrstellen finden Sie auf jobs."+worldDomain+". Spontanbewerbungen senden Sie bitte an hr@"+worldDomain+"."))

	type article struct {
		title, slug, cat string
		by               int64
		paras            []string
		image            string
	}
	arts := []article{
		{"Neue Bahnverbindung Basel-Rotterdam: dreimal pro Woche auf der Schiene", "neue-bahnverbindung-basel-rotterdam", "Unternehmen", editor, []string{
			"Ab sofort verbinden wir unseren Terminal im Basler Rheinhafen dreimal wöchentlich per Ganzzug mit Rotterdam Waalhaven. Die Laufzeit beträgt im Regelbetrieb 38 Stunden von Terminal zu Terminal.",
			"Für unsere Kunden bedeutet das mehr Planbarkeit bei Seefracht-Exporten und rund 70 Prozent weniger CO₂ gegenüber dem reinen Strassentransport. Buchungen sind wie gewohnt über Veltrona Connect oder Ihre Kundenberaterin möglich."}, "rheinhafen-basel"},
		{"Veltrona erhält GDP-Zertifizierung für den Hub Rümlang", "gdp-zertifizierung-hub-ruemlang", "Unternehmen", editor, []string{
			"Unser Hub in Rümlang beim Flughafen Zürich ist nach den Leitlinien der Good Distribution Practice (GDP) zertifiziert. Damit können wir pharmazeutische Produkte im Bereich 2-8 °C und 15-25 °C lückenlos lagern und umschlagen.",
			"Die Temperaturdaten jeder Sendung sind im Kundenportal einsehbar und werden zehn Jahre archiviert."}, ""},
		{"Air Freight Update: additional capacity Zurich-Chicago", "air-freight-update-zurich-chicago", "Branchennews", author, []string{
			"Together with our airline partners we have secured additional weekly main-deck capacity on the Zurich-Chicago lane. Cut-off at our Rümlang hub is Tuesday and Thursday 14:00.",
			"Please contact your account manager for spot rates or book directly in Veltrona Connect."}, ""},
		{"Zollabfertigung mit Passar: Was Schweizer Exporteure wissen müssen", "zollabfertigung-passar-exporteure", "Zoll & Compliance", editor, []string{
			"Das BAZG löst e-dec schrittweise durch das neue System Passar ab. Für Exporteure ändern sich vor allem die Datenanforderungen an die Ausfuhranmeldung.",
			"Unsere Zollspezialistinnen und -spezialisten in Basel und Zürich begleiten die Umstellung. Bitte stellen Sie sicher, dass Handelsrechnungen künftig Zolltarifnummer und Warenursprung je Position enthalten."}, ""},
		{"Zwölf neue Elektro-LKW für die Region Zürich", "zwoelf-neue-elektro-lkw-region-zuerich", "Nachhaltigkeit", author, []string{
			"Seit diesem Monat sind zwölf vollelektrische 26-Tonner in der Verteilung rund um Zürich und Zug unterwegs. Die Fahrzeuge werden nachts im Hub Rümlang mit Strom aus erneuerbaren Quellen geladen.",
			"Bis Ende des nächsten Jahres soll die Hälfte unserer Verteilerflotte in der Schweiz elektrisch fahren."}, "e-lkw-ruemlang"},
		{"Sendungsverfolgung jetzt auch per API", "sendungsverfolgung-per-api", "Unternehmen", editor, []string{
			"Kundinnen und Kunden von Veltrona Connect können Sendungsstatus ab sofort direkt in ihr ERP übernehmen. Die REST-Schnittstelle liefert Statusmeldungen, ETA und Zolldokumente im JSON-Format.",
			"API-Zugangsdaten erhalten Sie in Ihrem Benutzerkonto unter «Einstellungen &gt; API-Zugriff»."}, ""},
		{"New office in Warsaw strengthens our Eastern Europe network", "new-office-warsaw", "Unternehmen", author, []string{
			"Veltrona Logistics has opened a new branch and cross-dock facility in Warsaw. The team of 18 handles groupage traffic between Poland, Switzerland, Germany and Italy.",
			"Daily departures to our hubs in Frankfurt and Zurich ensure transit times of 48 to 72 hours."}, ""},
		{"Seefracht ab Fernost: Buchungsfristen für die Peak Season", "seefracht-fernost-peak-season", "Branchennews", editor, []string{
			"Wie jedes Jahr erwarten wir ab September knappe Kapazitäten auf den Routen ab Shanghai, Ningbo und Shenzhen. Wir empfehlen, Buchungen mindestens drei Wochen vor dem gewünschten Abfahrtsdatum zu platzieren.",
			"Für Kunden mit Jahreskontrakten sind Allokationen auf den Diensten nach Rotterdam und Hamburg gesichert."}, ""},
		{"Niedrigwasser am Rhein: Auswirkungen auf Binnenschiff-Verkehre", "niedrigwasser-rhein-binnenschiff", "Branchennews", editor, []string{
			"Aufgrund des tiefen Pegels in Kaub können Binnenschiffe derzeit nur mit reduzierter Abladetiefe verkehren. Es fallen Kleinwasserzuschläge an, die wir transparent an unsere Kunden weitergeben.",
			"Wo möglich verlagern wir Container auf die Schiene. Bitte rechnen Sie mit Laufzeitverlängerungen von zwei bis vier Tagen."}, ""},
	}
	type metaRow struct {
		post     int64
		key, val string
	}
	var meta []metaRow
	cats := []string{"Allgemein", "Branchennews", "Unternehmen", "Nachhaltigkeit", "Zoll & Compliance"}
	postCat := map[int64]int{}
	span := c.now.AddDate(0, 0, -100).Sub(blogStart.AddDate(0, 0, 20))
	var published []*wdPost
	for i, a := range arts {
		frac := (float64(i) + 0.15 + r.Float64()*0.6) / float64(len(arts))
		frac = math.Pow(frac, 1.25) // the blog got quieter over time
		pt := r.work(blogStart.AddDate(0, 0, 20).Add(time.Duration(float64(span) * frac)))
		var img *wdPost
		if a.image != "" {
			img = newPost(pt.Add(-40*time.Minute), a.by, "attachment", "inherit", a.image, a.image, "")
			img.Mime, img.CommentStatus = "image/jpeg", "open"
			ym := wdZurich(img.Date).Format("2006/01")
			img.GUID = fmt.Sprintf("%s/wp-content/uploads/%s/%s.jpg", site, ym, a.image)
			meta = append(meta, metaRow{img.ID, "_wp_attached_file", ym + "/" + a.image + ".jpg"},
				metaRow{img.ID, "_wp_attachment_metadata", wdPHP(wdArr{{"width", 1920}, {"height", 1280},
					{"file", ym + "/" + a.image + ".jpg"}, {"sizes", wdArr{
						{"medium", wdArr{{"file", a.image + "-300x200.jpg"}, {"width", 300}, {"height", 200}, {"mime-type", "image/jpeg"}}},
						{"large", wdArr{{"file", a.image + "-1024x683.jpg"}, {"width", 1024}, {"height", 683}, {"mime-type", "image/jpeg"}}},
						{"thumbnail", wdArr{{"file", a.image + "-150x150.jpg"}, {"width", 150}, {"height", 150}, {"mime-type", "image/jpeg"}}}}},
					{"image_meta", wdArr{{"aperture", "0"}, {"credit", ""}, {"camera", ""}, {"caption", ""}, {"created_timestamp", "0"},
						{"copyright", ""}, {"focal_length", "0"}, {"iso", "0"}, {"shutter_speed", "0"}, {"title", ""},
						{"orientation", "0"}, {"keywords", wdArr{}}}}})})
		}
		content := wdBlocks(a.paras...)
		p := newPost(pt, a.by, "post", "publish", a.title, a.slug, content)
		p.Modified = pt.Add(r.dur(10*time.Minute, 30*24*time.Hour))
		if p.Modified.After(c.now) {
			p.Modified = pt
		}
		if img != nil {
			img.Parent = p.ID
			meta = append(meta, metaRow{p.ID, "_thumbnail_id", strconv.FormatInt(img.ID, 10)})
		}
		for ci, name := range cats {
			if name == a.cat {
				postCat[p.ID] = ci
			}
		}
		meta = append(meta, metaRow{p.ID, "_edit_last", strconv.FormatInt(a.by, 10)},
			metaRow{p.ID, "_edit_lock", fmt.Sprintf("%d:%d", p.Modified.Unix()+int64(r.between(30, 900)), a.by)},
			metaRow{p.ID, "_yoast_wpseo_metadesc", strings.SplitN(a.paras[0], ". ", 2)[0] + "."})
		if r.chance(0.6) {
			rev := newPost(p.Modified, a.by, "revision", "inherit", a.title, fmt.Sprintf("%d-revision-v1", p.ID), content)
			rev.Parent, rev.CommentStatus, rev.GUID = p.ID, "closed", fmt.Sprintf("%s/?p=%d", site, rev.ID)
		}
		published = append(published, p)
	}
	draft := newPost(r.work(c.now.AddDate(0, 0, -r.between(140, 260))), author, "post", "draft", "Jahresrückblick: Was uns bewegt hat", "",
		wdBlocks("ENTWURF - Zahlen vom Controlling noch ausstehend (Sendungsvolumen, Kundenzufriedenheit, CO₂-Bilanz). Bitte vor Veröffentlichung mit Sandra abstimmen."))
	meta = append(meta, metaRow{draft.ID, "_edit_lock", fmt.Sprintf("%d:%d", draft.Date.Unix()+600, author)})
	meta = append(meta, metaRow{cf7.ID, "_form", cf7.Content},
		metaRow{cf7.ID, "_mail", wdPHP(wdArr{{"active", true}, {"subject", "Veltrona Website: [your-subject]"},
			{"sender", "Veltrona Website <wordpress@" + worldDomain + ">"}, {"recipient", "marketing@" + worldDomain},
			{"body", "Von: [your-name] <[your-email]>\nFirma: [your-company]\nBetreff: [your-subject]\n\nNachricht:\n[your-message]\n\n-- \nDiese E-Mail wurde über das Kontaktformular auf Veltrona Logistics (" + site + ") gesendet."},
			{"additional_headers", "Reply-To: [your-email]"}, {"attachments", ""}, {"use_html", false}, {"exclude_blank", false}})},
		metaRow{cf7.ID, "_locale", "de_CH"})
	for _, p := range posts {
		if p.Type == "page" {
			meta = append(meta, metaRow{p.ID, "_wp_page_template", "default"})
		}
	}
	meta = append(meta, metaRow{1, "_wp_trash_meta_status", "publish"}, metaRow{1, "_wp_trash_meta_time", strconv.FormatInt(blogStart.Add(3*time.Hour).Unix(), 10)},
		metaRow{1, "_wp_desired_post_slug", "hallo-welt"})

	// comments
	type cm struct {
		post                         *wdPost
		author, email, url, ip, text string
		approved, typ, agent         string
		user                         int64
		at                           time.Time
		parent                       int
	}
	var comments []cm
	if len(published) >= 6 {
		p1, p2, p3, p4 := published[0], published[1], published[3], published[5]
		after := func(p *wdPost, d int) time.Time { return c.capNow(r, r.work(p.Date.AddDate(0, 0, d))) }
		comments = append(comments,
			cm{p1, "Thomas Gerber", "t.gerber@gerber-praezisionsteile.ch", "", "85.2." + strconv.Itoa(r.between(1, 254)) + "." + strconv.Itoa(r.between(2, 253)), "Gibt es für die Bahnverbindung auch Teilladungen (LCL) oder nur komplette Container?", "1", "comment", wdUA(0, p1.Date), 0, after(p1, 2), 0},
			cm{p1, "", "", "", "10.20.10.57", "Hallo Herr Gerber, aktuell bieten wir nur FCL an. LCL ab Basel ist für das nächste Quartal geplant. Ihre Kundenberaterin meldet sich bei Ihnen.", "1", "comment", wdUA(1, p1.Date), editor, after(p1, 3), 1},
			cm{p2, "Martina Odermatt", "martina.odermatt@seetal-pharma.ch", "", "178.197." + strconv.Itoa(r.between(1, 254)) + "." + strconv.Itoa(r.between(2, 253)), "Gratulation! Ist die Zertifizierung auch für Betäubungsmittel (BetmG) gültig?", "1", "comment", wdUA(4, p2.Date), 0, after(p2, 5), 0},
			cm{p3, "Linkbuilder Pro", "seo.outreach.team@gmail.com", "https://bit.ly/3xQm8Zr", "103.152.118." + strconv.Itoa(r.between(2, 250)), "Great article! I really like your content. We can help you get more traffic with high DA backlinks, check our offer.", "spam", "comment", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36", 0, after(p3, 9), 0},
			cm{p3, "Logistik-Blog", "", "https://www.logistik-heute-news.de/zoll/passar-umstellung-exporteure", "195.201." + strconv.Itoa(r.between(1, 254)) + ".17", "[&#8230;] Mehr dazu im Beitrag von Veltrona Logistics zu Passar [&#8230;]", "1", "pingback", "WordPress/5.9; https://www.logistik-heute-news.de", 0, after(p3, 12), 0},
			cm{p4, "casino bonus", "info@slotsbonus24.online", "https://slotsbonus24.online", "45.155.205." + strconv.Itoa(r.between(2, 250)), "Free spins no deposit, best online casino bonus here >>> slotsbonus24 online", "spam", "comment", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0", 0, after(p4, 20), 0},
			cm{p4, "Kevin Brandl", "kevin.brandl@brandl-agrartechnik.at", "", "84.112." + strconv.Itoa(r.between(1, 254)) + "." + strconv.Itoa(r.between(2, 253)), "Bekommen wir als Bestandskunde die API-Zugangsdaten automatisch oder müssen wir sie beantragen?", "0", "comment", wdUA(2, p4.Date), 0, after(p4, 4), 0},
			cm{published[len(published)-1], "Pharmacy Online", "orders@rx-cheap-meds.su", "https://rx-cheap-meds.su", "91.240.118." + strconv.Itoa(r.between(2, 250)), "buy cialis online without prescription fast shipping to Switzerland", "spam", "comment", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36", 0, after(published[len(published)-1], 30), 0},
		)
	}
	sort.SliceStable(comments, func(i, j int) bool { return comments[i].at.Before(comments[j].at) })
	rows = nil
	for i, x := range comments {
		if x.approved == "1" {
			x.post.CommentCount++
		}
		au, em, url := x.author, x.email, x.url
		if x.user != 0 {
			for _, u := range users {
				if int64(u.ID) == x.user {
					au, em, url = u.Display, u.Email, ""
				}
			}
		}
		parent := int64(0)
		if x.parent != 0 {
			for j, y := range comments {
				if y.post == x.post && y.parent == 0 && j < i {
					parent = int64(j + 1)
				}
			}
		}
		rows = append(rows, []any{wdI(i + 1), x.post.ID, au, em, url, x.ip, wdT(wdZurich(x.at)), wdT(x.at), x.text, int64(0),
			x.approved, x.agent, x.typ, parent, x.user})
	}
	tables = append(tables, wdTable("wp_comments", []Column{wdc("comment_ID", "bigint(20) unsigned", "ai"),
		wdc("comment_post_ID", "bigint(20) unsigned", "mul|def=0"), wdc("comment_author", "tinytext", ""),
		wdc("comment_author_email", "varchar(100)", "mul|def="), wdc("comment_author_url", "varchar(200)", "def="),
		wdc("comment_author_IP", "varchar(100)", "def="), wdc("comment_date", "datetime", "def=0000-00-00 00:00:00"),
		wdc("comment_date_gmt", "datetime", "mul|def=0000-00-00 00:00:00"), wdc("comment_content", "text", ""),
		wdc("comment_karma", "int(11)", "def=0"), wdc("comment_approved", "varchar(20)", "mul|def=1"),
		wdc("comment_agent", "varchar(255)", "def="), wdc("comment_type", "varchar(20)", "def=comment"),
		wdc("comment_parent", "bigint(20) unsigned", "mul|def=0"), wdc("user_id", "bigint(20) unsigned", "mul|def=0")}, rows))
	tables = append(tables, wdTable("wp_commentmeta", []Column{wdc("meta_id", "bigint(20) unsigned", "ai"),
		wdc("comment_id", "bigint(20) unsigned", "mul|def=0"), wdc("meta_key", "varchar(255)", "null|mul"), wdc("meta_value", "longtext", "null")}, nil))
	tables = append(tables, wdTable("wp_links", []Column{wdc("link_id", "bigint(20) unsigned", "ai"), wdc("link_url", "varchar(255)", "def="),
		wdc("link_name", "varchar(255)", "def="), wdc("link_image", "varchar(255)", "def="), wdc("link_target", "varchar(25)", "def="),
		wdc("link_description", "varchar(255)", "def="), wdc("link_visible", "varchar(20)", "mul|def=Y"),
		wdc("link_owner", "bigint(20) unsigned", "def=1"), wdc("link_rating", "int(11)", "def=0"),
		wdc("link_updated", "datetime", "def=0000-00-00 00:00:00"), wdc("link_rel", "varchar(255)", "def="),
		wdc("link_notes", "mediumtext", ""), wdc("link_rss", "varchar(255)", "def=")}, nil))

	// posts table
	rows = nil
	for _, p := range posts {
		rows = append(rows, []any{p.ID, p.Author, wdT(wdZurich(p.Date)), wdT(p.Date), p.Content, p.Title, p.Excerpt, p.Status,
			p.CommentStatus, map[bool]string{true: "closed", false: "open"}[p.Type != "post"], "", p.Name, "", "",
			wdT(wdZurich(p.Modified)), wdT(p.Modified), "", p.Parent, p.GUID, int64(0), p.Type, p.Mime, int64(p.CommentCount)})
	}
	if draft != nil {
		for _, row := range rows {
			if row[0].(int64) == draft.ID {
				row[3] = "0000-00-00 00:00:00" // drafts have no GMT date
			}
		}
	}
	tables = append(tables, wdTable("wp_posts", []Column{wdc("ID", "bigint(20) unsigned", "ai"),
		wdc("post_author", "bigint(20) unsigned", "mul|def=0"), wdc("post_date", "datetime", "def=0000-00-00 00:00:00"),
		wdc("post_date_gmt", "datetime", "def=0000-00-00 00:00:00"), wdc("post_content", "longtext", ""), wdc("post_title", "text", ""),
		wdc("post_excerpt", "text", ""), wdc("post_status", "varchar(20)", "def=publish"), wdc("comment_status", "varchar(20)", "def=open"),
		wdc("ping_status", "varchar(20)", "def=open"), wdc("post_password", "varchar(255)", "def="), wdc("post_name", "varchar(200)", "mul|def="),
		wdc("to_ping", "text", ""), wdc("pinged", "text", ""), wdc("post_modified", "datetime", "def=0000-00-00 00:00:00"),
		wdc("post_modified_gmt", "datetime", "def=0000-00-00 00:00:00"), wdc("post_content_filtered", "longtext", ""),
		wdc("post_parent", "bigint(20) unsigned", "mul|def=0"), wdc("guid", "varchar(255)", "def="), wdc("menu_order", "int(11)", "def=0"),
		wdc("post_type", "varchar(20)", "mul|def=post"), wdc("post_mime_type", "varchar(100)", "def="),
		wdc("comment_count", "bigint(20)", "def=0")}, rows))

	rows = nil
	for i, m := range meta {
		rows = append(rows, []any{wdI(i + 1), m.post, m.key, m.val})
	}
	tables = append(tables, wdTable("wp_postmeta", []Column{wdc("meta_id", "bigint(20) unsigned", "ai"),
		wdc("post_id", "bigint(20) unsigned", "mul|def=0"), wdc("meta_key", "varchar(255)", "null|mul"), wdc("meta_value", "longtext", "null")}, rows))

	// terms
	counts := make([]int, len(cats))
	for _, ci := range postCat {
		counts[ci]++
	}
	rows = nil
	var ttRows, relRows [][]any
	for i, name := range cats {
		slug := []string{"allgemein", "branchennews", "unternehmen", "nachhaltigkeit", "zoll-und-compliance"}[i]
		rows = append(rows, []any{wdI(i + 1), name, slug, int64(0)})
		ttRows = append(ttRows, []any{wdI(i + 1), wdI(i + 1), "category", "", int64(0), wdI(counts[i])})
	}
	rows = append(rows, []any{wdI(len(cats) + 1), "Hauptmenü", "hauptmenue", int64(0)})
	ttRows = append(ttRows, []any{wdI(len(cats) + 1), wdI(len(cats) + 1), "nav_menu", "", int64(0), int64(0)})
	for _, p := range posts {
		if ci, ok := postCat[p.ID]; ok {
			relRows = append(relRows, []any{p.ID, wdI(ci + 1), int64(0)})
		}
	}
	relRows = append(relRows, []any{draft.ID, int64(1), int64(0)})
	tables = append(tables,
		wdTable("wp_terms", []Column{wdc("term_id", "bigint(20) unsigned", "ai"), wdc("name", "varchar(200)", "mul|def="),
			wdc("slug", "varchar(200)", "mul|def="), wdc("term_group", "bigint(10)", "def=0")}, rows),
		wdTable("wp_term_taxonomy", []Column{wdc("term_taxonomy_id", "bigint(20) unsigned", "ai"),
			wdc("term_id", "bigint(20) unsigned", "mul|def=0"), wdc("taxonomy", "varchar(32)", "mul|def="),
			wdc("description", "longtext", ""), wdc("parent", "bigint(20) unsigned", "def=0"), wdc("count", "bigint(20)", "def=0")}, ttRows),
		wdTable("wp_term_relationships", []Column{wdc("object_id", "bigint(20) unsigned", "pk|def=0"),
			wdc("term_taxonomy_id", "bigint(20) unsigned", "pk|def=0"), wdc("term_order", "int(11)", "def=0")}, relRows),
		wdTable("wp_termmeta", []Column{wdc("meta_id", "bigint(20) unsigned", "ai"), wdc("term_id", "bigint(20) unsigned", "mul|def=0"),
			wdc("meta_key", "varchar(255)", "null|mul"), wdc("meta_value", "longtext", "null")}, nil))

	// usermeta
	rows = nil
	umID := int64(0)
	um := func(user int, k, v string) {
		umID++
		rows = append(rows, []any{umID, wdI(user), k, v})
	}
	level := map[string]string{"administrator": "10", "editor": "7", "author": "2", "contributor": "1", "subscriber": "0"}
	for _, u := range users {
		first, last := "", ""
		if strings.Contains(u.Login, ".") {
			first, last, _ = strings.Cut(u.Display, " ")
		}
		um(u.ID, "nickname", u.Login)
		um(u.ID, "first_name", first)
		um(u.ID, "last_name", last)
		um(u.ID, "description", "")
		um(u.ID, "rich_editing", "true")
		um(u.ID, "syntax_highlighting", "true")
		um(u.ID, "comment_shortcuts", "false")
		um(u.ID, "admin_color", "fresh")
		um(u.ID, "use_ssl", "0")
		um(u.ID, "show_admin_bar_front", "true")
		um(u.ID, "locale", "")
		um(u.ID, "wp_capabilities", wdPHP(wdArr{{u.Role, true}}))
		um(u.ID, "wp_user_level", level[u.Role])
		um(u.ID, "dismissed_wp_pointers", "")
		if u.Role == "administrator" {
			um(u.ID, "show_welcome_panel", "0")
		}
		last1 := c.capNow(r, r.work(c.now.AddDate(0, 0, -r.between(3, 200))))
		if last1.Before(reg[u.ID]) {
			last1 = reg[u.ID].Add(time.Hour)
		}
		um(u.ID, "wp_dashboard_quick_press_last_post_id", strconv.FormatInt(nextID+int64(u.ID), 10))
		um(u.ID, "wp_user-settings", "libraryContent=browse&editor=tinymce&mfold=o")
		um(u.ID, "wp_user-settings-time", strconv.FormatInt(last1.Unix(), 10))
		if int64(u.ID) == admin || u.Role == "editor" {
			ip := "10.20.10." + strconv.Itoa(r.between(30, 199))
			um(u.ID, "session_tokens", wdPHP(wdArr{{r.hex(64), wdArr{{"expiration", last1.Add(14 * 24 * time.Hour).Unix()},
				{"ip", ip}, {"ua", wdUA(int(u.ID), last1)}, {"login", last1.Unix()}}}}))
			um(u.ID, "community-events-location", wdPHP(wdArr{{"ip", "10.20.10.0"}}))
		}
	}
	tables = append(tables, wdTable("wp_usermeta", []Column{wdc("umeta_id", "bigint(20) unsigned", "ai"),
		wdc("user_id", "bigint(20) unsigned", "mul|def=0"), wdc("meta_key", "varchar(255)", "null|mul"), wdc("meta_value", "longtext", "null")}, rows))

	tables = append(tables, c.wpOptions(r, site, blogStart, priv.ID))
	sort.SliceStable(tables, func(i, j int) bool { return tables[i].Name < tables[j].Name })
	return Database{Name: worldWPDB, Tables: tables}
}

func wdCaps(names ...string) wdArr {
	var a wdArr
	for _, n := range names {
		a = append(a, wdKV{n, true})
	}
	return a
}

func wdLevels(max int) []string {
	var out []string
	for i := max; i >= 0; i-- {
		out = append(out, "level_"+strconv.Itoa(i))
	}
	return out
}

func (c *wdCtx) wpOptions(r wdRand, site string, blogStart time.Time, privacyID int64) Table {
	editorCaps := append([]string{"moderate_comments", "manage_categories", "manage_links", "upload_files", "unfiltered_html",
		"edit_posts", "edit_others_posts", "edit_published_posts", "publish_posts", "edit_pages", "read"}, wdLevels(7)...)
	editorCaps = append(editorCaps, "edit_others_pages", "edit_published_pages", "publish_pages", "delete_pages", "delete_others_pages",
		"delete_published_pages", "delete_posts", "delete_others_posts", "delete_published_posts", "delete_private_posts",
		"edit_private_posts", "read_private_posts", "delete_private_pages", "edit_private_pages", "read_private_pages")
	adminCaps := append([]string{"switch_themes", "edit_themes", "activate_plugins", "edit_plugins", "edit_users", "edit_files",
		"manage_options", "moderate_comments", "manage_categories", "manage_links", "upload_files", "import", "unfiltered_html",
		"edit_posts", "edit_others_posts", "edit_published_posts", "publish_posts", "edit_pages", "read"}, wdLevels(10)...)
	adminCaps = append(adminCaps, "edit_others_pages", "edit_published_pages", "publish_pages", "delete_pages", "delete_others_pages",
		"delete_published_pages", "delete_posts", "delete_others_posts", "delete_published_posts", "delete_private_posts",
		"edit_private_posts", "read_private_posts", "delete_private_pages", "edit_private_pages", "read_private_pages", "delete_users",
		"create_users", "unfiltered_upload", "edit_dashboard", "update_plugins", "delete_plugins", "install_plugins", "update_themes",
		"install_themes", "update_core", "list_users", "remove_users", "promote_users", "edit_theme_options", "delete_themes", "export",
		"wpseo_manage_options", "wpcf7_edit_contact_forms", "wpcf7_read_contact_forms", "wpcf7_delete_contact_forms",
		"wpcf7_manage_integration", "wpcf7_submit", "export_others_personal_data", "erase_others_personal_data")
	roles := wdArr{
		{"administrator", wdArr{{"name", "Administrator"}, {"capabilities", wdCaps(adminCaps...)}}},
		{"editor", wdArr{{"name", "Editor"}, {"capabilities", wdCaps(editorCaps...)}}},
		{"author", wdArr{{"name", "Author"}, {"capabilities", wdCaps("upload_files", "edit_posts", "edit_published_posts", "publish_posts",
			"read", "level_2", "level_1", "level_0", "delete_posts", "delete_published_posts")}}},
		{"contributor", wdArr{{"name", "Contributor"}, {"capabilities", wdCaps("edit_posts", "read", "level_1", "level_0", "delete_posts")}}},
		{"subscriber", wdArr{{"name", "Subscriber"}, {"capabilities", wdCaps("read", "level_0")}}},
		{"wpseo_manager", wdArr{{"name", "SEO Manager"}, {"capabilities", wdCaps("read", "edit_posts", "edit_others_posts", "wpseo_manage_options", "wpseo_bulk_edit")}}},
		{"wpseo_editor", wdArr{{"name", "SEO Editor"}, {"capabilities", wdCaps("read", "edit_posts", "edit_others_posts", "wpseo_bulk_edit")}}},
	}
	cronBase := c.now.Add(-time.Duration(r.IntN(3600)) * time.Second).Unix()
	ev := func(off int64, hook, sched string, interval int) wdKV {
		inner := wdArr{{"schedule", sched}, {"args", wdArr{}}}
		if sched != "" {
			inner = append(inner, wdKV{"interval", interval})
		} else {
			inner[0].V = false
		}
		return wdKV{cronBase + off, wdArr{{hook, wdArr{{"40cd750bba9870f18aada2478b24840a", inner}}}}}
	}
	cron := wdArr{ev(312, "wp_privacy_delete_old_export_files", "hourly", 3600), ev(1904, "wp_version_check", "twicedaily", 43200),
		ev(1905, "wp_update_plugins", "twicedaily", 43200), ev(1906, "wp_update_themes", "twicedaily", 43200),
		ev(5513, "wpseo-reindex-links", "daily", 86400), ev(9121, "wp_scheduled_delete", "daily", 86400),
		ev(9140, "delete_expired_transients", "daily", 86400), ev(20311, "duplicator_pro_cleanup", "daily", 86400),
		ev(43012, "wp_site_health_scheduled_check", "weekly", 604800), {"version", 2}}
	theme := wdArr{{0, false}, {"nav_menu_locations", wdArr{{"primary", 6}}}, {"custom_css_post_id", -1},
		{"header_textcolor", "1a2b4c"}, {"custom_logo", 0}}
	smtpPass := make([]byte, 0, 48)
	for i := 0; i < 48; i++ {
		smtpPass = append(smtpPass, wdBcryptAlpha[2+r.IntN(62)])
	}
	opts := []struct{ k, v, auto string }{
		{"siteurl", site, "yes"}, {"home", site, "yes"}, {"blogname", "Veltrona Logistics Blog", "yes"},
		{"blogdescription", "News und Insights aus der Logistik", "yes"}, {"users_can_register", "0", "yes"},
		{"admin_email", "webmaster@" + worldDomain, "yes"}, {"start_of_week", "1", "yes"}, {"use_balanceTags", "0", "yes"},
		{"use_smilies", "1", "yes"}, {"require_name_email", "1", "yes"}, {"comments_notify", "1", "yes"},
		{"posts_per_rss", "10", "yes"}, {"rss_use_excerpt", "0", "yes"}, {"default_category", "1", "yes"}, {"default_comment_status", "open", "yes"}, {"default_ping_status", "open", "yes"},
		{"default_pingback_flag", "1", "yes"}, {"posts_per_page", "10", "yes"}, {"date_format", "j. F Y", "yes"},
		{"time_format", "H:i", "yes"}, {"links_updated_date_format", "j. F Y G:i", "yes"}, {"comment_moderation", "0", "yes"},
		{"moderation_notify", "1", "yes"}, {"permalink_structure", "/%year%/%monthnum%/%postname%/", "yes"},
		{"hack_file", "0", "yes"}, {"blog_charset", "UTF-8", "yes"}, {"active_plugins", wdPHP(wdList(
			"classic-editor/classic-editor.php", "contact-form-7/wp-contact-form-7.php", "duplicator/duplicator.php",
			"wp-file-manager/file_folder_manager.php", "wp-mail-smtp/wp_mail_smtp.php", "wordpress-seo/wp-seo.php")), "yes"},
		{"category_base", "", "yes"}, {"ping_sites", "http://rpc.pingomatic.com/", "yes"}, {"comment_max_links", "2", "yes"},
		{"gmt_offset", "", "yes"}, {"default_email_category", "1", "yes"}, {"recently_edited", "", "no"},
		{"template", "astra", "yes"}, {"stylesheet", "veltrona-child", "yes"}, {"comment_registration", "0", "yes"},
		{"html_type", "text/html", "yes"}, {"use_trackback", "0", "yes"}, {"default_role", "subscriber", "yes"},
		{"db_version", "49752", "yes"}, {"uploads_use_yearmonth_folders", "1", "yes"}, {"upload_path", "", "yes"},
		{"blog_public", "1", "yes"}, {"default_link_category", "2", "yes"}, {"show_on_front", "posts", "yes"},
		{"tag_base", "", "yes"}, {"show_avatars", "1", "yes"}, {"avatar_rating", "G", "yes"}, {"upload_url_path", "", "yes"},
		{"thumbnail_size_w", "150", "yes"}, {"thumbnail_size_h", "150", "yes"}, {"thumbnail_crop", "1", "yes"},
		{"medium_size_w", "300", "yes"}, {"medium_size_h", "300", "yes"}, {"large_size_w", "1024", "yes"}, {"large_size_h", "1024", "yes"},
		{"timezone_string", "Europe/Zurich", "yes"}, {"page_for_posts", "0", "yes"}, {"page_on_front", "0", "yes"},
		{"default_post_format", "0", "yes"}, {"initial_db_version", "44719", "yes"},
		{"wp_user_roles", wdPHP(roles), "yes"}, {"fresh_site", "0", "yes"}, {"WPLANG", "de_CH", "yes"},
		{"wp_page_for_privacy_policy", strconv.FormatInt(privacyID, 10), "yes"}, {"show_comments_cookies_opt_in", "1", "yes"},
		{"admin_email_lifespan", strconv.FormatInt(c.now.AddDate(0, 0, -r.between(10, 150)).Unix(), 10), "yes"},
		{"disallowed_keys", "", "no"}, {"comment_previously_approved", "1", "yes"}, {"auto_plugin_theme_update_emails", "a:0:{}", "no"},
		{"auto_update_core_dev", "enabled", "yes"}, {"auto_update_core_minor", "enabled", "yes"}, {"auto_update_core_major", "unset", "yes"},
		{"finished_updating_comment_type", "1", "yes"}, {"cron", wdPHP(cron), "yes"},
		{"theme_mods_veltrona-child", wdPHP(theme), "yes"}, {"recovery_keys", "a:0:{}", "yes"}, {"https_detection_errors", "a:0:{}", "yes"},
		{"can_compress_scripts", "1", "no"}, {"db_upgraded", "", "yes"}, {"recently_activated", "a:0:{}", "yes"},
		{"wpcf7", wdPHP(wdArr{{"version", "5.4.2"}, {"bulk_validate", wdArr{{"timestamp", blogStart.Unix() + 7200}, {"version", "5.1.6"},
			{"count_valid", 1}, {"count_invalid", 0}}}}), "yes"},
		{"duplicator_settings", wdPHP(wdArr{{"version", "1.3.26"}, {"uninstall_settings", true}, {"uninstall_files", true},
			{"uninstall_tables", true}, {"package_debug", false}, {"package_mysqldump", true}, {"package_mysqldump_path", ""},
			{"package_phpdump_qrylimit", "100"}, {"package_zip_flush", false}, {"storage_htaccess_off", true}, {"archive_build_mode", 2},
			{"skip_archive_scan", false}, {"unhook_third_party_js", false}, {"unhook_third_party_css", false}, {"active_package_id", 3}}), "yes"},
		{"duplicator_version_plugin", "1.3.26", "yes"},
		{"wp_file_manager_settings", wdPHP(wdArr{{"public_path", "/var/www/blog/"}, {"fm_enable_trash", "0"},
			{"fm_enable_media_upload", "1"}, {"fm_max_upload_size", "64"}, {"allowed_upload_ext", ""}}), "yes"},
		{"wpfm_version", "6.0", "yes"},
		{"wp_mail_smtp", wdPHP(wdArr{{"mail", wdArr{{"from_email", c.w.Keys.MailUser}, {"from_name", "Veltrona Logistics"},
			{"mailer", "smtp"}, {"return_path", false}, {"from_email_force", true}, {"from_name_force", false}}},
			{"smtp", wdArr{{"autotls", true}, {"auth", true}, {"host", "smtp.office365.com"}, {"encryption", "tls"}, {"port", 587},
				{"user", c.w.Keys.MailUser}, {"pass", string(smtpPass) + "=="}}}}), "no"},
		{"wpseo", wdPHP(wdArr{{"tracking", false}, {"license_server_version", false}, {"ms_defaults_set", false},
			{"ignore_search_engines_discouraged_notice", false}, {"indexing_first_time", true}, {"indexing_started", false},
			{"indexing_reason", ""}, {"indexables_indexing_completed", true}, {"version", "17.2"}, {"previous_version", "16.9"},
			{"disableadvanced_meta", true}, {"enable_headless_rest_endpoints", true}, {"enable_xml_sitemap", true},
			{"enable_text_link_counter", true}, {"show_onboarding_notice", false}, {"first_activated_on", blogStart.Unix() + 3600}}), "yes"},
		{"wpseo_titles", wdPHP(wdArr{{"separator", "sc-dash"}, {"title-home-wpseo", "%%sitename%% %%page%% %%sep%% %%sitedesc%%"},
			{"title-post", "%%title%% %%page%% %%sep%% %%sitename%%"}, {"company_or_person", "company"},
			{"company_name", "Veltrona Logistics AG"}, {"website_name", "Veltrona Logistics"}}), "yes"},
		{"classic-editor-replace", "block", "yes"}, {"classic-editor-allow-users", "allow", "yes"},
		{"astra-settings", wdPHP(wdArr{{"theme-auto-version", "3.6.9"}, {"site-content-layout", "plain-container"},
			{"footer-sml-section-1-credit", "Copyright &copy; [current_year] Veltrona Logistics AG, Zug"}}), "yes"},
		{"widget_block", "a:1:{s:12:\"_multiwidget\";i:1;}", "yes"},
		{"sidebars_widgets", wdPHP(wdArr{{"wp_inactive_widgets", wdArr{}}, {"sidebar-1", wdList("block-2", "block-3")},
			{"array_version", 3}}), "yes"},
		{"_site_transient_timeout_theme_roots", strconv.FormatInt(c.now.Unix()+3600, 10), "no"},
		{"_site_transient_theme_roots", wdPHP(wdArr{{"astra", "/themes"}, {"twentytwentyone", "/themes"}, {"veltrona-child", "/themes"}}), "no"},
		{"_transient_doing_cron", fmt.Sprintf("%d.%s", c.now.Unix()-int64(r.IntN(600)), r.digits(22)), "yes"},
	}
	var rows [][]any
	id := int64(0)
	for i, o := range opts {
		id++
		if i > 95 {
			id += int64(r.IntN(40)) // later options, many transients in between were deleted
		}
		rows = append(rows, []any{id, o.k, o.v, o.auto})
	}
	return wdTable("wp_options", []Column{wdc("option_id", "bigint(20) unsigned", "ai"), wdc("option_name", "varchar(191)", "uni|def="),
		wdc("option_value", "longtext", ""), wdc("autoload", "varchar(20)", "mul|def=yes")}, rows)
}

// ---------- mysql (grant tables) ----------

var wdUserPrivs = []string{"Select", "Insert", "Update", "Delete", "Create", "Drop", "Reload", "Shutdown", "Process", "File", "Grant",
	"References", "Index", "Alter", "Show_db", "Super", "Create_tmp_table", "Lock_tables", "Execute", "Repl_slave", "Repl_client",
	"Create_view", "Show_view", "Create_routine", "Alter_routine", "Create_user", "Event", "Trigger", "Create_tablespace"}

var wdDBPrivs = []string{"Select", "Insert", "Update", "Delete", "Create", "Drop", "Grant", "References", "Index", "Alter",
	"Create_tmp_table", "Lock_tables", "Create_view", "Show_view", "Create_routine", "Alter_routine", "Execute", "Event", "Trigger"}

var wdGrantName = map[string]string{"SELECT": "Select", "INSERT": "Insert", "UPDATE": "Update", "DELETE": "Delete", "CREATE": "Create",
	"DROP": "Drop", "RELOAD": "Reload", "SHUTDOWN": "Shutdown", "PROCESS": "Process", "FILE": "File", "REFERENCES": "References",
	"INDEX": "Index", "ALTER": "Alter", "SHOW DATABASES": "Show_db", "SUPER": "Super", "CREATE TEMPORARY TABLES": "Create_tmp_table",
	"LOCK TABLES": "Lock_tables", "EXECUTE": "Execute", "REPLICATION SLAVE": "Repl_slave", "REPLICATION CLIENT": "Repl_client",
	"CREATE VIEW": "Create_view", "SHOW VIEW": "Show_view", "CREATE ROUTINE": "Create_routine", "ALTER ROUTINE": "Alter_routine",
	"CREATE USER": "Create_user", "EVENT": "Event", "TRIGGER": "Trigger", "CREATE TABLESPACE": "Create_tablespace"}

type wdGrant struct {
	privs map[string]bool
	all   bool
}

// wdParseGrants splits SHOW GRANTS lines into global ("*") and per-database privileges.
func wdParseGrants(lines []string) map[string]*wdGrant {
	out := map[string]*wdGrant{}
	for _, l := range lines {
		rest, ok := strings.CutPrefix(l, "GRANT ")
		if !ok {
			continue
		}
		privs, after, ok := strings.Cut(rest, " ON ")
		if !ok || privs == "PROXY" {
			continue
		}
		obj, _, _ := strings.Cut(after, " TO ")
		db := "*"
		if obj != "*.*" {
			db = strings.Trim(strings.TrimSuffix(obj, ".*"), "`")
		}
		g := out[db]
		if g == nil {
			g = &wdGrant{privs: map[string]bool{}}
			out[db] = g
		}
		for _, p := range strings.Split(privs, ",") {
			p = strings.TrimSpace(p)
			if p == "ALL PRIVILEGES" || p == "ALL" {
				g.all = true
			} else if n := wdGrantName[p]; n != "" {
				g.privs[n] = true
			}
		}
		if strings.Contains(after, "WITH GRANT OPTION") {
			g.privs["Grant"] = true
		}
	}
	return out
}

func (c *wdCtx) mysqlDB() Database {
	r := newWDRand(c.w, 30)
	ucols := []Column{wdc("Host", "char(60)", "pk|def="), wdc("User", "char(32)", "pk|def=")}
	for _, p := range wdUserPrivs {
		ucols = append(ucols, wdc(p+"_priv", "enum('N','Y')", "def=N"))
	}
	ucols = append(ucols, wdc("ssl_type", "enum('','ANY','X509','SPECIFIED')", "def="), wdc("ssl_cipher", "blob", ""),
		wdc("x509_issuer", "blob", ""), wdc("x509_subject", "blob", ""), wdc("max_questions", "int(11) unsigned", "def=0"),
		wdc("max_updates", "int(11) unsigned", "def=0"), wdc("max_connections", "int(11) unsigned", "def=0"),
		wdc("max_user_connections", "int(11) unsigned", "def=0"), wdc("plugin", "char(64)", "def=mysql_native_password"),
		wdc("authentication_string", "text", "null"), wdc("password_expired", "enum('N','Y')", "def=N"),
		wdc("password_last_changed", "timestamp", "null"), wdc("password_lifetime", "smallint(5) unsigned", "null"),
		wdc("account_locked", "enum('N','Y')", "def=N"))
	dcols := []Column{wdc("Host", "char(60)", "pk|def="), wdc("Db", "char(64)", "pk|def="), wdc("User", "char(32)", "pk|def=")}
	for _, p := range wdDBPrivs {
		dcols = append(dcols, wdc(p+"_priv", "enum('N','Y')", "def=N"))
	}
	install := c.start.AddDate(0, 0, -62).Add(10*time.Hour + 3*time.Minute)
	var urows, drows [][]any
	addUser := func(host, user, plugin, auth string, changed time.Time, locked bool, g *wdGrant) {
		row := []any{host, user}
		for _, p := range wdUserPrivs {
			y := g != nil && (g.privs[p] || (g.all && p != "Grant"))
			row = append(row, map[bool]string{true: "Y", false: "N"}[y])
		}
		row = append(row, "", "", "", "", int64(0), int64(0), int64(0), int64(0), plugin, auth, "N", wdT(changed), nil,
			map[bool]string{true: "Y", false: "N"}[locked])
		urows = append(urows, row)
	}
	addDB := func(host, db, user string, g *wdGrant) {
		row := []any{host, db, user}
		for _, p := range wdDBPrivs {
			y := g.privs[p] || (g.all && p != "Grant")
			row = append(row, map[bool]string{true: "Y", false: "N"}[y])
		}
		drows = append(drows, row)
	}
	all := &wdGrant{privs: map[string]bool{"Grant": true}, all: true}
	addUser("localhost", "root", "auth_socket", "", install, false, all)
	addUser("localhost", "mysql.session", "mysql_native_password", "*THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE", install, true,
		&wdGrant{privs: map[string]bool{"Super": true}})
	addUser("localhost", "mysql.sys", "mysql_native_password", "*THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE", install, true, nil)
	addUser("localhost", "debian-sys-maint", "mysql_native_password", mysqlNativeHash(r.str(alnum, 16)), install, false, all)
	addDB("localhost", "performance_schema", "mysql.session", &wdGrant{privs: map[string]bool{"Select": true}})
	addDB("localhost", "sys", "mysql.sys", &wdGrant{privs: map[string]bool{"Trigger": true}})

	order := map[string]int{"connect_app": 1, "wp_blog": 2, "backup": 3, "root": 4}
	var names []string
	for k := range c.w.MySQL {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool {
		oi, oj := order[names[i]], order[names[j]]
		if oi == 0 {
			oi = 100
		}
		if oj == 0 {
			oj = 100
		}
		if oi != oj {
			return oi < oj
		}
		return names[i] < names[j]
	})
	for i, k := range names {
		a := c.w.MySQL[k]
		grants := wdParseGrants(a.Grants)
		changed := r.work(c.start.AddDate(0, 0, -30+i*r.between(20, 160)))
		if changed.After(c.now) {
			changed = install
		}
		addUser(a.Host, a.User, "mysql_native_password", a.Hash, changed, false, grants["*"])
		var dbs []string
		for db := range grants {
			if db != "*" {
				dbs = append(dbs, db)
			}
		}
		sort.Strings(dbs)
		for _, db := range dbs {
			addDB(a.Host, db, a.User, grants[db])
		}
	}
	return Database{Name: "mysql", Tables: []Table{
		{Name: "db", Engine: "MyISAM", Comment: "Database privileges", Columns: dcols, Rows: drows},
		{Name: "user", Engine: "MyISAM", Comment: "Users and global privileges", Columns: ucols, Rows: urows},
	}}
}
