package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"strings"
)

// Real password hash formats, so dumped hashes are consistent with the plaintext (crackable if weak).

const cryptB64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// sha512Crypt implements glibc crypt(3) "$6$" with the default 5000 rounds.
func sha512Crypt(pw, salt string) string {
	if len(salt) > 16 {
		salt = salt[:16]
	}
	p, s := []byte(pw), []byte(salt)

	b := sha512.New()
	b.Write(p)
	b.Write(s)
	b.Write(p)
	bSum := b.Sum(nil)

	a := sha512.New()
	a.Write(p)
	a.Write(s)
	i := len(p)
	for ; i > 64; i -= 64 {
		a.Write(bSum)
	}
	a.Write(bSum[:i])
	for i = len(p); i > 0; i >>= 1 {
		if i&1 != 0 {
			a.Write(bSum)
		} else {
			a.Write(p)
		}
	}
	aSum := a.Sum(nil)

	dp := sha512.New()
	for i := 0; i < len(p); i++ {
		dp.Write(p)
	}
	dpSum := dp.Sum(nil)
	pSeq := make([]byte, 0, len(p))
	for len(pSeq)+64 <= len(p) {
		pSeq = append(pSeq, dpSum...)
	}
	pSeq = append(pSeq, dpSum[:len(p)-len(pSeq)]...)

	ds := sha512.New()
	for i := 0; i < 16+int(aSum[0]); i++ {
		ds.Write(s)
	}
	dsSum := ds.Sum(nil)
	sSeq := make([]byte, 0, len(s))
	for len(sSeq)+64 <= len(s) {
		sSeq = append(sSeq, dsSum...)
	}
	sSeq = append(sSeq, dsSum[:len(s)-len(sSeq)]...)

	for r := 0; r < 5000; r++ {
		c := sha512.New()
		if r&1 != 0 {
			c.Write(pSeq)
		} else {
			c.Write(aSum)
		}
		if r%3 != 0 {
			c.Write(sSeq)
		}
		if r%7 != 0 {
			c.Write(pSeq)
		}
		if r&1 != 0 {
			c.Write(aSum)
		} else {
			c.Write(pSeq)
		}
		aSum = c.Sum(nil)
	}

	var out strings.Builder
	out.WriteString("$6$" + salt + "$")
	enc := func(b2, b1, b0 byte, n int) {
		w := uint(b2)<<16 | uint(b1)<<8 | uint(b0)
		for ; n > 0; n-- {
			out.WriteByte(cryptB64[w&0x3f])
			w >>= 6
		}
	}
	for k := 0; k < 21; k++ {
		x, y, z := aSum[k], aSum[k+21], aSum[k+42]
		switch k % 3 {
		case 0:
			enc(x, y, z, 4)
		case 1:
			enc(y, z, x, 4)
		case 2:
			enc(z, x, y, 4)
		}
	}
	enc(0, 0, aSum[63], 2)
	return out.String()
}

func phpassEncode64(in []byte, count int) string {
	var out strings.Builder
	i := 0
	for i < count {
		v := uint(in[i])
		i++
		out.WriteByte(cryptB64[v&0x3f])
		if i < count {
			v |= uint(in[i]) << 8
		}
		out.WriteByte(cryptB64[(v>>6)&0x3f])
		if i >= count {
			break
		}
		i++
		if i < count {
			v |= uint(in[i]) << 16
		}
		out.WriteByte(cryptB64[(v>>12)&0x3f])
		if i >= count {
			break
		}
		i++
		out.WriteByte(cryptB64[(v>>18)&0x3f])
	}
	return out.String()
}

// phpassHash implements the WordPress (phpass portable, 2^13 rounds) "$P$B" hash.
func phpassHash(pw string) string {
	salt := make([]byte, 6)
	_, _ = rand.Read(salt)
	return phpassWithSalt(pw, "$P$B"+phpassEncode64(salt, 6))
}

func phpassWithSalt(pw, setting string) string {
	countLog2 := strings.IndexByte(cryptB64, setting[3])
	salt := setting[4:12]
	h := md5.Sum([]byte(salt + pw))
	for n := 1 << countLog2; n > 0; n-- {
		h = md5.Sum(append(h[:], pw...))
	}
	return setting[:12] + phpassEncode64(h[:], 16)
}

// mysqlNativeHash is MySQL's mysql_native_password: "*" + HEX(SHA1(SHA1(pw))).
func mysqlNativeHash(pw string) string {
	a := sha1.Sum([]byte(pw))
	b := sha1.Sum(a[:])
	return "*" + strings.ToUpper(hex.EncodeToString(b[:]))
}
