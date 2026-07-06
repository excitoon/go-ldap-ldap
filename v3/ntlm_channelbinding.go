package ldap

// Channel-binding-aware NTLMv2 AUTHENTICATE builder for the SASL "NTLM" bind.
//
// Upstream `github.com/Azure/go-ntlmssp` is authentication-only: it cannot inject
// the `MsvAvChannelBindings` AV pair or emit the AUTHENTICATE MIC, so an NTLM-SASL
// bind over LDAPS against a hardened Samba/AD DC (which enforces LDAP channel
// binding) fails with `SEC_E_BAD_BINDINGS` (0x80090346). This file reimplements
// just enough of MS-NLMP to attach the `tls-server-end-point` channel binding token
// derived from the TLS peer certificate, so the bind succeeds over LDAPS.
//
// Scope: LDAPS (transport already encrypted) only. It does NOT establish a SASL
// sign/seal security layer, so it does not fix the plaintext `ldap://389` path where
// the server answers "Sign or Seal are required"; use LDAPS (or simple bind over
// LDAPS) there.

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4" //nolint:staticcheck
)

// NTLMSSP negotiate flag (MS-NLMP 2.2.2.5) we need to clear on the AUTHENTICATE
// message because we send an all-zero (absent) `Version` field.
const ntlmNegotiateVersion uint32 = 0x02000000

// AV_PAIR identifiers (MS-NLMP 2.2.2.1).
const (
	msvAvEOL             uint16 = 0x0000
	msvAvFlags           uint16 = 0x0006
	msvAvTimestamp       uint16 = 0x0007
	msvAvChannelBindings uint16 = 0x000A
)

// `msvAvFlagMICPresent`, set in `MsvAvFlags`, tells the server the AUTHENTICATE
// message carries a MIC (MS-NLMP 2.2.2.10).
const msvAvFlagMICPresent uint32 = 0x00000002

// tlsServerEndPointChannelBinding returns the `MsvAvChannelBindings` value for the
// given TLS server certificate: MD5 of the `gss_channel_bindings_struct` wrapping
// the RFC 5929 `tls-server-end-point:` + certificate-hash application data.
func tlsServerEndPointChannelBinding(cert *x509.Certificate) []byte {
	appData := append([]byte("tls-server-end-point:"), certHashForChannelBinding(cert)...)

	// `gss_channel_bindings_struct` with empty initiator/acceptor addresses:
	// 4x uint32 zero (addr type+len pairs) then the application-data length+bytes.
	var gss bytes.Buffer
	gss.Write(make([]byte, 16))
	_ = binary.Write(&gss, binary.LittleEndian, uint32(len(appData)))
	gss.Write(appData)

	sum := md5.Sum(gss.Bytes())
	return sum[:]
}

// certHashForChannelBinding hashes the certificate DER per RFC 5929 §4.1: use the
// certificate's signature hash algorithm, upgrading MD5/SHA-1 (and unknown) to
// SHA-256.
func certHashForChannelBinding(cert *x509.Certificate) []byte {
	var h hash.Hash
	switch cert.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		h = sha512.New384()
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		h = sha512.New()
	default:
		h = sha256.New()
	}
	h.Write(cert.Raw)
	return h.Sum(nil)
}

// ntlmAuthenticateWithChannelBinding builds an NTLMv2 AUTHENTICATE (type 3) message
// in response to the given CHALLENGE (type 2), binding it to the TLS channel via
// the supplied channel-binding token (`cb`) and protecting it with a MIC.
//
// `negMsg` is the exact NEGOTIATE (type 1) message that was sent; it is required to
// compute the MIC. Exactly one of `password` / `hexHash` must be non-empty (`hexHash`
// is the hex NT hash, for pass-the-hash).
func ntlmAuthenticateWithChannelBinding(negMsg, challenge []byte, username, password, hexHash string, cb []byte) ([]byte, error) {
	if len(challenge) < 48 || !bytes.HasPrefix(challenge, []byte("NTLMSSP\x00")) {
		return nil, errors.New("ldap ntlm: malformed challenge message")
	}
	if binary.LittleEndian.Uint32(challenge[8:12]) != 2 {
		return nil, errors.New("ldap ntlm: not an NTLMSSP CHALLENGE message")
	}
	challengeFlags := binary.LittleEndian.Uint32(challenge[20:24])
	serverChallenge := challenge[24:32]
	// Samba's SASL "NTLM" challenge omits the target info entirely (`tiLen` == 0). The
	// channel binding still has to be carried in the AUTHENTICATE, so we synthesize
	// the target info below rather than requiring the server to provide it.
	tiLen := int(binary.LittleEndian.Uint16(challenge[40:42]))
	tiOff := int(binary.LittleEndian.Uint32(challenge[44:48]))
	var targetInfo []byte
	if tiLen > 0 {
		if tiOff+tiLen > len(challenge) {
			return nil, fmt.Errorf("ldap ntlm: challenge target info out of bounds (len=%d tiLen=%d tiOff=%d)", len(challenge), tiLen, tiOff)
		}
		targetInfo = challenge[tiOff : tiOff+tiLen]
	}

	user, domain := splitNTLMName(username)

	responseKeyNT, err := ntowfV2(user, domain, password, hexHash)
	if err != nil {
		return nil, err
	}

	timestamp := avPairValue(targetInfo, msvAvTimestamp)
	if timestamp == nil {
		timestamp = ntlmFileTimeNow()
	}
	boundTargetInfo := targetInfoWithChannelBinding(targetInfo, cb)

	clientChallenge := make([]byte, 8)
	if _, err := rand.Read(clientChallenge); err != nil {
		return nil, err
	}

	// temp = Responserversion || HiResponserversion || Z(6) || Time || ClientChallenge
	//        || Z(4) || ServerName(targetInfo) || Z(4)   (MS-NLMP 3.3.2)
	var temp bytes.Buffer
	temp.Write([]byte{0x01, 0x01, 0, 0, 0, 0, 0, 0})
	temp.Write(timestamp)
	temp.Write(clientChallenge)
	temp.Write([]byte{0, 0, 0, 0})
	temp.Write(boundTargetInfo)
	temp.Write([]byte{0, 0, 0, 0})

	ntProof := hmacMD5(responseKeyNT, concatBytes(serverChallenge, temp.Bytes()))
	ntChallengeResponse := concatBytes(ntProof, temp.Bytes())
	sessionBaseKey := hmacMD5(responseKeyNT, ntProof)
	// No key exchange requested, so `ExportedSessionKey` == `SessionBaseKey` (MS-NLMP 3.4.5.1).
	exportedSessionKey := sessionBaseKey

	authFlags := challengeFlags &^ ntlmNegotiateVersion
	// Timestamp present -> `LmChallengeResponse` is Z(24) (MS-NLMP 3.1.5.1.2).
	lm := make([]byte, 24)

	msg := buildAuthenticateMessage(authFlags, lm, ntChallengeResponse, domain, user)
	mic := hmacMD5(exportedSessionKey, concatBytes(negMsg, challenge, msg))
	copy(msg[micOffset:micOffset+16], mic)
	return msg, nil
}

// splitNTLMName mirrors `go-ntlmssp`'s identity handling: "DOMAIN\\user" splits into
// (user, DOMAIN); a bare name or UPN ("user@realm") is used verbatim as the user
// with an empty domain.
func splitNTLMName(username string) (user, domain string) {
	if i := strings.IndexByte(username, '\\'); i >= 0 {
		return username[i+1:], username[:i]
	}
	return username, ""
}

// ntowfV2 computes the NTLMv2 response key from a password or a hex NT hash.
func ntowfV2(user, domain, password, hexHash string) ([]byte, error) {
	var ntowfV1 []byte
	if hexHash != "" {
		// Accept "LM:NT" or bare NT hex.
		if parts := strings.Split(hexHash, ":"); len(parts) > 1 {
			hexHash = parts[len(parts)-1]
		}
		b, err := hex.DecodeString(hexHash)
		if err != nil {
			return nil, err
		}
		ntowfV1 = b
	} else {
		h := md4.New()
		h.Write(utf16LE(password))
		ntowfV1 = h.Sum(nil)
	}
	mac := hmac.New(md5.New, ntowfV1)
	mac.Write(utf16LE(strings.ToUpper(user) + domain))
	return mac.Sum(nil), nil
}

// targetInfoWithChannelBinding copies the server target info, ensures `MsvAvFlags` has
// the MIC-present bit, appends `MsvAvChannelBindings`, and re-terminates with `MsvAvEOL`.
func targetInfoWithChannelBinding(targetInfo, cb []byte) []byte {
	var out bytes.Buffer
	sawFlags := false
	rest := targetInfo
	for len(rest) >= 4 {
		id := binary.LittleEndian.Uint16(rest[0:2])
		l := int(binary.LittleEndian.Uint16(rest[2:4]))
		if 4+l > len(rest) {
			break
		}
		val := rest[4 : 4+l]
		rest = rest[4+l:]
		switch id {
		case msvAvEOL:
			rest = nil
		case msvAvChannelBindings:
			// drop any pre-existing binding; we append our own below
		case msvAvFlags:
			sawFlags = true
			f := uint32(0)
			if l >= 4 {
				f = binary.LittleEndian.Uint32(val)
			}
			writeAVPair(&out, msvAvFlags, uint32LE(f|msvAvFlagMICPresent))
		default:
			writeAVPair(&out, id, val)
		}
		if rest == nil {
			break
		}
	}
	if !sawFlags {
		writeAVPair(&out, msvAvFlags, uint32LE(msvAvFlagMICPresent))
	}
	writeAVPair(&out, msvAvChannelBindings, cb)
	writeAVPair(&out, msvAvEOL, nil)
	return out.Bytes()
}

// avPairValue returns the value of the first AV pair with the given id, or nil.
func avPairValue(targetInfo []byte, id uint16) []byte {
	rest := targetInfo
	for len(rest) >= 4 {
		aid := binary.LittleEndian.Uint16(rest[0:2])
		l := int(binary.LittleEndian.Uint16(rest[2:4]))
		if aid == msvAvEOL || 4+l > len(rest) {
			return nil
		}
		if aid == id {
			return rest[4 : 4+l]
		}
		rest = rest[4+l:]
	}
	return nil
}

func writeAVPair(b *bytes.Buffer, id uint16, val []byte) {
	var hdr [4]byte
	binary.LittleEndian.PutUint16(hdr[0:2], id)
	binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(val)))
	b.Write(hdr[:])
	b.Write(val)
}

// micOffset is the byte offset of the 16-byte MIC field inside the AUTHENTICATE
// message: 64-byte fixed header + 8-byte (zero) `Version` field.
const micOffset = 72

// buildAuthenticateMessage assembles an AUTHENTICATE (type 3) message including a
// zeroed 8-byte `Version` field and a zeroed 16-byte MIC placeholder (to be filled in
// by the caller). `EncryptedRandomSessionKey` and `Workstation` are empty.
func buildAuthenticateMessage(flags uint32, lm, nt []byte, domain, user string) []byte {
	domainU := utf16LE(domain)
	userU := utf16LE(user)

	const headerLen = micOffset + 16 // fixed header + version + MIC
	var payload bytes.Buffer
	off := headerLen
	field := func(v []byte) []byte {
		var f [8]byte
		binary.LittleEndian.PutUint16(f[0:2], uint16(len(v)))
		binary.LittleEndian.PutUint16(f[2:4], uint16(len(v)))
		binary.LittleEndian.PutUint32(f[4:8], uint32(off))
		payload.Write(v)
		off += len(v)
		return f[:]
	}
	lmField := field(lm)
	ntField := field(nt)
	domainField := field(domainU)
	userField := field(userU)
	wsField := field(nil)
	sessionKeyField := field(nil)

	var b bytes.Buffer
	b.WriteString("NTLMSSP\x00")
	_ = binary.Write(&b, binary.LittleEndian, uint32(3))
	b.Write(lmField)
	b.Write(ntField)
	b.Write(domainField)
	b.Write(userField)
	b.Write(wsField)
	b.Write(sessionKeyField)
	_ = binary.Write(&b, binary.LittleEndian, flags)
	b.Write(make([]byte, 8))  // Version (absent -> zero)
	b.Write(make([]byte, 16)) // MIC placeholder
	b.Write(payload.Bytes())
	return b.Bytes()
}

func hmacMD5(key, data []byte) []byte {
	m := hmac.New(md5.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func utf16LE(s string) []byte {
	codes := utf16.Encode([]rune(s))
	b := make([]byte, len(codes)*2)
	for i, c := range codes {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	return b
}

func uint32LE(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func concatBytes(parts ...[]byte) []byte {
	var b bytes.Buffer
	for _, p := range parts {
		b.Write(p)
	}
	return b.Bytes()
}

func ntlmFileTimeNow() []byte {
	ft := uint64(time.Now().UnixNano())/100 + 116444736000000000
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, ft)
	return b
}
