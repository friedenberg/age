package age

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"strings"

	"filippo.io/age/internal/bech32"
	"filippo.io/age/internal/format"
	"github.com/go-piv/piv-go/piv"
	"github.com/pkg/errors"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const PivYubikeyEC256Label = "age-encryption.org/v1/PivYubikeyEC256"
const PivYubikeyEC256LabelBech = "agepyec256"

// PivYubikeyEC256Recipient is the standard age public key. Messages encrypted to this
// recipient can be decrypted with the corresponding PivYubikeyEC256Identity.
//
// This recipient is anonymous, in the sense that an attacker can't tell from
// the message alone if it is encrypted to a certain recipient.
type PivYubikeyEC256Recipient struct {
	*ecdsa.PublicKey
	compressed []byte
}

func ParseBech32PivYubikeyEC256Recipient(
	s string,
) (r *PivYubikeyEC256Recipient, err error) {
	var t string
	var k []byte

	t, k, err = bech32.Decode(s)

	switch {
	case err != nil:
		err = fmt.Errorf("malformed recipient %q: %v", s, err)
		return

	case t != PivYubikeyEC256LabelBech:
		err = fmt.Errorf("malformed recipient %q: invalid type %q", s, t)
		return
	}

	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), k)

	r = &PivYubikeyEC256Recipient{
		PublicKey: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		},
    compressed: k,
	}

	return
}

func ParsePEMPivYubikeyEC256Recipient(
	s string,
) (r *PivYubikeyEC256Recipient, err error) {
	block, rest := pem.Decode([]byte(s))

	switch {
	case block == nil || block.Type != "PUBLIC KEY":
		err = errors.Errorf("failed to decode PEM block containing public key")
		return

	case len(rest) > 0:
		err = errors.Errorf("did not expect remaining data: %q", rest)
		return
	}

	if r, err = ParseRawPivYubikeyEC256Recipient(block.Bytes); err != nil {
		return
	}

	return
}

func ParseRawPivYubikeyEC256Recipient(b []byte) (r *PivYubikeyEC256Recipient, err error) {
	var pub interface{}

	if pub, err = x509.ParsePKIXPublicKey(b); err != nil {
		return
	}

	r = &PivYubikeyEC256Recipient{}

	ok := false

	if r.PublicKey, ok = pub.(*ecdsa.PublicKey); !ok {
		err = errors.Errorf("wrong format for pub key")
		return
	}

	r.compressed = elliptic.MarshalCompressed(
		elliptic.P256(),
		r.X,
		r.Y,
	)

	return
}

func (r *PivYubikeyEC256Recipient) Bech32() (s string, err error) {
	if s, err = bech32.Encode("agepyec256", r.compressed); err != nil {
    return
	}

	return
}

func (r *PivYubikeyEC256Recipient) PEM() (s string, err error) {
  var bPKIX []byte

	if bPKIX, err = x509.MarshalPKIXPublicKey(r.PublicKey); err != nil {
		return
	}

  pemBlock := &pem.Block{
    Type: "PUBLIC KEY",
    Bytes: bPKIX,
  }

  sPEM := &strings.Builder{}

	if err = pem.Encode(sPEM, pemBlock); err != nil {
    return
  }

  s = sPEM.String()

	return
}

func (r *PivYubikeyEC256Recipient) Wrap(fileKey []byte) (ss []*Stanza, err error) {
	var eph *ecdsa.PrivateKey

	if eph, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return
	}

	ephCompressed := elliptic.MarshalCompressed(
		eph.Curve,
		eph.PublicKey.X,
		eph.PublicKey.Y,
	)

	var s1 Stanza
	s1.Type = PivYubikeyEC256Label
	s1.Args = []string{format.EncodeToString(ephCompressed)}

	// ECDH shared secret between ephemeral key and yubikey
	sharedSecretNum, _ := eph.PublicKey.ScalarMult(r.X, r.Y, eph.D.Bytes())
	sharedSecret := sharedSecretNum.Bytes()

	salt := make([]byte, 0, len(ephCompressed)+len(r.compressed))
	salt = append(salt, ephCompressed...)
	salt = append(salt, r.compressed...)

	h := hkdf.New(sha256.New, sharedSecret, salt, []byte(PivYubikeyEC256Label))

	var wrappingKey []byte
	wrappingKey = make([]byte, chacha20poly1305.KeySize)

	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	var wrappedKey []byte

	if wrappedKey, err = aeadEncrypt(wrappingKey, fileKey); err != nil {
		return
	}

	s1.Body = wrappedKey

	ss = append(ss, &s1)

	return
}

// PivYubikeyEC256Identity is the standard age private key, which can decrypt messages
// encrypted to the corresponding EC256Recipient.
type PivYubikeyEC256Identity struct {
	yk           *piv.YubiKey
	slot         piv.Slot
	privateKey   *piv.ECDSAPrivateKey
	ourPublicKey PivYubikeyEC256Recipient
}

// ParsePivYubikeyEC256Identity returns a new PivYubikeyEC256Identity from a Bech32 private key
// encoding with the "AGE-SECRET-KEY-1" prefix.
func ReadPivYubikeyEC256Identity(
	r PivYubikeyEC256Recipient,
	slots ...piv.Slot,
) (i *PivYubikeyEC256Identity, err error) {
	i = &PivYubikeyEC256Identity{
		ourPublicKey: r,
	}

	auth := piv.KeyAuth{PIN: piv.DefaultPIN}

	var cards []string

	if cards, err = piv.Cards(); err != nil {
		return
	}

	if len(slots) == 0 {
		slots = []piv.Slot{piv.SlotAuthentication}
	}

	// Find a YubiKey and open the reader.
	found := false

	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			var yk1 *piv.YubiKey

			if yk1, err = piv.Open(card); err != nil {
				return
			}

			for _, s := range slots {
				var cert *x509.Certificate

				if cert, err = yk1.Attest(s); err != nil {
					return
				}

				pub := cert.PublicKey

				if r.Equal(pub) {
					i.yk = yk1
					i.slot = s

					var key crypto.PrivateKey

					if key, err = i.yk.PrivateKey(s, pub, auth); err != nil {
						return
					}

					ok := false

					if i.privateKey, ok = key.(*piv.ECDSAPrivateKey); !ok {
						err = errors.Errorf("expected %T but got %T", i.privateKey, key)
						return
					}

					found = true

					break
				}
			}
		}
	}

	if !found {
		err = ErrIncorrectIdentity
		return
	}

	return
}

func (i *PivYubikeyEC256Identity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	return multiUnwrap(i.unwrap, stanzas)
}

func (i *PivYubikeyEC256Identity) unwrap(block *Stanza) (fileKey []byte, err error) {
	if block.Type != PivYubikeyEC256Label {
		err = ErrIncorrectIdentity
		return
	}

	if len(block.Args) != 1 {
		err = errors.New("invalid EC256 recipient block")
		return
	}

	var publicKeyBytes []byte

	if publicKeyBytes, err = format.DecodeString(block.Args[0]); err != nil {
		return
	}

	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), publicKeyBytes)

	if x == nil {
		err = errors.New("cannot unmarshal P256 key")
		return
	}

	publicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	var sharedSecret []byte

	if sharedSecret, err = i.privateKey.SharedKey(publicKey); err != nil {
		err = fmt.Errorf("PIV ECDHE error: %v", err)
		return
	}

	salt := make([]byte, 0, len(publicKeyBytes)+len(i.ourPublicKey.compressed))
	salt = append(salt, publicKeyBytes...)
	salt = append(salt, i.ourPublicKey.compressed...)

	h := hkdf.New(sha256.New, sharedSecret, salt, []byte(PivYubikeyEC256Label))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)

	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	if fileKey, err = aeadDecrypt(wrappingKey, fileKeySize, block.Body); err != nil {
		return
	}

	return
}

// Recipient returns the public EC256Recipient value corresponding to i.
func (i *PivYubikeyEC256Identity) Recipient() (r PivYubikeyEC256Recipient) {
	r = i.ourPublicKey
	return
}

// String returns the Bech32 private key encoding of i.
// func (i *PivYubikeyEC256Identity) String() string {
// 	s, _ := bech32.Encode("AGE-SECRET-KEY-", i.secretKey)
// 	return strings.ToUpper(s)
// }
