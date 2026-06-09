package signature

import (
	"bytes"
	"crypto"
	"encoding/base64"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func init() {
	addEngine(NewPgpEngine())
}

func NewPgpEngine() Engine {
	return &pgpEngine{}
}

type pgpEngine struct {
	Engine
}

type pgpPrivateKey struct {
	crypto.PrivateKey
	key *openpgp.Entity
}

type pgpPublicKey struct {
	crypto.PublicKey
	key *openpgp.Entity
}

type pgpSigner struct {
	Signer
	engine    Engine
	key       *openpgp.Entity
	publicKey *pgpPublicKey
	keyId     string
	config    *packet.Config
}

type pgpVerifier struct {
	Verifier
	engine Engine
	key    *openpgp.Entity
	keys   openpgp.EntityList
	keyId  string
	config *packet.Config
}

func ReadPgpArmorPrivateKey(input string) (crypto.PrivateKey, error) {
	entityList, err := openpgp.ReadArmoredKeyRing(bytes.NewReader([]byte(input)))
	if err != nil {
		return nil, err
	}
	key := entityList[0]
	if key.PrivateKey == nil {
		return nil, ErrInvalidKey
	}
	return &pgpPrivateKey{
		key: entityList[0],
	}, nil
}

func ReadPgpArmorPublicKey(input string) (crypto.PublicKey, error) {
	entityList, err := openpgp.ReadArmoredKeyRing(bytes.NewReader([]byte(input)))
	if err != nil {
		return nil, err
	}
	return &pgpPublicKey{
		key: entityList[0],
	}, nil
}

func PgpPublicKeySerialize(key crypto.PublicKey) ([]byte, error) {
	pgpKey, ok := key.(*pgpPublicKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	var buf bytes.Buffer
	if err := pgpKey.key.Serialize(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (e *pgpEngine) Schema() string {
	return "pgp"
}

func (e *pgpEngine) GeneratePublicKey(privateKey crypto.PrivateKey) (crypto.PublicKey, error) {
	pgpKey, ok := privateKey.(*pgpPrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}

	entity, err := pgpPrivateToPublic(pgpKey.key)
	if err != nil {
		return nil, err
	}

	return &pgpPublicKey{
		key: entity,
	}, nil
}

func (e *pgpEngine) KeyTypeByPublicKey(key crypto.PublicKey) (string, error) {
	_, ok := key.(*pgpPublicKey)
	if !ok {
		return "", ErrInvalidKey
	}
	return "pgp", nil
}

func (e *pgpEngine) KeyTypeByPrivateKey(key crypto.PrivateKey) (string, error) {
	_, ok := key.(*pgpPrivateKey)
	if !ok {
		return "", ErrInvalidKey
	}
	return "pgp", nil
}

func (e *pgpEngine) NewSigner(key crypto.PrivateKey, keyId string) (Signer, error) {
	return e.NewSignerWithConfig(key, keyId, nil)
}

func (e *pgpEngine) NewSignerWithConfig(key crypto.PrivateKey, keyId string, config *packet.Config) (Signer, error) {
	pgpKey, ok := key.(*pgpPrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}

	publicKey, err := pgpPrivateToPublic(pgpKey.key)
	if err != nil {
		return nil, err
	}

	if keyId == "" {
		keyId = pgpKeyId(publicKey)
	}
	if config == nil {
		config = &packet.Config{}
	}

	return &pgpSigner{
		engine: e,
		key:    pgpKey.key,
		publicKey: &pgpPublicKey{
			key: publicKey,
		},
		keyId:  keyId,
		config: config,
	}, nil
}

func (e *pgpEngine) NewVerifier(key crypto.PublicKey, keyId string) (Verifier, error) {
	return e.NewVerifierWithConfig(key, keyId, nil)
}

func (e *pgpEngine) NewVerifierWithConfig(key crypto.PublicKey, keyId string, config *packet.Config) (Verifier, error) {
	pgpKey, ok := key.(*pgpPublicKey)
	if !ok {
		return nil, ErrInvalidKey
	}

	if keyId == "" {
		keyId = pgpKeyId(pgpKey.key)
	}
	if config == nil {
		config = &packet.Config{}
	}

	return &pgpVerifier{
		engine: e,
		key:    pgpKey.key,
		keyId:  keyId,
		keys:   []*openpgp.Entity{pgpKey.key},
		config: config,
	}, nil
}

func (e *pgpSigner) Engine() Engine {
	return e.engine
}

func (e *pgpSigner) PrivateKey() crypto.PrivateKey {
	return e.key
}

func (e *pgpSigner) PublicKey() crypto.PublicKey {
	return e.publicKey
}

func (e *pgpSigner) KeyId() string {
	return pgpKeyId(e.publicKey.key)
}

func (e *pgpSigner) SignMessage(msg []byte) ([]byte, error) {
	var out bytes.Buffer
	err := openpgp.DetachSign(&out, e.key, bytes.NewReader(msg), e.config)
	if err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

func (e *pgpSigner) SignJson(msg *SignedJson[any]) error {
	return signJson(e, msg)
}

func (e *pgpVerifier) Engine() Engine {
	return e.engine
}

func (e *pgpVerifier) PublicKey() crypto.PublicKey {
	return e.key
}

func (e *pgpVerifier) KeyId() string {
	return pgpKeyId(e.key)
}

func (e *pgpVerifier) VerifyMessage(msg []byte, sig []byte) (bool, error) {
	_, _, err := openpgp.VerifyDetachedSignature(e.keys, bytes.NewReader(msg), bytes.NewReader(sig), e.config)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (e *pgpVerifier) VerifyJson(msg *SignedJson[any]) (bool, error) {
	return verifyJson(e, msg)
}

func pgpKeyId(key *openpgp.Entity) string {
	return base64.RawURLEncoding.EncodeToString(key.PrimaryKey.Fingerprint)
}

func pgpPrivateToPublic(private *openpgp.Entity) (*openpgp.Entity, error) {
	var buf bytes.Buffer
	if err := private.Serialize(&buf); err != nil {
		return nil, err
	}

	keyEntityList, err := openpgp.ReadKeyRing(bytes.NewReader(buf.Bytes()))
	if err != nil {
		return nil, err
	}

	return keyEntityList[0], nil
}
