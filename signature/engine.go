package signature

import (
	"crypto"
	"errors"
	"log"
	"strings"
	"sync"
)

var (
	ErrInvalid    = errors.New("tuf: signature verification failed")
	ErrInvalidKey = errors.New("invalid key")
)

const (
	MaxJSONKeySize = 512 * 1024
)

type Engine interface {
	Schema() string

	KeyTypeByPublicKey(key crypto.PublicKey) (string, error)
	KeyTypeByPrivateKey(key crypto.PrivateKey) (string, error)

	GeneratePublicKey(privateKey crypto.PrivateKey) (crypto.PublicKey, error)

	NewSigner(key crypto.PrivateKey, keyId string) (Signer, error)
	NewVerifier(key crypto.PublicKey, keyId string) (Verifier, error)
}

type Verifier interface {
	Engine() Engine

	PublicKey() crypto.PublicKey
	KeyId() string

	VerifyMessage(msg []byte, sig []byte) (bool, error)
	VerifyJson(msg *SignedJson[any]) (bool, error)
}

type Signer interface {
	Engine() Engine

	PrivateKey() crypto.PrivateKey
	PublicKey() crypto.PublicKey
	KeyId() string

	SignMessage(msg []byte) ([]byte, error)
	SignJson(msg *SignedJson[any]) error
}

var engineMap sync.Map

func addEngine(engine Engine) {
	engineMap.Store(engine.Schema(), engine)
}

func GetEngine(schema string) (Engine, error) {
	if strings.HasPrefix(schema, "jclab-prs-2301") {
		log.Printf("jclab-prs-2301 engine is UNSAFE, DO NOT USE IT!")
	}
	engine, ok := engineMap.Load(schema)
	if !ok {
		return nil, ErrInvalid
	}
	return engine.(Engine), nil
}
