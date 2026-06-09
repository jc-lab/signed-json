package signature

import (
	"crypto"
	"errors"
)

func init() {
	addEngine(NewJclabPrs2601FirstEngine())
}

func NewJclabPrs2601FirstEngine() Engine {
	return &jclabPrs2601FirstEngine{}
}

type jclabPrs2601FirstEngine struct {
	Engine
}

type jclabPrs2601FirstSigner struct {
	Signer
	engine Engine
	key    *JclabPrs2601PrivateKey
	keyId  string
}

type jclabPrs2601FirstVerifier struct {
	Verifier
	engine Engine
	key    *JclabPrs2601PublicKey
	keyId  string
}

func (e *jclabPrs2601FirstEngine) Schema() string {
	return "jclab-prs-2601:first"
}

func (e *jclabPrs2601FirstEngine) KeyTypeByPublicKey(key crypto.PublicKey) (string, error) {
	keyImpl, ok := key.(*JclabPrs2601PublicKey)
	if !ok {
		return "", ErrInvalidKey
	}
	return keyImpl.keyType, nil
}

func (e *jclabPrs2601FirstEngine) KeyTypeByPrivateKey(key crypto.PrivateKey) (string, error) {
	keyImpl, ok := key.(*JclabPrs2601PrivateKey)
	if !ok {
		return "", ErrInvalidKey
	}
	return keyImpl.keyType, nil
}

func (e *jclabPrs2601FirstEngine) GeneratePublicKey(privateKey crypto.PrivateKey) (crypto.PublicKey, error) {
	keyImpl, ok := privateKey.(*JclabPrs2601PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return NewJclabPrs2601PublicKey(keyImpl.curve, keyImpl.keyType, keyImpl.w1)
}

func (e *jclabPrs2601FirstEngine) NewSigner(key crypto.PrivateKey, keyId string) (Signer, error) {
	keyImpl, ok := key.(*JclabPrs2601PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &jclabPrs2601FirstSigner{
		engine: e,
		key:    keyImpl,
		keyId:  keyId,
	}, nil
}

func (e *jclabPrs2601FirstEngine) NewVerifier(key crypto.PublicKey, keyId string) (Verifier, error) {
	keyImpl, ok := key.(*JclabPrs2601PublicKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &jclabPrs2601FirstVerifier{
		engine: e,
		key:    keyImpl,
		keyId:  keyId,
	}, nil
}

func (e *jclabPrs2601FirstSigner) Engine() Engine {
	return e.engine
}

func (e *jclabPrs2601FirstSigner) PrivateKey() crypto.PrivateKey {
	return e.key
}

func (e *jclabPrs2601FirstSigner) PublicKey() crypto.PublicKey {
	return jclabPrs2601PrivateToPublic(e.key)
}

func (e *jclabPrs2601FirstSigner) KeyId() string {
	return e.keyId
}

func (e *jclabPrs2601FirstSigner) SignMessage(msg []byte) ([]byte, error) {
	sig, err := e.key.curve.Sign(msg, e.key.s)
	if err != nil {
		return nil, err
	}
	return append([]byte{0x01}, sig.Encode()...), nil
}

func (e *jclabPrs2601FirstSigner) SignJson(msg *SignedJson[any]) error {
	return signJson(e, msg)
}

func (e *jclabPrs2601FirstVerifier) Engine() Engine {
	return e.engine
}

func (e *jclabPrs2601FirstVerifier) PublicKey() crypto.PublicKey {
	return e.key
}

func (e *jclabPrs2601FirstVerifier) KeyId() string {
	return e.keyId
}

func (e *jclabPrs2601FirstVerifier) VerifyMessage(msg []byte, sig []byte) (bool, error) {
	sigType := sig[0]
	if sigType != 0x01 {
		return false, errors.New("invalid signature")
	}
	sig1 := e.key.curve.Signature1FromBytes(sig[1:])
	return e.key.curve.VerifyL1(sig1, msg, e.key.w1), nil
}

func (e *jclabPrs2601FirstVerifier) VerifyJson(msg *SignedJson[any]) (bool, error) {
	return verifyJson(e, msg)
}
