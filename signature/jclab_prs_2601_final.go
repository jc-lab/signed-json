package signature

import (
	"crypto"
	"errors"

	"github.com/jc-lab/jclab-prs-2601/engine"
)

func init() {
	addEngine(NewJclabPrs2601FinalEngine())
}

func NewJclabPrs2601FinalEngine() Engine {
	return &jclabPrs2601FinalEngine{}
}

type jclabPrs2601FinalEngine struct {
	Engine
}

type jclabPrs2601FinalPrivateKey struct {
	keyType string
	curve   engine.CurveEngine
	key     []byte
}

type jclabPrs2601FinalPublicKey struct {
	keyType string
	curve   engine.CurveEngine
	key     []byte
}

type jclabPrs2601FinalSigner struct {
	Signer
	engine Engine
	key    *JclabPrs2601ResignKey
	keyId  string
}

type jclabPrs2601FinalVerifier struct {
	Verifier
	engine Engine
	key    *JclabPrs2601PublicKey
	keyId  string
}

func (e *jclabPrs2601FinalEngine) Schema() string {
	return "jclab-prs-2601:final"
}

func (e *jclabPrs2601FinalEngine) KeyTypeByPublicKey(key crypto.PublicKey) (string, error) {
	keyImpl, ok := key.(*JclabPrs2601PublicKey)
	if !ok {
		return "", ErrInvalidKey
	}
	return keyImpl.keyType, nil
}

func (e *jclabPrs2601FinalEngine) KeyTypeByPrivateKey(key crypto.PrivateKey) (string, error) {
	keyImpl, ok := key.(*JclabPrs2601ResignKey)
	if !ok {
		return "", ErrInvalidKey
	}
	return keyImpl.keyType, nil
}

func (e *jclabPrs2601FinalEngine) GeneratePublicKey(privateKey crypto.PrivateKey) (crypto.PublicKey, error) {
	keyImpl, ok := privateKey.(*JclabPrs2601ResignKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return NewJclabPrs2601PublicKey(keyImpl.curve, keyImpl.keyType, keyImpl.w1)
}

func (e *jclabPrs2601FinalEngine) NewSigner(key crypto.PrivateKey, keyId string) (Signer, error) {
	keyImpl, ok := key.(*JclabPrs2601ResignKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &jclabPrs2601FinalSigner{
		engine: e,
		key:    keyImpl,
		keyId:  keyId,
	}, nil
}

func (e *jclabPrs2601FinalEngine) NewVerifier(key crypto.PublicKey, keyId string) (Verifier, error) {
	keyImpl, ok := key.(*JclabPrs2601PublicKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &jclabPrs2601FinalVerifier{
		engine: e,
		key:    keyImpl,
		keyId:  keyId,
	}, nil
}

func (e *jclabPrs2601FinalSigner) Engine() Engine {
	return e.engine
}

func (e *jclabPrs2601FinalSigner) PrivateKey() crypto.PrivateKey {
	return e.key
}

func (e *jclabPrs2601FinalSigner) PublicKey() crypto.PublicKey {
	return jclabPrs2601RkToPublic(e.key)
}

func (e *jclabPrs2601FinalSigner) KeyId() string {
	return e.keyId
}

func (e *jclabPrs2601FinalSigner) SignMessage(msg []byte) ([]byte, error) {
	return nil, errors.New("not supported")
}

func (e *jclabPrs2601FinalSigner) SignJson(msg *SignedJson[any]) error {
	encoded, err := cjson(msg.Signed)
	if err != nil {
		return err
	}
	for _, signature := range msg.Signatures {
		rawSig1, err := Decode(signature.Sig)
		if err != nil {
			return err
		}
		sigType := rawSig1[0]
		if sigType != 0x01 {
			return errors.New("invalid signature")
		}
		sig1 := e.key.curve.Signature1FromBytes(rawSig1[1:])
		//PrsResign(inSig *Signature1, M []byte, SignerW1 []byte, RK []byte) (*Signature2, error)
		sig2, err := e.key.curve.PrsResign(sig1, encoded, e.key.firstSignerW1, e.key.rk)
		if err != nil {
			return err
		}
		signature.Sig = Encode(append([]byte{0x02}, sig2.Encode()...))
		signature.Keyid = e.keyId
		return nil
	}
	return errors.New("input json is not signed")
}

func (e *jclabPrs2601FinalVerifier) Engine() Engine {
	return e.engine
}

func (e *jclabPrs2601FinalVerifier) PublicKey() crypto.PublicKey {
	return e.key
}

func (e *jclabPrs2601FinalVerifier) KeyId() string {
	return e.keyId
}

func (e *jclabPrs2601FinalVerifier) VerifyMessage(msg []byte, sig []byte) (bool, error) {
	sigType := sig[0]
	if sigType != 0x02 {
		return false, errors.New("invalid signature")
	}
	sig2 := e.key.curve.Signature2FromBytes(sig[1:])
	return e.key.curve.VerifyL2(sig2, msg, e.key.w1), nil
}

func (e *jclabPrs2601FinalVerifier) VerifyJson(msg *SignedJson[any]) (bool, error) {
	return verifyJson(e, msg)
}
