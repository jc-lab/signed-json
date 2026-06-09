package signature

import (
	"crypto"

	"github.com/jc-lab/jclab-prs-2601/engine"
)

type JclabPrs2601PrivateKey struct {
	keyType string
	curve   engine.CurveEngine
	s       []byte
	w1      []byte
}

type JclabPrs2601PublicKey struct {
	keyType string
	curve   engine.CurveEngine
	w1      []byte
}

type JclabPrs2601ResignKey struct {
	keyType       string
	curve         engine.CurveEngine
	firstSignerW1 []byte
	rk            []byte
	w1            []byte
}

func (k *JclabPrs2601PrivateKey) GetS() []byte {
	return k.s
}

func (k *JclabPrs2601PublicKey) GetW1() []byte {
	return k.w1
}

func NewJclabPrs2601PrivateKey(curveEngine engine.CurveEngine, keyType string, S []byte) (crypto.PrivateKey, error) {
	w, err := curveEngine.GeneratePublicKey(S)
	if err != nil {
		return nil, err
	}
	return &JclabPrs2601PrivateKey{
		curve:   curveEngine,
		keyType: keyType,
		s:       S,
		w1:      w,
	}, nil
}

func NewJclabPrs2601PublicKey(curveEngine engine.CurveEngine, keyType string, W1 []byte) (crypto.PublicKey, error) {
	return &JclabPrs2601PublicKey{
		curve:   curveEngine,
		keyType: keyType,
		w1:      W1,
	}, nil
}

func NewJclabPrs2601ResignKey(curveEngine engine.CurveEngine, keyType string, firstSignerW1 []byte, RK []byte, W1 []byte) (crypto.PrivateKey, error) {
	return &JclabPrs2601ResignKey{
		curve:         curveEngine,
		keyType:       keyType,
		firstSignerW1: firstSignerW1,
		rk:            RK,
		w1:            W1,
	}, nil
}

func NewJclabPrs2601Bls12381PrivateKey(S []byte) (crypto.PrivateKey, error) {
	curveEngine, err := engine.NewBLS12381Engine()
	if err != nil {
		return nil, err
	}
	w, err := curveEngine.GeneratePublicKey(S)
	if err != nil {
		return nil, err
	}
	return &JclabPrs2601PrivateKey{
		curve:   curveEngine,
		keyType: "bls12-381",
		s:       S,
		w1:      w,
	}, nil
}

func NewJclabPrs2601Bls12381PublicKey(W1 []byte) (crypto.PrivateKey, error) {
	curveEngine, err := engine.NewBLS12381Engine()
	if err != nil {
		return nil, err
	}
	return &JclabPrs2601PublicKey{
		curve:   curveEngine,
		keyType: "bls12-381",
		w1:      W1,
	}, nil
}

func NewJclabPrs2601Bls12381ResignKey(firstSignerW1 []byte, RK []byte, W1 []byte) (crypto.PrivateKey, error) {
	curveEngine, err := engine.NewBLS12381Engine()
	if err != nil {
		return nil, err
	}
	return &JclabPrs2601ResignKey{
		curve:         curveEngine,
		keyType:       "bls12-381",
		firstSignerW1: firstSignerW1,
		rk:            RK,
	}, nil
}

func jclabPrs2601PrivateToPublic(key *JclabPrs2601PrivateKey) *JclabPrs2601PublicKey {
	return &JclabPrs2601PublicKey{
		curve:   key.curve,
		keyType: key.keyType,
		w1:      key.w1,
	}
}

func jclabPrs2601RkToPublic(key *JclabPrs2601ResignKey) *JclabPrs2601PublicKey {
	return &JclabPrs2601PublicKey{
		curve:   key.curve,
		keyType: key.keyType,
		w1:      key.w1,
	}
}
