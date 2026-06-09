package signature

import (
	"encoding/base64"
	"testing"

	"github.com/jc-lab/jclab-prs-2601/engine"
	"github.com/stretchr/testify/assert"
)

var testingJclabPrs2601FirstEngine = NewJclabPrs2601FirstEngine()

var (
	testingJclabPrs2601Bls12381, _ = engine.NewBLS12381Engine()

	testingJclabPrs2601Alice_S, _  = base64.RawURLEncoding.DecodeString("FsafwnA2xEibPErXM0G0_dr3tBtZS9C45P9s-Ry6N-I")
	testingJclabPrs2601Alice_W1, _ = base64.RawURLEncoding.DecodeString("AgxeoRZJOUkrgJLgjSnNKbRLZxxeqTktcR_RG4jRkgAXIPF8g9BdbqvrWFsWm7X4bw")
	testingJclabPrs2601Alice_W2, _ = base64.RawURLEncoding.DecodeString("AgcFybh8HCVvh14aJqz8mf8pulmHOwU23sSnih0ZgwKo_M1pEFBpdvGid5J5X7fi3xCmCgDtAbcRUktST4LzahQw-4seBG-3mQE3oO9_4TGkexQsjjfWlz3P1G4K6T7tEw")

	testingJclabPrs2601Bob_S, _  = base64.RawURLEncoding.DecodeString("T4OKowkb3OARsvTzqQYSKO_tPJQAdSbRQaCHDhHwhJ8")
	testingJclabPrs2601Bob_W1, _ = base64.RawURLEncoding.DecodeString("Axmc2yYH04804aRsGR0bnbK3Zoz99itzagN2MI7VcpFuqdYZ2JY6DRsbBrXybMBTwQ")
	testingJclabPrs2601Bob_W2, _ = base64.RawURLEncoding.DecodeString("AgX38iPqAD0epVokMbKhcjVtavWyy6B2QMn8x9rkG9JuskuZKiAurYOqB2RnVKmSIRlgjTESS9VVPiZwcbTAkMkw2Op8HGwd9GO8hUStSm940Wz0V7OX7FSNrTvQ2LrVHQ")
)

func Test_jclabPrs2601FirstEngine_GetEngine(t *testing.T) {
	engine, err := GetEngine("jclab-prs-2601:first")
	assert.Nil(t, err)
	assert.IsType(t, &jclabPrs2601FirstEngine{}, engine)
}

func Test_jclabPrs2601FirstEngine_Schema(t *testing.T) {
	assert.Equal(t, testingJclabPrs2601FirstEngine.Schema(), "jclab-prs-2601:first")
}

func Test_jclabPrs2601FirstEngine_KeyTypeByPublicKey(t *testing.T) {
	publicKey, _ := NewJclabPrs2601Bls12381PublicKey(testingJclabPrs2601Alice_W1)
	keyType, _ := testingJclabPrs2601FirstEngine.KeyTypeByPublicKey(publicKey)
	assert.Equal(t, "bls12-381", keyType)
}

func Test_jclabPrs2601FirstEngine_KeyTypeByPrivateKey(t *testing.T) {
	privateKey, _ := NewJclabPrs2601Bls12381PrivateKey(testingJclabPrs2601Alice_S)
	keyType, _ := testingJclabPrs2601FirstEngine.KeyTypeByPrivateKey(privateKey)
	assert.Equal(t, "bls12-381", keyType)
}

func Test_jclabPrs2601FirstEngine_SignVerifyJson(t *testing.T) {
	privateKey, _ := NewJclabPrs2601Bls12381PrivateKey(testingJclabPrs2601Alice_S)

	signer, err := testingJclabPrs2601FirstEngine.NewSigner(privateKey, "aaaa")
	assert.Nil(t, err)

	verifier, err := testingJclabPrs2601FirstEngine.NewVerifier(signer.PublicKey(), "aaaa")
	assert.Nil(t, err)

	commonJsonTest(t, signer, verifier, "aaaa", "")
}
