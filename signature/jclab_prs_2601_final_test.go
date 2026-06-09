package signature

import (
	"encoding/json"
	"testing"

	"github.com/jc-lab/jclab-prs-2601/engine"
	"github.com/stretchr/testify/assert"
)

var testingJclabPrs2601FinalEngine = NewJclabPrs2601FinalEngine()

func Test_jclabPrs2601FinalEngine_GetEngine(t *testing.T) {
	engine, err := GetEngine("jclab-prs-2601:final")
	assert.Nil(t, err)
	assert.IsType(t, &jclabPrs2601FinalEngine{}, engine)
}

func Test_jclabPrs2601FinalEngine_Schema(t *testing.T) {
	assert.Equal(t, testingJclabPrs2601FinalEngine.Schema(), "jclab-prs-2601:final")
}

func Test_jclabPrs2601FinalEngine_KeyTypeByPublicKey(t *testing.T) {
	publicKey, _ := NewJclabPrs2601Bls12381PublicKey(testingJclabPrs2601Alice_W1)
	keyType, _ := testingJclabPrs2601FinalEngine.KeyTypeByPublicKey(publicKey)
	assert.Equal(t, "bls12-381", keyType)
}

func Test_jclabPrs2601FinalEngine_KeyTypeByPrivateKey(t *testing.T) {
	curveEngine, err := engine.NewBLS12381Engine()
	if err != nil {
		t.Fatal(err)
	}
	testingJclabPrs2601AliceToBob_RK, err := curveEngine.PrsResigningKey(testingJclabPrs2601Alice_W2, testingJclabPrs2601Bob_S)
	if err != nil {
		t.Fatal(err)
	}

	resignKey, _ := NewJclabPrs2601Bls12381ResignKey(testingJclabPrs2601Alice_W1, testingJclabPrs2601AliceToBob_RK, testingJclabPrs2601Bob_W1)
	keyType, _ := testingJclabPrs2601FinalEngine.KeyTypeByPrivateKey(resignKey)
	assert.Equal(t, "bls12-381", keyType)
}

func Test_jclabPrs2601FinalEngine_ReSignVerifyJson(t *testing.T) {
	curveEngine, err := engine.NewBLS12381Engine()
	if err != nil {
		t.Fatal(err)
	}
	testingJclabPrs2601AliceToBob_RK, err := curveEngine.PrsResigningKey(testingJclabPrs2601Alice_W2, testingJclabPrs2601Bob_S)
	if err != nil {
		t.Fatal(err)
	}

	signedJsonString := `{"signed":{"hello":"WORLD"},"signatures":[{"keyid":"aaaa","sig":"AQIKVn36F3FvRnAn3LZO2tlDNPpHJoYY9eb7CEAGsdV4_mzNRQLBx1iTWnCPgh4hTjMNUh62k6V_qAJj8has1ZFwq04O1336XcKxf6fb2pA1goTY2oGNp1X6_Q5bLHWlBrc"}]}`

	resignKey, _ := NewJclabPrs2601Bls12381ResignKey(testingJclabPrs2601Alice_W1, testingJclabPrs2601AliceToBob_RK, testingJclabPrs2601Bob_W1)

	signer, err := testingJclabPrs2601FinalEngine.NewSigner(resignKey, "aaaa")
	assert.Nil(t, err)

	publicKey, _ := NewJclabPrs2601Bls12381PublicKey(testingJclabPrs2601Bob_W1)
	verifier, err := testingJclabPrs2601FinalEngine.NewVerifier(publicKey, "aaaa")
	assert.Nil(t, err)

	root := &SignedJson[any]{
		Signed: &TestMessage{},
	}
	err = json.Unmarshal([]byte(signedJsonString), root)
	assert.Nil(t, err)

	err = signer.SignJson(root)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(root.Signatures))

	assert.Equal(t, "aaaa", root.Signatures[0].Keyid)

	res, err := verifier.VerifyJson(root)
	assert.True(t, res)
}
