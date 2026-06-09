package signature

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type TestMessage struct {
	Hello string `json:"hello"`
}

func commonJsonTest(t *testing.T, signer Signer, verifier Verifier, keyId string, expectedSig string) {
	root := &SignedJson[any]{
		Signed: &TestMessage{
			Hello: "WORLD",
		},
	}

	err := signer.SignJson(root)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(root.Signatures))

	assert.Equal(t, keyId, root.Signatures[0].Keyid)
	if expectedSig != "" {
		assert.Equal(t, expectedSig, root.Signatures[0].Sig)
	}

	res, err := verifier.VerifyJson(root)
	assert.True(t, res)

	root.Signatures[0].Sig = "XXXX" + root.Signatures[0].Sig[4:]
	res, err = verifier.VerifyJson(root)
	assert.False(t, res)
}

func Test_cjsonCrLf(t *testing.T) {
	input := &TestMessage{
		Hello: "Hello\nWorld",
	}

	output, err := cjson(input)
	assert.Nil(t, err)

	assert.Equal(t, "{\"hello\":\"Hello\\nWorld\"}", string(output))
}
