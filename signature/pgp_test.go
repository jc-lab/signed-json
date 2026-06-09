package signature

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/stretchr/testify/assert"
)

var testingPgpEngine = NewPgpEngine().(*pgpEngine)

func Test_pgp_GetEngine(t *testing.T) {
	engine, err := GetEngine("pgp")
	assert.Nil(t, err)
	assert.IsType(t, &pgpEngine{}, engine)
}

func Test_pgpEngine_Schema(t *testing.T) {
	assert.Equal(t, testingPgpEngine.Schema(), "pgp")
}

func Test_pgpEngine_GeneratePublicKey(t *testing.T) {
	privateKey, err := ReadPgpArmorPrivateKey(testGpgRsaPrivateKey)
	assert.Nil(t, err)

	regenPublicKey, err := testingPgpEngine.GeneratePublicKey(privateKey)
	assert.Nil(t, err)

	regenPublicKeyRaw, _ := PgpPublicKeySerialize(regenPublicKey)
	assert.Equal(t, "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", base64.StdEncoding.EncodeToString(regenPublicKeyRaw))
}

func Test_pgpEngine_KeyTypeByPublicKey(t *testing.T) {
	privateKey, _ := ReadPgpArmorPrivateKey(testGpgRsaPrivateKey)
	publicKey, _ := testingPgpEngine.GeneratePublicKey(privateKey)
	keyType, _ := testingPgpEngine.KeyTypeByPublicKey(publicKey)
	assert.Equal(t, "pgp", keyType)
}

func Test_pgpEngine_KeyTypeByPrivateKey(t *testing.T) {
	privateKey, _ := ReadPgpArmorPrivateKey(testGpgRsaPrivateKey)
	keyType, _ := testingPgpEngine.KeyTypeByPrivateKey(privateKey)
	assert.Equal(t, "pgp", keyType)
}

func Test_pgpEngine_SignVerifyJson(t *testing.T) {
	privateKey, err := ReadPgpArmorPrivateKey(testGpgRsaPrivateKey)
	assert.Nil(t, err)

	config := &packet.Config{
		Time: func() time.Time {
			return time.Unix(1704067200, 0)
		},
	}

	signer, err := testingPgpEngine.NewSignerWithConfig(privateKey, "aaaa", config)
	assert.Nil(t, err)

	verifier, err := testingPgpEngine.NewVerifierWithConfig(signer.PublicKey(), "aaaa", config)
	assert.Nil(t, err)

	commonJsonTest(t, signer, verifier, "VFjJlpA8bbOu-jd6gxS0JgDT2WY", "")
}
