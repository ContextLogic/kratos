package hash_test

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/hash"
	"github.com/ory/kratos/internal"
)

func mkpw(t *testing.T, length int) []byte {
	pw := make([]byte, length)
	_, err := rand.Read(pw)
	require.NoError(t, err)
	return pw
}

func TestArgonHasher(t *testing.T) {
	for k, pw := range [][]byte{
		mkpw(t, 8),
		mkpw(t, 16),
		mkpw(t, 32),
		mkpw(t, 64),
		mkpw(t, 128),
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			_, reg := internal.NewFastRegistryWithMocks(t)
			for kk, h := range []hash.Hasher{
				hash.NewHasherArgon2(reg),
			} {
				t.Run(fmt.Sprintf("hasher=%T/password=%d", h, kk), func(t *testing.T) {
					hs, err := h.Generate(context.Background(), pw)
					require.NoError(t, err)
					assert.NotEqual(t, pw, hs)

					t.Logf("hash: %s", hs)
					require.NoError(t, hash.CompareArgon2id(context.Background(), pw, hs))

					mod := make([]byte, len(pw))
					copy(mod, pw)
					mod[len(pw)-1] = ^pw[len(pw)-1]
					require.Error(t, hash.CompareArgon2id(context.Background(), mod, hs))
				})
			}
		})
	}
}

func TestBcryptHasherGeneratesErrorWhenPasswordIsLong(t *testing.T) {
	_, reg := internal.NewFastRegistryWithMocks(t)
	hasher := hash.NewHasherBcrypt(reg)

	password := mkpw(t, 73)
	res, err := hasher.Generate(context.Background(), password)

	assert.Error(t, err, "password is too long")
	assert.Nil(t, res)
}

func TestBcryptHasherGeneratesHash(t *testing.T) {
	for k, pw := range [][]byte{
		mkpw(t, 8),
		mkpw(t, 16),
		mkpw(t, 32),
		mkpw(t, 64),
		mkpw(t, 72),
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			_, reg := internal.NewFastRegistryWithMocks(t)
			hasher := hash.NewHasherBcrypt(reg)
			res, err := hasher.Generate(context.Background(), pw)

			assert.Nil(t, err)

			// Valid format: $2a$12$[22 character salt][31 character hash]
			assert.Equal(t, 60, len(string(res)), "invalid bcrypt hash length")
			assert.Equal(t, "$2a$04$", string(res)[:7], "invalid bcrypt identifier")
		})
	}
}

func TestComparatorBcryptFailsWhenPasswordIsTooLong(t *testing.T) {
	password := mkpw(t, 73)
	err := hash.CompareBcrypt(context.Background(), password, []byte("hash"))

	assert.Error(t, err, "password is too long")
}

func TestComparatorBcryptSuccess(t *testing.T) {
	for k, pw := range [][]byte{
		mkpw(t, 8),
		mkpw(t, 16),
		mkpw(t, 32),
		mkpw(t, 64),
		mkpw(t, 72),
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			_, reg := internal.NewFastRegistryWithMocks(t)
			hasher := hash.NewHasherBcrypt(reg)

			hs, err := hasher.Generate(context.Background(), pw)

			assert.Nil(t, err)

			err = hash.CompareBcrypt(context.Background(), pw, hs)
			assert.Nil(t, err, "hash validation fails")
		})
	}
}

func TestComparatorBcryptFail(t *testing.T) {
	for k, pw := range [][]byte{
		mkpw(t, 8),
		mkpw(t, 16),
		mkpw(t, 32),
		mkpw(t, 64),
		mkpw(t, 72),
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			mod := make([]byte, len(pw))
			copy(mod, pw)
			mod[len(pw)-1] = ^pw[len(pw)-1]

			err := hash.CompareBcrypt(context.Background(), pw, mod)
			assert.Error(t, err)
		})
	}
}

func TestCompare(t *testing.T) {
	assert.Nil(t, hash.Compare(context.Background(), []byte("test"), []byte("$2a$12$o6hx.Wog/wvFSkT/Bp/6DOxCtLRTDj7lm9on9suF/WaCGNVHbkfL6")))
	assert.Nil(t, hash.CompareBcrypt(context.Background(), []byte("test"), []byte("$2a$12$o6hx.Wog/wvFSkT/Bp/6DOxCtLRTDj7lm9on9suF/WaCGNVHbkfL6")))
	assert.Error(t, hash.Compare(context.Background(), []byte("test"), []byte("$2a$12$o6hx.Wog/wvFSkT/Bp/6DOxCtLRTDj7lm9on9suF/WaCGNVHbkfL7")))

	assert.Nil(t, hash.Compare(context.Background(), []byte("test"), []byte("$2a$15$GRvRO2nrpYTEuPQX6AieaOlZ4.7nMGsXpt.QWMev1zrP86JNspZbO")))
	assert.Nil(t, hash.CompareBcrypt(context.Background(), []byte("test"), []byte("$2a$15$GRvRO2nrpYTEuPQX6AieaOlZ4.7nMGsXpt.QWMev1zrP86JNspZbO")))
	assert.Error(t, hash.Compare(context.Background(), []byte("test"), []byte("$2a$15$GRvRO2nrpYTEuPQX6AieaOlZ4.7nMGsXpt.QWMev1zrP86JNspZb1")))

	assert.Nil(t, hash.Compare(context.Background(), []byte("test"), []byte("$argon2id$v=19$m=32,t=2,p=4$cm94YnRVOW5jZzFzcVE4bQ$MNzk5BtR2vUhrp6qQEjRNw")))
	assert.Nil(t, hash.CompareArgon2id(context.Background(), []byte("test"), []byte("$argon2id$v=19$m=32,t=2,p=4$cm94YnRVOW5jZzFzcVE4bQ$MNzk5BtR2vUhrp6qQEjRNw")))
	assert.Error(t, hash.Compare(context.Background(), []byte("test"), []byte("$argon2id$v=19$m=32,t=2,p=4$cm94YnRVOW5jZzFzcVE4bQ$MNzk5BtR2vUhrp6qQEjRN2")))

	assert.Nil(t, hash.Compare(context.Background(), []byte("test"), []byte("$argon2id$v=19$m=32,t=5,p=4$cm94YnRVOW5jZzFzcVE4bQ$fBxypOL0nP/zdPE71JtAV71i487LbX3fJI5PoTN6Lp4")))
	assert.Nil(t, hash.CompareArgon2id(context.Background(), []byte("test"), []byte("$argon2id$v=19$m=32,t=5,p=4$cm94YnRVOW5jZzFzcVE4bQ$fBxypOL0nP/zdPE71JtAV71i487LbX3fJI5PoTN6Lp4")))
	assert.Error(t, hash.Compare(context.Background(), []byte("test"), []byte("$argon2id$v=19$m=32,t=5,p=4$cm94YnRVOW5jZzFzcVE4bQ$fBxypOL0nP/zdPE71JtAV71i487LbX3fJI5PoTN6Lp5")))
}

func TestTest(t *testing.T) {
	assert.False(t, hash.IsPbkdf2Hash([]byte("$pbkdf2-sha512$i=10000$O484sW7giRw+nt5WVnp15w$jEUMVZ9adB+63ko/8Dr9oB1jWdndpVVQ65xRlT+tA1GTKcJ7BWlTjdaiILzZAhIPEtgTImKvbgnu8TS/ZrjKgA")))
	assert.True(t, hash.IsPbkdf2Hash([]byte("$pbkdf2-sha256$i=10000$O484sW7giRw+nt5WVnp15w$jEUMVZ9adB+63ko/8Dr9oB1jWdndpVVQ65xRlT+tA1GTKcJ7BWlTjdaiILzZAhIPEtgTImKvbgnu8TS/ZrjKgA")))
	assert.False(t, hash.IsPbkdf2Hash([]byte("$pbkdf2-sha1$i=10000$O484sW7giRw+nt5WVnp15w$jEUMVZ9adB+63ko/8Dr9oB1jWdndpVVQ65xRlT+tA1GTKcJ7BWlTjdaiILzZAhIPEtgTImKvbgnu8TS/ZrjKgA")))

	assert.False(t, hash.IsPbkdf2Hash([]byte("$pbkdf2-sha1123$i=10000$O484sW7giRw+nt5WVnp15w$jEUMVZ9adB+63ko/8Dr9oB1jWdndpVVQ65xRlT+tA1GTKcJ7BWlTjdaiILzZAhIPEtgTImKvbgnu8TS/ZrjKgA")))
	assert.False(t, hash.IsPbkdf2Hash([]byte("$pbkdf2-256$i=10000$O484sW7giRw+nt5WVnp15w$jEUMVZ9adB+63ko/8Dr9oB1jWdndpVVQ65xRlT+tA1GTKcJ7BWlTjdaiILzZAhIPEtgTImKvbgnu8TS/ZrjKgA")))
}

func TestTest2(t *testing.T) {
	assert.Nil(t, hash.Compare(context.Background(),
		[]byte("WC2Bgb4YEMmYXbD"),
		[]byte("$pbkdf2-sha256$i=16000$UmqN8V4rhXBuTakVolRKSWltrXXunXMuhTDmnDPmXCsF4DznXEsJ4dy7l1JKqVVKaU2pNUbI.d87J0RIKUUIYaw1pjQGQAhhTMmZ875XqjXmXCvlHOM8J0TIWSslZGzt3TvHmNOa856zFqK0ljLmfE.JcY6xtlYK4TxnbE1pTakVwtibU2oNodTaG2PMuff.3xtjbE3pndPa23vvHaM0RgiB0BojRMg5Z.y91/ofY.w9p5SSUqqVMmYMwdibE6IUYkypNUbIuXeOcY4Rwvj/3xuDcE4JoXTuvRcCIESodY5xjrG2ds7Zm9N6753z3tv7f09pzRnDOGeMEcJ4b.29Fw$WZfa.Njy04CY4w526qwn7GZC1V8/9RidpXCEC0Oyle0"),
	))
	assert.Nil(t, hash.Compare(context.Background(),
		[]byte("MyT3stPa55WoRD123"),
		[]byte("$pbkdf2-sha256$i=16000$hVBqbW3NmbP23htDiLH2PkdIqZUypnSuFSKEMIZQai2l1FrL2fufcy7lXMs5R0ipNSaEUAoBwFgLwbh3LuVcy9mbs7Y25hxDKOU8h7AWIgTgnFPKmbN2ztk7pxQCoJQS4hzj3DvHmFOKEaLU2jvH.B/D2BuDMOY8h/AeoxQC4FxrTYnR.l9LKeU8Z8w5p3TOmbMWghBirLW29r73HmPs/b93DqH0/h.jdO6d0zrH.D8HgHDOOQcgJCSk9N67FwIgRGiNkVJKqRVirBVCCOF8r1VKybk3JgQAoNS6F0JojXGOkdKaM2bMmRNizLmXMubcW0uJsVYK4dybk/Ieo7RWCg$M7TqF6cv1vDHMtcVAWEqFNwd5QZQJBFVBdpP.aT7fOE"),
	))
	assert.Error(t, hash.Compare(context.Background(),
		[]byte("MyT3stPa55WoRD123"),
		[]byte("$pbkdf2-sha256$i=16000$hVBqbW3NmbP23htDiLH2PkdIqZUypnSuFSKEMIZQai2l1FrL2fufcy7lXMs5R0ipNSaEUAoBwFgLwbh3LuVcy9mbs7Y25hxDKOU8h7AWIgTgnFPKmbN2ztk7pxQCoJQS4hzj3DvHmFOKEaLU2jvH.B/D2BuDMOY8h/AeoxQC4FxrTYnR.l9LKeU8Z8w5p3TOmbMWghBirLW29r73HmPs/b93DqH0/h.jdO6d0zrH.D8HgHDOOQcgJCSk9N67FwIgRGiNkVJKqRVirBVCCOF8r1VKybk3JgQAoNS6F0JojXGOkdKaM2bMmRNizLmXMubcW0uJsVYK4dybk/Ieo7RWCg$M7TqF6cv1vDHMtcVAWEqFNwd5QZQJBFVBdpP.fail"),
	))
}

func TestTest3(t *testing.T) {
	file, err := os.Open("hashes.txt")
	assert.NoError(t, err)
	defer file.Close()

	r := bufio.NewReader(file)
	for i := 1; i <= 10000; i++ {
		line, _, _ := r.ReadLine()
		data := make([]string, 2)
		err := json.Unmarshal(line, &data)
		assert.NoError(t, err)
		assert.Nil(t, hash.Compare(context.Background(),
			[]byte(data[0]),
			[]byte(data[1]),
		))
	}
}
