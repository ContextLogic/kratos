package hash

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"

	"github.com/ory/kratos/driver/config"
)

var ErrUnknownHashAlgorithm = errors.New("unknown hash algorithm")

func Compare(ctx context.Context, password []byte, hash []byte) error {
	if IsBcryptHash(hash) {
		return CompareBcrypt(ctx, password, hash)
	} else if IsArgon2idHash(hash) {
		return CompareArgon2id(ctx, password, hash)
	} else if IsPbkdf2Hash(hash) {
		return ComparePbkdf2(ctx, password, hash)
	} else {
		return ErrUnknownHashAlgorithm
	}
}

func CompareBcrypt(_ context.Context, password []byte, hash []byte) error {
	if err := validateBcryptPasswordLength(password); err != nil {
		return err
	}

	err := bcrypt.CompareHashAndPassword(hash, password)
	if err != nil {
		return err
	}

	return nil
}

func ComparePbkdf2(_ context.Context, password []byte, hash []byte) error {
	parts := strings.Split(string(hash), "$")

	if len(parts) != 5 {
		return ErrInvalidHash
	}

	rawSalt, err := parseBase64(parts[3])
	if err != nil {
		fmt.Println(err)
		return ErrInvalidHash
	}

	options := parseOptions(parts[2])

	if iterations, ok := options["i"]; ok {
		if verifyPBKDF2(sha256.New, string(password), iterations, rawSalt, parts[4]) {
			return nil
		}

		return ErrMismatchedHashAndPassword
	}

	return ErrInvalidHash
}

func CompareArgon2id(_ context.Context, password []byte, hash []byte) error {
	// Extract the parameters, salt and derived key from the encoded password
	// hash.
	p, salt, hash, err := decodeArgon2idHash(string(hash))
	if err != nil {
		return err
	}

	// Derive the key from the other password using the same parameters.
	otherHash := argon2.IDKey([]byte(password), salt, p.Iterations, uint32(p.Memory), p.Parallelism, p.KeyLength)

	// Check that the contents of the hashed passwords are identical. Note
	// that we are using the subtle.ConstantTimeCompare() function for this
	// to help prevent timing attacks.
	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return nil
	}
	return ErrMismatchedHashAndPassword
}

func IsBcryptHash(hash []byte) bool {
	res, _ := regexp.Match("^\\$2[abzy]?\\$", hash)
	return res
}

func IsArgon2idHash(hash []byte) bool {
	res, _ := regexp.Match("^\\$argon2id\\$", hash)
	return res
}

func IsPbkdf2Hash(hash []byte) bool {
	res, _ := regexp.Match("^\\$pbkdf2-sha256\\$", hash)
	return res
}

func decodeArgon2idHash(encodedHash string) (p *config.Argon2, salt, hash []byte, err error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err = fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	p = new(config.Argon2)
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, err
	}
	p.SaltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, err
	}
	p.KeyLength = uint32(len(hash))

	return p, salt, hash, nil
}

// copied from https://github.com/aykevl/pwhash/blob/master/pwhash.go#L115
func parseBase64(s string) ([]byte, error) {
	// Strip off trailing '=' chars.
	s = strings.TrimRight(s, "=")

	// Use standard encoding (not URL encoding).
	s = strings.Replace(s, ".", "+", -1) // for MCF
	s = strings.Replace(s, "-", "+", -1)
	s = strings.Replace(s, "_", "/", -1)

	return base64.RawStdEncoding.Strict().DecodeString(s)
}

// copied from https://github.com/aykevl/pwhash/blob/master/pwhash.go#L115
// verifyPBKDF2 checks whether the given PBKDF2 hash is valid and returns true
// iff the password matches the hash.
func verifyPBKDF2(hashFunc func() hash.Hash, password string, iterations int, salt []byte, hash string) bool {
	rawHash, err := parseBase64(hash)
	if err != nil {
		return false
	}

	key := pbkdf2.Key([]byte(password), salt, iterations, len(rawHash), hashFunc)
	return subtle.ConstantTimeCompare(rawHash, key) == 1
}

// parseOptions parses an option string like "m=65536,t=1,p=4" into its
// individual values: {"m": 65536, "t": 1, "p"=4}. A parse error results in a
// nil map.
func parseOptions(s string) map[string]int {
	parts := strings.Split(s, ",")
	opts := make(map[string]int)
	for _, part := range parts {
		index := strings.IndexByte(s, '=')
		if index < 0 {
			return nil
		}
		key := part[:index]
		value, err := strconv.Atoi(part[index+1:])
		if err != nil {
			return nil
		}
		if _, ok := opts[key]; ok {
			return nil // key already exists (invalid)
		}
		opts[key] = value
	}
	return opts
}
