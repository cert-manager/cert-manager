package pemutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"hash"
	"io"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/pbkdf2"
)

// PBKDF2SaltSize is the default size of the salt for PBKDF2, 128-bit salt.
const PBKDF2SaltSize = 16

// PBKDF2Iterations is the default number of iterations for PBKDF2, 100k
// iterations. Nist recommends at least 10k, 1Passsword uses 100k.
const PBKDF2Iterations = 100000

// pkcs8 reflects an ASN.1, PKCS#8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algo      pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// Encrypted pkcs8
// Based on https://github.com/youmark/pkcs8
// MIT license
type prfParam struct {
	Algo      asn1.ObjectIdentifier
	NullParam asn1.RawValue
}

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	PrfParam       prfParam `asn1:"optional"`
}

type pbkdf2Algorithms struct {
	Algo         asn1.ObjectIdentifier
	PBKDF2Params pbkdf2Params
}

type pbkdf2Encs struct {
	EncryAlgo asn1.ObjectIdentifier
	IV        []byte
}

type pbes2Params struct {
	KeyDerivationFunc pbkdf2Algorithms
	EncryptionScheme  pbkdf2Encs
}

type encryptedlAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters pbes2Params
}

type encryptedPrivateKeyInfo struct {
	Algo       encryptedlAlgorithmIdentifier
	PrivateKey []byte
}

// Algorithm Identifiers for Ed25519, Ed448, X25519 and X448 for use in the
// Internet X.509 Public Key Infrastructure
// https://tools.ietf.org/html/draft-ietf-curdle-pkix-10
var (
	// oidX25519  = asn1.ObjectIdentifier{1, 3, 101, 110}
	oidEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}

	// key derivation functions
	oidPKCS5PBKDF2    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidPBES2          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}

	// encryption
	oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES196CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidDESCBC    = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
	oidD3DESCBC  = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

// rfc1423Algo holds a method for enciphering a PEM block.
type rfc1423Algo struct {
	cipher     x509.PEMCipher
	name       string
	cipherFunc func(key []byte) (cipher.Block, error)
	keySize    int
	blockSize  int
	identifier asn1.ObjectIdentifier
}

// rfc1423Algos holds a slice of the possible ways to encrypt a PEM
// block. The ivSize numbers were taken from the OpenSSL source.
var rfc1423Algos = []rfc1423Algo{{
	cipher:     x509.PEMCipherDES,
	name:       "DES-CBC",
	cipherFunc: des.NewCipher,
	keySize:    8,
	blockSize:  des.BlockSize,
	identifier: oidDESCBC,
}, {
	cipher:     x509.PEMCipher3DES,
	name:       "DES-EDE3-CBC",
	cipherFunc: des.NewTripleDESCipher,
	keySize:    24,
	blockSize:  des.BlockSize,
	identifier: oidD3DESCBC,
}, {
	cipher:     x509.PEMCipherAES128,
	name:       "AES-128-CBC",
	cipherFunc: aes.NewCipher,
	keySize:    16,
	blockSize:  aes.BlockSize,
	identifier: oidAES128CBC,
}, {
	cipher:     x509.PEMCipherAES192,
	name:       "AES-192-CBC",
	cipherFunc: aes.NewCipher,
	keySize:    24,
	blockSize:  aes.BlockSize,
	identifier: oidAES196CBC,
}, {
	cipher:     x509.PEMCipherAES256,
	name:       "AES-256-CBC",
	cipherFunc: aes.NewCipher,
	keySize:    32,
	blockSize:  aes.BlockSize,
	identifier: oidAES256CBC,
},
}

func cipherByKey(key x509.PEMCipher) *rfc1423Algo {
	for i := range rfc1423Algos {
		alg := &rfc1423Algos[i]
		if alg.cipher == key {
			return alg
		}
	}
	return nil
}

// deriveKey uses a key derivation function to stretch the password into a key
// with the number of bits our cipher requires. This algorithm was derived from
// the OpenSSL source.
func (c rfc1423Algo) deriveKey(password, salt []byte, h func() hash.Hash) []byte {
	return pbkdf2.Key(password, salt, PBKDF2Iterations, c.keySize, h)
}

// ParsePKCS8PrivateKey parses an unencrypted, PKCS#8 private key. See RFC
// 5208.
//
// Supported key types include RSA, ECDSA, and Ed25519. Unknown key types
// result in an error.
//
// On success, key will be of type *rsa.PrivateKey, *ecdsa.PublicKey, or
// ed25519.PrivateKey.
func ParsePKCS8PrivateKey(der []byte) (key interface{}, err error) {
	var privKey pkcs8
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, err
	}

	switch {
	case privKey.Algo.Algorithm.Equal(oidEd25519):
		seed := make([]byte, ed25519.SeedSize)
		copy(seed, privKey.PrivateKey[2:])
		key = ed25519.NewKeyFromSeed(seed)
		return key, nil
	// Proof of concept for key agreement algorithm X25519.
	// A real implementation would use their own types.
	//
	// case privKey.Algo.Algorithm.Equal(oidX25519):
	// 	k := make([]byte, ed25519.PrivateKeySize)
	// 	var pub, priv [32]byte
	// 	copy(priv[:], privKey.PrivateKey[2:])
	// 	curve25519.ScalarBaseMult(&pub, &priv)
	// 	copy(k, priv[:])
	// 	copy(k[32:], pub[:])
	// 	key = ed25519.PrivateKey(k)
	// 	return key, nil
	default:
		return x509.ParsePKCS8PrivateKey(der)
	}
}

// ParsePKIXPublicKey parses a DER encoded public key. These values are
// typically found in PEM blocks with "BEGIN PUBLIC KEY".
//
// Supported key types include RSA, DSA, ECDSA, and Ed25519. Unknown key types
// result in an error.
//
// On success, pub will be of type *rsa.PublicKey, *dsa.PublicKey,
// *ecdsa.PublicKey, or ed25519.PublicKey.
func ParsePKIXPublicKey(derBytes []byte) (pub interface{}, err error) {
	var pki publicKeyInfo
	if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}

	switch {
	case pki.Algo.Algorithm.Equal(oidEd25519):
		pub = ed25519.PublicKey(pki.PublicKey.Bytes)
		return pub, nil
	// Prove of concept for key agreement algorithm X25519.
	// A real implementation would use their own types.
	//
	// case pki.Algo.Algorithm.Equal(oidX25519):
	// 	pub = ed25519.PublicKey(pki.PublicKey.Bytes)
	// 	fmt.Fprintf(os.Stderr, "% x\n", pub)
	// 	return pub, nil
	default:
		return x509.ParsePKIXPublicKey(derBytes)
	}
}

// MarshalPKIXPublicKey serialises a public key to DER-encoded PKIX format. The
// following key types are supported: *rsa.PublicKey, *ecdsa.PublicKey,
// ed25519.Publickey. Unsupported key types result in an error.
func MarshalPKIXPublicKey(pub interface{}) ([]byte, error) {
	switch p := pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return x509.MarshalPKIXPublicKey(pub)
	case ed25519.PublicKey:
		var pkix publicKeyInfo
		pkix.Algo.Algorithm = oidEd25519
		pkix.PublicKey = asn1.BitString{
			Bytes:     p,
			BitLength: 8 * len(p),
		}
		return asn1.Marshal(pkix)
	default:
		return nil, errors.Errorf("x509: unknown public key type: %T", pub)
	}
}

// MarshalPKCS8PrivateKey converts a private key to PKCS#8 encoded form. The
// following key types are supported: *rsa.PrivateKey, *ecdsa.PublicKey,
// ed25519.PrivateKey. Unsupported key types result in an error.
func MarshalPKCS8PrivateKey(key interface{}) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		b, err := x509.MarshalPKCS8PrivateKey(key)
		return b, errors.Wrap(err, "error marshalling PKCS#8")
	case ed25519.PrivateKey:
		var priv pkcs8
		priv.PrivateKey = append([]byte{4, 32}, k.Seed()...)[:34]
		priv.Algo = pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 3, 101, 112},
		}
		b, err := asn1.Marshal(priv)
		return b, errors.Wrap(err, "error marshalling PKCS#8")
	default:
		return nil, errors.Errorf("x509: unknown key type while marshalling PKCS#8: %T", key)
	}
}

// DecryptPEMBlock takes a password encrypted PEM block and the password used
// to encrypt it and returns a slice of decrypted DER encoded bytes.
//
// If the PEM blocks has the Proc-Type header set to "4,ENCRYPTED" it uses
// x509.DecryptPEMBlock to decrypt the block. If not it tries to decrypt the
// block using AES-128-CBC, AES-192-CBC, AES-256-CBC, DES, or 3DES using the
// key derived using PBKDF2 over the given password.
func DecryptPEMBlock(block *pem.Block, password []byte) ([]byte, error) {
	if block.Headers["Proc-Type"] == "4,ENCRYPTED" {
		return x509.DecryptPEMBlock(block, password)
	}

	// PKCS#8 header defined in RFC7468 section 11
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		return DecryptPKCS8PrivateKey(block.Bytes, password)
	}

	return nil, errors.New("unsupported encrypted PEM")
}

// DecryptPKCS8PrivateKey takes a password encrypted private key using the
// PKCS#8 encoding and returns the decrypted data in PKCS#8 form.
//
// It supports AES-128-CBC, AES-192-CBC, AES-256-CBC, DES, or 3DES encrypted
// data using the key derived with PBKDF2 over the given password.
func DecryptPKCS8PrivateKey(data, password []byte) ([]byte, error) {
	var pki encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(data, &pki); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal private key")
	}

	if !pki.Algo.Algorithm.Equal(oidPBES2) {
		return nil, errors.New("unsupported encrypted PEM: only PBES2 is supported")
	}

	if !pki.Algo.Parameters.KeyDerivationFunc.Algo.Equal(oidPKCS5PBKDF2) {
		return nil, errors.New("unsupported encrypted PEM: only PBKDF2 is supported")
	}

	encParam := pki.Algo.Parameters.EncryptionScheme
	kdfParam := pki.Algo.Parameters.KeyDerivationFunc.PBKDF2Params

	iv := encParam.IV
	salt := kdfParam.Salt
	iter := kdfParam.IterationCount

	// pbkdf2 hash function
	keyHash := sha1.New
	if kdfParam.PrfParam.Algo.Equal(oidHMACWithSHA256) {
		keyHash = sha256.New
	}

	encryptedKey := pki.PrivateKey
	var symkey []byte
	var block cipher.Block
	var err error
	switch {
	// AES-128-CBC, AES-192-CBC, AES-256-CBC
	case encParam.EncryAlgo.Equal(oidAES128CBC):
		symkey = pbkdf2.Key(password, salt, iter, 16, keyHash)
		block, err = aes.NewCipher(symkey)
	case encParam.EncryAlgo.Equal(oidAES196CBC):
		symkey = pbkdf2.Key(password, salt, iter, 24, keyHash)
		block, err = aes.NewCipher(symkey)
	case encParam.EncryAlgo.Equal(oidAES256CBC):
		symkey = pbkdf2.Key(password, salt, iter, 32, keyHash)
		block, err = aes.NewCipher(symkey)
	// DES, TripleDES
	case encParam.EncryAlgo.Equal(oidDESCBC):
		symkey = pbkdf2.Key(password, salt, iter, 8, keyHash)
		block, err = des.NewCipher(symkey)
	case encParam.EncryAlgo.Equal(oidD3DESCBC):
		symkey = pbkdf2.Key(password, salt, iter, 24, keyHash)
		block, err = des.NewTripleDESCipher(symkey)
	default:
		return nil, errors.Errorf("unsupported encrypted PEM: unknown algorithm %v", encParam.EncryAlgo)
	}
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(encryptedKey, encryptedKey)

	return encryptedKey, nil
}

// EncryptPKCS8PrivateKey returns a PEM block holding the given PKCS#8 encroded
// private key, encrypted with the specified algorithm and a PBKDF2 derived key
// from the given password.
func EncryptPKCS8PrivateKey(rand io.Reader, data, password []byte, alg x509.PEMCipher) (*pem.Block, error) {
	ciph := cipherByKey(alg)
	if ciph == nil {
		return nil, errors.Errorf("failed to encrypt PEM: unknown algorithm %v", alg)
	}

	salt := make([]byte, PBKDF2SaltSize)
	if _, err := io.ReadFull(rand, salt); err != nil {
		return nil, errors.Wrap(err, "failed to generate salt")
	}
	iv := make([]byte, ciph.blockSize)
	if _, err := io.ReadFull(rand, iv); err != nil {
		return nil, errors.Wrap(err, "failed to generate IV")
	}

	key := ciph.deriveKey(password, salt, sha256.New)
	block, err := ciph.cipherFunc(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher")
	}
	enc := cipher.NewCBCEncrypter(block, iv)
	pad := ciph.blockSize - len(data)%ciph.blockSize
	encrypted := make([]byte, len(data), len(data)+pad)
	// We could save this copy by encrypting all the whole blocks in
	// the data separately, but it doesn't seem worth the additional
	// code.
	copy(encrypted, data)
	// See RFC 1423, section 1.1
	for i := 0; i < pad; i++ {
		encrypted = append(encrypted, byte(pad))
	}
	enc.CryptBlocks(encrypted, encrypted)

	// Build encrypted ans1 data
	pki := encryptedPrivateKeyInfo{
		Algo: encryptedlAlgorithmIdentifier{
			Algorithm: oidPBES2,
			Parameters: pbes2Params{
				KeyDerivationFunc: pbkdf2Algorithms{
					Algo: oidPKCS5PBKDF2,
					PBKDF2Params: pbkdf2Params{
						Salt:           salt,
						IterationCount: PBKDF2Iterations,
						PrfParam: prfParam{
							Algo: oidHMACWithSHA256,
						},
					},
				},
				EncryptionScheme: pbkdf2Encs{
					EncryAlgo: ciph.identifier,
					IV:        iv,
				},
			},
		},
		PrivateKey: encrypted,
	}

	b, err := asn1.Marshal(pki)
	if err != nil {
		return nil, errors.Wrap(err, "error marshalling encrypted key")
	}
	return &pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: b,
	}, nil
}
