// Package bls implements a go-wrapper around a library implementing the
// the BLS12-381 curve and signature scheme. This package exposes a public API for
// verifying and aggregating BLS signatures used by Ethereum 2.0.
package bls

import (
	"crypto/rand"
	"fmt"
	"math"
	"runtime"

	"github.com/dgraph-io/ristretto"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/prysm/shared/featureconfig"
	"github.com/prysmaticlabs/prysm/shared/params"
	blst "github.com/supranational/blst/bindings/go"
)

var dst = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")

func init() {
	maxProcs := int(math.Ceil(float64(runtime.GOMAXPROCS(0)) * 0.75))
	if maxProcs <= 0 {
		maxProcs = 1
	}
	blst.SetMaxProcs(maxProcs)
}

// DomainByteLength length of domain byte array.
const DomainByteLength = 4

var maxKeys = int64(100000)
var pubkeyCache, _ = ristretto.NewCache(&ristretto.Config{
	NumCounters: maxKeys,
	MaxCost:     1 << 22, // ~4mb is cache max size
	BufferItems: 64,
})

// CurveOrder for the BLS12-381 curve.
const CurveOrder = "52435875175126190479447740508185965837690552500527637822603658699938581184513"

// Internal types for min-pk
type blstSecretKey = blst.SecretKey
type blstPublicKey = blst.P1Affine
type blstSignature = blst.P2Affine
type blstAggregateSignature = blst.P2Aggregate
type blstAggregatePublicKey = blst.P1Aggregate

// Signature used in the BLS signature scheme.
type Signature struct {
	s *blstSignature
}

// PublicKey used in the BLS signature scheme.
type PublicKey struct {
	p *blstPublicKey
}

// SecretKey used in the BLS signature scheme.
type SecretKey struct {
	p *blstSecretKey
}

// RandKey creates a new private key using a random method provided as an io.Reader.
func RandKey() *SecretKey {
	// TODO: use CSPRNG?
	// Generate 32 bytes of randomness
	var ikm [32]byte
	_, err := rand.Read(ikm[:])
	if err != nil {
		return nil
	}
	return &SecretKey{blst.KeyGen(ikm[:])}
}

// SecretKeyFromBytes creates a BLS private key from a BigEndian byte slice.
func SecretKeyFromBytes(privKey []byte) (*SecretKey, error) {
	if len(privKey) != params.BeaconConfig().BLSSecretKeyLength {
		return nil, fmt.Errorf("secret key must be %d bytes", params.BeaconConfig().BLSSecretKeyLength)
	}

	secKey := new(blstSecretKey).Deserialize(privKey)
	if secKey == nil {
		return nil, errors.New("could not unmarshal bytes into secret key")
	}

	return &SecretKey{p: secKey}, nil
}

// PublicKeyFromBytes creates a BLS public key from a  BigEndian byte slice.
func PublicKeyFromBytes(pubKey []byte) (*PublicKey, error) {
	if featureconfig.Get().SkipBLSVerify {
		return &PublicKey{}, nil
	}
	if len(pubKey) != params.BeaconConfig().BLSPubkeyLength {
		return nil, fmt.Errorf("public key must be %d bytes", params.BeaconConfig().BLSPubkeyLength)
	}
	if cv, ok := pubkeyCache.Get(string(pubKey)); ok {
		return cv.(*PublicKey).Copy()
	}

	p := new(blstPublicKey).Uncompress(pubKey)
	if p == nil {
		return nil, errors.New("could not unmarshal bytes into public key")
	}
	pubKeyObj := &PublicKey{p: p}
	copiedKey, err := pubKeyObj.Copy()
	if err != nil {
		return nil, errors.New("could not copy public key")
	}
	pubkeyCache.Set(string(pubKey), copiedKey, 48)
	return pubKeyObj, nil
}

// SignatureFromBytes creates a BLS signature from a LittleEndian byte slice.
func SignatureFromBytes(sig []byte) (*Signature, error) {
	if featureconfig.Get().SkipBLSVerify {
		return &Signature{}, nil
	}
	if len(sig) != params.BeaconConfig().BLSSignatureLength {
		return nil, fmt.Errorf("signature must be %d bytes", params.BeaconConfig().BLSSignatureLength)
	}
	signature := new(blstSignature).Uncompress(sig)
	if signature == nil {
		return nil, errors.New("could not unmarshal bytes into signature")
	}
	return &Signature{s: signature}, nil
}

// PublicKey obtains the public key corresponding to the BLS secret key.
func (s *SecretKey) PublicKey() *PublicKey {
	return &PublicKey{p: new(blstPublicKey).From(s.p)}
}

// Sign a message using a secret key - in a beacon/validator client.
//
// In IETF draft BLS specification:
// Sign(SK, message) -> signature: a signing algorithm that generates
//      a deterministic signature given a secret key SK and a message.
//
// In ETH2.0 specification:
// def Sign(SK: int, message: Bytes) -> BLSSignature
func (s *SecretKey) Sign(msg []byte) *Signature {
	if featureconfig.Get().SkipBLSVerify {
		return &Signature{}
	}

	signature := new(blstSignature).Sign(s.p, msg, dst)
	return &Signature{s: signature}
}

// Marshal a secret key into a LittleEndian byte slice.
func (s *SecretKey) Marshal() []byte {
	keyBytes := s.p.Serialize()
	if len(keyBytes) < params.BeaconConfig().BLSSecretKeyLength {
		emptyBytes := make([]byte, params.BeaconConfig().BLSSecretKeyLength-len(keyBytes))
		keyBytes = append(emptyBytes, keyBytes...)
	}
	return keyBytes
}

// Marshal a public key into a LittleEndian byte slice.
func (p *PublicKey) Marshal() []byte {
	return p.p.Compress()
}

// Copy the public key to a new pointer reference.
func (p *PublicKey) Copy() (*PublicKey, error) {
	np := *p.p
	return &PublicKey{p: &np}, nil
}

// Aggregate two public keys.
func (p *PublicKey) Aggregate(p2 *PublicKey) *PublicKey {
	if featureconfig.Get().SkipBLSVerify {
		return p
	}

	agg := new(blstAggregatePublicKey)
	agg.Add(p.p)
	agg.Add(p2.p)
	p.p = agg.ToAffine()

	return p
}

// Verify a bls signature given a public key, a message.
//
// In IETF draft BLS specification:
// Verify(PK, message, signature) -> VALID or INVALID: a verification
//      algorithm that outputs VALID if signature is a valid signature of
//      message under public key PK, and INVALID otherwise.
//
// In ETH2.0 specification:
// def Verify(PK: BLSPubkey, message: Bytes, signature: BLSSignature) -> bool
func (s *Signature) Verify(pubKey *PublicKey, msg []byte) bool {
	if featureconfig.Get().SkipBLSVerify {
		return true
	}
	return s.s.Verify(pubKey.p, msg, dst)
}

func VerifyCompressed(signature []byte, pub []byte, msg []byte) bool {
	return new(blstSignature).VerifyCompressed(signature, pub, msg, dst)
}

// AggregateVerify verifies each public key against its respective message.
// This is vulnerable to rogue public-key attack. Each user must
// provide a proof-of-knowledge of the public key.
//
// In IETF draft BLS specification:
// AggregateVerify((PK_1, message_1), ..., (PK_n, message_n),
//      signature) -> VALID or INVALID: an aggregate verification
//      algorithm that outputs VALID if signature is a valid aggregated
//      signature for a collection of public keys and messages, and
//      outputs INVALID otherwise.
//
// In ETH2.0 specification:
// def AggregateVerify(pairs: Sequence[PK: BLSPubkey, message: Bytes], signature: BLSSignature) -> boo
func (s *Signature) AggregateVerify(pubKeys []*PublicKey, msgs [][32]byte) bool {
	if featureconfig.Get().SkipBLSVerify {
		return true
	}
	size := len(pubKeys)
	if size == 0 {
		return false
	}
	if size != len(msgs) {
		return false
	}
	msgSlices := make([][]byte, len(msgs))
	rawKeys := make([]*blstPublicKey, len(msgs))
	for i := 0; i < size; i++ {
		msgSlices[i] = msgs[i][:]
		rawKeys[i] = pubKeys[i].p
	}
	// Use "NoCheck" because we do not care if the messages are unique or not.
	//return s.s.AggregateVerifyNoCheck(rawKeys, msgSlices)
	return s.s.AggregateVerify(rawKeys, msgSlices, dst)
}

// FastAggregateVerify verifies all the provided public keys with their aggregated signature.
//
// In IETF draft BLS specification:
// FastAggregateVerify(PK_1, ..., PK_n, message, signature) -> VALID
//      or INVALID: a verification algorithm for the aggregate of multiple
//      signatures on the same message.  This function is faster than
//      AggregateVerify.
//
// In ETH2.0 specification:
// def FastAggregateVerify(PKs: Sequence[BLSPubkey], message: Bytes, signature: BLSSignature) -> bool
func (s *Signature) FastAggregateVerify(pubKeys []*PublicKey, msg [32]byte) bool {
	if featureconfig.Get().SkipBLSVerify {
		return true
	}
	if len(pubKeys) == 0 {
		return false
	}
	rawKeys := make([]*blstPublicKey, len(pubKeys))
	for i := 0; i < len(pubKeys); i++ {
		rawKeys[i] = pubKeys[i].p
	}

	return s.s.FastAggregateVerify(rawKeys, msg[:], dst)
}

// NewAggregateSignature creates a blank aggregate signature.
func NewAggregateSignature() *Signature {
	sig := blst.HashToG2([]byte{'m', 'o', 'c', 'k'}, dst).ToAffine()
	return &Signature{s: sig}
}

// AggregateSignatures converts a list of signatures into a single, aggregated sig.
func AggregateSignatures(sigs []*Signature) *Signature {
	if len(sigs) == 0 {
		return nil
	}
	if featureconfig.Get().SkipBLSVerify {
		return sigs[0]
	}

	rawSigs := make([]*blstSignature, len(sigs))
	for i := 0; i < len(sigs); i++ {
		rawSigs[i] = sigs[i].s
	}

	signature := new(blstAggregateSignature).Aggregate(rawSigs)
	if signature == nil {
		return nil
	}
	return &Signature{s: signature.ToAffine()}
}

// Aggregate is an alias for AggregateSignatures, defined to conform to BLS specification.
//
// In IETF draft BLS specification:
// Aggregate(signature_1, ..., signature_n) -> signature: an
//      aggregation algorithm that compresses a collection of signatures
//      into a single signature.
//
// In ETH2.0 specification:
// def Aggregate(signatures: Sequence[BLSSignature]) -> BLSSignature
//
// Deprecated: Use AggregateSignatures.
func Aggregate(sigs []*Signature) *Signature {
	return AggregateSignatures(sigs)
}

// Marshal a signature into a LittleEndian byte slice.
func (s *Signature) Marshal() []byte {
	if featureconfig.Get().SkipBLSVerify {
		return make([]byte, params.BeaconConfig().BLSSignatureLength)
	}

	return s.s.Compress()
}
