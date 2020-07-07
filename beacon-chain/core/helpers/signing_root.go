package helpers

import (
	"github.com/pkg/errors"
	ethpb "github.com/prysmaticlabs/ethereumapis/eth/v1alpha1"
	"github.com/prysmaticlabs/go-ssz"
	"github.com/prysmaticlabs/prysm/beacon-chain/state/stateutil"
	p2ppb "github.com/prysmaticlabs/prysm/proto/beacon/p2p/v1"
	pb "github.com/prysmaticlabs/prysm/proto/beacon/p2p/v1"
	"github.com/prysmaticlabs/prysm/shared/bls"
	"github.com/prysmaticlabs/prysm/shared/bytesutil"
	"github.com/prysmaticlabs/prysm/shared/params"
)

// ForkVersionByteLength length of fork version byte array.
const ForkVersionByteLength = 4

// DomainByteLength length of domain byte array.
const DomainByteLength = 4

// ErrSigFailedToVerify returns when a signature of a block object(ie attestation, slashing, exit... etc)
// failed to verify.
var ErrSigFailedToVerify = errors.New("signature did not verify")

// ComputeSigningRoot computes the root of the object by calculating the hash tree root of the signing data with the given domain.
//
// Spec pseudocode definition:
//	def compute_signing_root(ssz_object: SSZObject, domain: Domain) -> Root:
//    """
//    Return the signing root for the corresponding signing data.
//    """
//    return hash_tree_root(SigningData(
//        object_root=hash_tree_root(ssz_object),
//        domain=domain,
//    ))
func ComputeSigningRoot(object interface{}, domain []byte) ([32]byte, error) {
	return signingData(func() ([32]byte, error) {
		switch object.(type) {
		case *ethpb.BeaconBlock:
			return stateutil.BlockRoot(object.(*ethpb.BeaconBlock))
		case *ethpb.AttestationData:
			return stateutil.AttestationDataRoot(object.(*ethpb.AttestationData))
		default:
			// utilise generic ssz library
			return ssz.HashTreeRoot(object)
		}
	}, domain)
}

// Computes the signing data by utilising the provided root function and then
// returning the signing data of the container object.
func signingData(rootFunc func() ([32]byte, error), domain []byte) ([32]byte, error) {
	objRoot, err := rootFunc()
	if err != nil {
		return [32]byte{}, err
	}
	container := &p2ppb.SigningData{
		ObjectRoot: objRoot[:],
		Domain:     domain,
	}
	return ssz.HashTreeRoot(container)
}

// VerifySigningRoot verifies the signing root of an object given it's public key, signature and domain.
func VerifySigningRoot(obj interface{}, pub []byte, signature []byte, domain []byte) error {
	publicKey, err := bls.PublicKeyFromBytes(pub)
	if err != nil {
		return errors.Wrap(err, "could not convert bytes to public key")
	}
	sig, err := bls.SignatureFromBytes(signature)
	if err != nil {
		return errors.Wrap(err, "could not convert bytes to signature")
	}
	root, err := ComputeSigningRoot(obj, domain)
	if err != nil {
		return errors.Wrap(err, "could not compute signing root")
	}
	if !sig.Verify(publicKey, root[:]) {
		return ErrSigFailedToVerify
	}
	return nil
}

// VerifyBlockSigningRoot verifies the signing root of a block given it's public key, signature and domain.
func VerifyBlockSigningRoot(blk *ethpb.BeaconBlock, pub []byte, signature []byte, domain []byte) error {
	root, err := signingData(func() ([32]byte, error) {
		// utilize custom block hashing function
		return stateutil.BlockRoot(blk)
	}, domain)
	if err != nil {
		return errors.Wrap(err, "could not compute signing root")
	}
	if !bls.VerifyCompressed(signature, pub, root[:]) {
		return ErrSigFailedToVerify
	}
	return nil
}

// VerifyBlockHeaderSigningRoot verifies the signing root of a block header given it's public key, signature and domain.
func VerifyBlockHeaderSigningRoot(blkHdr *ethpb.BeaconBlockHeader, pub []byte, signature []byte, domain []byte) error {
	publicKey, err := bls.PublicKeyFromBytes(pub)
	if err != nil {
		return errors.Wrap(err, "could not convert bytes to public key")
	}
	sig, err := bls.SignatureFromBytes(signature)
	if err != nil {
		return errors.Wrap(err, "could not convert bytes to signature")
	}
	root, err := signingData(func() ([32]byte, error) {
		return stateutil.BlockHeaderRoot(blkHdr)
	}, domain)
	if err != nil {
		return errors.Wrap(err, "could not compute signing root")
	}
	if !sig.Verify(publicKey, root[:]) {
		return ErrSigFailedToVerify
	}
	return nil
}

// ComputeDomain returns the domain version for BLS private key to sign and verify with a zeroed 4-byte
// array as the fork version.
//
// def compute_domain(domain_type: DomainType, fork_version: Version=None, genesis_validators_root: Root=None) -> Domain:
//    """
//    Return the domain for the ``domain_type`` and ``fork_version``.
//    """
//    if fork_version is None:
//        fork_version = GENESIS_FORK_VERSION
//    if genesis_validators_root is None:
//        genesis_validators_root = Root()  # all bytes zero by default
//    fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root)
//    return Domain(domain_type + fork_data_root[:28])
func ComputeDomain(domainType [DomainByteLength]byte, forkVersion []byte, genesisValidatorsRoot []byte) ([]byte, error) {
	if forkVersion == nil {
		forkVersion = params.BeaconConfig().GenesisForkVersion
	}
	if genesisValidatorsRoot == nil {
		genesisValidatorsRoot = params.BeaconConfig().ZeroHash[:]
	}
	forkBytes := [ForkVersionByteLength]byte{}
	copy(forkBytes[:], forkVersion)

	forkDataRoot, err := computeForkDataRoot(forkBytes[:], genesisValidatorsRoot)
	if err != nil {
		return nil, err
	}

	return domain(domainType, forkDataRoot[:]), nil
}

// This returns the bls domain given by the domain type and fork data root.
func domain(domainType [DomainByteLength]byte, forkDataRoot []byte) []byte {
	b := []byte{}
	b = append(b, domainType[:4]...)
	b = append(b, forkDataRoot[:28]...)
	return b
}

// this returns the 32byte fork data root for the ``current_version`` and ``genesis_validators_root``.
// This is used primarily in signature domains to avoid collisions across forks/chains.
//
// Spec pseudocode definition:
//	def compute_fork_data_root(current_version: Version, genesis_validators_root: Root) -> Root:
//    """
//    Return the 32-byte fork data root for the ``current_version`` and ``genesis_validators_root``.
//    This is used primarily in signature domains to avoid collisions across forks/chains.
//    """
//    return hash_tree_root(ForkData(
//        current_version=current_version,
//        genesis_validators_root=genesis_validators_root,
//    ))
func computeForkDataRoot(version []byte, root []byte) ([32]byte, error) {
	r, err := ssz.HashTreeRoot(&pb.ForkData{
		CurrentVersion:        version,
		GenesisValidatorsRoot: root,
	})
	if err != nil {
		return [32]byte{}, err
	}
	return r, nil
}

// ComputeForkDigest returns the fork for the current version and genesis validator root
//
// Spec pseudocode definition:
//	def compute_fork_digest(current_version: Version, genesis_validators_root: Root) -> ForkDigest:
//    """
//    Return the 4-byte fork digest for the ``current_version`` and ``genesis_validators_root``.
//    This is a digest primarily used for domain separation on the p2p layer.
//    4-bytes suffices for practical separation of forks/chains.
//    """
//    return ForkDigest(compute_fork_data_root(current_version, genesis_validators_root)[:4])
func ComputeForkDigest(version []byte, genesisValidatorsRoot []byte) ([4]byte, error) {
	dataRoot, err := computeForkDataRoot(version, genesisValidatorsRoot)
	if err != nil {
		return [4]byte{}, nil
	}
	return bytesutil.ToBytes4(dataRoot[:]), nil
}
