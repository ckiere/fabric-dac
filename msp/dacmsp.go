/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"
	"time"

	"github.com/dbogatov/dac-lib/dac"
	"github.com/golang/protobuf/proto"
	m "github.com/hyperledger/fabric-protos-go/msp"
	"github.com/pkg/errors"
	"go.uber.org/zap/zapcore"
)

type dacmsp struct {
	version      MSPVersion
	ipk          dac.PK
	name         string
	revocationPK dac.PK
	epoch        int
	Ys           [][]interface{}
	H            *FP256BN.ECP2
}

// newDacMsp creates a new instance of dacmsp
func newDacMsp(version MSPVersion) (MSP, error) {
	mspLogger.Debugf("Creating Dac-based MSP instance")

	msp := dacmsp{name: "DacMSP"}
	msp.version = version
	return &msp, nil
}

func (msp *dacmsp) Setup(conf1 *m.MSPConfig) error {
	mspLogger.Debugf("Setting up Dac-based MSP instance")

	if conf1 == nil {
		return errors.Errorf("setup error: nil conf reference")
	}

	if conf1.Type != int32(DAC) {
		return errors.Errorf("setup error: config is not of type DAC")
	}

	dacConfig, err := CreateDacConfigFromBytes(conf1.Config)

	if err != nil {
		return errors.Wrap(err, "failed unmarshalling dac msp config")
	}

	// Import Issuer Public Key
	IssuerPublicKey, err := dacConfig.RootPk()
	if err != nil {
		return errors.WithMessage(err, "Invalid issuer public key")
	}
	msp.ipk = IssuerPublicKey

	// Import Ys
	Ys, err := dacConfig.Ys()
	if err != nil {
		return errors.WithMessage(err, "Invalid Ys")
	}
	msp.Ys = Ys

	// Import H
	H, err := dacConfig.H()
	if err != nil {
		return errors.WithMessage(err, "Invalid H")
	}
	msp.H = H.(*FP256BN.ECP2)

	// Default signer not supported
	return nil
}

// GetVersion returns the version of this MSP
func (msp *dacmsp) GetVersion() MSPVersion {
	return msp.version
}

func (msp *dacmsp) GetType() ProviderType {
	return DAC
}

func (msp *dacmsp) GetIdentifier() (string, error) {
	return msp.name, nil
}

func (msp *dacmsp) GetSigningIdentity(identifier *IdentityIdentifier) (SigningIdentity, error) {
	return nil, errors.Errorf("GetSigningIdentity not implemented")
}

func (msp *dacmsp) GetDefaultSigningIdentity() (SigningIdentity, error) {
	return nil, errors.Errorf("GetDefaultSigningIdentity not implemented")
}

func (msp *dacmsp) DeserializeIdentity(serializedID []byte) (Identity, error) {
	sID := &m.SerializedIdentity{}
	err := proto.Unmarshal(serializedID, sID)
	if err != nil {
		return nil, errors.Wrap(err, "could not deserialize a SerializedIdentity")
	}

	if sID.Mspid != msp.name {
		return nil, errors.Errorf("expected MSP ID %s, received %s", msp.name, sID.Mspid)
	}

	return msp.deserializeIdentityInternal(sID.GetIdBytes())
}

func (msp *dacmsp) deserializeIdentityInternal(serializedID []byte) (Identity, error) {
	mspLogger.Debug("dacmsp: deserializing identity")
	serialized := new(m.SerializedIdemixIdentity)
	err := proto.Unmarshal(serializedID, serialized)
	if err != nil {
		return nil, errors.Wrap(err, "could not deserialize a SerializedDacIdentity")
	}
	if serialized.NymX == nil || serialized.NymY == nil {
		return nil, errors.Errorf("unable to deserialize dac identity: pseudonym is invalid")
	}

	// Import NymPublicKey
	var rawNymPublicKey []byte
	rawNymPublicKey = append(rawNymPublicKey, serialized.NymX...)
	rawNymPublicKey = append(rawNymPublicKey, serialized.NymY...)
	NymPublicKey, err := dac.PointFromBytes(rawNymPublicKey)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to import nym public key")
	}

	// OU
	ou := &m.OrganizationUnit{}
	err = proto.Unmarshal(serialized.Ou, ou)
	if err != nil {
		return nil, errors.Wrap(err, "cannot deserialize the OU of the identity")
	}

	// Role
	role := &m.MSPRole{}
	err = proto.Unmarshal(serialized.Role, role)
	if err != nil {
		return nil, errors.Wrap(err, "cannot deserialize the role of the identity")
	}

	return newDacIdentity(msp, NymPublicKey, role, ou, serialized.Proof), nil
}

func (msp *dacmsp) Validate(id Identity) error {
	var identity *dacidentity
	switch t := id.(type) {
	case *dacidentity:
		identity = id.(*dacidentity)
	default:
		return errors.Errorf("identity type %T is not recognized", t)
	}

	mspLogger.Debugf("Validating identity %+v", identity)
	if identity.GetMSPIdentifier() != msp.name {
		return errors.Errorf("the supplied identity does not belong to this msp")
	}
	return identity.verifyProof()
}

func (id *dacidentity) verifyProof() error {
	// Verify signature
	// TODO check if ProofFromBytes can panic!
	indices := dac.Indices{}
	proof := dac.ProofFromBytes(id.associationProof)
	err := proof.VerifyProof(id.msp.ipk, id.msp.Ys, id.msp.H, id.NymPublicKey, indices, []byte{})

	return err
}

func (msp *dacmsp) SatisfiesPrincipal(id Identity, principal *m.MSPPrincipal) error {
	err := msp.Validate(id)
	if err != nil {
		return errors.Wrap(err, "identity is not valid with respect to this MSP")
	}

	return msp.satisfiesPrincipalValidated(id, principal)
}

// satisfiesPrincipalValidated performs all the tasks of satisfiesPrincipal except the identity validation,
// such that combined principals will not cause multiple expensive identity validations.
func (msp *dacmsp) satisfiesPrincipalValidated(id Identity, principal *m.MSPPrincipal) error {
	switch principal.PrincipalClassification {
	// in this case, we have to check whether the
	// identity has a role in the msp - member or admin
	case m.MSPPrincipal_ROLE:
		// Principal contains the msp role
		mspRole := &m.MSPRole{}
		err := proto.Unmarshal(principal.Principal, mspRole)
		if err != nil {
			return errors.Wrap(err, "could not unmarshal MSPRole from principal")
		}

		// at first, we check whether the MSP
		// identifier is the same as that of the identity
		if mspRole.MspIdentifier != msp.name {
			return errors.Errorf("the identity is a member of a different MSP (expected %s, got %s)", mspRole.MspIdentifier, id.GetMSPIdentifier())
		}

		// now we validate the different msp roles
		switch mspRole.Role {
		case m.MSPRole_MEMBER:
			// in the case of member, we simply check
			// whether this identity is valid for the MSP
			mspLogger.Debugf("Checking if identity satisfies MEMBER role for %s", msp.name)
			return nil
		case m.MSPRole_ADMIN:
			mspLogger.Debugf("Checking if identity satisfies ADMIN role for %s", msp.name)
			if id.(*dacidentity).Role.Role != m.MSPRole_ADMIN {
				return errors.Errorf("user is not an admin")
			}
			return nil
		case m.MSPRole_PEER:
			if msp.version >= MSPv1_3 {
				return errors.Errorf("dacmsp only supports client use, so it cannot satisfy an MSPRole PEER principal")
			}
			fallthrough
		case m.MSPRole_CLIENT:
			if msp.version >= MSPv1_3 {
				return nil // any valid dacmsp member must be a client
			}
			fallthrough
		default:
			return errors.Errorf("invalid MSP role type %d", int32(mspRole.Role))
		}
		// in this case we have to serialize this instance
		// and compare it byte-by-byte with Principal
	case m.MSPPrincipal_IDENTITY:
		mspLogger.Debugf("Checking if identity satisfies IDENTITY principal")
		idBytes, err := id.Serialize()
		if err != nil {
			return errors.Wrap(err, "could not serialize this identity instance")
		}

		rv := bytes.Compare(idBytes, principal.Principal)
		if rv == 0 {
			return nil
		}
		return errors.Errorf("the identities do not match")

	case m.MSPPrincipal_ORGANIZATION_UNIT:
		ou := &m.OrganizationUnit{}
		err := proto.Unmarshal(principal.Principal, ou)
		if err != nil {
			return errors.Wrap(err, "could not unmarshal OU from principal")
		}

		mspLogger.Debugf("Checking if identity is part of OU \"%s\" of mspid \"%s\"", ou.OrganizationalUnitIdentifier, ou.MspIdentifier)

		// at first, we check whether the MSP
		// identifier is the same as that of the identity
		if ou.MspIdentifier != msp.name {
			return errors.Errorf("the identity is a member of a different MSP (expected %s, got %s)", ou.MspIdentifier, id.GetMSPIdentifier())
		}

		if ou.OrganizationalUnitIdentifier != id.(*dacidentity).OU.OrganizationalUnitIdentifier {
			return errors.Errorf("user is not part of the desired organizational unit")
		}

		return nil
	case m.MSPPrincipal_COMBINED:
		if msp.version <= MSPv1_1 {
			return errors.Errorf("Combined MSP Principals are unsupported in MSPv1_1")
		}

		// Principal is a combination of multiple principals.
		principals := &m.CombinedPrincipal{}
		err := proto.Unmarshal(principal.Principal, principals)
		if err != nil {
			return errors.Wrap(err, "could not unmarshal CombinedPrincipal from principal")
		}
		// Return an error if there are no principals in the combined principal.
		if len(principals.Principals) == 0 {
			return errors.New("no principals in CombinedPrincipal")
		}
		// Recursively call msp.SatisfiesPrincipal for all combined principals.
		// There is no limit for the levels of nesting for the combined principals.
		for _, cp := range principals.Principals {
			err = msp.satisfiesPrincipalValidated(id, cp)
			if err != nil {
				return err
			}
		}
		// The identity satisfies all the principals
		return nil
	case m.MSPPrincipal_ANONYMITY:
		if msp.version <= MSPv1_1 {
			return errors.Errorf("Anonymity MSP Principals are unsupported in MSPv1_1")
		}

		anon := &m.MSPIdentityAnonymity{}
		err := proto.Unmarshal(principal.Principal, anon)
		if err != nil {
			return errors.Wrap(err, "could not unmarshal MSPIdentityAnonymity from principal")
		}
		switch anon.AnonymityType {
		case m.MSPIdentityAnonymity_ANONYMOUS:
			return nil
		case m.MSPIdentityAnonymity_NOMINAL:
			return errors.New("principal is nominal, but dac MSP is anonymous")
		default:
			return errors.Errorf("unknown principal anonymity type: %d", anon.AnonymityType)
		}
	default:
		return errors.Errorf("invalid principal type %d", int32(principal.PrincipalClassification))
	}
}

// IsWellFormed checks if the given identity can be deserialized into its provider-specific .
// In this MSP implementation, an identity is considered well formed if it contains a
// marshaled SerializedDacIdentity protobuf message.
func (id *dacmsp) IsWellFormed(identity *m.SerializedIdentity) error {
	sId := new(SerializedDacIdentity)
	err := proto.Unmarshal(identity.IdBytes, sId)
	if err != nil {
		return errors.Wrap(err, "not an dac identity")
	}
	return nil
}

func (msp *dacmsp) GetTLSRootCerts() [][]byte {
	// TODO
	return nil
}

func (msp *dacmsp) GetTLSIntermediateCerts() [][]byte {
	// TODO
	return nil
}

type dacidentity struct {
	NymPublicKey dac.PK
	msp          *dacmsp
	id           *IdentityIdentifier
	Role         *m.MSPRole
	OU           *m.OrganizationUnit
	// associationProof contains cryptographic proof that this identity
	// belongs to the MSP id.msp, i.e., it proves that the pseudonym
	// is constructed from a secret key on which the CA issued a credential.
	associationProof []byte
}

func (id *dacidentity) Anonymous() bool {
	return true
}

func newDacIdentity(msp *dacmsp, NymPublicKey dac.PK, role *m.MSPRole, ou *m.OrganizationUnit, proof []byte) *dacidentity {
	id := &dacidentity{}
	id.NymPublicKey = NymPublicKey
	id.msp = msp
	id.Role = role
	id.OU = ou
	id.associationProof = proof

	raw := dac.PointToBytes(NymPublicKey)
	/*if err != nil {
		panic(fmt.Sprintf("unexpected condition, failed marshalling nym public key [%s]", err))
	}*/
	id.id = &IdentityIdentifier{
		Mspid: msp.name,
		Id:    bytes.NewBuffer(raw).String(),
	}

	return id
}

func (id *dacidentity) ExpiresAt() time.Time {
	// Dac MSP currently does not use expiration dates or revocation,
	// so we return the zero time to indicate this.
	return time.Time{}
}

func (id *dacidentity) GetIdentifier() *IdentityIdentifier {
	return id.id
}

func (id *dacidentity) GetMSPIdentifier() string {
	mspid, _ := id.msp.GetIdentifier()
	return mspid
}

func (id *dacidentity) GetOrganizationalUnits() []*OUIdentifier {
	// we use the (serialized) public key of this MSP as the CertifiersIdentifier
	certifiersIdentifier := dac.PointToBytes(id.msp.ipk)
	/*if err != nil {
		mspIdentityLogger.Errorf("Failed to marshal ipk in GetOrganizationalUnits: %s", err)
		return nil
	}*/

	return []*OUIdentifier{{certifiersIdentifier, id.OU.OrganizationalUnitIdentifier}}
}

func (id *dacidentity) Validate() error {
	return id.msp.Validate(id)
}

func (id *dacidentity) Verify(msg []byte, sigBytes []byte) error {
	if mspIdentityLogger.IsEnabledFor(zapcore.DebugLevel) {
		mspIdentityLogger.Debugf("Verify Dac sig: msg = %s", hex.Dump(msg))
		mspIdentityLogger.Debugf("Verify Dac sig: sig = %s", hex.Dump(sigBytes))
	}
	sig := dac.NymSignatureFromBytes(sigBytes)
	h := sha256.New()
	h.Write(msg)
	digest := h.Sum(nil)
	err := sig.VerifyNym(id.msp.H, id.NymPublicKey, digest)
	return err
}

func (id *dacidentity) SatisfiesPrincipal(principal *m.MSPPrincipal) error {
	return id.msp.SatisfiesPrincipal(id, principal)
}

func (id *dacidentity) Serialize() ([]byte, error) {
	serialized := &SerializedDacIdentity{}

	raw := dac.PointToBytes(id.NymPublicKey)
	/*if err != nil {
		return nil, errors.Wrapf(err, "could not serialize nym of identity %s", id.id)
	}*/
	// This is an assumption on how the underlying dac implementation work.
	// TODO: change this in future version
	serialized.NymX = raw[:len(raw)/2]
	serialized.NymY = raw[len(raw)/2:]
	ouBytes, err := proto.Marshal(id.OU)
	if err != nil {
		return nil, errors.Wrapf(err, "could not marshal OU of identity %s", id.id)
	}

	roleBytes, err := proto.Marshal(id.Role)
	if err != nil {
		return nil, errors.Wrapf(err, "could not marshal role of identity %s", id.id)
	}

	serialized.Ou = ouBytes
	serialized.Role = roleBytes
	serialized.Proof = id.associationProof

	dacIDBytes, err := proto.Marshal(serialized)
	if err != nil {
		return nil, err
	}

	sID := &m.SerializedIdentity{Mspid: id.GetMSPIdentifier(), IdBytes: dacIDBytes}
	idBytes, err := proto.Marshal(sID)
	if err != nil {
		return nil, errors.Wrapf(err, "could not marshal a SerializedIdentity structure for identity %s", id.id)
	}

	return idBytes, nil
}

type SerializedDacIdentity struct {
	*m.SerializedIdemixIdentity
}
