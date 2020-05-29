package dsig

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"

	"github.com/ucarion/c14n"
	"github.com/ucarion/dsig/internal/sigsplit"
)

// Signature represents an enveloped XML signature.
//
// If you have a struct that is supposed to contain an envloped XML signature,
// then you should embed Signature into your struct.
type Signature struct {
	XMLName        xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	SignedInfo     SignedInfo
	SignatureValue string
}

// ErrPublicKeyNotRSA is returned by Verify if the given x509.Certificate
// doesn't contain an RSA public key.
var ErrPublicKeyNotRSA = errors.New("dsig: public key must be a *rsa.PublicKey")

// ErrBadDigest is returned by Verify if the embedded signature doesn't match
// the data it's supposed to be a signature for.
//
// This can indicate that the data being signed was tampered with. For instance,
// if you take a valid Signature for one message, but drop it into a different
// message, then you'll get this error.
//
// You should treat this error as an indication that the input data was forged.
var ErrBadDigest = errors.New("dsig: incorrect digest")

// ErrBadDigestAlgorithm is returned by Verify if the signature uses a digest
// algorithm that this package does not support.
var ErrBadDigestAlgorithm = errors.New("dsig: invalid or unsupported digest algorithm")

// ErrBadSignatureAlgorithm is returned by Verify if the signature uses a
// signature algorithm that this package does not support.
var ErrBadSignatureAlgorithm = errors.New("dsig: invalid or unsupported signature algorithm")

// Verify uses cert to check if s is a valid signature for the token sequence r.
//
// If the digest in the signature is incorrect, Verify returns ErrBadDigest. If
// the signature is incorrect, Verify returns ErrVerification from the
// crypto/rsa package.
//
// Verify does not check if the given x509.Certificate is expired.
//
// Verify's return value is undefined if r does not correspond to the XML you
// used to construct s to begin with. In other words, you almost always want to
// invoke Verify roughly like so:
//
//  type Foo struct {
//    MyData string
//    Signature dsig.Signature
//  }
//
//  var foo Foo
//  xml.Unmarshal(data, &foo)
//  foo.Signature.Verify(cert, xml.NewDecoder(data))
//
// Verify supports only the SHA1 and SHA256 digest algorithms, and only the
// RSA-SHA1 and RSA-SHA256 signature algorithms. All other algorithms will lead
// Verify to return ErrBadDigestAlgorithm or ErrBadSignatureAlgorithm.
//
// Verify supports only the Exclusive Canonical XML canonicalization algorithm,
// and does not support the InclusiveNamespaces argument. No special error will
// be returned if s uses a different c14n algorithm, but most likely Verify will
// return ErrBadDigest in this case.
func (s *Signature) Verify(cert *x509.Certificate, r c14n.RawTokenReader) error {
	// Split the token stream into the part that needs to be digested and the part
	// that needs to be signed.
	toDigest, toVerify, err := sigsplit.SplitSignature(r)
	if err != nil {
		return err
	}

	expectedDigest, err := base64.StdEncoding.DecodeString(s.SignedInfo.Reference.DigestValue)
	if err != nil {
		return err
	}

	digestHash, err := s.SignedInfo.Reference.DigestMethod.hash()
	if err != nil {
		return err
	}

	h := digestHash.New()
	h.Write(toDigest)

	// This does not need to be a subtle.ConstantTimeCompare, because the digest
	// is not being used as an HMAC. There is no secret key here.
	//
	// Instead, verifying the digest here can act as a hint to the caller that the
	// embedded signature does not correspond to the data it's embedded in.
	if !bytes.Equal(expectedDigest, h.Sum(nil)) {
		return ErrBadDigest
	}

	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return ErrPublicKeyNotRSA
	}

	signatureHash, err := s.SignedInfo.SignatureMethod.hash()
	if err != nil {
		return err
	}

	h = signatureHash.New()
	h.Write(toVerify)

	expectedSignature, err := base64.StdEncoding.DecodeString(s.SignatureValue)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(publicKey, signatureHash, h.Sum(nil), expectedSignature)
}

// SignedInfo contains information about what is signed by a Signature.
type SignedInfo struct {
	XMLName                xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`
	CanonicalizationMethod CanonicalizationMethod
	SignatureMethod        SignatureMethod
	Reference              Reference
}

// CanonicalizationMethod contains information about the c14n algorithm used to
// compute the bytes that are digested or signed.
type CanonicalizationMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

// CanonicalizationMethodAlgorithmExclusive is the URI for the Exclusive
// Canonical XML c14n algorithm.
var CanonicalizationMethodAlgorithmExclusive = "http://www.w3.org/2001/10/xml-exc-c14n#"

// SignatureMethod contains information about the signature algorithm used to
// calculate a Signature's SignatureValue.
type SignatureMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignatureMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

// SignatureMethodAlgorithmSHA1 is the URI for the RSA-SHA1 signature algorithm.
var SignatureMethodAlgorithmSHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"

// SignatureMethodAlgorithmSHA256 is the URI for the RSA-SHA256 signature
// algorithm.
var SignatureMethodAlgorithmSHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

func (s *SignatureMethod) hash() (crypto.Hash, error) {
	switch s.Algorithm {
	case SignatureMethodAlgorithmSHA1:
		return crypto.SHA1, nil
	case SignatureMethodAlgorithmSHA256:
		return crypto.SHA256, nil
	default:
		return 0, ErrBadSignatureAlgorithm
	}
}

// Reference contains details about the data that makes up the DigestValue of a
// Signature.
type Reference struct {
	XMLName      xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Reference"`
	DigestMethod DigestMethod
	DigestValue  string
}

// DigestMethod contains information about the digest algorithm used to
// calculate a Signature's DigestValue.
type DigestMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

// DigestMethodAlgorithmSHA1 is the URI for the SHA1 digest algorithm.
var DigestMethodAlgorithmSHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"

// DigestMethodAlgorithmSHA256 is the URI for the SHA256 digest algorithm.
var DigestMethodAlgorithmSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"

func (d *DigestMethod) hash() (crypto.Hash, error) {
	switch d.Algorithm {
	case DigestMethodAlgorithmSHA1:
		return crypto.SHA1, nil
	case DigestMethodAlgorithmSHA256:
		return crypto.SHA256, nil
	default:
		return 0, ErrBadDigestAlgorithm
	}
}
