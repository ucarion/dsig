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

type Signature struct {
	XMLName        xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	SignedInfo     SignedInfo
	SignatureValue string
}

var ErrPublicKeyNotRSA = errors.New("dsig: public key must be a *rsa.PublicKey")
var ErrBadDigest = errors.New("dsig: incorrect digest")
var ErrBadDigestAlgorithm = errors.New("dsig: invalid or unsupported digest algorithm")
var ErrBadSignatureAlgorithm = errors.New("dsig: invalid or unsupported signature algorithm")

func (s *Signature) Verify(cert *x509.Certificate, r c14n.RawTokenReader) error {
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

type SignedInfo struct {
	XMLName                xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`
	CanonicalizationMethod CanonicalizationMethod
	SignatureMethod        SignatureMethod
	Reference              Reference
}

type CanonicalizationMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

var CanonicalizationMethodAlgorithmExclusive = "http://www.w3.org/2001/10/xml-exc-c14n#"

type SignatureMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignatureMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

var SignatureMethodAlgorithmSHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
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

type Reference struct {
	XMLName      xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Reference"`
	URI          string   `xml:"URI,attr"`
	Transforms   Transforms
	DigestMethod DigestMethod
	DigestValue  string
}

type Transforms struct {
	XMLName    xml.Name    `xml:"http://www.w3.org/2000/09/xmldsig# Transforms"`
	Transforms []Transform `xml:"Transform"`
}

type Transform struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Transform"`
	Algorithm string   `xml:"Algorithm,attr"`
}

type DigestMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

var DigestMethodAlgorithmSHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"
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
