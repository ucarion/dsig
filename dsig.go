package dsig

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"

	"github.com/ucarion/c14n"
	"github.com/ucarion/dsig/internal/sigsplit"
)

type Signature struct {
	XMLName        xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	SignedInfo     SignedInfo
	SignatureValue string
}

func (s *Signature) Verify(cert *x509.Certificate, r c14n.RawTokenReader) error {
	toDigest, toVerify, err := sigsplit.SplitSignature(r)
	if err != nil {
		return err
	}

	expectedDigest, err := base64.StdEncoding.DecodeString(s.SignedInfo.Reference.DigestValue)
	if err != nil {
		return err
	}

	h := s.SignedInfo.Reference.DigestMethod.hash().New()
	h.Write(toDigest)

	// This does not need to be a subtle.ConstantTimeCompare, because the digest
	// is not being used as an HMAC. There is no secret key here.
	//
	// Instead, verifying the digest here can act as a hint to the caller that the
	// embedded signature does not correspond to the data it's embedded in.
	if !bytes.Equal(expectedDigest, h.Sum(nil)) {
		return errors.New("digest not correct")
	}

	fmt.Println("toVerify", string(toVerify))

	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("not rsa public key")
	}

	h = s.SignedInfo.SignatureMethod.hash().New()
	h.Write(toVerify)

	expectedSignature, err := base64.StdEncoding.DecodeString(s.SignatureValue)
	if err != nil {
		return err
	}

	if err := rsa.VerifyPKCS1v15(publicKey, s.SignedInfo.SignatureMethod.hash(), h.Sum(nil), expectedSignature); err != nil {
		return err
	}

	return nil
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

func (s *SignatureMethod) hash() crypto.Hash {
	switch s.Algorithm {
	case SignatureMethodAlgorithmSHA1:
		return crypto.SHA1
	case SignatureMethodAlgorithmSHA256:
		return crypto.SHA256
	default:
		return 0
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

func (d *DigestMethod) hash() crypto.Hash {
	switch d.Algorithm {
	case DigestMethodAlgorithmSHA1:
		return crypto.SHA1
	case DigestMethodAlgorithmSHA256:
		return crypto.SHA256
	default:
		return 0
	}
}
