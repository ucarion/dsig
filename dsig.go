package dsig

import (
	"crypto"
	"crypto/rsa"
	"crypto/subtle"
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
	if subtle.ConstantTimeCompare(expectedDigest, h.Sum(nil)) != 0 {
		return errors.New("digest not correct")
	}

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

type SignatureMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignatureMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

func (s *SignatureMethod) hash() crypto.Hash {
	switch s.Algorithm {
	case "http://www.w3.org/2000/09/xmldsig#rsa-sha1":
		return crypto.SHA1
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
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

func (d *DigestMethod) hash() crypto.Hash {
	switch d.Algorithm {
	case "http://www.w3.org/2000/09/xmldsig#sha1":
		return crypto.SHA1
	case "http://www.w3.org/2001/04/xmlenc#sha256":
		return crypto.SHA256
	default:
		return 0
	}
}
