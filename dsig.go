package dsig

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
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
	// if !strings.HasPrefix(s.SignedInfo.Reference.URI, "#") {
	// 	return errors.New("not a fragment")
	// }

	toDigest, toVerify, err := sigsplit.SplitSignature(r)
	if err != nil {
		return err
	}

	// id := s.SignedInfo.Reference.URI[1:]
	// tokenReader := omitSignatureReader{RawTokenReader: r, stack: &stack.Stack{}}
	// payload, err := c14n.Canonicalize(id, &tokenReader)
	// if err != nil {
	// 	return err
	// }

	expectedDigest, err := base64.StdEncoding.DecodeString(s.SignedInfo.Reference.DigestValue)
	if err != nil {
		return err
	}

	h := sha1.New()
	h.Write(toDigest)
	if subtle.ConstantTimeCompare(expectedDigest, h.Sum(nil)) != 0 {
		return errors.New("digest not correct")
	}

	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("not rsa public key")
	}

	h = sha256.New()
	h.Write(toVerify)

	expectedSignature, err := base64.StdEncoding.DecodeString(s.SignatureValue)
	if err != nil {
		return err
	}

	fmt.Println("ucarion", toVerify)
	fmt.Println(hex.EncodeToString(expectedSignature))
	fmt.Println(hex.EncodeToString(h.Sum(nil)))

	fmt.Println(s.SignedInfo.SignatureMethod.Algorithm)
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, h.Sum(nil), expectedSignature); err != nil {
		return err
	} else {
		fmt.Println("RSA WORKED")
	}

	fmt.Println(string(toVerify))
	return nil
}

// type omitSignatureReader struct {
// 	depth       int  // the current depth in the node tree
// 	inSignature bool // whether we are currently in the signature to skip
// 	stack       *stack.Stack
// 	c14n.RawTokenReader
// }

// func (r *omitSignatureReader) RawToken() (xml.Token, error) {
// 	t, err := r.RawTokenReader.RawToken()
// 	// fmt.Println("RAWTOKEN", t, err)
// 	if err != nil {
// 		return nil, err
// 	}

// 	switch t := t.(type) {
// 	case xml.StartElement:
// 		names := map[string]string{}
// 		for _, attr := range t.Attr {
// 			if attr.Name.Space == "xmlns" {
// 				names[attr.Name.Local] = attr.Value
// 			} else if attr.Name.Space == "" && attr.Name.Local == "xmlns" {
// 				names[""] = attr.Value
// 			}
// 		}

// 		r.stack.Push(names)

// 		// fmt.Println("start", r.depth, r.stack.Get(t.Name.Space), t.Name.Local)
// 		if r.depth == 1 && r.stack.Get(t.Name.Space) == "http://www.w3.org/2000/09/xmldsig#" && t.Name.Local == "Signature" {
// 			// fmt.Println("found sig", r.depth)
// 			r.inSignature = true
// 		}

// 		r.depth++

// 		if r.inSignature {
// 			return r.RawToken()
// 		}

// 		return t, nil
// 	case xml.EndElement:
// 		r.depth--
// 		r.stack.Pop()

// 		// fmt.Println("end", r.depth)

// 		if r.depth == 1 && r.inSignature {
// 			// fmt.Println("foudn end of sig")
// 			r.inSignature = false
// 			return r.RawToken()
// 		}

// 		if r.inSignature {
// 			return r.RawToken()
// 		}

// 		// fmt.Println("return this end")
// 		return t, nil
// 	default:
// 		if r.inSignature {
// 			return r.RawToken()
// 		}

// 		return t, nil
// 	}
// }

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
