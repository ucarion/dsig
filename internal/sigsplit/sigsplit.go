package sigsplit

import (
	"encoding/xml"
	"io"

	"github.com/ucarion/c14n"
	"github.com/ucarion/dsig/internal/stack"
)

var signatureName = xml.Name{
	Space: "http://www.w3.org/2000/09/xmldsig#",
	Local: "Signature",
}

var signatureDepth = 1

var signedInfoName = xml.Name{
	Space: "http://www.w3.org/2000/09/xmldsig#",
	Local: "SignedInfo",
}

var signedInfoDepth = 2

// SplitSignature takes a raw sequence of tokens, and splits them into data
// outside of ds:Signature and data inside ds:SignedInfo.
//
// The "outer" data needs to be digested, and the "inner" data needs to be
// cryptographically verified.
//
// This function assumes that the data has ds:Signature at the child-of-root
// level, and ds:SignedInfo immediately inside ds:Signature.
func SplitSignature(r c14n.RawTokenReader) ([]byte, []byte, error) {
	outer := []xml.Token{}
	inner := []xml.Token{}

	inSignature := false
	inSignedInfo := false
	stack := stack.Stack{}

	for {
		t, err := r.RawToken()
		if err != nil {
			if err == io.EOF {
				break
			}

			return nil, nil, err
		}

		switch t := t.(type) {
		case xml.StartElement:
			names := map[string]string{}
			for _, attr := range t.Attr {
				if attr.Name.Space == "xmlns" {
					names[attr.Name.Local] = attr.Value
				} else if attr.Name.Space == "" && attr.Name.Local == "xmlns" {
					names[""] = attr.Value
				}
			}

			stack.Push(names)

			resolvedName := xml.Name{
				Space: stack.Get(t.Name.Space),
				Local: t.Name.Local,
			}

			if stack.Len() == signatureDepth+1 && resolvedName == signatureName {
				inSignature = true
			}

			if stack.Len() == signedInfoDepth+1 && resolvedName == signedInfoName {
				// A bit of a hack here:
				//
				// SplitSignature is all about selectively copying XML elements into
				// outer or inner. But the c14n of inner is a function of namespace
				// declarations that might appear above it.
				//
				// To work around this, we copy over all of the known namespace
				// declarations into root of inner, and then we'll let the c14n
				// algorithm filter away any namespace declarations that don't end up
				// being visibly used.
				allNames := map[string]string{}
				for _, names := range stack {
					for k, v := range names {
						allNames[k] = v
					}
				}

				for k, v := range allNames {
					if k == "" {
						t.Attr = append(t.Attr, xml.Attr{
							Name:  xml.Name{Space: "", Local: "xmlns"},
							Value: v,
						})
					} else {
						t.Attr = append(t.Attr, xml.Attr{
							Name:  xml.Name{Space: "xmlns", Local: k},
							Value: v,
						})
					}
				}

				inSignedInfo = true
			}

			if inSignedInfo {
				inner = append(inner, t.Copy())
			}

			if !inSignature {
				outer = append(outer, t.Copy())
			}
		case xml.EndElement:
			if inSignedInfo {
				inner = append(inner, t)
			}

			if !inSignature {
				outer = append(outer, t)
			}

			stack.Pop()

			if stack.Len() == signatureDepth && inSignature {
				inSignature = false
			}

			if stack.Len() == signedInfoDepth && inSignedInfo {
				inSignedInfo = false
			}

		case xml.CharData:
			if inSignedInfo {
				inner = append(inner, t.Copy())
			}

			if !inSignature {
				outer = append(outer, t.Copy())
			}
		case xml.Comment:
			if inSignedInfo {
				inner = append(inner, t.Copy())
			}

			if !inSignature {
				outer = append(outer, t.Copy())
			}
		case xml.ProcInst:
			if inSignedInfo {
				inner = append(inner, t.Copy())
			}

			if !inSignature {
				outer = append(outer, t.Copy())
			}
		case xml.Directive:
			if inSignedInfo {
				inner = append(inner, t.Copy())
			}

			if !inSignature {
				outer = append(outer, t.Copy())
			}
		}
	}

	outerReader := bufRawTokenReader(outer)
	outerBytes, err := c14n.Canonicalize(&outerReader)
	if err != nil {
		return nil, nil, err
	}

	innerReader := bufRawTokenReader(inner)
	innerBytes, err := c14n.Canonicalize(&innerReader)
	if err != nil {
		return nil, nil, err
	}

	return outerBytes, innerBytes, nil
}

type bufRawTokenReader []xml.Token

func (b *bufRawTokenReader) RawToken() (xml.Token, error) {
	if len(*b) == 0 {
		return nil, io.EOF
	}

	t, rest := (*b)[0], (*b)[1:]
	*b = rest
	return t, nil
}
