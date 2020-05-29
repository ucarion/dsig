# dsig

[![go.dev reference](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/mod/github.com/ucarion/dsig?tab=overview)

This package is a Golang implementation of [XML Digital Signature][w3], or
"XML-DSig". In particular, it implements a restricted subset of the
specification:

1. This package only knows how to *verify* signatures, not sign them.
1. Only the common case of an "enveloped signature" with just the
   canonicalization and digest transforms are supported; the `URI` field of
   `ds:Reference`, as well as `ds:Transforms`, are ignored.
1. Only the RSA-SHA1 and RSA-SHA256 signature algorithms are supported.
1. Only the SHA1 and SHA256 digest algorithms are supported.

The XML-DSig specification is vast, complex, and very challenging to implement
in its entirety. In practice, supporting the subset provided by this package is
good enough to securely implement SAML and other protocols built on top of
XML-DSig.

If you're looking to verify XML because you're implementing SAML, consider using [`github.com/ucarion/saml`][saml].

[w3]: https://www.w3.org/TR/xmldsig-core/
[saml]: https://github.com/ucarion/saml

## Installation

Install this package by running:

```bash
go get github.com/ucarion/dsig
```

## Usage

The most common way to use this package is to embed `dsig.Signature` into a
struct representing your data, and then calling `Signature.Verify()` on the
`[]byte` you unmarshalled your struct from. For example:

```go
input := `
    <Foo favoriteNumber="42">
      <favoriteQuote>hello</favoriteQuote>
      <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
          <ds:Reference>
            <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
            <ds:DigestValue>TakSS5ndDNzYd32+E3GGQlZJ3j0=</ds:DigestValue>
          </ds:Reference>
          <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
        </ds:SignedInfo>
        <ds:SignatureValue>L4l1Qyp8kVFaZ9893/IW0bEBGBuAavssuv916PuM/e7RAR7qQ/PZ4M8Lo5WcMXV2GYLoRttTurt0I9udTs4SO4yv+JitlXdvWUllgLQNR9kMHpFwzkyv2Pw6m3j6Jdix9kVD7nh50OUcBJDJSk+WLa55TWLe++RejjPfUezPoAY=</ds:SignatureValue>
      </ds:Signature>
    </Foo>
`

type Foo struct {
  FavoriteNumber int            `xml:"favoriteNumber,attr"`
  FavoriteQuote  string         `xml:"favoriteQuote"`
  Signature      dsig.Signature `xml:"Signature"`
}

// First, unmarshal an instance of your struct, with the Signature embedded in
// it, from your []byte input.
var foo Foo
err = xml.Unmarshal([]byte(input), &foo)
fmt.Println(err)

// Next, construct a decoder from the bytes you just unmarshalled from.
decoder := xml.NewDecoder(strings.NewReader(input))

// Finally, call Verify using an X509 certificate and the decoder you just made.
err = foo.Signature.Verify(cert, decoder)
fmt.Println(err)
// Output:
// <nil>
// <nil>
// <nil>
```

The code above works if you construct `cert` as:

```go
block, _ := pem.Decode([]byte(`-----BEGIN CERTIFICATE-----
MIICVzCCAcACCQC9lei8Ir3KDzANBgkqhkiG9w0BAQsFADBwMQswCQYDVQQGEwJV
UzEPMA0GA1UECAwGT3JlZ29uMREwDwYDVQQHDAhQb3J0bGFuZDEVMBMGA1UECgwM
Q29tcGFueSBOYW1lMQwwCgYDVQQLDANPcmcxGDAWBgNVBAMMD3d3dy5leGFtcGxl
LmNvbTAeFw0yMDA1MjgxNzUzNTJaFw0yMTA1MjgxNzUzNTJaMHAxCzAJBgNVBAYT
AlVTMQ8wDQYDVQQIDAZPcmVnb24xETAPBgNVBAcMCFBvcnRsYW5kMRUwEwYDVQQK
DAxDb21wYW55IE5hbWUxDDAKBgNVBAsMA09yZzEYMBYGA1UEAwwPd3d3LmV4YW1w
bGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAqmyYL/bNqAL7uHFx
lHT2Ullmh0UvMb1mJrtTVb/j+k+nKNklbdbz/mSOdc7OJ8kwu9xNcKvDADr8acir
74p8Tp9hYEOR8p2XBcFiB7x5g76Vdm6NM4g3Ib5utXBRd13YSQajD6ynJYprrTBn
gGnXzdvZ6ZhX3QeJebO9m9u7WQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAL8vaXlm
1dd8U9UCrnt6X0MHvd5l5RRWqvXcV7FvjBqs6U9TP+soCKAzQSpJh4WpY1qaMlgc
FVaTFT9FFMoqYHTn4yj/C6GS7tcyXEStKvr7UA6mH4yfepwndoc6/KAuCph1ucsb
VuPh47/DnXFpm4ZKNsojqBwUjM9/EkP0UGGK
-----END CERTIFICATE-----`))

cert, err := x509.ParseCertificate(block.Bytes)
fmt.Println(err)
```

But you'll find that if you tamper with the cert or the data being signed (in a
way that meaningfully alters the XML data), you'll get an error.
