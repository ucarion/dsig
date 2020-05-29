package dsig_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ucarion/dsig"
)

func ExampleSignature() {
	type Foo struct {
		FavoriteNumber int            `xml:"favoriteNumber,attr"`
		FavoriteQuote  string         `xml:"favoriteQuote"`
		Signature      dsig.Signature `xml:"Signature"`
	}

	input := `
		<Foo favoriteNumber="42">
			<favoriteQuote>hello</favoriteQuote>
			<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
				<ds:SignedInfo>
					<ds:Reference>
						<ds:DigestValue>xxx</ds:DigestValue>
					</ds:Reference>
				</ds:SignedInfo>
				<ds:SignatureValue>yyy</ds:SignatureValue>
			</ds:Signature>
		</Foo>
	`

	var foo Foo
	err := xml.Unmarshal([]byte(input), &foo)
	fmt.Println(foo.FavoriteNumber, foo.FavoriteQuote, foo.Signature.SignedInfo.Reference.DigestValue, foo.Signature.SignatureValue, err)
	// Output:
	// 42 hello xxx yyy <nil>
}

func ExampleSignature_Verify() {
	// This example shows how you manually construct a signature that this package
	// will successfully verify.
	//
	// First, you'll need to create a x509 certificate and its corresponding RSA
	// private key. You can do that by running:

	// openssl req -x509 -newkey rsa:1024 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=US/ST=Oregon/L=Portland/O=Company Name/OU=Org/CN=www.example.com"

	// Note: don't use a key like this in production. 1024 bits is usually
	// insufficient for RSA in production.
	//
	// Running that command will generate a file like this:
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

	// It will also generate an RSA private key in a file called "key.pem". For
	// this example, that file contained:

	// -----BEGIN PRIVATE KEY-----
	// MIICeQIBADANBgkqhkiG9w0BAQEFAASCAmMwggJfAgEAAoGBAMCqbJgv9s2oAvu4
	// cXGUdPZSWWaHRS8xvWYmu1NVv+P6T6co2SVt1vP+ZI51zs4nyTC73E1wq8MAOvxp
	// yKvvinxOn2FgQ5HynZcFwWIHvHmDvpV2bo0ziDchvm61cFF3XdhJBqMPrKclimut
	// MGeAadfN29npmFfdB4l5s72b27tZAgMBAAECgYEAsd9lfKejisDXaEAjdAHkbdkf
	// MnomVGjufBW8Ejbzfu2EhkY/G8ApmH+/pIp9EHVI2JZH0LL50IEw9AJRwvLW/Usn
	// ftKh5wuTp2+0D5NSaIyaW4GuKTZvxsr+GW2ot3qACOQXAj/Lh97kn0K8czZv9u1e
	// fJyUhFb5vRbDo2EDVJUCQQDxwWgVdEm64MKv2y+q0lOvfUolX9/lLUkvJbaskJvN
	// /4qCKQKLfGCjRITnKLW58f29FRZa6JOD4kdYWL/CLHinAkEAzASOkDVoj+bBQZaJ
	// l86IP2YBsR7gzc/BpBkmmgPvcbcS7TH+KcNtwAgcSD30JfdxJYpqm4xnd0zI2WUR
	// wkir/wJBAJIdbQUahb13PvP+q+64tG+qb/fq3G2tU0A1sRTXSfPVcSd+FdWsVNQZ
	// A6KazksWYV+4sQw86XuadbiF21BGhJ0CQQCbKLQLtLKrDkHX0dce3vH71WZgAC3U
	// GLcaSA51f5yxDRyVzDmSJZDoRMLNpmByJ3ejp1tgpS1jK8BspVMWQRKdAkEArOjw
	// I6a8DR91f+zxDkFne31qP6FENL+esVHkGUd61/U35pezUx1jdhDrq5Xmr42QJlw1
	// 28GdnqzGoINvvv8JQQ==
	// -----END PRIVATE KEY-----

	// Note: don't use this private key in production. This is just an example
	// key, and because it's shared in this example, it's now useless for
	// real-world use.

	cert, err := x509.ParseCertificate(block.Bytes)
	fmt.Println(err)

	type Foo struct {
		FavoriteNumber int            `xml:"favoriteNumber,attr"`
		FavoriteQuote  string         `xml:"favoriteQuote"`
		Signature      dsig.Signature `xml:"Signature"`
	}

	// The DigestValue in this example is calculated by running:

	// echo -n '<Foo favoriteNumber="42">\n\t\t\t<favoriteQuote>hello</favoriteQuote>\n\t\t\t\n\t\t</Foo>' | sha1sum | cut -d' ' -f1 | xxd -r -p | base64

	// That string is the canonicalized representation of all of the data outside
	// of the ds:Signature.
	//
	// The SignatureValue is calculated by running:

	// echo -n '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">\n\t\t\t\t\t<ds:Reference>\n\t\t\t\t\t\t<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod>\n\t\t\t\t\t\t<ds:DigestValue>TakSS5ndDNzYd32+E3GGQlZJ3j0=</ds:DigestValue>\n\t\t\t\t\t</ds:Reference>\n\t\t\t\t\t<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod>\n\t\t\t\t</ds:SignedInfo>' | openssl dgst -sha1 -sign key.pem | base64

	// That string is canonicalized representation of the ds:SignedInfo, including
	// the DigestValue we just calculated.
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

	var foo Foo
	err = xml.Unmarshal([]byte(input), &foo)
	fmt.Println(err)

	decoder := xml.NewDecoder(strings.NewReader(input))
	err = foo.Signature.Verify(cert, decoder)
	fmt.Println(err)
	// Output:
	// <nil>
	// <nil>
	// <nil>
}

// The cert and key used in these tests were generated by running:
//
// openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
// -nodes -subj "/C=US/ST=Oregon/L=Portland/O=Company
// Name/OU=Org/CN=www.example.com"
//
// Which generated the certificate used in TestVerify. It also generated this
// corresponding RSA private key:
//
// -----BEGIN PRIVATE KEY-----
// MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQC4yrnAdbSwMQz8
// CPL0ir2TbhNadYCjukgxQxxjGeVVuRxHFzKyLlaM17ZG6x67F7DqvxXwO8Bvfnur
// eFDG8uq13eIni3Tvl38G4pFQOLHgY/hvKS9E4L8bBPDaXag6jD463arduvOo0ZzB
// movgoqw4ryze53I2z8D+eIPa3WmRX93gZ69UemcAo7MJv/WzpByimefah/+TSTFd
// r5q1kVOxaJclcoAbTcDRxZEVGc6l/BRZQHrz5VG3JEO8M1KuzAq0nMyFkyP1ynGv
// P66syV+DYcqjSJ3cB+fgeIC1VT2ZgwzdxBWJeRIgCNT8YOmI9FpiYrurEcU9iLnf
// HQ0O3422QLZrJVxyY47c7q9kBPUNUZ+ewWgPeSeRDSl3L0wfknNebemmZr7IRYUV
// h6bTIqB/MRORp70E/Vnp5QBrofdkaF8Z6zslnz50FAj3pZVsmEaQjh/yBqxghV4H
// qivNmf+6p8/38PjhlU9x/M1dmmjr1NKau4ILrS9meEL2+rweqV4TZq++T7d57Bor
// oz1zytKXp/QwvGQcpD+TRtuhHZkpLHROyGSdCR9XnYBI5FeQOVi53vhT+BDrbrXE
// +CkfmALylLFsflBeF/9IhmyHAcEpkj/0FZYjAXoEZEEeAphawd/qVspt30J7X35O
// cqTIPDilNVL+WWMi0lHsWO5h9FzPMwIDAQABAoICAH3d353ezp8AGgcFlW7JnYzw
// +g+wX1mmBYxAWPKLbfDwr/kgLPC+rUcrmsU9WuY2odOTKj9Cg7WtolDOF78bMJGF
// u4gR7ilPuD8ZTb8ljsr3bP1SQRcaOjEOMXubNX4DjlOMLtjugQ6pD6uzN7lfNA08
// DEUbwmjhI2Rw8+a8zy4s7TTvirXw1X3TAp0Oei3NB5AdYpYv8f4BabWVabxoa2g4
// hFMGZYmzcTWw6zxDIsVeKQIN8HF17i3fbp+fGZ9j7ZrN/mSxL1o4dSzYJIMeeodD
// scF8McHwRJlZmtloYRfR8o6PA9hqddUKDwCEhi05uuKuu4MvDHj4SxpUcFOEI8Iq
// cxtM4m8kbLPpWnHYC0xUUigP5lY0P8HoQqO6ktLJNv2s2pEKxXFCA7kTiA2xyiEC
// iisuoyGGlXQ8HB8L1ShYDrwjPlbJ7CCTl3yZ8kruq6kp5kF/Cps39cmM0WsvJXK0
// OjYBNFAO2RnoRaoJQrh60rWPjK/JoqpUGrRPG7+k1VuGdGBaOw4YvC339koALXpK
// sEDvwIztPsv2AwE0WMw5NmhnRtmNUXb3LhlrjPOZ5e2HyRhdrLpBu5y79tcF8VN9
// mksfIQqhNxKpidBkju4u6nyYOvQL013vKJSJRfXxYXRKQgGO0gBhasjjwBRjeOvY
// uLKVpnJ1Ncq4nr1yFLdZAoIBAQDfl0kxOJeFBYSVQRKxiXIL+xXm9mSQ3fu2Ir4T
// JoMkkz0pBkXCI5aC+JnR8CmmTVXD+T5BDYcXGngGAZQZDPvFhXs9J0dpJJRVajBT
// Cj7OPRu51o95gjmYVpOHtKwRQal8LerPajd60YsRNNuMsExkJkmirUly3bkaevEh
// Gqt0RK6/qTGDy5M0u5KYhMy/mgg+mSWLfjLmdR7FaszVmIEa6WZr5dTMmmidPq7b
// GHWvXwLZg6VIeGzRhAb33XLDBrB/S/IOY98dz4hasVZ/f+EskgFqkEXe/X1i1YSN
// PT1VNSOWA6Rj/h+rmA7NOdLZMrzi12sId2Y6sjvbPERNPhftAoIBAQDTk7xn6usz
// /MIJk4HhYwlVJadPnfsFP7Z0AGXGY83OclpsiDpJPC8nWGvc40oqtmqz4cOcdy+H
// KFtu1JGyDn9W36y9+NViQp+RJ1NKosdV4/N7L9nXXi1y7uNe9QvdTjtS44xXFEk5
// FLDoKzGDXkPp77eA6BPfqMMFymf8mgq+MpWioKLiR43w+Zc+/Ncz6zMSsr/nPH6e
// 1Gjh0Nva4/M5aelJU+i5P1bJlcrRs6//N3RQjPgCBF5NDj2SEseAH8cQkxhfsXB+
// xfWyY7ocGPNlO+sGarLqaftqSSD1J7wZ8dbgHysnTJkdhhWJmRbYxSoZBwSG1CSI
// kvDugRZ8N1+fAoIBACCb2crZ7A80bM+vu+A0oXNp3RngGW6fUVSQ4JO+bCXra2IO
// TiIwOoVDaHubwRdF9BouwYuPQ4J1E8gcdtLod9eozf5vOhT1hsSmRgH2Xo6Jjv+d
// cTNRcMDs73s9OFMT9nnr4HD7lrfM07FguhxcoeeBRf/5sdqUx6g7AevIDfVZBvtg
// 253TFNb9/DVOOOZAuq8WeslLUHUX47L7DoCgS0P3gj5+OHjWlCdKuwmtGYzIGIxM
// jNBy77vmu3Vu0Ivs79TA6L58hk+8srA3aNwTdG2hpZ87B1WsNpsxdLF8mvNQWq5I
// PbNvnoLSHGaF5mBS7AVRUYTclQY+dEhXE8cIJUkCggEBAMU9bN7TugD1GU8kHGip
// kwG14IvwkxsJkmYCGN8iG7LiGDolpXCwkqTzYVrC6Vl4RXD8fwdWdRBjJxnjQQ/l
// RAEQ9FEFsKexxF/lcVia94mywEGPEl4chfInkf/sIetmCxfy2do0Jy73gxRtb/Mv
// 5dAokcGymRRgl67GSrrKQEmfjq/VYQPiAQktJTqrK1RTZ4F+8jf3xXL8QeqCcvNU
// nmJfwgOCHerUiWvUIQfto50hbWXKhUocGG1tYSjUKPfgqAtjlc1f9ae5lJuBLPcU
// q5MskKWiwriVpLQpCHiDWnA1bEPzyp8QYY2MeneUKCBdbil2yVmIW6aWldVCsluK
// o7ECggEAbp+MZOPzKYTEGVWLNQh0CVairBVrOexlOFrup7sOW0NFQXu8ExHsRsgC
// HMEvBj24jJM6FeaJ4Fkc1WAfJqY0KnpWeEPFzLY9W7ZEHbkyiHJ0DzvReXPYGWSC
// Qj0dgv0jfDODdsfTqI6zW/WXHEQ8399JiAEVGVphMUo2oY+rhDAiZCFFlt7heyq2
// fLf4MAmc3vK6slbyaDb9kYm+fsiCBVqvwVIKvIZ1/IOOU5q6KQIYjJXryLIBORuw
// 3jlAmnFMZFC0dBPJAHeon8m47S/1Te2EkyH1D1GvcDnE07PjhFUl3LpbD4qrw0Wv
// tRNOxnQnlHJKcCgbfcUOD3hpFKtY9g==
// -----END PRIVATE KEY-----

func TestVerify(t *testing.T) {
	block, _ := pem.Decode([]byte(`-----BEGIN CERTIFICATE-----
MIIFXDCCA0QCCQCl4WZtbTlavDANBgkqhkiG9w0BAQsFADBwMQswCQYDVQQGEwJV
UzEPMA0GA1UECAwGT3JlZ29uMREwDwYDVQQHDAhQb3J0bGFuZDEVMBMGA1UECgwM
Q29tcGFueSBOYW1lMQwwCgYDVQQLDANPcmcxGDAWBgNVBAMMD3d3dy5leGFtcGxl
LmNvbTAeFw0yMDA1MjAxNzI0MzFaFw0yMTA1MjAxNzI0MzFaMHAxCzAJBgNVBAYT
AlVTMQ8wDQYDVQQIDAZPcmVnb24xETAPBgNVBAcMCFBvcnRsYW5kMRUwEwYDVQQK
DAxDb21wYW55IE5hbWUxDDAKBgNVBAsMA09yZzEYMBYGA1UEAwwPd3d3LmV4YW1w
bGUuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuMq5wHW0sDEM
/Ajy9Iq9k24TWnWAo7pIMUMcYxnlVbkcRxcysi5WjNe2Ruseuxew6r8V8DvAb357
q3hQxvLqtd3iJ4t075d/BuKRUDix4GP4bykvROC/GwTw2l2oOow+Ot2q3brzqNGc
wZqL4KKsOK8s3udyNs/A/niD2t1pkV/d4GevVHpnAKOzCb/1s6Qcopnn2of/k0kx
Xa+atZFTsWiXJXKAG03A0cWRFRnOpfwUWUB68+VRtyRDvDNSrswKtJzMhZMj9cpx
rz+urMlfg2HKo0id3Afn4HiAtVU9mYMM3cQViXkSIAjU/GDpiPRaYmK7qxHFPYi5
3x0NDt+NtkC2ayVccmOO3O6vZAT1DVGfnsFoD3knkQ0pdy9MH5JzXm3ppma+yEWF
FYem0yKgfzETkae9BP1Z6eUAa6H3ZGhfGes7JZ8+dBQI96WVbJhGkI4f8gasYIVe
B6orzZn/uqfP9/D44ZVPcfzNXZpo69TSmruCC60vZnhC9vq8HqleE2avvk+3eewa
K6M9c8rSl6f0MLxkHKQ/k0bboR2ZKSx0TshknQkfV52ASORXkDlYud74U/gQ6261
xPgpH5gC8pSxbH5QXhf/SIZshwHBKZI/9BWWIwF6BGRBHgKYWsHf6lbKbd9Ce19+
TnKkyDw4pTVS/lljItJR7FjuYfRczzMCAwEAATANBgkqhkiG9w0BAQsFAAOCAgEA
r6UAa9n4FkiA4ZqugCJEoC5Ehc1X/qdNFkY4EIHc33sqscqVZhHC0MbfNmKuiirk
XKTR+M3U62IvD8HXpkBMTYMpnvsH4jFuP3SpTFfUuqarueqsawiPAejhjF9829fg
K1+s1rD/fI3H3UuHWChTXKA4KpnCYr5B1om4ZoCcTVVdZjhO256iM7p/DHze08Eo
Rdhaj+rgs6NC5vLHWX9bezACeqA3YwJYHRH0zuoCQfRKXkikIjj18wpWNARFhDoQ
FEhJXIAO/skpuK6Q9Ml1wWuFaqgXtKN1iVzuGi7P8O3bCLexwmqnmsnEZPPpzjoQ
T8zVIjCH6jBX533f1B745IrGNzMSr6YC/9RT3DrPoNT9pCAozSoZxldqIegxLgWG
zBT6jj/fR92E5kJh8Hy3koeXGkyAkcHB0PH8yyFtYIlP0stENkG/fDCLuMUqf6GZ
P/oSyJH1Ro/qV6kwc1XYDB+6NGC8Xd1JQKZD49c/GZYpo77ZYKQtCoTrMuPKSG5/
jP7OTrdylTj+V4r7jYLLpvWCUe0ON0QPKClo+15tXATWep6PFk0U5W+efvavG70e
Fu9GKMOkTgv5F/ngzDgXKo7T6poRDZAgolUAq2kwDUp42AVx/7UqmOdp0yUTNmJG
A70UwPLAvWk5vX1IMpaEFjBd3LqWLeSmbKZ03zr1jnA=
-----END CERTIFICATE-----`))

	cert, err := x509.ParseCertificate(block.Bytes)
	assert.NoError(t, err)

	blockEC, _ := pem.Decode([]byte(`-----BEGIN CERTIFICATE-----
MIIB0TCCAXYCCQDW+s9OdMppmzAKBggqhkjOPQQDAjBwMQswCQYDVQQGEwJVUzEP
MA0GA1UECAwGT3JlZ29uMREwDwYDVQQHDAhQb3J0bGFuZDEVMBMGA1UECgwMQ29t
cGFueSBOYW1lMQwwCgYDVQQLDANPcmcxGDAWBgNVBAMMD3d3dy5leGFtcGxlLmNv
bTAeFw0yMDA1MjIwMTIzMzNaFw0yMTA1MjIwMTIzMzNaMHAxCzAJBgNVBAYTAlVT
MQ8wDQYDVQQIDAZPcmVnb24xETAPBgNVBAcMCFBvcnRsYW5kMRUwEwYDVQQKDAxD
b21wYW55IE5hbWUxDDAKBgNVBAsMA09yZzEYMBYGA1UEAwwPd3d3LmV4YW1wbGUu
Y29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBEHpQCB2XIoK1HNKr47JCF66
ysNNXOsauFO+6OLus4tgcwCr61D/I7tTED7+9If2TgDZpvx/IA2qzaSVa6EJbjAK
BggqhkjOPQQDAgNJADBGAiEAh1th49i2qBgQtLFbuoriHLRWabHWpBqhhFg+RcBs
diwCIQC/JKDqOZLQ3+PrWMHO+fh3uU8cj/cPRlsUkE3wjaM4lA==
-----END CERTIFICATE-----`))

	certEC, err := x509.ParseCertificate(blockEC.Bytes)
	assert.NoError(t, err)

	signatureFormat := strings.ReplaceAll(`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="%s"></ds:CanonicalizationMethod>
<ds:SignatureMethod Algorithm="%s"></ds:SignatureMethod>
<ds:Reference>
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>
<ds:Transform Algorithm="%s"></ds:Transform>
</ds:Transforms>
<ds:DigestMethod Algorithm="%s"></ds:DigestMethod>
<ds:DigestValue>%s</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue>%s</ds:SignatureValue>
</ds:Signature>`, "\n", "")

	type payloadStruct struct {
		XMLName   xml.Name       `xml:"root"`
		Foo       string         `xml:"foo"`
		Signature dsig.Signature `xml:"Signature"`
	}

	type testCase struct {
		Cert            *x509.Certificate
		PayloadFormat   string
		C14NMethod      string
		DigestMethod    string
		DigestValue     string
		SignatureMethod string
		SignatureValue  string
		Err             error
	}

	testCases := map[string]testCase{
		"happy sha1 sha1": testCase{
			Cert:          cert,
			PayloadFormat: `<root>%s<foo>xxx</foo></root>`,
			C14NMethod:    dsig.CanonicalizationMethodAlgorithmExclusive,
			DigestMethod:  dsig.DigestMethodAlgorithmSHA1,

			// echo -n '<root><foo>xxx</foo></root>' | sha1sum | cut -d' ' -f1 | xxd -r -p | base64
			DigestValue:     "7kvXOcbFqnvhPOTWR6rVaMjjh6o=",
			SignatureMethod: dsig.SignatureMethodAlgorithmSHA1,

			// echo -n 'echo -n '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">...</ds:SignedInfo>' | openssl dgst -sha1 -sign key.pem | base64
			SignatureValue: "lNEz9jdCMk5RZI5iIwnPhJ1Xfi18ezpU5CjIHCFLdgJPuv5e9xTwM2HQUkgzayZDOnUi/Gvw/NxU8+gigt6ORp26a3t136uAYFO151OgRarb3Qm+xsvsRCNeDV9d3Lg60YZXRtgOpqd/X2/HWTnwvLu4DphS/7/qVCEVKxqSsnuyUnnXHgz5w0U4QpBsBGe8KkhrobE4xmxVxwHokISObrl0/4OT8XLezrp8N5Q4HlSQM1et6I/WLggyXQAN31qyd03EwejBqex1xiR/b4mhnfmQVaFMfHHV4kRKXoYxXsBa6kdlVIOC7GvaIQYT0MDFCxMqNbqJxwmFqCzkG4jobg91eStWFzaDS7XmevqxVveHiADkLULisXnv20HQbehigib9xeMUjruzd+86mB2i863PU4DdXZ0qEcIBI6QyrVOyCI8fFsC7+qPFjtt7juZQ1BT1p6MNcKgFn/0Du+LB9RLTUJEwZsFqDGQ6405LdNIFiqbL/8Tbk6Q2IyTkp3AVtwn/aUUkVtoEMMf+tDfp3Ujtqo+qgXI/AxmwPX2JbvhuGdDR4bhIWCL7I1yyV0uGafV1jJyfle2hImIrMW5DzKtb4FlnOfEUQxYJyZnM8i6dikAOqmhj7hpuS7+vxyDpglZ6r2XoPYjaUMIl5gdkhHWCToCsqjUbwhv4H3/ji14=",
			Err:            nil,
		},
		"happy sha1 sha256": testCase{
			Cert:          cert,
			PayloadFormat: `<root>%s<foo>xxx</foo></root>`,
			C14NMethod:    dsig.CanonicalizationMethodAlgorithmExclusive,
			DigestMethod:  dsig.DigestMethodAlgorithmSHA1,

			// echo -n '<root><foo>xxx</foo></root>' | sha1sum | cut -d' ' -f1 | xxd -r -p | base64
			DigestValue:     "7kvXOcbFqnvhPOTWR6rVaMjjh6o=",
			SignatureMethod: dsig.SignatureMethodAlgorithmSHA256,

			// echo -n 'echo -n '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">...</ds:SignedInfo>' | openssl dgst -sha256 -sign key.pem | base64
			SignatureValue: "FQuimbNo1g+5PGUZ1Z535eM1CmScPXB+QNCSPmD1TScI0oORE+PAP9j+X+jZud5dj46AWbym7qQstLsrG53Bf4FS/OqA5dU5G9wGjr3lOH0supmTS8tBIsEykW1/i5wQd2hhK9901HpS9v31ZAUcoeE2dXN8zk1KCx48I1Urt+52BKdUn0/aM9LDojWoqAHQWtJvxb11zuUufpbGy32Xf7v3e787MPl0c69bW94l5UIpHPGXh+Ayws9AyMmSl0STCQB8OyxaOIN9tLySpgXsjYsD3BB0VN+Q27QCUMmfTn8I4JpZ5pEREnrksaGYml7gFegHfwHfYJuXxM4OyPQp15Ij9aVcpDKxsiouDN8d53etinzxoMSsW8+ZRXq7rwb7YSLqCBxJMEEfkUP+m1fmPEfPJC92BRrZpQ/Y7amGpap1e6MnxKRCaliizR0iAEXDQcnAwvWT8MF0uMwfgBOojEnAOgzxu9O14LMdGf5rKtmExemrEp2AGrWLYQJbVUHiTqBIGHDxyWRnfUPir8BSYrkIzXqf23RIoK07f5Xrog53LXXWmIAw55YcH6UUCbtPTdB7e+CyJeG7T9wTgxLIuXUh6sRpOtGeQCYoWksIgpeapMbqtm+gjtRHNgBJQepNLw82/dqFLfKbS0fh0adVz34gu+ImG9HOKCq6eDVm1pU=",
			Err:            nil,
		},
		"happy sha256 sha1": testCase{
			Cert:          cert,
			PayloadFormat: `<root>%s<foo>xxx</foo></root>`,
			C14NMethod:    dsig.CanonicalizationMethodAlgorithmExclusive,
			DigestMethod:  dsig.DigestMethodAlgorithmSHA256,

			// echo -n '<root><foo>xxx</foo></root>' | sha256sum | cut -d' ' -f1 | xxd -r -p | base64
			DigestValue:     "TguIzbsTiB/7WATV3090uvckGWxV3D4JKOdTa7pFb7w=",
			SignatureMethod: dsig.SignatureMethodAlgorithmSHA1,

			// echo -n 'echo -n '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">...</ds:SignedInfo>' | openssl dgst -sha1 -sign key.pem | base64
			SignatureValue: "Gqmcq6pxP37Xudgn4cizeDxeC+s2dDTLa1+qpQpWx3e9qD4TW455UYREYA5G5TiAfii4GJViV+jmN4qr/OQgy+iDut5Dg2FMuyPpqbCmfJZxULvqrm59wrShcNwzJBd51vDFuuGA4TPeAYxDCQVfnK+SXO3aerkx/D6U3H2a7l4vLdrwL9KRhQHSzO4YimCEk8Ccpe7FjqPYuj8ZyZCzxouzv/Zk2/NCWAGPvGlXNK+2F0zyIqBeiTFjouiDV66+xqeXXEL5cBPruxzqTIqZRCfpdqggXjC7Lr9zK4Hz5HHiVCs6WhoGnIN6CTPSNo0fb8O7+6oAIpdK0FNTp68hapIqpS9EL1bVY3XPeIjcd/aMQ7JhN/KW/SwwRJjVKHATDB71vxGZe05TwGsppNAYFTbbtNq//HgMqT+QVbbLTSb1dZhGxeZBG1e68RwBddZA5YLqrveUu/3HlgAdG9XV/Oj+3vWceIzVu6CXvpCL3/9QQdnA6erBouTxICosjopNyeCOjQxseeUDX95a/a1MCP6K/sSiiGRQI6WJzEaFAh4lsvsdNhhMqHRxV2lJjj36QMqhfD8W93K2//RGAwZuhae3ZIbJOie+8SFMUjwyDJgPkZJBel7UwyLn1038MwzK066J0VIB9Xxt9hHIo+sUJeiIgAZOtWght3TTCKLCBYw=",
			Err:            nil,
		},
		"happy sha256 sha256": testCase{
			Cert:          cert,
			PayloadFormat: `<root>%s<foo>xxx</foo></root>`,
			C14NMethod:    dsig.CanonicalizationMethodAlgorithmExclusive,
			DigestMethod:  dsig.DigestMethodAlgorithmSHA256,

			// echo -n '<root><foo>xxx</foo></root>' | sha256sum | cut -d' ' -f1 | xxd -r -p | base64
			DigestValue:     "TguIzbsTiB/7WATV3090uvckGWxV3D4JKOdTa7pFb7w=",
			SignatureMethod: dsig.SignatureMethodAlgorithmSHA256,

			// echo -n 'echo -n '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">...</ds:SignedInfo>' | openssl dgst -sha256 -sign key.pem | base64
			SignatureValue: "OYOiO9eioy1H873jemKmgaJsJ9tceGmCxcdU/o37pfdssYyb7dbp/AQtRSJK4TcZkS4PZoDxdbDgoL+TijRFK4uCVlrcP2njXaaaqbR9DevRSenRy+jwvb8uHc3x8t5u2imeWHxwO6fVveAchl0Hq8Ha0CdQ5kL6cUMAvKdDYjK6nqC1E8u/kfxrIdQY7bXxDNs7T25N4LmvAiWVUbbYZNWCUdVfrjLNc7xDfoJussSecfMM0cYwMITmFmzAOvFu/ovXXguQBGrBJ2FpkAHuqQZtLyTHiHy4AAcTC0MbMYShenGFn0xVl7y/7JPeJ8OS5OOZLrUbauh5zfSLt0WJt8qhKEy1RwFx3xvW+819gyo/W8sPFDRELl2N5oCo7AG2Mb2JBwrRjl60TxiopUm+RodIrirdYx25kSaeebP8ButBUdgMxPuOqNn+wNwagVfAJlaQv2gaunm9CQ470EWu45RoKl8rlkjTKWaQ+0ZoD2Z4K4hgwZHu3DW2f7k/PAL+ZmlyuQymAUBWJ/H2FkqL0pT5DwTJfYk6uLKw1ImPaeoIoynfcDAl6UQae13B4LTAIR8h9h0N0NU6F5tatUcGAg4gjlMogkDhbzISyznLwzgQngTIi3NTagIbogCMUK80d6mOfDc5dUPd/lkCe2BdsP/A+RR7wlSWBJAdc4c2sjQ=",
			Err:            nil,
		},
		"unsupported digest algorithm": testCase{
			PayloadFormat:   `<root>%s<foo>xxx</foo></root>`,
			C14NMethod:      dsig.CanonicalizationMethodAlgorithmExclusive,
			DigestMethod:    "nonsense",
			DigestValue:     "",
			SignatureMethod: dsig.SignatureMethodAlgorithmSHA1,
			SignatureValue:  "",
			Err:             dsig.ErrBadDigestAlgorithm,
		},
		"unsupported signature algorithm": testCase{
			Cert:          cert,
			PayloadFormat: `<root>%s<foo>xxx</foo></root>`,
			C14NMethod:    dsig.CanonicalizationMethodAlgorithmExclusive,
			DigestMethod:  dsig.DigestMethodAlgorithmSHA1,

			// echo -n '<root><foo>xxx</foo></root>' | sha1sum | cut -d' ' -f1 | xxd -r -p | base64
			DigestValue:     "7kvXOcbFqnvhPOTWR6rVaMjjh6o=",
			SignatureMethod: "nonsense",
			SignatureValue:  "",
			Err:             dsig.ErrBadSignatureAlgorithm,
		},
		"bad digest": testCase{
			Cert:            cert,
			PayloadFormat:   `<root>%s<foo>xxx</foo></root>`,
			C14NMethod:      dsig.CanonicalizationMethodAlgorithmExclusive,
			DigestMethod:    dsig.DigestMethodAlgorithmSHA1,
			DigestValue:     "",
			SignatureMethod: dsig.SignatureMethodAlgorithmSHA1,
			SignatureValue:  "",
			Err:             dsig.ErrBadDigest,
		},
		"bad signature": testCase{
			Cert:          cert,
			PayloadFormat: `<root>%s<foo>xxx</foo></root>`,
			C14NMethod:    dsig.CanonicalizationMethodAlgorithmExclusive,
			DigestMethod:  dsig.DigestMethodAlgorithmSHA1,

			// echo -n '<root><foo>xxx</foo></root>' | sha1sum | cut -d' ' -f1 | xxd -r -p | base64
			DigestValue:     "7kvXOcbFqnvhPOTWR6rVaMjjh6o=",
			SignatureMethod: dsig.SignatureMethodAlgorithmSHA1,
			SignatureValue:  "",
			Err:             rsa.ErrVerification,
		},
		"non-rsa x509 cert": testCase{
			Cert:          certEC,
			PayloadFormat: `<root>%s<foo>xxx</foo></root>`,
			C14NMethod:    dsig.CanonicalizationMethodAlgorithmExclusive,
			DigestMethod:  dsig.DigestMethodAlgorithmSHA1,

			// echo -n '<root><foo>xxx</foo></root>' | sha1sum | cut -d' ' -f1 | xxd -r -p | base64
			DigestValue:     "7kvXOcbFqnvhPOTWR6rVaMjjh6o=",
			SignatureMethod: dsig.SignatureMethodAlgorithmSHA1,

			// echo -n 'echo -n '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">...</ds:SignedInfo>' | openssl dgst -sha1 -sign key.pem | base64
			SignatureValue: "lNEz9jdCMk5RZI5iIwnPhJ1Xfi18ezpU5CjIHCFLdgJPuv5e9xTwM2HQUkgzayZDOnUi/Gvw/NxU8+gigt6ORp26a3t136uAYFO151OgRarb3Qm+xsvsRCNeDV9d3Lg60YZXRtgOpqd/X2/HWTnwvLu4DphS/7/qVCEVKxqSsnuyUnnXHgz5w0U4QpBsBGe8KkhrobE4xmxVxwHokISObrl0/4OT8XLezrp8N5Q4HlSQM1et6I/WLggyXQAN31qyd03EwejBqex1xiR/b4mhnfmQVaFMfHHV4kRKXoYxXsBa6kdlVIOC7GvaIQYT0MDFCxMqNbqJxwmFqCzkG4jobg91eStWFzaDS7XmevqxVveHiADkLULisXnv20HQbehigib9xeMUjruzd+86mB2i863PU4DdXZ0qEcIBI6QyrVOyCI8fFsC7+qPFjtt7juZQ1BT1p6MNcKgFn/0Du+LB9RLTUJEwZsFqDGQ6405LdNIFiqbL/8Tbk6Q2IyTkp3AVtwn/aUUkVtoEMMf+tDfp3Ujtqo+qgXI/AxmwPX2JbvhuGdDR4bhIWCL7I1yyV0uGafV1jJyfle2hImIrMW5DzKtb4FlnOfEUQxYJyZnM8i6dikAOqmhj7hpuS7+vxyDpglZ6r2XoPYjaUMIl5gdkhHWCToCsqjUbwhv4H3/ji14=",
			Err:            dsig.ErrPublicKeyNotRSA,
		},
		"digest not base64": testCase{
			Cert:            cert,
			PayloadFormat:   `<root>%s<foo>xxx</foo></root>`,
			C14NMethod:      dsig.CanonicalizationMethodAlgorithmExclusive,
			DigestMethod:    dsig.DigestMethodAlgorithmSHA1,
			DigestValue:     "NOT BASE64",
			SignatureMethod: dsig.SignatureMethodAlgorithmSHA1,
			SignatureValue:  "",
			Err:             base64.CorruptInputError(3),
		},
		"signature not base64": testCase{
			Cert:          cert,
			PayloadFormat: `<root>%s<foo>xxx</foo></root>`,
			C14NMethod:    dsig.CanonicalizationMethodAlgorithmExclusive,
			DigestMethod:  dsig.DigestMethodAlgorithmSHA1,

			// echo -n '<root><foo>xxx</foo></root>' | sha1sum | cut -d' ' -f1 | xxd -r -p | base64
			DigestValue:     "7kvXOcbFqnvhPOTWR6rVaMjjh6o=",
			SignatureMethod: dsig.SignatureMethodAlgorithmSHA1,

			SignatureValue: "NOT BASE64",
			Err:            base64.CorruptInputError(3),
		},
		"no signature": testCase{
			Cert:          cert,
			PayloadFormat: `<root><!-- %s --><foo>xxx</foo></root>`,
			Err:           io.ErrUnexpectedEOF,
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			payloadString := fmt.Sprintf(tt.PayloadFormat, fmt.Sprintf(signatureFormat, tt.C14NMethod, tt.SignatureMethod, tt.C14NMethod, tt.DigestMethod, tt.DigestValue, tt.SignatureValue))

			var payload payloadStruct
			assert.NoError(t, xml.Unmarshal([]byte(payloadString), &payload))

			decoder := xml.NewDecoder(strings.NewReader(payloadString))
			assert.Equal(t, tt.Err, payload.Signature.Verify(tt.Cert, decoder))
		})
	}
}
