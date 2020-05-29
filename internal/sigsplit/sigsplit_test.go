package sigsplit_test

import (
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ucarion/dsig/internal/sigsplit"
)

func TestSplitSignature(t *testing.T) {
	s := `<Root xmlns="http://example.com">
<xxx:Signature xmlns:xxx="http://www.w3.org/2000/09/xmldsig#">
<DropMe />
<xxx:SignedInfo>
<IncludeMe />
<!-- include me -->
<?include-me?>
<!include-me>
</xxx:SignedInfo>
</xxx:Signature>
<IncludeMeToo />
<!-- include me too -->
<?include-me-too?>
<!include-me-too>
<NestedSignature>
<xxx:Signature xmlns:xxx="http://www.w3.org/2000/09/xmldsig#">
<DropMe />
<xxx:SignedInfo>
<IncludeMe />
</xxx:SignedInfo>
</xxx:Signature>
</NestedSignature>
</Root>`

	expectedOuter := `<Root xmlns="http://example.com">

<IncludeMeToo></IncludeMeToo>

<?include-me-too?>

<NestedSignature>
<xxx:Signature xmlns:xxx="http://www.w3.org/2000/09/xmldsig#">
<DropMe></DropMe>
<xxx:SignedInfo>
<IncludeMe></IncludeMe>
</xxx:SignedInfo>
</xxx:Signature>
</NestedSignature>
</Root>`

	expectedInner := `<xxx:SignedInfo xmlns:xxx="http://www.w3.org/2000/09/xmldsig#">
<IncludeMe xmlns="http://example.com"></IncludeMe>

<?include-me?>

</xxx:SignedInfo>`

	decoder := xml.NewDecoder(strings.NewReader(s))
	outer, inner, err := sigsplit.SplitSignature(decoder)
	assert.NoError(t, err)
	assert.Equal(t, expectedOuter, string(outer))
	assert.Equal(t, expectedInner, string(inner))
}

func TestSplitSignature_UnbalancedOuter(t *testing.T) {
	decoder := xml.NewDecoder(strings.NewReader(`
<Root>
	<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
	</ds:Signature>
<Open>
</Root>
`))

	_, _, err := sigsplit.SplitSignature(decoder)
	assert.Equal(t, io.ErrUnexpectedEOF, err)
}

func TestSplitSignature_UnbalancedInner(t *testing.T) {
	decoder := xml.NewDecoder(strings.NewReader(`
<Root>
	<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
		<Open>
		</Close>
	</ds:Signature>
</Root>
`))

	_, _, err := sigsplit.SplitSignature(decoder)
	assert.Equal(t, io.ErrUnexpectedEOF, err)
}

func TestSplitSignature_RawTokenError(t *testing.T) {
	_, _, err := sigsplit.SplitSignature(&errRawTokener{})
	assert.Equal(t, errDummy, err)
}

var errDummy = errors.New("dummy error")

type errRawTokener struct{}

func (e *errRawTokener) RawToken() (xml.Token, error) {
	return nil, errDummy
}
