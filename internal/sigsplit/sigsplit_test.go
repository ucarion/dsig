package sigsplit_test

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ucarion/dsig/internal/sigsplit"
)

func TestSplitSignature(t *testing.T) {
	s := `<Root>
<xxx:Signature xmlns:xxx="http://www.w3.org/2000/09/xmldsig#">
<DropMe />
<xxx:SignedInfo>
<IncludeMe />
</xxx:SignedInfo>
</xxx:Signature>
<IncludeMeToo />
<NestedSignature>
<xxx:Signature xmlns:xxx="http://www.w3.org/2000/09/xmldsig#">
<DropMe />
<xxx:SignedInfo>
<IncludeMe />
</xxx:SignedInfo>
</xxx:Signature>
</NestedSignature>
</Root>`

	expectedOuter := `<Root>

<IncludeMeToo></IncludeMeToo>
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
<IncludeMe></IncludeMe>
</xxx:SignedInfo>`

	decoder := xml.NewDecoder(strings.NewReader(s))
	outer, inner, err := sigsplit.SplitSignature(decoder)
	assert.NoError(t, err)
	assert.Equal(t, expectedOuter, string(outer))
	assert.Equal(t, expectedInner, string(inner))
}
