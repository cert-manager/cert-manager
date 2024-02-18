package pki

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMustKeepOrderInRawDerBytes(t *testing.T) {
	subject := "CN=foo-long.com,OU=FooLong,OU=Barq,OU=Baz,OU=Dept.,O=Corp.,C=US"
	rdnSeq, err := UnmarshalSubjectStringToRDNSequence(subject)
	if err != nil {
		t.Fatal(err)
	}

	expectedRdnSeq :=
		pkix.RDNSequence{
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.Country, Value: "US"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.Organization, Value: "Corp."},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.OrganizationalUnit, Value: "Dept."},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.OrganizationalUnit, Value: "Baz"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.OrganizationalUnit, Value: "Barq"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.OrganizationalUnit, Value: "FooLong"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.CommonName, Value: "foo-long.com"},
			},
		}

	assert.Equal(t, expectedRdnSeq, rdnSeq)
	assert.Equal(t, subject, rdnSeq.String())
}

func TestRoundTripRDNSequence(t *testing.T) {
	rdnSequences := []pkix.RDNSequence{
		{
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.Organization, Value: "Corp."},
				{Type: OIDConstants.OrganizationalUnit, Value: "FooLong"},
			},
		},
		{
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.CommonName, Value: "foo-lon❤️\\g.com    "},
				{Type: OIDConstants.OrganizationalUnit, Value: "Foo===Long"},
				{Type: OIDConstants.OrganizationalUnit, Value: "Ba  rq"},
				{Type: OIDConstants.OrganizationalUnit, Value: "Baz"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.Organization, Value: "C; orp."},
				{Type: OIDConstants.Country, Value: "US"},
			},
		},
		{
			[]pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 6}, Value: "fo\x00o-long.com"},
			},
		},
	}

	for _, rdnSeq := range rdnSequences {
		subjectString := rdnSeq.String()

		newRDNSeq, err := UnmarshalSubjectStringToRDNSequence(subjectString)
		if err != nil {
			t.Fatal(err)
		}

		ans1Seq1, err := asn1.Marshal(rdnSeq)
		if err != nil {
			t.Fatal(err)
		}

		ans1Seq2, err := asn1.Marshal(newRDNSeq)
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, ans1Seq1, ans1Seq2)
	}
}

func FuzzRoundTripRDNSequence(f *testing.F) {
	f.Add("CN=foo-long.com,OU=FooLong,OU=Barq,OU=Baz,OU=Dept.,O=Corp.,C=US")
	f.Add("CN=foo-lon❤️\\,g.com,OU=Foo===Long,OU=Ba # rq,OU=Baz,O=C\\; orp.,C=US")
	f.Add("CN=fo\x00o-long.com,OU=\x04FooLong")

	f.Fuzz(func(t *testing.T, subjectString string) {
		t.Parallel()
		rdnSeq, err := UnmarshalSubjectStringToRDNSequence(subjectString)
		if err != nil || subjectString != rdnSeq.String() {
			t.Skip()
		}

		newRDNSeq, err := UnmarshalSubjectStringToRDNSequence(rdnSeq.String())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, rdnSeq, newRDNSeq)
	})
}

func TestRoundTripLiteralSubject(t *testing.T) {
	rdnSequences := []string{
		"CN=foo-long.com,OU=FooLong,OU=Barq,OU=Baz,OU=Dept.,O=Corp.,C=US",
		"CN=foo-lon❤️\\,g.com,OU=Foo===Long,OU=Ba # rq,OU=Baz,O=C\\; orp.,C=US",
		"CN=fo\x00o-long.com,OU=\x04FooLong",
	}

	for _, subjectString := range rdnSequences {
		t.Logf("Testing subject: %s", subjectString)

		newRDNSeq, err := UnmarshalSubjectStringToRDNSequence(subjectString)
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, subjectString, newRDNSeq.String())
	}
}

func FuzzASN1Contains(f *testing.F) {
	f.Add([]byte{0, 3, 2, 1, 1})
	f.Add([]byte{19, 2, 48, 38})

	f.Fuzz(func(t *testing.T, data []byte) {
		t.Parallel()
		newRDNSeq, err := UnmarshalSubjectStringToRDNSequence("CN=#" + hex.EncodeToString(data))
		if err != nil {
			t.Skip()
		}

		encoded, err := asn1.Marshal(newRDNSeq)
		if err != nil {
			t.Fatal(err)
		}

		t.Log("Original:", data)
		t.Log("RDNS:", fmt.Sprintf("%+v", newRDNSeq))
		assert.True(t, bytes.Contains(encoded, data))
	})
}
