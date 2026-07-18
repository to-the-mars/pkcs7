package pkcs7

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"testing"
	"time"
)

var oidSignatureTimeStampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

func TestCertificateSetCanonicalizationAcrossChainPermutations(t *testing.T) {
	root, intermediate, leaf := newCanonicalizationTestChain(t)
	chain := []*x509.Certificate{leaf.Certificate, intermediate.Certificate, root.Certificate}
	permutations := certificatePermutations(chain)
	content := []byte("canonical certificate set")
	timestampToken := []byte{0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}
	roots := x509.NewCertPool()
	roots.AddCert(root.Certificate)

	var canonicalSet []byte
	wantSignedData := make(map[bool][]byte)
	for permutationIndex, permutation := range permutations {
		permutation := permutation
		t.Run(fmt.Sprintf("permutation-%d", permutationIndex+1), func(t *testing.T) {
			beforeOrder := append([]*x509.Certificate(nil), permutation...)
			beforeDER := cloneCertificateDER(permutation)

			encodedSet, err := marshalCertificates(permutation)
			if err != nil {
				t.Fatal(err)
			}
			assertCanonicalCertificateSet(t, encodedSet.Raw)
			if canonicalSet == nil {
				canonicalSet = append([]byte(nil), encodedSet.Raw...)
			} else if !bytes.Equal(encodedSet.Raw, canonicalSet) {
				t.Fatalf("certificate set differs by input permutation\n got: %x\nwant: %x", encodedSet.Raw, canonicalSet)
			}
			assertCertificateInputUnchanged(t, permutation, beforeOrder, beforeDER)

			for _, detached := range []bool{false, true} {
				detached := detached
				t.Run(fmt.Sprintf("detached-%t", detached), func(t *testing.T) {
					signedData, err := NewSignedData(content)
					if err != nil {
						t.Fatal(err)
					}
					if err := signedData.AddSignerChain(
						leaf.Certificate,
						*leaf.PrivateKey,
						[]*x509.Certificate{intermediate.Certificate, root.Certificate},
						SignerInfoConfig{
							OmitSigningTime: true,
							ExtraUnsignedAttributes: []Attribute{{
								Type:  oidSignatureTimeStampToken,
								Value: asn1.RawValue{FullBytes: timestampToken},
							}},
						},
					); err != nil {
						t.Fatal(err)
					}
					signedData.certs = permutation
					if detached {
						signedData.Detach()
					}
					der, err := signedData.Finish()
					if err != nil {
						t.Fatal(err)
					}
					if want := wantSignedData[detached]; want == nil {
						wantSignedData[detached] = append([]byte(nil), der...)
					} else if !bytes.Equal(der, want) {
						t.Fatal("signed data differs by certificate input permutation")
					}
					assertCertificateInputUnchanged(t, permutation, beforeOrder, beforeDER)

					parsed, err := Parse(der)
					if err != nil {
						t.Fatal(err)
					}
					if detached {
						parsed.Content = content
					}
					if err := parsed.VerifyWithChainAtTime(roots, time.Now()); err != nil {
						t.Fatalf("verify: %v", err)
					}
					assertTimestampTokenUnchanged(t, parsed, timestampToken)
				})
			}
		})
	}
}

func TestDegenerateCertificateCanonicalizesChainPermutations(t *testing.T) {
	root, intermediate, leaf := newCanonicalizationTestChain(t)
	permutations := certificatePermutations([]*x509.Certificate{
		leaf.Certificate,
		intermediate.Certificate,
		root.Certificate,
	})

	var canonical []byte
	for permutationIndex, permutation := range permutations {
		input := concatenateCertificateDER(permutation)
		before := append([]byte(nil), input...)
		der, err := DegenerateCertificate(input)
		if err != nil {
			t.Fatalf("permutation %d: %v", permutationIndex+1, err)
		}
		if !bytes.Equal(input, before) {
			t.Fatalf("permutation %d: input bytes were mutated", permutationIndex+1)
		}
		if canonical == nil {
			canonical = append([]byte(nil), der...)
		} else if !bytes.Equal(der, canonical) {
			t.Fatalf("permutation %d: degenerate SignedData differs by input order", permutationIndex+1)
		}
		parsed, err := Parse(der)
		if err != nil {
			t.Fatalf("permutation %d parse: %v", permutationIndex+1, err)
		}
		if len(parsed.Certificates) != 3 {
			t.Fatalf("permutation %d: parsed %d certificates, want 3", permutationIndex+1, len(parsed.Certificates))
		}
	}
}

func TestDegenerateCertificateRejectsInvalidCertificateDER(t *testing.T) {
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string][]byte{
		"trailing data":             append(append([]byte(nil), cert.Certificate.Raw...), 0x00),
		"truncated certificate":     append([]byte(nil), cert.Certificate.Raw[:len(cert.Certificate.Raw)-1]...),
		"invalid choice":            {0x05, 0x00},
		"malformed choice contents": {0xa0, 0x01, 0x00},
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := DegenerateCertificate(input); err == nil {
				t.Fatal("DegenerateCertificate returned nil error")
			}
		})
	}
}

func TestDegenerateCertificatePreservesSingleCertificateEncoding(t *testing.T) {
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	want := legacyDegenerateCertificate(t, cert.Certificate.Raw)
	got, err := DegenerateCertificate(cert.Certificate.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("single-certificate encoding changed")
	}
}

func newCanonicalizationTestChain(t *testing.T) (root, intermediate, leaf *certKeyPair) {
	t.Helper()
	var err error
	root, err = createTestCertificateByIssuer("Canonical Root", nil, x509.SHA256WithRSA, true)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err = createTestCertificateByIssuer("Canonical Intermediate", root, x509.ECDSAWithSHA256, true)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = createTestCertificateByIssuer("Canonical Leaf", intermediate, x509.PureEd25519, false)
	if err != nil {
		t.Fatal(err)
	}
	return root, intermediate, leaf
}

func certificatePermutations(certs []*x509.Certificate) [][]*x509.Certificate {
	return [][]*x509.Certificate{
		{certs[0], certs[1], certs[2]},
		{certs[0], certs[2], certs[1]},
		{certs[1], certs[0], certs[2]},
		{certs[1], certs[2], certs[0]},
		{certs[2], certs[0], certs[1]},
		{certs[2], certs[1], certs[0]},
	}
}

func cloneCertificateDER(certs []*x509.Certificate) [][]byte {
	clones := make([][]byte, len(certs))
	for i, cert := range certs {
		clones[i] = append([]byte(nil), cert.Raw...)
	}
	return clones
}

func assertCertificateInputUnchanged(t *testing.T, got, wantOrder []*x509.Certificate, wantDER [][]byte) {
	t.Helper()
	for i := range wantOrder {
		if got[i] != wantOrder[i] {
			t.Fatalf("certificate order mutated at index %d", i)
		}
		if !bytes.Equal(got[i].Raw, wantDER[i]) {
			t.Fatalf("certificate DER mutated at index %d", i)
		}
	}
}

func concatenateCertificateDER(certs []*x509.Certificate) []byte {
	var der []byte
	for _, cert := range certs {
		der = append(der, cert.Raw...)
	}
	return der
}

func assertCanonicalCertificateSet(t *testing.T, der []byte) {
	t.Helper()
	var set asn1.RawValue
	rest, err := asn1.Unmarshal(der, &set)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 {
		t.Fatalf("certificate set has trailing DER: %x", rest)
	}
	if set.Class != 2 || set.Tag != 0 || !set.IsCompound {
		t.Fatalf("unexpected certificate set wrapper: class %d tag %d compound %t", set.Class, set.Tag, set.IsCompound)
	}
	contents := set.Bytes
	var previous []byte
	for len(contents) > 0 {
		var choice asn1.RawValue
		contents, err = asn1.Unmarshal(contents, &choice)
		if err != nil {
			t.Fatal(err)
		}
		if previous != nil && bytes.Compare(previous, choice.FullBytes) > 0 {
			t.Fatalf("certificate set is not in canonical DER order: %x before %x", previous, choice.FullBytes)
		}
		previous = choice.FullBytes
	}
}

func assertTimestampTokenUnchanged(t *testing.T, parsed *PKCS7, want []byte) {
	t.Helper()
	if len(parsed.Signers) != 1 {
		t.Fatalf("got %d signers, want 1", len(parsed.Signers))
	}
	count := 0
	for _, attr := range parsed.Signers[0].UnauthenticatedAttributes {
		if !attr.Type.Equal(oidSignatureTimeStampToken) {
			continue
		}
		count++
		var token asn1.RawValue
		rest, err := asn1.Unmarshal(attr.Value.Bytes, &token)
		if err != nil {
			t.Fatal(err)
		}
		if len(rest) != 0 {
			t.Fatalf("timestamp token has trailing DER: %x", rest)
		}
		if !bytes.Equal(token.FullBytes, want) {
			t.Fatalf("timestamp token changed: got %x, want %x", token.FullBytes, want)
		}
	}
	if count != 1 {
		t.Fatalf("got %d signature timestamp attributes, want 1", count)
	}
}

func legacyDegenerateCertificate(t *testing.T, cert []byte) []byte {
	t.Helper()
	wrapped, err := asn1.Marshal(asn1.RawValue{Bytes: cert, Class: 2, Tag: 0, IsCompound: true})
	if err != nil {
		t.Fatal(err)
	}
	inner, err := asn1.Marshal(signedData{
		Version:      1,
		ContentInfo:  contentInfo{ContentType: OIDData},
		Certificates: rawCertificates{Raw: wrapped},
		CRLs:         []pkix.CertificateList{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return mustMarshalASN1(t, contentInfo{
		ContentType: OIDSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: inner, IsCompound: true},
	})
}

func mustMarshalASN1(t *testing.T, value interface{}) []byte {
	t.Helper()
	der, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
