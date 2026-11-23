package dns

import "testing"

func mustDenialTestRR(t *testing.T, s string) RR {
	t.Helper()
	rr, err := NewRR(s)
	if err != nil {
		t.Fatalf("NewRR(%q): %v", s, err)
	}
	return rr
}

func TestLocalDenialProofNSEC3Combination(t *testing.T) {
	records := func(flags string) []RR {
		return []RR{
			mustDenialTestRR(t, "sk4e8fj94u78smusb40o1n0oltbblu2r.nl. IN NSEC3 1 "+flags+" 5 F10E9F7EA83FC8F3 SK4F38CQ0ATIEI8MH3RGD0P5I4II6QAN NS SOA TXT RRSIG DNSKEY NSEC3PARAM"),
			mustDenialTestRR(t, "39p91242oslggest5e6a7cci4iaeqvnk.nl. IN NSEC3 1 "+flags+" 5 F10E9F7EA83FC8F3 39P99DCGG0MDLARTCRMCF6OFLLUL7PR6 NS DS RRSIG"),
			mustDenialTestRR(t, "t98kg1p1cjtdoc4ksb7g57jc9vulltcd.nl. IN NSEC3 1 "+flags+" 5 F10E9F7EA83FC8F3 T98MULSKU3E499AGCTTRJK6H0L3E5T92 NS DS RRSIG"),
		}
	}

	if err := VerifyNameError(records("0"), "snasajsksasasa.nl.", TypeA); err != nil {
		t.Fatalf("VerifyNameError rejected a valid NSEC3 proof: %v", err)
	}
	if status, err := ClassifyDenial(records("0"), "snasajsksasasa.nl.", TypeA); err != nil || status != DenialNXDomain {
		t.Fatalf("ClassifyDenial = %v, %v; want NXDOMAIN", status, err)
	}
	if err := VerifyNameError(records("1"), "snasajsksasasa.nl.", TypeA); err == nil {
		t.Fatal("VerifyNameError accepted an Opt-Out cover as proof that the name does not exist")
	}
	if status, err := ClassifyDenial(records("1"), "snasajsksasasa.nl.", TypeA); err != nil || status != DenialInsecureDelegation {
		t.Fatalf("ClassifyDenial = %v, %v; want insecure delegation", status, err)
	}

	bad := records("0")
	bad[0] = mustDenialTestRR(t, "sk4e8fj94u78smusb40o1n0oltbblu2r.com. IN NSEC3 1 0 5 F10E9F7EA83FC8F3 SK4F38CQ0ATIEI8MH3RGD0P5I4II6QAN NS SOA TXT RRSIG DNSKEY NSEC3PARAM")
	if err := VerifyNameError(bad, "snasajsksasasa.nl.", TypeA); err == nil {
		t.Fatal("VerifyNameError accepted records from different zones")
	}
}

func TestLocalDenialProofNSEC3NODATA(t *testing.T) {
	rr := mustDenialTestRR(t, "CK0POJMG874LJREF7EFN8430QVIT8BSM.com. 86400 IN NSEC3 1 1 0 - CK0Q1GIN43N1ARRC9OSM6QPQR81H5M9A NS SOA RRSIG DNSKEY NSEC3PARAM")
	records := []RR{rr}

	if err := VerifyNODATA(records, "com.", TypeA); err != nil {
		t.Fatalf("VerifyNODATA rejected a valid exact-owner NODATA proof: %v", err)
	}
	if status, err := ClassifyDenial(records, "com.", TypeA); err != nil || status != DenialNoData {
		t.Fatalf("ClassifyDenial = %v, %v; want NODATA", status, err)
	}
	if err := VerifyNODATA(records, "com.", TypeNS); err == nil {
		t.Fatal("VerifyNODATA accepted a bitmap containing the queried type")
	}
	if err := VerifyNoData([]RR{rr}, "com.", TypeA); err != nil {
		t.Fatalf("VerifyNoData rejected a valid proof: %v", err)
	}

	wildcard := []RR{
		mustDenialTestRR(t, "k8udemvp1j2f7eg6jebps17vp3n8i58h.example. 3600 IN NSEC3 1 1 12 AABBCCDD KOHAR7MBB8DC2CE8A9QVL8HON4K53UHI"),
		mustDenialTestRR(t, "q04jkcevqvmu85r014c7dkba38o0ji5r.example. 3600 IN NSEC3 1 1 12 AABBCCDD R53BQ7CC2UVMUBFU5OCMM6PERS9TK9EN A RRSIG"),
		mustDenialTestRR(t, "r53bq7cc2uvmubfu5ocmm6pers9tk9en.example. 3600 IN NSEC3 1 1 12 AABBCCDD T644EBQK9BIBCNA874GIVR6JOJ62MLHV"),
	}
	if err := VerifyNODATA(wildcard, "a.z.w.example.", TypeMX); err != nil {
		t.Fatalf("VerifyNODATA rejected a wildcard NODATA proof: %v", err)
	}
	if status, err := ClassifyDenial(wildcard, "a.z.w.example.", TypeMX); err != nil || status != DenialNoData {
		t.Fatalf("ClassifyDenial = %v, %v; want wildcard NODATA", status, err)
	}
}

func TestLocalDenialProofNSECNameError(t *testing.T) {
	records := []RR{
		mustDenialTestRR(t, "example.com. 3600 IN NSEC a.example.com. SOA NS NSEC RRSIG"),
		mustDenialTestRR(t, "a.example.com. 3600 IN NSEC z.example.com. A NSEC RRSIG"),
	}
	if err := VerifyNameError(records, "b.example.com.", TypeA); err != nil {
		t.Fatalf("VerifyNameError rejected a valid NSEC proof: %v", err)
	}
	if err := VerifyNODATA(records, "a.example.com.", TypeMX); err != nil {
		t.Fatalf("VerifyNODATA rejected a valid NSEC proof: %v", err)
	}
	if err := VerifyNODATA(records, "a.example.com.", TypeA); err == nil {
		t.Fatal("VerifyNODATA accepted a bitmap containing the queried type")
	}
}

func TestLocalDenialProofNSEC3ExactOwner(t *testing.T) {
	rr := mustDenialTestRR(t, "CK0POJMG874LJREF7EFN8430QVIT8BSM.com. 86400 IN NSEC3 1 0 0 - CK0Q1GIN43N1ARRC9OSM6QPQR81H5M9A NS SOA RRSIG DNSKEY NSEC3PARAM").(*NSEC3)
	if !rr.Match("com.") {
		t.Fatal("NSEC3 does not match its owner")
	}
	if rr.Cover("com.") {
		t.Fatal("NSEC3 Cover reports the exact owner as covered")
	}
	if !rr.HasType(TypeSOA) || rr.OptOut() {
		t.Fatal("NSEC3 bitmap or flag accessors are inconsistent")
	}
}

func TestLocalDenialProofNSEC3Delegation(t *testing.T) {
	records := []RR{
		mustDenialTestRR(t, "35mthgpgcu1qg68fab165klnsnk3dpvl.example. 3600 IN NSEC3 1 1 12 AABBCCDD B4UM86EGHHDS6NEA196SMVMLO4ORS995 NS DS RRSIG"),
		mustDenialTestRR(t, "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 3600 IN NSEC3 1 1 12 AABBCCDD 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR MX DNSKEY NS SOA NSEC3PARAM RRSIG"),
	}
	if err := VerifyDelegation(records, "c.example.", nil); err != nil {
		t.Fatalf("VerifyDelegation rejected a valid Opt-Out delegation: %v", err)
	}
	noOptOut := records[0].(*NSEC3).copy().(*NSEC3)
	noOptOut.Flags = 0
	if err := VerifyDelegation([]RR{noOptOut, records[1]}, "c.example.", nil); err == nil {
		t.Fatal("VerifyDelegation accepted an Opt-Out proof without the flag")
	}
}

func TestLocalDenialProofNSEC3RRsetSemantics(t *testing.T) {
	rr := mustDenialTestRR(t, "CK0POJMG874LJREF7EFN8430QVIT8BSM.com. 86400 IN NSEC3 1 0 0 - CK0Q1GIN43N1ARRC9OSM6QPQR81H5M9A NS SOA RRSIG DNSKEY NSEC3PARAM")
	if err := verifyDenialRRsetSemantics(TypeNSEC3, []RR{rr}, "com."); err != nil {
		t.Fatalf("rejected valid NSEC3 RRset: %v", err)
	}
	bad := rr.(*NSEC3).copy().(*NSEC3)
	bad.Flags = 2
	if err := verifyDenialRRsetSemantics(TypeNSEC3, []RR{bad}, "com."); err != ErrSig {
		t.Fatalf("invalid NSEC3 flags: got %v, want %v", err, ErrSig)
	}
	if err := verifyDenialRRsetSemantics(TypeNSEC3, []RR{rr}, "example."); err != ErrRRset {
		t.Fatalf("invalid NSEC3 signer zone: got %v, want %v", err, ErrRRset)
	}
}
