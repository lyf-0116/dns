package dns

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"
)

// HashName hashes a string (label) according to RFC 5155. It returns the hashed string in uppercase.
func HashName(label string, ha uint8, iter uint16, salt string) string {
	if ha != SHA1 {
		return ""
	}

	wireSalt := make([]byte, hex.DecodedLen(len(salt)))
	n, err := packStringHex(salt, wireSalt, 0)
	if err != nil {
		return ""
	}
	wireSalt = wireSalt[:n]

	name := make([]byte, 255)
	off, err := PackDomainName(strings.ToLower(label), name, 0, nil, false)
	if err != nil {
		return ""
	}
	name = name[:off]

	s := sha1.New()
	// k = 0
	s.Write(name)
	s.Write(wireSalt)
	nsec3 := s.Sum(nil)

	// k > 0
	for k := uint16(0); k < iter; k++ {
		s.Reset()
		s.Write(nsec3)
		s.Write(wireSalt)
		nsec3 = s.Sum(nsec3[:0])
	}

	return toBase32(nsec3)
}

// OptOut reports whether the NSEC3 record has the Opt-Out flag set (RFC 5155,
// Section 7.1).
func (rr *NSEC3) OptOut() bool {
	return rr != nil && rr.Flags&0x01 != 0
}

// HasType reports whether the NSEC3 type bitmap contains t.
func (rr *NSEC3) HasType(t uint16) bool {
	return rr != nil && typeInBitmap(rr.TypeBitMap, t)
}

// HasType reports whether the NSEC type bitmap contains t.
func (rr *NSEC) HasType(t uint16) bool {
	return rr != nil && typeInBitmap(rr.TypeBitMap, t)
}

func typeInBitmap(bitmap []uint16, t uint16) bool {
	for _, v := range bitmap {
		if v == t {
			return true
		}
	}
	return false
}

// Denialer is implemented by NSEC and NSEC3 records. Cover reports whether a
// name falls in the record's authenticated interval; Match reports whether the
// record's owner is the name.
type Denialer interface {
	Cover(name string) bool
	Match(name string) bool
}

// Cover returns true if a name is strictly covered by the NSEC3 record.
func (rr *NSEC3) Cover(name string) bool {
	if rr.Flags&^uint8(0x01) != 0 {
		return false
	}
	ownerHash, _, ok := splitNSEC3Owner(rr.Hdr.Name)
	if !ok || rr.NextDomain == "" {
		return false
	}
	nameHash := HashName(name, rr.Hash, rr.Iterations, rr.Salt)
	if nameHash == "" {
		return false
	}
	_, ownerZone, _ := splitNSEC3Owner(rr.Hdr.Name)
	if !IsSubDomain(ownerZone, CanonicalName(name)) {
		return false
	}

	nextHash := strings.ToUpper(strings.TrimSuffix(rr.NextDomain, "."))

	if ownerHash == nextHash {
		return nameHash != ownerHash
	}
	if ownerHash < nextHash {
		return nameHash > ownerHash && nameHash < nextHash
	}
	return nameHash > ownerHash || nameHash < nextHash
}

// Match returns true if a name matches the NSEC3 record
func (rr *NSEC3) Match(name string) bool {
	if rr.Flags&^uint8(0x01) != 0 {
		return false
	}
	ownerHash, ownerZone, ok := splitNSEC3Owner(rr.Hdr.Name)
	if !ok {
		return false
	}
	nameHash := HashName(name, rr.Hash, rr.Iterations, rr.Salt)
	if nameHash == "" {
		return false
	}
	if !IsSubDomain(ownerZone, CanonicalName(name)) {
		return false
	}
	return ownerHash == nameHash
}

// splitNSEC3Owner splits an NSEC3 owner name into its hashed owner label and
// zone. It reports false when the owner does not carry a zone suffix.
func splitNSEC3Owner(owner string) (hash, zone string, ok bool) {
	owner = CanonicalName(owner)
	labels := SplitDomainName(owner)
	if len(labels) == 0 {
		return "", "", false
	}
	if !validNSEC3Hash(labels[0]) {
		return "", "", false
	}
	if len(labels) == 1 {
		return strings.ToUpper(labels[0]), ".", true
	}
	return strings.ToUpper(labels[0]), strings.Join(labels[1:], ".") + ".", true
}

func validNSEC3Hash(hash string) bool {
	if len(hash) != 32 {
		return false
	}
	for i := 0; i < len(hash); i++ {
		c := hash[i]
		if (c < '0' || c > '9') && (c < 'A' || c > 'V') && (c < 'a' || c > 'v') {
			return false
		}
	}
	return true
}

// Cover returns true if a name is strictly covered by the NSEC record. Names
// are compared using the canonical DNS name order from RFC 4034, Section 6.1.
func (rr *NSEC) Cover(name string) bool {
	if rr.NextDomain == "" {
		return false
	}
	return nsecCovers(rr.Hdr.Name, rr.NextDomain, name)
}

// Match returns true if name is the owner name of the NSEC record.
func (rr *NSEC) Match(name string) bool {
	return equal(CanonicalName(rr.Hdr.Name), CanonicalName(name))
}

func nsecCovers(owner, next, name string) bool {
	owner = CanonicalName(owner)
	next = CanonicalName(next)
	name = CanonicalName(name)

	cmpON := canonicalNameCompare(owner, next)
	cmpNameOwner := canonicalNameCompare(name, owner)
	cmpNameNext := canonicalNameCompare(name, next)
	if cmpON == 0 {
		return cmpNameOwner != 0
	}
	if cmpON < 0 {
		return cmpNameOwner > 0 && cmpNameNext < 0
	}
	return cmpNameOwner > 0 || cmpNameNext < 0
}

// canonicalNameCompare orders names as defined by RFC 4034, Section 6.1.
func canonicalNameCompare(a, b string) int {
	a = CanonicalName(a)
	b = CanonicalName(b)
	if a == b {
		return 0
	}
	aLabels := SplitDomainName(a)
	bLabels := SplitDomainName(b)
	for i := 1; i <= len(aLabels) && i <= len(bLabels); i++ {
		al := aLabels[len(aLabels)-i]
		bl := bLabels[len(bLabels)-i]
		if al < bl {
			return -1
		}
		if al > bl {
			return 1
		}
	}
	switch {
	case len(aLabels) < len(bLabels):
		return -1
	case len(aLabels) > len(bLabels):
		return 1
	}
	return 0
}

// DenialStatus is the result of classifying an authenticated denial of
// existence proof.
type DenialStatus uint8

const (
	// DenialInvalid means no valid denial proof was found.
	DenialInvalid DenialStatus = iota
	// DenialNXDomain proves that the queried name does not exist.
	DenialNXDomain
	// DenialNoData proves that the queried name exists without the queried type.
	DenialNoData
	// DenialInsecureDelegation proves an Opt-Out insecure delegation; it does
	// not prove that the delegation name itself is absent.
	DenialInsecureDelegation
)

const (
	// DenialNameError is an alias for DenialNXDomain.
	DenialNameError = DenialNXDomain
	// DenialNODATA is an alias for DenialNoData.
	DenialNODATA = DenialNoData
	// DenialInsecure is an alias for DenialInsecureDelegation.
	DenialInsecure = DenialInsecureDelegation

	// NSEC3_NXDOMAIN and NSEC3_NODATA are retained for callers that used the
	// historical NSEC3 proof result constants.
	NSEC3_NXDOMAIN = int(DenialNXDomain)
	NSEC3_NODATA   = int(DenialNoData)
)

type denialKind uint8

const (
	denialKindAny denialKind = iota
	denialKindNSEC
	denialKindNSEC3
)

// VerifyNameError verifies an authenticated NXDOMAIN proof. The records may be
// NSEC or NSEC3 records, but a proof must not mix the two.
//
// The accepted forms are:
//
//	VerifyNameError(records, qname, qtype)
//	VerifyNameError(msg, records)
//	VerifyNameError(msg)
//
// The first form is compatible with the historical API. In the message forms
// the question supplies qname and qtype; when records are omitted, denial
// records are collected from the message.
func VerifyNameError(args ...any) error {
	return verifyNameErrorArgs(denialKindAny, args)
}

// VerifyNameErrorNSEC verifies an NXDOMAIN proof using NSEC records only.
func VerifyNameErrorNSEC(args ...any) error {
	return verifyNameErrorArgs(denialKindNSEC, args)
}

// VerifyNameErrorNSEC3 verifies an NXDOMAIN proof using NSEC3 records only.
func VerifyNameErrorNSEC3(args ...any) error {
	return verifyNameErrorArgs(denialKindNSEC3, args)
}

func verifyNameErrorArgs(kind denialKind, args []any) error {
	records, qname, qtype, err := denialArgs(args)
	if err != nil {
		return err
	}
	return verifyNameError(records, qname, qtype, kind)
}

// VerifyNoData verifies an authenticated NODATA proof. NODATA means the name
// exists but the queried type does not.
func VerifyNoData(args ...any) error {
	return verifyNoDataArgs(denialKindAny, args)
}

// VerifyNODATA is an alias for VerifyNoData.
func VerifyNODATA(args ...any) error {
	return verifyNoDataArgs(denialKindAny, args)
}

// VerifyNODATANSEC verifies a NODATA proof using NSEC records only.
func VerifyNODATANSEC(args ...any) error {
	return verifyNoDataArgs(denialKindNSEC, args)
}

// VerifyNODATANSEC3 verifies a NODATA proof using NSEC3 records only.
func VerifyNODATANSEC3(args ...any) error {
	return verifyNoDataArgs(denialKindNSEC3, args)
}

func verifyNoDataArgs(kind denialKind, args []any) error {
	records, qname, qtype, err := denialArgs(args)
	if err != nil {
		return err
	}
	return verifyNoData(records, qname, qtype, kind)
}

// VerifyDenial verifies either an NXDOMAIN or a NODATA proof.
func VerifyDenial(args ...any) error {
	records, qname, qtype, err := denialArgs(args)
	if err != nil {
		return err
	}
	if err := verifyNameError(records, qname, qtype, denialKindAny); err == nil {
		return nil
	}
	return verifyNoData(records, qname, qtype, denialKindAny)
}

// VerifyDenialProof is an alias for VerifyDenial.
func VerifyDenialProof(args ...any) error {
	return VerifyDenial(args...)
}

// Proof is an alias for VerifyDenial.
func Proof(args ...any) error {
	return VerifyDenial(args...)
}

// ClassifyDenial reports whether the supplied records prove NXDOMAIN, NODATA,
// or an insecure delegation. ErrSig is returned when no valid proof exists.
func ClassifyDenial(args ...any) (DenialStatus, error) {
	records, qname, qtype, err := denialArgs(args)
	if err != nil {
		return DenialInvalid, err
	}

	set, err := prepareDenialSet(records, denialKindAny)
	if err != nil {
		return DenialInvalid, err
	}
	switch set.kind {
	case denialKindNSEC3:
		return set.nsec3.classify(qname, qtype)
	case denialKindNSEC:
		return set.nsec.classify(qname, qtype)
	default:
		return DenialInvalid, ErrSig
	}
}

// VerifyDelegation verifies an insecure-delegation proof. With NSEC3 records,
// an exact delegation with NS and without DS/SOA is accepted, as is an Opt-Out
// cover of the next closer name.
func VerifyDelegation(args ...any) error {
	records, delegation, _, err := denialArgs(args)
	if err != nil || delegation == "" {
		return ErrSig
	}
	set, err := prepareDenialSet(records, denialKindAny)
	if err != nil {
		return err
	}
	switch set.kind {
	case denialKindNSEC3:
		return set.nsec3.verifyDelegation(delegation)
	case denialKindNSEC:
		return set.nsec.verifyDelegation(delegation)
	default:
		return ErrSig
	}
}

// VerifyDelegationNSEC verifies an insecure-delegation proof using NSEC.
func VerifyDelegationNSEC(args ...any) error {
	records, delegation, _, err := denialArgs(args)
	if err != nil {
		return err
	}
	set, err := prepareDenialSet(records, denialKindNSEC)
	if err != nil || set.kind != denialKindNSEC {
		return ErrSig
	}
	return set.nsec.verifyDelegation(delegation)
}

// VerifyDelegationNSEC3 verifies an insecure-delegation proof using NSEC3.
func VerifyDelegationNSEC3(args ...any) error {
	records, delegation, _, err := denialArgs(args)
	if err != nil {
		return err
	}
	set, err := prepareDenialSet(records, denialKindNSEC3)
	if err != nil || set.kind != denialKindNSEC3 {
		return ErrSig
	}
	return set.nsec3.verifyDelegation(delegation)
}

func denialArgs(args []any) (records []RR, qname string, qtype uint16, err error) {
	var msg *Msg
	var question *Question
	var names []string

	add := func(rr RR) {
		if rr != nil {
			records = append(records, rr)
		}
	}

	for _, arg := range args {
		switch v := arg.(type) {
		case *Msg:
			msg = v
		case *Question:
			question = v
		case Question:
			q := v
			question = &q
		case []RR:
			for _, rr := range v {
				add(rr)
			}
		case []*NSEC3:
			for _, rr := range v {
				if rr != nil {
					add(rr)
				}
			}
		case []NSEC3:
			for i := range v {
				rr := v[i]
				add(&rr)
			}
		case []*NSEC:
			for _, rr := range v {
				if rr != nil {
					add(rr)
				}
			}
		case []NSEC:
			for i := range v {
				rr := v[i]
				add(&rr)
			}
		case []*NXT:
			for _, rr := range v {
				if rr != nil {
					add(&rr.NSEC)
				}
			}
		case string:
			names = append(names, v)
		case uint16:
			qtype = v
		case int:
			if v >= 0 && v <= 0xffff {
				qtype = uint16(v)
			}
		case *DNSKEY, *RRSIG, *NSEC3PARAM:
			// Signature-bearing records do not participate in the proof
			// itself. They are deliberately ignored here.
		}
	}

	if msg != nil {
		if len(msg.Question) > 0 {
			if qname == "" {
				qname = msg.Question[0].Name
			}
			if qtype == 0 {
				qtype = msg.Question[0].Qtype
			}
		}
		if len(records) == 0 {
			for _, section := range [][]RR{msg.Answer, msg.Ns, msg.Extra} {
				for _, rr := range section {
					switch rr.(type) {
					case *NSEC, *NSEC3:
						add(rr)
					}
				}
			}
		}
	}
	if question != nil {
		if qname == "" {
			qname = question.Name
		}
		if qtype == 0 {
			qtype = question.Qtype
		}
	}
	if qname == "" && len(names) > 0 {
		qname = names[0]
	}
	if qname == "" {
		return nil, "", 0, ErrSig
	}
	return records, CanonicalName(qname), qtype, nil
}

type denialSet struct {
	kind  denialKind
	nsec  *nsecSet
	nsec3 *nsec3Set
}

func prepareDenialSet(records []RR, expected denialKind) (*denialSet, error) {
	var (
		nsecs  []*NSEC
		nsec3s []*NSEC3
	)
	for _, rr := range records {
		switch v := rr.(type) {
		case *NSEC:
			if v != nil {
				nsecs = append(nsecs, v)
			}
		case *NXT:
			if v != nil {
				nsecs = append(nsecs, &v.NSEC)
			}
		case *NSEC3:
			if v != nil {
				nsec3s = append(nsec3s, v)
			}
		}
	}

	switch {
	case len(nsecs) > 0 && len(nsec3s) > 0:
		return nil, ErrSig
	case len(nsecs) > 0:
		if expected == denialKindNSEC3 {
			return nil, ErrSig
		}
		set := &denialSet{kind: denialKindNSEC, nsec: newNSECSet(nsecs)}
		return set, nil
	case len(nsec3s) > 0:
		if expected == denialKindNSEC {
			return nil, ErrSig
		}
		set, err := newNSEC3Set(nsec3s)
		if err != nil {
			return nil, err
		}
		return &denialSet{kind: denialKindNSEC3, nsec3: set}, nil
	default:
		return nil, ErrSig
	}
}

type nsec3Record struct {
	rr        *NSEC3
	ownerHash string
	nextHash  string
}

type nsec3Set struct {
	records    []nsec3Record
	zone       string
	hash       uint8
	iterations uint16
	salt       string
}

func newNSEC3Set(nsec3s []*NSEC3) (*nsec3Set, error) {
	set := &nsec3Set{}
	haveParams := false
	for _, rr := range nsec3s {
		if rr == nil || rr.Hash != SHA1 || rr.Flags&^uint8(0x01) != 0 {
			continue
		}
		ownerHash, zone, ok := splitNSEC3Owner(rr.Hdr.Name)
		if !ok {
			continue
		}
		if !haveParams {
			set.zone = zone
			set.hash = rr.Hash
			set.iterations = rr.Iterations
			set.salt = strings.ToUpper(rr.Salt)
			haveParams = true
		} else if zone != set.zone ||
			rr.Hash != set.hash ||
			rr.Iterations != set.iterations ||
			!strings.EqualFold(rr.Salt, set.salt) {
			return nil, ErrSig
		}
		set.records = append(set.records, nsec3Record{
			rr:        rr,
			ownerHash: ownerHash,
			nextHash:  strings.ToUpper(strings.TrimSuffix(rr.NextDomain, ".")),
		})
	}
	if !haveParams || len(set.records) == 0 {
		return nil, ErrSig
	}
	return set, nil
}

func (set *nsec3Set) inZone(name string) bool {
	return IsSubDomain(set.zone, CanonicalName(name))
}

func (set *nsec3Set) matching(name string) (*nsec3Record, bool) {
	if !set.inZone(name) {
		return nil, false
	}
	h := HashName(name, set.hash, set.iterations, set.salt)
	if h == "" {
		return nil, false
	}
	for i := range set.records {
		if set.records[i].ownerHash == h {
			return &set.records[i], true
		}
	}
	return nil, false
}

func (set *nsec3Set) covering(name string) (*nsec3Record, bool) {
	if !set.inZone(name) {
		return nil, false
	}
	if _, ok := set.matching(name); ok {
		return nil, false
	}
	h := HashName(name, set.hash, set.iterations, set.salt)
	if h == "" {
		return nil, false
	}
	var found *nsec3Record
	for i := range set.records {
		entry := &set.records[i]
		if entry.nextHash == "" {
			continue
		}
		if entry.ownerHash == entry.nextHash {
			if h != entry.ownerHash {
				if found != nil {
					return nil, false
				}
				found = entry
			}
			continue
		}
		if entry.ownerHash < entry.nextHash {
			if h > entry.ownerHash && h < entry.nextHash {
				if found != nil {
					return nil, false
				}
				found = entry
			}
			continue
		}
		if h > entry.ownerHash || h < entry.nextHash {
			if found != nil {
				return nil, false
			}
			found = entry
		}
	}
	return found, found != nil
}

type nsec3ClosestEncloser struct {
	name       string
	nextCloser string
	record     *nsec3Record
}

func (set *nsec3Set) closestEncloser(qname string) (nsec3ClosestEncloser, bool) {
	qname = CanonicalName(qname)
	offsets := Split(qname)
	for i, off := range offsets {
		candidate := qname[off:]
		if record, ok := set.matching(candidate); ok {
			nextCloser := qname
			if i > 0 {
				nextCloser = qname[offsets[i-1]:]
			}
			return nsec3ClosestEncloser{
				name:       candidate,
				nextCloser: nextCloser,
				record:     record,
			}, true
		}
	}
	if record, ok := set.matching("."); ok {
		nextCloser := "."
		if len(offsets) > 0 {
			nextCloser = qname[offsets[len(offsets)-1]:]
		}
		return nsec3ClosestEncloser{name: ".", nextCloser: nextCloser, record: record}, true
	}
	return nsec3ClosestEncloser{}, false
}

func (set *nsec3Set) verifyNameError(qname string) error {
	closest, ok := set.closestEncloser(qname)
	if !ok || equal(closest.name, qname) {
		return ErrSig
	}
	cover, ok := set.covering(closest.nextCloser)
	if !ok || cover.rr.OptOut() {
		return ErrSig
	}
	if closest.name != "." {
		if _, ok := set.covering("*." + closest.name); !ok {
			return ErrSig
		}
	}
	return nil
}

func (set *nsec3Set) verifyNoData(qname string, qtype uint16) error {
	if record, ok := set.matching(qname); ok {
		return checkNoDataTypes(record.rr.TypeBitMap, qtype)
	}

	closest, ok := set.closestEncloser(qname)
	if !ok {
		return ErrSig
	}
	cover, ok := set.covering(closest.nextCloser)
	if !ok {
		return ErrSig
	}
	if qtype == TypeDS {
		if !cover.rr.OptOut() {
			return ErrSig
		}
		return nil
	}

	wildcard, ok := set.matching("*." + closest.name)
	if !ok {
		return ErrSig
	}
	return checkNoDataTypes(wildcard.rr.TypeBitMap, qtype)
}

func (set *nsec3Set) verifyDelegation(delegation string) error {
	delegation = CanonicalName(delegation)
	if record, ok := set.matching(delegation); ok {
		return checkDelegationTypes(record.rr.TypeBitMap)
	}
	closest, ok := set.closestEncloser(delegation)
	if !ok {
		return ErrSig
	}
	cover, ok := set.covering(closest.nextCloser)
	if !ok || !cover.rr.OptOut() {
		return ErrSig
	}
	return nil
}

func (set *nsec3Set) classify(qname string, qtype uint16) (DenialStatus, error) {
	if record, ok := set.matching(qname); ok {
		if err := checkNoDataTypes(record.rr.TypeBitMap, qtype); err == nil {
			if qtype == TypeDS && typeInBitmap(record.rr.TypeBitMap, TypeNS) &&
				!typeInBitmap(record.rr.TypeBitMap, TypeSOA) {
				return DenialInsecureDelegation, nil
			}
			return DenialNoData, nil
		}
		return DenialInvalid, ErrSig
	}

	closest, ok := set.closestEncloser(qname)
	if !ok || equal(closest.name, qname) {
		return DenialInvalid, ErrSig
	}
	cover, ok := set.covering(closest.nextCloser)
	if !ok {
		return DenialInvalid, ErrSig
	}
	if err := set.verifyNoData(qname, qtype); err == nil {
		if qtype == TypeDS {
			return DenialInsecureDelegation, nil
		}
		return DenialNoData, nil
	}
	if cover.rr.OptOut() {
		return DenialInsecureDelegation, nil
	}
	if closest.name != "." {
		if _, ok := set.covering("*." + closest.name); !ok {
			return DenialInvalid, ErrSig
		}
	}
	return DenialNXDomain, nil
}

type nsecSet struct {
	records []*NSEC
}

func newNSECSet(nsecs []*NSEC) *nsecSet {
	set := &nsecSet{}
	for _, rr := range nsecs {
		if rr != nil && rr.NextDomain != "" {
			set.records = append(set.records, rr)
		}
	}
	return set
}

func (set *nsecSet) matching(name string) (*NSEC, bool) {
	name = CanonicalName(name)
	for _, rr := range set.records {
		if equal(rr.Hdr.Name, name) {
			return rr, true
		}
	}
	return nil, false
}

func (set *nsecSet) covering(name string) (*NSEC, bool) {
	name = CanonicalName(name)
	if _, ok := set.matching(name); ok {
		return nil, false
	}
	for _, rr := range set.records {
		if rr.Cover(name) {
			return rr, true
		}
	}
	return nil, false
}

func (set *nsecSet) verifyNameError(qname string) error {
	cover, ok := set.covering(qname)
	if !ok {
		return ErrSig
	}
	closest := closestEncloserFromNSEC(qname, cover)
	if closest == "" {
		return ErrSig
	}
	if closest == "." {
		return nil
	}
	if _, ok := set.covering("*." + closest); !ok {
		return ErrSig
	}
	return nil
}

func (set *nsecSet) verifyNoData(qname string, qtype uint16) error {
	if rr, ok := set.matching(qname); ok {
		return checkNoDataTypes(rr.TypeBitMap, qtype)
	}

	cover, ok := set.covering(qname)
	if !ok {
		return ErrSig
	}
	if !equal(cover.NextDomain, qname) && IsSubDomain(qname, cover.NextDomain) {
		return nil
	}
	closest := closestEncloserFromNSEC(qname, cover)
	if closest == "" {
		return ErrSig
	}
	wildcard, ok := set.matching("*." + closest)
	if !ok {
		return ErrSig
	}
	return checkNoDataTypes(wildcard.TypeBitMap, qtype)
}

func (set *nsecSet) verifyDelegation(delegation string) error {
	rr, ok := set.matching(delegation)
	if !ok {
		return ErrSig
	}
	return checkDelegationTypes(rr.TypeBitMap)
}

func (set *nsecSet) classify(qname string, qtype uint16) (DenialStatus, error) {
	if rr, ok := set.matching(qname); ok {
		if err := checkNoDataTypes(rr.TypeBitMap, qtype); err == nil {
			if qtype == TypeDS && typeInBitmap(rr.TypeBitMap, TypeNS) &&
				!typeInBitmap(rr.TypeBitMap, TypeSOA) {
				return DenialInsecureDelegation, nil
			}
			return DenialNoData, nil
		}
		return DenialInvalid, ErrSig
	}
	if err := set.verifyNameError(qname); err == nil {
		return DenialNXDomain, nil
	}
	if err := set.verifyNoData(qname, qtype); err == nil {
		return DenialNoData, nil
	}
	return DenialInvalid, ErrSig
}

func checkNoDataTypes(bitmap []uint16, qtype uint16) error {
	if typeInBitmap(bitmap, qtype) || typeInBitmap(bitmap, TypeCNAME) {
		return ErrSig
	}
	if qtype == TypeDS && typeInBitmap(bitmap, TypeSOA) {
		return ErrSig
	}
	return nil
}

func checkDelegationTypes(bitmap []uint16) error {
	if !typeInBitmap(bitmap, TypeNS) {
		return ErrSig
	}
	if typeInBitmap(bitmap, TypeDS) || typeInBitmap(bitmap, TypeSOA) {
		return ErrSig
	}
	return nil
}

func closestEncloserFromNSEC(qname string, rr *NSEC) string {
	qname = CanonicalName(qname)
	qLabels := CountLabel(qname)
	common := CompareDomainName(qname, CanonicalName(rr.Hdr.Name))
	if n := CompareDomainName(qname, CanonicalName(rr.NextDomain)); n > common {
		common = n
	}
	if common >= qLabels {
		common = qLabels - 1
	}
	if common <= 0 {
		return "."
	}
	off, _ := PrevLabel(qname, common)
	return qname[off:]
}

func verifyNameError(records []RR, qname string, qtype uint16, kind denialKind) error {
	set, err := prepareDenialSet(records, kind)
	if err != nil {
		return err
	}
	switch set.kind {
	case denialKindNSEC3:
		return set.nsec3.verifyNameError(qname)
	case denialKindNSEC:
		return set.nsec.verifyNameError(qname)
	default:
		return ErrSig
	}
}

func verifyNoData(records []RR, qname string, qtype uint16, kind denialKind) error {
	set, err := prepareDenialSet(records, kind)
	if err != nil {
		return err
	}
	switch set.kind {
	case denialKindNSEC3:
		return set.nsec3.verifyNoData(qname, qtype)
	case denialKindNSEC:
		return set.nsec.verifyNoData(qname, qtype)
	default:
		return ErrSig
	}
}

// verifyDenialRRsetSemantics applies the denial-specific checks that can be
// made while an RRSIG is being verified. The full three-record proof needs the
// question and the other NSEC/NSEC3 records, so it is evaluated by
// VerifyNameError, VerifyNoData, and ClassifyDenial.
func verifyDenialRRsetSemantics(covered uint16, rrset []RR, signer string) error {
	signer = CanonicalName(signer)
	switch covered {
	case TypeNSEC:
		for _, rr := range rrset {
			nsec, ok := rr.(*NSEC)
			if !ok {
				return ErrRRset
			}
			if nsec.NextDomain == "" || !IsSubDomain(signer, nsec.Hdr.Name) {
				return ErrSig
			}
		}
	case TypeNSEC3:
		var (
			haveParams bool
			hash       uint8
			iterations uint16
			salt       string
		)
		for _, rr := range rrset {
			nsec3, ok := rr.(*NSEC3)
			if !ok {
				return ErrRRset
			}
			_, zone, ok := splitNSEC3Owner(nsec3.Hdr.Name)
			if !ok || !equal(zone, signer) {
				return ErrRRset
			}
			if nsec3.Hash != SHA1 || nsec3.Flags&^uint8(0x01) != 0 {
				return ErrSig
			}
			if !haveParams {
				hash, iterations, salt = nsec3.Hash, nsec3.Iterations, nsec3.Salt
				haveParams = true
				continue
			}
			if nsec3.Hash != hash || nsec3.Iterations != iterations ||
				!strings.EqualFold(nsec3.Salt, salt) {
				return ErrSig
			}
		}
	}
	return nil
}

// VerifyNameError verifies the NXDOMAIN proof carried by m.
func (m *Msg) VerifyNameError(args ...any) error {
	if m == nil {
		return ErrSig
	}
	return VerifyNameError(append([]any{m}, args...)...)
}

// VerifyNoData verifies the NODATA proof carried by m.
func (m *Msg) VerifyNoData(args ...any) error {
	if m == nil {
		return ErrSig
	}
	return VerifyNoData(append([]any{m}, args...)...)
}

// VerifyNODATA is an alias for Msg.VerifyNoData.
func (m *Msg) VerifyNODATA(args ...any) error {
	return m.VerifyNoData(args...)
}

// NsecVerify verifies an NXDOMAIN proof carried in m using NSEC records.
func (m *Msg) NsecVerify(q Question) error {
	if m == nil {
		return ErrSig
	}
	return VerifyNameErrorNSEC(m, q)
}

// Nsec3Verify classifies the denial proof carried in m. The returned value is
// NSEC3_NXDOMAIN or NSEC3_NODATA on success.
func (m *Msg) Nsec3Verify(q Question) (int, error) {
	if m == nil {
		return 0, ErrSig
	}
	status, err := ClassifyDenial(m, q)
	if err != nil {
		return 0, err
	}
	switch status {
	case DenialNXDomain:
		return NSEC3_NXDOMAIN, nil
	case DenialNoData:
		return NSEC3_NODATA, nil
	default:
		return 0, ErrSig
	}
}
