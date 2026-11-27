package dns

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestIsPacketConn(t *testing.T) {
	t.Run("UDP", func(t *testing.T) {
		s, addrstr, _, err := RunLocalUDPServer(":0")
		if err != nil {
			t.Fatalf("unable to run test server: %v", err)
		}
		defer s.Shutdown()
		c, err := net.Dial("udp", addrstr)
		if err != nil {
			t.Fatalf("failed to dial: %v", err)
		}
		defer c.Close()
		if !isPacketConn(c) {
			t.Error("UDP connection should be a packet conn")
		}
		if !isPacketConn(struct{ *net.UDPConn }{c.(*net.UDPConn)}) {
			t.Error("UDP connection (wrapped type) should be a packet conn")
		}
	})

	t.Run("TCP", func(t *testing.T) {
		s, addrstr, _, err := RunLocalTCPServer(":0")
		if err != nil {
			t.Fatalf("unable to run test server: %v", err)
		}
		defer s.Shutdown()
		c, err := net.Dial("tcp", addrstr)
		if err != nil {
			t.Fatalf("failed to dial: %v", err)
		}
		defer c.Close()
		if isPacketConn(c) {
			t.Error("TCP connection should not be a packet conn")
		}
		if isPacketConn(struct{ *net.TCPConn }{c.(*net.TCPConn)}) {
			t.Error("TCP connection (wrapped type) should not be a packet conn")
		}
	})

	t.Run("Unix datagram", func(t *testing.T) {
		s, addrstr, _, err := RunLocalUnixGramServer(tempFile(t, "unixgram.sock"))
		if err != nil {
			t.Fatalf("unable to run test server: %v", err)
		}
		defer s.Shutdown()
		c, err := net.Dial("unixgram", addrstr)
		if err != nil {
			t.Fatalf("failed to dial: %v", err)
		}
		defer c.Close()
		if !isPacketConn(c) {
			t.Error("Unix datagram connection should be a packet conn")
		}
		if !isPacketConn(struct{ *net.UnixConn }{c.(*net.UnixConn)}) {
			t.Error("Unix datagram connection (wrapped type) should be a packet conn")
		}
	})

	t.Run("Unix Seqpacket", func(t *testing.T) {
		shutChan, addrstr, err := RunLocalUnixSeqPacketServer(tempFile(t, "unixpacket.sock"))
		if err != nil {
			if errors.Is(err, syscall.EPROTONOSUPPORT) {
				t.Skip("unix seqpacket not supported on this OS")
			}
			t.Fatalf("unable to run test server: %v", err)
		}

		defer func() {
			shutChan <- &struct{}{}
		}()
		c, err := net.Dial("unixpacket", addrstr)
		if err != nil {
			t.Fatalf("failed to dial: %v", err)
		}
		defer c.Close()
		if !isPacketConn(c) {
			t.Error("Unix datagram connection should be a packet conn")
		}
		if !isPacketConn(struct{ *net.UnixConn }{c.(*net.UnixConn)}) {
			t.Error("Unix datagram connection (wrapped type) should be a packet conn")
		}
	})

	t.Run("Unix stream", func(t *testing.T) {
		s, addrstr, _, err := RunLocalUnixServer(tempFile(t, "unixstream.sock"))
		if err != nil {
			t.Fatalf("unable to run test server: %v", err)
		}
		defer s.Shutdown()
		c, err := net.Dial("unix", addrstr)
		if err != nil {
			t.Fatalf("failed to dial: %v", err)
		}
		defer c.Close()
		if isPacketConn(c) {
			t.Error("Unix stream connection should not be a packet conn")
		}
		if isPacketConn(struct{ *net.UnixConn }{c.(*net.UnixConn)}) {
			t.Error("Unix stream connection (wrapped type) should not be a packet conn")
		}
	})
}

func TestDialUDP(t *testing.T) {
	HandleFunc("miek.nl.", HelloServer)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

	c := new(Client)
	conn, err := c.Dial(addrstr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	if conn == nil {
		t.Fatalf("conn is nil")
	}
}

func TestClientSync(t *testing.T) {
	HandleFunc("miek.nl.", HelloServer)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

	c := new(Client)
	r, _, err := c.Exchange(m, addrstr)
	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}
	if r == nil {
		t.Fatal("response is nil")
	}
	if r.Rcode != RcodeSuccess {
		t.Errorf("failed to get an valid answer\n%v", r)
	}
	// And now with plain Exchange().
	r, err = Exchange(m, addrstr)
	if err != nil {
		t.Errorf("failed to exchange: %v", err)
	}
	if r == nil || r.Rcode != RcodeSuccess {
		t.Errorf("failed to get an valid answer\n%v", r)
	}
}

func TestClientLocalAddress(t *testing.T) {
	HandleFunc("miek.nl.", HelloServerEchoAddrPort)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

	c := new(Client)
	laddr := net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 12345, Zone: ""}
	c.Dialer = &net.Dialer{LocalAddr: &laddr}
	r, _, err := c.Exchange(m, addrstr)
	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}
	if r != nil && r.Rcode != RcodeSuccess {
		t.Errorf("failed to get an valid answer\n%v", r)
	}
	if len(r.Extra) != 1 {
		t.Fatalf("failed to get additional answers\n%v", r)
	}
	txt := r.Extra[0].(*TXT)
	if txt == nil {
		t.Errorf("invalid TXT response\n%v", txt)
	}
	if len(txt.Txt) != 1 || !strings.Contains(txt.Txt[0], ":12345") {
		t.Errorf("invalid TXT response\n%v", txt.Txt)
	}
}

func TestClientTLSSyncV4(t *testing.T) {
	HandleFunc("miek.nl.", HelloServer)
	defer HandleRemove("miek.nl.")

	cert, err := tls.X509KeyPair(CertPEMBlock, KeyPEMBlock)
	if err != nil {
		t.Fatalf("unable to build certificate: %v", err)
	}

	config := tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	s, addrstr, _, err := RunLocalTLSServer(":0", &config)
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

	c := new(Client)

	// test tcp-tls
	c.Net = "tcp-tls"
	c.TLSConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	r, _, err := c.Exchange(m, addrstr)
	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}
	if r == nil {
		t.Fatal("response is nil")
	}
	if r.Rcode != RcodeSuccess {
		t.Errorf("failed to get an valid answer\n%v", r)
	}

	// test tcp4-tls
	c.Net = "tcp4-tls"
	c.TLSConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	r, _, err = c.Exchange(m, addrstr)
	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}
	if r == nil {
		t.Fatal("response is nil")
	}
	if r.Rcode != RcodeSuccess {
		t.Errorf("failed to get an valid answer\n%v", r)
	}
}

func isNetworkTimeout(err error) bool {
	// TODO: when Go 1.14 support is dropped, do this: https://golang.org/doc/go1.15#net
	var netError net.Error
	return errors.As(err, &netError) && netError.Timeout()
}

func TestClientSyncBadID(t *testing.T) {
	HandleFunc("miek.nl.", HelloServerBadID)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

	// Test with client.Exchange, the plain Exchange function is just a wrapper, so
	// we don't need to test that separately.
	c := &Client{
		Timeout: 10 * time.Millisecond,
	}
	if _, _, err := c.Exchange(m, addrstr); err == nil || !isNetworkTimeout(err) {
		t.Errorf("query did not time out")
	}
}

func TestClientSyncBadThenGoodID(t *testing.T) {
	HandleFunc("miek.nl.", HelloServerBadThenGoodID)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

	c := new(Client)
	r, _, err := c.Exchange(m, addrstr)
	if err != nil {
		t.Errorf("failed to exchange: %v", err)
	}
	if r.Id != m.Id {
		t.Errorf("failed to get response with expected Id")
	}
}

func TestClientSyncTCPBadID(t *testing.T) {
	HandleFunc("miek.nl.", HelloServerBadID)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalTCPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

	c := &Client{
		Net: "tcp",
	}
	if _, _, err := c.Exchange(m, addrstr); err != ErrId {
		t.Errorf("did not find a bad Id")
	}
}

// helloServerBadQuestion replies with a matching ID but a question section that
// names a different domain, simulating a forged answer.
func helloServerBadQuestion(w ResponseWriter, req *Msg) {
	m := new(Msg)
	m.SetReply(req)
	m.Question[0].Name = "example.org."

	m.Extra = make([]RR, 1)
	m.Extra[0] = &TXT{Hdr: RR_Header{Name: m.Question[0].Name, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: []string{"Forged answer"}}
	w.WriteMsg(m)
}

// helloServerBadThenGoodQuestion first sends a forged reply (matching ID, wrong
// question section) followed by the legitimate reply.
func helloServerBadThenGoodQuestion(w ResponseWriter, req *Msg) {
	forged := new(Msg)
	forged.SetReply(req)
	forged.Question[0].Name = "example.org."
	forged.Extra = make([]RR, 1)
	forged.Extra[0] = &TXT{Hdr: RR_Header{Name: forged.Question[0].Name, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: []string{"Forged answer"}}
	w.WriteMsg(forged)

	good := new(Msg)
	good.SetReply(req)
	good.Extra = make([]RR, 1)
	good.Extra[0] = &TXT{Hdr: RR_Header{Name: good.Question[0].Name, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: []string{"Hello world"}}
	w.WriteMsg(good)
}

func TestClientSyncBadQuestion(t *testing.T) {
	HandleFunc("miek.nl.", helloServerBadQuestion)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

	// Over UDP a mismatched question section must be treated as a forgery: the
	// client keeps waiting rather than accepting the unrelated reply, so the
	// exchange eventually times out.
	c := &Client{
		Timeout: 10 * time.Millisecond,
	}
	if _, _, err := c.Exchange(m, addrstr); err == nil || !isNetworkTimeout(err) {
		t.Errorf("forged reply was not ignored: %v", err)
	}
}

func TestClientSyncBadThenGoodQuestion(t *testing.T) {
	HandleFunc("miek.nl.", helloServerBadThenGoodQuestion)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

	c := new(Client)
	r, _, err := c.Exchange(m, addrstr)
	if err != nil {
		t.Fatalf("failed to exchange after discarding forged reply: %v", err)
	}
	if r.Question[0].Name != m.Question[0].Name {
		t.Errorf("accepted reply with wrong question name %q", r.Question[0].Name)
	}
}

func TestClientSyncTCPBadQuestion(t *testing.T) {
	HandleFunc("miek.nl.", helloServerBadQuestion)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalTCPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

	c := &Client{Net: "tcp"}
	if _, _, err := c.Exchange(m, addrstr); err != ErrQuestion {
		t.Errorf("expected ErrQuestion, got %v", err)
	}
}

// A reply that compresses the question name or omits the EDNS(0) OPT record is
// still equivalent to the query and must be accepted.
func TestClientSyncEquivalentQuestion(t *testing.T) {
	t.Run("compressed question name", func(t *testing.T) {
		HandleFunc("miek.nl.", HelloServerCompress)
		defer HandleRemove("miek.nl.")

		s, addrstr, _, err := RunLocalUDPServer(":0")
		if err != nil {
			t.Fatalf("unable to run test server: %v", err)
		}
		defer s.Shutdown()

		m := new(Msg)
		m.SetQuestion("MIEK.NL.", TypeSOA)

		c := new(Client)
		r, _, err := c.Exchange(m, addrstr)
		if err != nil {
			t.Fatalf("compressed reply rejected: %v", err)
		}
		if CanonicalName(r.Question[0].Name) != CanonicalName(m.Question[0].Name) {
			t.Errorf("question name %q does not match %q", r.Question[0].Name, m.Question[0].Name)
		}
	})

	t.Run("edns option omitted by server", func(t *testing.T) {
		HandleFunc("miek.nl.", HelloServer)
		defer HandleRemove("miek.nl.")

		s, addrstr, _, err := RunLocalUDPServer(":0")
		if err != nil {
			t.Fatalf("unable to run test server: %v", err)
		}
		defer s.Shutdown()

		m := new(Msg)
		m.SetQuestion("miek.nl.", TypeTXT)
		m.SetEdns0(2048, true)

		c := new(Client)
		if _, _, err := c.Exchange(m, addrstr); err != nil {
			t.Fatalf("reply without EDNS(0) OPT rejected: %v", err)
		}
	})
}

func TestMatchQuestion(t *testing.T) {
	query := new(Msg)
	query.SetQuestion("miek.nl.", TypeSOA)

	tests := []struct {
		name     string
		question []Question
		want     bool
	}{
		{
			name:     "identical",
			question: []Question{{Name: "miek.nl.", Qtype: TypeSOA, Qclass: ClassINET}},
			want:     true,
		},
		{
			name:     "case-insensitive name",
			question: []Question{{Name: "MiEk.NL.", Qtype: TypeSOA, Qclass: ClassINET}},
			want:     true,
		},
		{
			name:     "missing trailing dot",
			question: []Question{{Name: "miek.nl", Qtype: TypeSOA, Qclass: ClassINET}},
			want:     true,
		},
		{
			name:     "different name",
			question: []Question{{Name: "example.org.", Qtype: TypeSOA, Qclass: ClassINET}},
			want:     false,
		},
		{
			name:     "different qtype",
			question: []Question{{Name: "miek.nl.", Qtype: TypeA, Qclass: ClassINET}},
			want:     false,
		},
		{
			name:     "different qclass",
			question: []Question{{Name: "miek.nl.", Qtype: TypeSOA, Qclass: ClassCHAOS}},
			want:     false,
		},
		{
			name:     "empty question section with error rcode",
			question: nil,
			want:     true,
		},
		{
			name: "extra question",
			question: []Question{
				{Name: "miek.nl.", Qtype: TypeSOA, Qclass: ClassINET},
				{Name: "example.org.", Qtype: TypeSOA, Qclass: ClassINET},
			},
			want: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reply := new(Msg)
			reply.Question = test.question
			if test.question == nil {
				// Minimal error replies are allowed to omit the question section.
				reply.Rcode = RcodeNotImplemented
			}
			if got := reply.matchQuestion(query); got != test.want {
				t.Errorf("matchQuestion = %v, want %v", got, test.want)
			}
		})
	}

	t.Run("empty question section with success rcode", func(t *testing.T) {
		reply := new(Msg)
		reply.Rcode = RcodeSuccess
		if reply.matchQuestion(query) {
			t.Error("successful reply without a question section must not match")
		}
	})
}

func TestClientEDNS0(t *testing.T) {
	HandleFunc("miek.nl.", HelloServer)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeDNSKEY)

	m.SetEdns0(2048, true)

	c := new(Client)
	r, _, err := c.Exchange(m, addrstr)
	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}

	if r != nil && r.Rcode != RcodeSuccess {
		t.Errorf("failed to get a valid answer\n%v", r)
	}
}

// Validates the transmission and parsing of local EDNS0 options.
func TestClientEDNS0Local(t *testing.T) {
	optStr1 := "1979:0x0707"
	optStr2 := strconv.Itoa(EDNS0LOCALSTART) + ":0x0601"

	handler := func(w ResponseWriter, req *Msg) {
		m := new(Msg)
		m.SetReply(req)

		m.Extra = make([]RR, 1, 2)
		m.Extra[0] = &TXT{Hdr: RR_Header{Name: m.Question[0].Name, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: []string{"Hello local edns"}}

		// If the local options are what we expect, then reflect them back.
		ec1 := req.Extra[0].(*OPT).Option[0].(*EDNS0_LOCAL).String()
		ec2 := req.Extra[0].(*OPT).Option[1].(*EDNS0_LOCAL).String()
		if ec1 == optStr1 && ec2 == optStr2 {
			m.Extra = append(m.Extra, req.Extra[0])
		}

		w.WriteMsg(m)
	}

	HandleFunc("miek.nl.", handler)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeTXT)

	// Add two local edns options to the query.
	ec1 := &EDNS0_LOCAL{Code: 1979, Data: []byte{7, 7}}
	ec2 := &EDNS0_LOCAL{Code: EDNS0LOCALSTART, Data: []byte{6, 1}}
	o := &OPT{Hdr: RR_Header{Name: ".", Rrtype: TypeOPT}, Option: []EDNS0{ec1, ec2}}
	m.Extra = append(m.Extra, o)

	c := new(Client)
	r, _, err := c.Exchange(m, addrstr)
	if err != nil {
		t.Fatalf("failed to exchange: %s", err)
	}

	if r == nil {
		t.Fatal("response is nil")
	}
	if r.Rcode != RcodeSuccess {
		t.Fatal("failed to get a valid answer")
	}

	txt := r.Extra[0].(*TXT).Txt[0]
	if txt != "Hello local edns" {
		t.Error("Unexpected result for miek.nl", txt, "!= Hello local edns")
	}

	// Validate the local options in the reply.
	got := r.Extra[1].(*OPT).Option[0].(*EDNS0_LOCAL).String()
	if got != optStr1 {
		t.Errorf("failed to get local edns0 answer; got %s, expected %s", got, optStr1)
	}

	got = r.Extra[1].(*OPT).Option[1].(*EDNS0_LOCAL).String()
	if got != optStr2 {
		t.Errorf("failed to get local edns0 answer; got %s, expected %s", got, optStr2)
	}
}

func TestClientConn(t *testing.T) {
	HandleFunc("miek.nl.", HelloServer)
	defer HandleRemove("miek.nl.")

	// This uses TCP just to make it slightly different than TestClientSync
	s, addrstr, _, err := RunLocalTCPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

	cn, err := Dial("tcp", addrstr)
	if err != nil {
		t.Errorf("failed to dial %s: %v", addrstr, err)
	}

	err = cn.WriteMsg(m)
	if err != nil {
		t.Errorf("failed to exchange: %v", err)
	}
	r, err := cn.ReadMsg()
	if err != nil {
		t.Errorf("failed to get a valid answer: %v", err)
	}
	if r == nil || r.Rcode != RcodeSuccess {
		t.Errorf("failed to get an valid answer\n%v", r)
	}

	err = cn.WriteMsg(m)
	if err != nil {
		t.Errorf("failed to exchange: %v", err)
	}
	h := new(Header)
	buf, err := cn.ReadMsgHeader(h)
	if buf == nil {
		t.Errorf("failed to get an valid answer\n%v", r)
	}
	if err != nil {
		t.Errorf("failed to get a valid answer: %v", err)
	}
	if int(h.Bits&0xF) != RcodeSuccess {
		t.Errorf("failed to get an valid answer in ReadMsgHeader\n%v", r)
	}
	if h.Ancount != 0 || h.Qdcount != 1 || h.Nscount != 0 || h.Arcount != 1 {
		t.Errorf("expected to have question and additional in response; got something else: %+v", h)
	}
	if err = r.Unpack(buf); err != nil {
		t.Errorf("unable to unpack message fully: %v", err)
	}
}

func TestClientConnWriteSinglePacket(t *testing.T) {
	c := &countingConn{}
	conn := Conn{
		Conn: c,
	}
	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeTXT)
	err := conn.WriteMsg(m)
	if err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	if c.writes != 1 {
		t.Fatalf("incorrect number of Write calls")
	}
}

func TestTruncatedMsg(t *testing.T) {
	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSRV)
	cnt := 10
	for i := 0; i < cnt; i++ {
		r := &SRV{
			Hdr:    RR_Header{Name: m.Question[0].Name, Rrtype: TypeSRV, Class: ClassINET, Ttl: 0},
			Port:   uint16(i + 8000),
			Target: "target.miek.nl.",
		}
		m.Answer = append(m.Answer, r)

		re := &A{
			Hdr: RR_Header{Name: m.Question[0].Name, Rrtype: TypeA, Class: ClassINET, Ttl: 0},
			A:   net.ParseIP(fmt.Sprintf("127.0.0.%d", i)).To4(),
		}
		m.Extra = append(m.Extra, re)
	}
	buf, err := m.Pack()
	if err != nil {
		t.Errorf("failed to pack: %v", err)
	}

	r := new(Msg)
	if err = r.Unpack(buf); err != nil {
		t.Errorf("unable to unpack message: %v", err)
	}
	if len(r.Answer) != cnt {
		t.Errorf("answer count after regular unpack doesn't match: %d", len(r.Answer))
	}
	if len(r.Extra) != cnt {
		t.Errorf("extra count after regular unpack doesn't match: %d", len(r.Extra))
	}

	m.Truncated = true
	buf, err = m.Pack()
	if err != nil {
		t.Errorf("failed to pack truncated message: %v", err)
	}

	r = new(Msg)
	if err = r.Unpack(buf); err != nil {
		t.Errorf("failed to unpack truncated message: %v", err)
	}
	if !r.Truncated {
		t.Errorf("truncated message wasn't unpacked as truncated")
	}
	if len(r.Answer) != cnt {
		t.Errorf("answer count after truncated unpack doesn't match: %d", len(r.Answer))
	}
	if len(r.Extra) != cnt {
		t.Errorf("extra count after truncated unpack doesn't match: %d", len(r.Extra))
	}

	// Now we want to remove almost all of the extra records
	// We're going to loop over the extra to get the count of the size of all
	// of them
	off := 0
	buf1 := make([]byte, m.Len())
	for i := 0; i < len(m.Extra); i++ {
		off, err = PackRR(m.Extra[i], buf1, off, nil, m.Compress)
		if err != nil {
			t.Errorf("failed to pack extra: %v", err)
		}
	}

	// Remove all of the extra bytes but 10 bytes from the end of buf
	off -= 10
	buf1 = buf[:len(buf)-off]

	r = new(Msg)
	if err = r.Unpack(buf1); err == nil {
		t.Error("cutoff message should have failed to unpack")
	}
	// r's header might be still usable.
	if !r.Truncated {
		t.Error("truncated cutoff message wasn't unpacked as truncated")
	}
	if len(r.Answer) != cnt {
		t.Errorf("answer count after cutoff unpack doesn't match: %d", len(r.Answer))
	}
	if len(r.Extra) != 0 {
		t.Errorf("extra count after cutoff unpack is not zero: %d", len(r.Extra))
	}

	// Now we want to remove almost all of the answer records too
	buf1 = make([]byte, m.Len())
	as := 0
	for i := 0; i < len(m.Extra); i++ {
		off1 := off
		off, err = PackRR(m.Extra[i], buf1, off, nil, m.Compress)
		as = off - off1
		if err != nil {
			t.Errorf("failed to pack extra: %v", err)
		}
	}

	// Keep exactly one answer left
	// This should still cause Answer to be nil
	off -= as
	buf1 = buf[:len(buf)-off]

	r = new(Msg)
	if err = r.Unpack(buf1); err == nil {
		t.Error("cutoff message should have failed to unpack")
	}
	if !r.Truncated {
		t.Error("truncated cutoff message wasn't unpacked as truncated")
	}
	if len(r.Answer) != 0 {
		t.Errorf("answer count after second cutoff unpack is not zero: %d", len(r.Answer))
	}

	// Now leave only 1 byte of the question
	// Since the header is always 12 bytes, we just need to keep 13
	buf1 = buf[:13]

	r = new(Msg)
	err = r.Unpack(buf1)
	if err == nil {
		t.Errorf("error should be nil after question cutoff unpack: %v", err)
	}

	// Finally, if we only have the header, we don't return an error.
	buf1 = buf[:12]

	r = new(Msg)
	if err = r.Unpack(buf1); err != nil {
		t.Errorf("from header-only unpack should not return an error: %v", err)
	}
}

func TestTimeout(t *testing.T) {
	// Set up a dummy UDP server that won't respond
	addr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		t.Fatalf("unable to resolve local udp address: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer conn.Close()
	addrstr := conn.LocalAddr().String()

	// Message to send
	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeTXT)

	runTest := func(name string, exchange func(m *Msg, addr string, timeout time.Duration) (*Msg, time.Duration, error)) {
		t.Run(name, func(t *testing.T) {
			start := time.Now()

			timeout := time.Millisecond
			allowable := timeout + 10*time.Millisecond

			_, _, err := exchange(m, addrstr, timeout)
			if err == nil {
				t.Errorf("no timeout using Client.%s", name)
			}

			length := time.Since(start)
			if length > allowable {
				t.Errorf("exchange took longer %v than specified Timeout %v", length, allowable)
			}
		})
	}
	runTest("Exchange", func(m *Msg, addr string, timeout time.Duration) (*Msg, time.Duration, error) {
		c := &Client{Timeout: timeout}
		return c.Exchange(m, addr)
	})
	runTest("ExchangeContext", func(m *Msg, addr string, timeout time.Duration) (*Msg, time.Duration, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		return new(Client).ExchangeContext(ctx, m, addrstr)
	})
}

func TestExchangeWithConn(t *testing.T) {
	HandleFunc("miek.nl.", HelloServer)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

	c := new(Client)
	conn, err := c.Dial(addrstr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}

	r, _, err := c.ExchangeWithConn(m, conn)
	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}
	if r == nil {
		t.Fatal("response is nil")
	}
	if r.Rcode != RcodeSuccess {
		t.Errorf("failed to get an valid answer\n%v", r)
	}
}
