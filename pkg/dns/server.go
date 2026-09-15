package dns

import (
	"context"
	"fmt"
	"middleware/pkg/pipeline"
	"middleware/pkg/storage"
	"net"
	"strings"

	"github.com/miekg/dns"
)

type Server struct {
	engine    *pipeline.Engine
	dnsServer *dns.Server
	upstream  string
	db        *storage.Database
}

func NewServer(addr string, upstream string, engine *pipeline.Engine, db *storage.Database) *Server {
	s := &Server{
		engine:   engine,
		upstream: upstream,
		db:       db,
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleDNSQuery)

	s.dnsServer = &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: mux,
	}
	return s
}

func (s *Server) Start() error {
	fmt.Printf("[DNS Server] Listening on UDP %s... \n", s.dnsServer.Addr)
	return s.dnsServer.ListenAndServe()
}

func (s *Server) handleDNSQuery(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	if len(r.Question) == 0 {
		err := w.WriteMsg(m)
		if err != nil {
			return
		}
		return
	}

	q := r.Question[0]
	domain := strings.TrimSuffix(q.Name, ".")

	clientIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())

	tctx := pipeline.NewTrafficContext("DNS-REQ", net.ParseIP(clientIP), domain, q.Qtype)

	s.engine.Process(context.Background(), tctx)

	s.db.Log(storage.LogEvent{
		Timestamp:   tctx.Timestamp,
		Protocol:    "DNS",
		ClientIP:    clientIP,
		Target:      domain,
		Action:      tctx.FinalAction.String(),
		BlockReason: tctx.BlockReason,
		MatchedBy:   tctx.MatchedBy,
	})

	if tctx.FinalAction == pipeline.ActionBlock {
		fmt.Printf("[BLOCKED] %s | Client: %s | Reason: %s (by %s) \n", domain, clientIP, tctx.BlockReason, tctx.MatchedBy)
		if q.Qtype == dns.TypeA {
			rr, _ := dns.NewRR(fmt.Sprintf("%s 60 in A 0.0.0.0", q.Name))
			m.Answer = append(m.Answer, rr)
		} else {
			m.Rcode = dns.RcodeNameError
		}
		err := w.WriteMsg(m)
		if err != nil {
			return
		}
		return
	}

	fmt.Printf("[ALLOWED] %s | Forwarding to upstream %s\n", domain, s.upstream)
	c := new(dns.Client)
	in, _, err := c.Exchange(r, s.upstream)
	if err != nil {
		fmt.Printf("[ERROR] upstream failed: %v\n", err)
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}

	w.WriteMsg(in)
}
