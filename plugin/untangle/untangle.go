// Package untangle implements a plugin that does query filtering
package untangle

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

// Untangle allows CoreDNS to submit DNS queries to a filter
// daemon and return a block address or allow normal processing

type Untangle struct {
	Next          plugin.Handler
	DaemonAddress string
	DaemonPort    int
	BlockFour     string
	BlockSix      string
}

type Category struct {
	Catid int
	Conf  int
}

type Response struct {
	Url        string
	Reputation int
	Cats       []Category
	A1cat      bool
	Source     string
}

// ServeDNS implements the plugin.Handler interface.
func (ut Untangle) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	// we only care about queries with INET class
	if state.QClass() != dns.ClassINET {
		return plugin.NextOrFailure(ut.Name(), ut.Next, ctx, w, r)
	}

	// we only care about queries for A and AAAA records
	if state.QType() != dns.TypeA && state.QType() != dns.TypeAAAA {
		return plugin.NextOrFailure(ut.Name(), ut.Next, ctx, w, r)
	}

	log.Debugf("QUERY: %v\n", state)

	blocked := false
	daemon := fmt.Sprintf("%s:%d", ut.DaemonAddress, ut.DaemonPort)
	filter := filterLookup(state.QName(), daemon)

	if filter != nil {
	if filter.Reputation > 20 {
		blocked = false
	} else {
		blocked = true
	}
	}

	if state.Name() == "block.this." {
		blocked = true
	}

	if blocked == false {
		return plugin.NextOrFailure(ut.Name(), ut.Next, ctx, w, r)
	}

	a := new(dns.Msg)
	a.SetReply(r)
	a.Authoritative = true
	var rr dns.RR

	if state.QType() == dns.TypeA {
		rr = new(dns.A)
		rr.(*dns.A).Hdr = dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeA, Class: state.QClass()}
		rr.(*dns.A).A = net.ParseIP(ut.BlockFour).To4()
		a.Answer = []dns.RR{rr}
	}
	if state.QType() == dns.TypeAAAA {
		rr = new(dns.AAAA)
		rr.(*dns.AAAA).Hdr = dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeAAAA, Class: state.QClass()}
		rr.(*dns.AAAA).AAAA = net.ParseIP(ut.BlockSix)
		a.Answer = []dns.RR{rr}
	}

	w.WriteMsg(a)
	return 0, nil
}

// Name implements the Handler interface.
func (ut Untangle) Name() string { return "untangle" }

func filterLookup(qname string, server string) (*Response) {
	var response []Response

	// connect to this socket
	conn, err := net.DialTimeout("tcp", server, time.Second)
	if err != nil {
		log.Errorf("Error connecting to daemon %s: %v\n", server, err)
		return nil
	}

	// send to socket
	command := fmt.Sprintf("{\"url/getinfo\":{\"urls\":[\"" + qname + "\"],\"a1cat\":1, \"reputation\":1}}" + "\r\n")
	log.Debugf("DAEMON COMMAND: %s\n", command)
	conn.Write([]byte(command))

	// listen for reply
	message, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Errorf("Error reading from daemon: %v\n", err)
		return nil
	}

	log.Debug("DAEMON RESPONSE: %s\n", message)
	json.Unmarshal([]byte(message), &response)

	return &response[0]
}
