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
	//	"github.com/coredns/coredns/plugin/pkg/log"
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
	if state.QClass() != dns.ClassINET {
		fmt.Printf("We only care about class=IN queries\n")
		return plugin.NextOrFailure(ut.Name(), ut.Next, ctx, w, r)
	}

	if state.QType() != dns.TypeA && state.QType() != dns.TypeAAAA {
		fmt.Printf("We only care about A and AAAA queries\n")
		return plugin.NextOrFailure(ut.Name(), ut.Next, ctx, w, r)
	}

	fmt.Printf("QUERY RECEIVED:%s\n", state.QName())

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

	fmt.Printf("LOOKUP:%s DAEMON:%s\n", qname, server)

	// connect to this socket
	conn, err := net.DialTimeout("tcp", server, time.Second)
	if err != nil {
		fmt.Printf("Unable to connect to daemon:%s\n", server)
		return nil
	}

	// send to socket
	fmt.Fprintf(conn, "{\"url/getinfo\":{\"urls\":[\"" + qname + "\"],\"a1cat\":1, \"reputation\":1}}" + "\r\n")

	// listen for reply
	message, _ := bufio.NewReader(conn).ReadString('\n')
	fmt.Print("Message from server: "+message)
	json.Unmarshal([]byte(message), &response)

	// fmt.Println(err)
	fmt.Printf("Stuff: %v\n", response)

	return &response[0]
}
