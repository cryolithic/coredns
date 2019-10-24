/*
 * untangle.go
 * This is the main query handling code for the Untangle DNS filter proxy
 * We lookup the reputation and categories for inbound queries and then
 * consult the customer policy to make the allow or block decision.
 */

package untangle

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

    "github.com/fsnotify/fsnotify"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/caddyserver/caddy"
)

// Untangle allows CoreDNS to submit DNS queries to a filter
// daemon and return a block address or allow normal processing

type Untangle struct {
	Next          plugin.Handler
	DaemonAddress string
	DaemonPort    int
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

	log.Debugf("QUERY: name:%s client:%s\n", state.Name(), state.IP())

	// pass the query name to the filterLookup function
	daemon := fmt.Sprintf("%s:%d", ut.DaemonAddress, ut.DaemonPort)
	filter := filterLookup(state.Name(), daemon)

	// if we get nothing from the filter we are done
	if filter == nil {
		return plugin.NextOrFailure(ut.Name(), ut.Next, ctx, w, r)
	}

	// pass the name, client, and policy result to the checkPolicy function
	// and get back the address of the block server or nil to allow
	blocker := checkPolicy(state.Name(), state.IP(), filter)

	// emtpy result from checkPolicy means we allow the query
	if len(blocker) == 0 {
		return plugin.NextOrFailure(ut.Name(), ut.Next, ctx, w, r)
	}

	// checkPolicy gave us a result so we need to block the query
	a := new(dns.Msg)
	a.SetReply(r)
	a.Authoritative = true
	var rr dns.RR

	if state.QType() == dns.TypeA {
		rr = new(dns.A)
		rr.(*dns.A).Hdr = dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeA, Class: state.QClass()}
		rr.(*dns.A).A = net.ParseIP(blocker).To4()
		a.Answer = []dns.RR{rr}
	}
	if state.QType() == dns.TypeAAAA {
		rr = new(dns.AAAA)
		rr.(*dns.AAAA).Hdr = dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeAAAA, Class: state.QClass()}
		rr.(*dns.AAAA).AAAA = net.ParseIP(blocker)
		a.Answer = []dns.RR{rr}
	}

	w.WriteMsg(a)
	return 0, nil
}

// Name implements the Handler interface.
func (ut Untangle) Name() string { return "untangle" }

func filterLookup(qname string, server string) *Response {
	var response []Response

	// connect to this socket
	conn, err := net.DialTimeout("tcp", server, time.Second)
	if err != nil {
		log.Errorf("Error connecting to daemon %s: %v\n", server, err)
		return nil
	}

	// make sure the socket is closed
	defer conn.Close()

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

	log.Debugf("DAEMON RESPONSE: %s\n", message)
	json.Unmarshal([]byte(message), &response)

	return &response[0]
}

func hook(event caddy.EventName, info interface{}) error {
	if event != caddy.InstanceStartupEvent {
		return nil
	}

	instance := info.(*caddy.Instance)
	// this should be an instance. ok to panic if not
	/*

	go func() {
		tick := time.NewTicker(10 * time.Second)

		for {
			select {
			case <-tick.C:
				corefile, err := caddy.LoadCaddyfile(instance.Caddyfile().ServerType())
				if err != nil {
					continue
				}
				_, err = instance.Restart(corefile)
				if err != nil {
					log.Errorf("Corefile changed but reload failed: %s", err)
					continue
				}
				return
			}
		}
	}()
	*/

    // creates a new file watcher
    watcher, err := fsnotify.NewWatcher()
    if err != nil {
        fmt.Println("ERROR", err)
    }
    defer watcher.Close()

    //
    done := make(chan bool)

    //
    go func() {
        for {
            select {
            // watch for events
            case event := <-watcher.Events:
                fmt.Printf("EVENT! %#v\n", event)
				corefile, err := caddy.LoadCaddyfile(instance.Caddyfile().ServerType())
				if err != nil {
					continue
				}
				_, err = instance.Restart(corefile)
				if err != nil {
					log.Errorf("Corefile changed but reload failed: %s", err)
					continue
				}


            // watch for errors
            case err := <-watcher.Errors:
                fmt.Println("ERROR", err)
            }
        }
    }()

    // out of the box fsnotify can watch a single file, or a single directory
    if err := watcher.Add("/etc/dnsproxy"); err != nil {
        fmt.Println("ERROR", err)
    }

    <-done


	return nil
}
