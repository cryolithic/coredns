/*
 * setup.go
 * This is the plugin setup file for the Untangle DNS filter proxy
 * We get the filter daemon address and port from the Corefile args
 * and then hook our plugin into the DNS procesing chain.
 */

package untangle

import (
	"strconv"
	"sync"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/log"

	"github.com/caddyserver/caddy"
)

var (
	once sync.Once
)

func init() { plugin.Register("untangle", setup) }

func setup(c *caddy.Controller) error {
	addr, port, block4, block6, err := parse(c)
	if err != nil {
		return plugin.Error("untangle", err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return Untangle{Next: next, DaemonAddress: addr, DaemonPort: port, BlockFour: block4, BlockSix: block6}
	})

	once.Do(func() {
		caddy.RegisterEventHook("untangle", hook)
	})

	return nil
}

func parse(c *caddy.Controller) (string, int, string, string, error) {
	for c.Next() {
		args := c.RemainingArgs()
		if len(args) != 4 {
			log.Warningf("Invalid arguments. Using defaults\n")
			return "127.0.0.1", 8484, "0.1.2.3", "1:2:3:4::1234", nil
		}
		port, _ := strconv.Atoi(args[1])
		log.Debugf("ADDR:%v PORT:%v BLOCK4:%v BLOCK6:%v\n", args[0], port, args[2], args[3])
		return args[0], port, args[2], args[3], nil
	}

	log.Warningf("Missing arguments. Using defaults\n")
	return "127.0.0.1", 8484, "0.1.2.3", "1:2:3:4::1234", nil
}
