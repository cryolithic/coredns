/*
 * policy.go
 * This is the policy logic for the Untangle DNS filter proxy
 * Our checkPolicy function receives the query name, client address, and
 * the result we received from the brightcloud daemon. Our job is to
 * lookup and apply the policy configured for the client.
 */

package untangle

import (
	"github.com/coredns/coredns/plugin/pkg/log"
)

func checkPolicy(name string, client string, filter *Response) string {
	log.Debugf("Checking policy for name:%s client:%s filter:%v\n", name, client, filter)
	if filter.Reputation > 20 {
		return ""
	}
	return "104.20.3.248"
}
