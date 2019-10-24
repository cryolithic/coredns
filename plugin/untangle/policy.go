/*
 * policy.go
 * This is the policy logic for the Untangle DNS filter proxy
 * Our checkPolicy function receives the query name, client address, and
 * the result we received from the brightcloud daemon. Our job is to
 * lookup and apply the policy configured for the client.
 */

package untangle

import (
	"sync"
	"time"

	"github.com/coredns/coredns/plugin/pkg/log"
)

type policyHolder struct {
	timestamp         time.Time
	networkAddress    string
	minimumReputation int
	blockCategories   []int
	blockServer       string
}

var policyTable map[string]*policyHolder
var policyMutex sync.RWMutex

func initializePolicy() {
	policyTable = make(map[string]*policyHolder)

	dummy := new(policyHolder)
	dummy.networkAddress = "192.168.10.1"
	dummy.timestamp = time.Now()
	dummy.minimumReputation = 20
	dummy.blockCategories = append(dummy.blockCategories, 2)
	dummy.blockCategories = append(dummy.blockCategories, 4)
	dummy.blockCategories = append(dummy.blockCategories, 6)

	policyTable[dummy.networkAddress] = dummy
}

func checkPolicy(name string, client string, filter *Response) string {
	log.Debugf("Checking policy for name:%s client:%s filter:%v\n", name, client, filter)

	// read lock the policy table get the policy for the client
	policyMutex.RLock()
	policy := policyTable[client]
	policyMutex.RUnlock()

	// if we did not find a policy for the client address return nothing to allow
	if policy == nil {
		return ""
	}

	// if the reputation is below the client minimum return the block server
	if filter.Reputation < policy.minimumReputation {
		log.Debugf("Reputation %d < %d - Blocking %s for %s\n", filter.Reputation, policy.minimumReputation, name, client)
		return policy.blockServer
	}

	cathit := 0

	// look through all of the categories returned from the daemon
	// and see if any are blocked by the client policy
	for xx := 0; xx < len(filter.Cats); xx++ {
		for yy := 0; yy < len(policy.blockCategories); yy++ {
			if (filter.Cats[xx].Catid == policy.blockCategories[yy]) {
				cathit++
			}
		}
	}

	// if no blocked categories were found return nothing to allow
	if cathit == 0 {
		return ""
	}

	log.Debugf("Category hit %d - Blocked %s for %s\n", cathit, name, client)
	return policy.blockServer
}
