/*
 * policy.go
 * This is the policy logic for the Untangle DNS filter proxy
 * Our checkPolicy function receives the query name, client address, and
 * the result we received from the brightcloud daemon. Our job is to
 * lookup and apply the policy configured for the client.
 */

package untangle

import (
    "io/ioutil"
	"fmt"
	"sync"
	"time"
    "os"

    "strings"
    "encoding/json"
    "path/filepath"
	"github.com/coredns/coredns/plugin/pkg/log"
)

type Policy struct {
    Ipv4Addrs []string
    Ipv6Addrs []string
    BlockCategories []int
    BlockReputation int
    RedirectIp string
}

type Configuration struct {
//    Next          plugin.Handler
    Version       int
    CustomerId    string
    Policies      []Policy
}

type policyHolder struct {
	timestamp         time.Time
	networkAddress    string
	minimumReputation int
	blockCategories   []int
	blockServer       string
}

var policyTable map[string]*policyHolder
var policyMutex sync.RWMutex

func getDnsConfigurationFiles() []string {
    var files []string

    root := "/etc/dnsproxy"
    err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
        // fmt.Printf(path)
        if strings.HasSuffix(path, ".json"){
            files = append(files, path)
        }
        return nil
    })
    if err != nil {
        panic(err)
    }
    return files    
}

func initializePolicy() {
	policyTable = make(map[string]*policyHolder)

	// dummy := new(policyHolder)
	// dummy.networkAddress = "192.168.10.1"
	// dummy.timestamp = time.Now()
	// dummy.minimumReputation = 20
	// dummy.blockCategories = append(dummy.blockCategories, 2)
	// dummy.blockCategories = append(dummy.blockCategories, 4)
	// dummy.blockCategories = append(dummy.blockCategories, 6)

	// policyTable[dummy.networkAddress] = dummy


    var customer Configuration
    for _, file := range getDnsConfigurationFiles() {
        // fmt.Println(file)

        // fmt.Println("Open... " + file)
        // Open our jsonFile
        jsonFile, err := os.Open(file)
        // if we os.Open returns an error then handle it
        if err != nil {
            fmt.Println(err)
        }
        // fmt.Println("Successfully opened " + file)
        byteValue, _ := ioutil.ReadAll(jsonFile)
        // fmt.Println("Successfully read " + file)
        // defer the closing of our jsonFile so that we can parse it later on
        defer jsonFile.Close()

        json.Unmarshal(byteValue, &customer)
        // fmt.Print(customer)
        // fmt.Print(customer.CustomerId)
        for _, policy := range customer.Policies{
            // fmt.Print(policy)
            for _, ipv4addr := range policy.Ipv4Addrs{
                fmt.Print(ipv4addr)
				pluginPolicy := new(policyHolder)
				pluginPolicy.networkAddress = ipv4addr
				pluginPolicy.minimumReputation = policy.BlockReputation
				for _, category := range policy.BlockCategories{
					pluginPolicy.blockCategories = append(pluginPolicy.blockCategories, category)
				}
				pluginPolicy.blockServer = policy.RedirectIp

				policyTable[pluginPolicy.networkAddress] = pluginPolicy
            }
        }
    }


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
