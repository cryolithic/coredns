# untangle

## Name

*untangle* - Allows filtering dns requests based on Brightcloud IP reputation and/or categorization

## Description

This plugin allows for filtering dns requests based on the Brightcloud IP reputation
and/or category.

Dns requests are keyed based on the client's source address.  This key is used to lookup the
filtering policy (if one exists).  A filtering policy may specify two criteria for filtering a dns request.

1.  An IP reputation threshold (ie. If IP reputation is less than this value, filter the request)
2.  A list of categories (ie. If the requested address is 'porn', filter the request)

If a dns request is to be filtered, the IP address returned to the requesting client will be the
address of a "block" page, which is also specified in the filtering policy.

Filtering policies are stored in /etc/dnsproxy.  If policies are modified or added,
the untangle plugin will restart coredns to integrate the updates. Filtering policies are
described using a json file.  The json schema can be seen in the schema.json file in this directory.

## Syntax

~~~ txt
untangle SERVER PORT
~~~

SERVER and PORT specify the IP/hostname and port used to communicate with the Brightcloud
daemon

## Examples

Communicate with the Brightcloud daemon at 192.168.1.200:8484

~~~ corefile
. {
    untangle 192.168.1.200 8484
}
~~~

