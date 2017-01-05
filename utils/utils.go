// Copyright 2016 Nick Johnson <arachnid@notdot.net>
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package utils

import (
    "errors"
    "fmt"
    "net"
    "strings"

    "github.com/miekg/dns"
)

var TimeoutError = errors.New("All DNS servers timed out")

func FindNS(client *dns.Client, servers []string, name, nssuffix string) (*dns.NS, error) {
    query := dns.Msg{}
    query.SetQuestion(name, dns.TypeNS)
    query.RecursionDesired = false

    for _, server := range servers {
        r, _, err := client.Exchange(&query, server+":53")
        if err, ok := err.(net.Error); ok && err.Timeout() {
            continue
        }
        if err != nil {
            return nil, err
        }
        if r == nil || r.Rcode != dns.RcodeSuccess {
            return nil, fmt.Errorf("Got nil or error response from NS query: %v", r)
        }

        subservers := make([]string, 0)
        for _, rec := range r.Ns {
            switch rec := rec.(type) {
            case *dns.NS:
                if strings.HasSuffix(rec.Ns, nssuffix) {
                    return rec, nil
                }
                subservers = append(subservers, rec.Ns)
            }
        }
        if len(subservers) > 0 {
            return FindNS(client, subservers, name, nssuffix)
        }
    }
    return nil, TimeoutError
}
