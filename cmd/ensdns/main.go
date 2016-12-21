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

package main

import (
	"encoding/hex"
	"flag"
	"log"
	"strings"

	"github.com/arachnid/ensdns/contract"
	"github.com/arachnid/ensdns/utils"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/miekg/dns"
)

var (
	ethapiFlag          = flag.String("ethapi", "ws://localhost:8546", "Path to connect to Ethereum node on")
	registryAddressFlag = flag.String("registry", "", "Address of ENS registry")
	listenAddressFlag   = flag.String("address", ":53", "Address and port to listen on")
)

func nameHash(name string) common.Hash {
	if name == "" {
		return common.Hash{}
	}

	parts := strings.SplitN(name, ".", 2)
	label := crypto.Keccak256Hash([]byte(parts[0]))
	parent := common.Hash{}
	if len(parts) > 1 {
		parent = nameHash(parts[1])
	}
	return crypto.Keccak256Hash(parent[:], label[:])
}

type ENSDNS struct {
	backend bind.ContractBackend
	ens     *contract.ENSSession
}

func New(backend bind.ContractBackend, registryAddress common.Address) (*ENSDNS, error) {
	ens, err := contract.NewENS(registryAddress, backend)
	if err != nil {
		return nil, err
	}

	return &ENSDNS{
		backend: backend,
		ens: &contract.ENSSession{
			Contract:     ens,
			TransactOpts: bind.TransactOpts{},
		},
	}, nil
}

func (ed *ENSDNS) Handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	for _, question := range r.Question {
		answers, err := ed.resolve(question)
		if err != nil {
			log.Printf("Error resolving query %v: %v", question, err)
			m.Rcode = dns.RcodeServerFailure
			break
		}

		// If no answer is found, and this wasn't a CNAME or * query, try looking for CNAMEs
		if len(answers) == 0 && question.Qtype != dns.TypeCNAME && question.Qtype != dns.TypeANY {
			question.Qtype = dns.TypeCNAME
			answers, err = ed.resolve(question)
			if err != nil {
				log.Printf("Error resolving query %v: %v", question, err)
				m.Rcode = dns.RcodeServerFailure
				break
			}
		}

		m.Answer = append(m.Answer, answers...)
		m.Authoritative = true
	}

	w.WriteMsg(m)
}

func (ed *ENSDNS) getResolver(node common.Hash) (*contract.ResolverSession, error) {
	resolverAddr, err := ed.ens.Resolver(node)
	if err != nil {
		return nil, err
	}

	resolver, err := contract.NewResolver(resolverAddr, ed.backend)
	if err != nil {
		return nil, err
	}

	return &contract.ResolverSession{
		Contract:     resolver,
		TransactOpts: ed.ens.TransactOpts,
	}, nil
}

func (ed *ENSDNS) resolve(question dns.Question) (records []dns.RR, err error) {
	log.Printf("Resolving query: %s", question.String())

	node := nameHash(question.Name)

	resolver, err := ed.getResolver(node)
	if err != nil {
		return nil, err
	}

	ttl, err := ed.ens.Ttl(node)
	if err != nil {
		return nil, err
	}

	for i := 0; ; i++ {
		response, err := resolver.Dnsrr(node, question.Qtype, question.Qclass, uint32(i))
		if err != nil {
			return nil, err
		} else if response.Rtype == 0 {
			break
		}

		hexdata := hex.EncodeToString(response.Data)

		records = append(records, &dns.RFC3597{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: response.Rtype,
				Class:  response.Rclass,
				Ttl:    uint32(ttl),
			},
			Rdata: hexdata,
		})
	}

	return records, nil
}

func serve(addr, proto string) {
	server := &dns.Server{Addr: addr, Net: proto, TsigSecret: nil}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("DNS server failed: %v", err)
	}
}

func main() {
	flag.Parse()

	client, err := ethclient.Dial(*ethapiFlag)
	if err != nil {
		log.Fatalf("Error connecting to Ethereum API: %v", err)
	}

	ensdns, err := New(client, common.HexToAddress(*registryAddressFlag))
	if err != nil {
		log.Fatalf("Error constructing ENSDNS: %v", err)
	}

	dns.HandleFunc(".", ensdns.Handle)
	go serve(*listenAddressFlag, "tcp")
	go serve(*listenAddressFlag, "udp")

	log.Printf("Listening on %s", *listenAddressFlag)

	select {}
}
