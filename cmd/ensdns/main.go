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

//go:generate abigen --sol ../../contract/ens.sol --pkg contract --out ../../contract/ens.go

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/arachnid/ensdns/ens"
	"github.com/arachnid/ensdns/utils"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	ethutils "github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/miekg/dns"
)

var (
	ethapiFlag          = flag.String("ethapi", "ws://localhost:8546", "Path to connect to Ethereum node on")
	nsDomainFlag        = flag.String("nsdomain", ".ens.domains.", "Domain name for this ENS server")

	uploadFlagSet       = flag.NewFlagSet("upload", flag.ExitOnError)
	uploadKeystoreFlag  = uploadFlagSet.String("keystore", "", "Path to keystore")
	uploadAccountFlag   = uploadFlagSet.String("account", "0", "Account to use to send transactions")
	uploadPasswordFlag  = uploadFlagSet.String("password", "", "Password to unlock account with")

	serveFlagSet		= flag.NewFlagSet("serve", flag.ExitOnError)
	listenAddressFlag   = serveFlagSet.String("address", ":53", "Local address and port to serve on")

	rootServers = []string{
		"a.root-servers.net",
		"b.root-servers.net",
		"c.root-servers.net",
		"d.root-servers.net",
		"e.root-servers.net",
		"f.root-servers.net",
		"g.root-servers.net",
		"h.root-servers.net",
		"i.root-servers.net",
		"j.root-servers.net",
		"k.root-servers.net",
		"l.root-servers.net",
		"m.root-servers.net",
	}
)

func main() {
	flag.Parse()

	client, err := ethclient.Dial(*ethapiFlag)
	if err != nil {
		log.Fatalf("Error connecting to Ethereum API: %v", err)
	}

	args := flag.Args()
	if len(args) == 0 {
		fmt.Println("usage: ensdns <command> [args]")
		fmt.Println("Commands include:")
		fmt.Println("  serve <address>   Start DNS server listening on <address>")
		fmt.Println("  upload <filename> Upload the provided zonefile to ENS")
		os.Exit(1)
	}

	switch(args[0]) {
	case "upload":
		upload(client, args[1:])
	case "serve":
		serve(client, args[1:])
	}
}

type Signer struct {
	accman *accounts.Manager
}

func (sig Signer) Sign(signer types.Signer, address common.Address, tx *types.Transaction) (*types.Transaction, error) {
	signature, err := sig.accman.SignEthereum(address, signer.Hash(tx).Bytes())
	if err != nil {
		return nil, err
	}

	return tx.WithSignature(signer, signature)
}

func getAccount() (*accounts.Manager, accounts.Account, error) {
	accman := accounts.NewManager(*uploadKeystoreFlag, 0, 0)
	account, err := ethutils.MakeAddress(accman, *uploadAccountFlag)
	if err != nil {
		return nil, accounts.Account{}, fmt.Errorf("Error parsing account: %s", err)
	}
	log.Printf("Uploading using account %s", account.Address.Hex())

	if err := accman.Unlock(account, *uploadPasswordFlag); err != nil {
		return nil, accounts.Account{}, fmt.Errorf("Error unlocking account: %s", err)
	}

	return accman, account, nil
}

func readRRs(filename string) (rrs []dns.RR, soa *dns.SOA, err error) {
	fh, err := os.Open(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("Error opening file: %s", err)
	}

	rrs = make([]dns.RR, 0)
	for token := range dns.ParseZone(fh, "", filename) {
		if token.Error != nil {
			return nil, nil, fmt.Errorf("Error parsing zonefile: %s", token.Error)
		}
		if rr, ok := token.RR.(*dns.SOA); ok {
			if soa != nil {
				return nil, nil, fmt.Errorf("Error parsing zonefile: Multiple SOA records")
			}
			soa = rr
		}
		rrs = append(rrs, token.RR)
	}

	if soa == nil {
		return nil, nil, fmt.Errorf("Error parsing zonefile: No SOA record")
	}

	return rrs, soa, nil
}

func upload(client *ethclient.Client, args []string) {
	uploadFlagSet.Parse(args)
	args = uploadFlagSet.Args()

	if len(args) != 1 {
		fmt.Println("usage: ensdns upload <filename>")
		os.Exit(1)
	}

	rrs, soa, err := readRRs(args[0])
	if err != nil {
		fmt.Printf("Error reading zonefile: %s\n", err)
		os.Exit(1)
	}

	if !strings.HasSuffix(soa.Ns, *nsDomainFlag) {
		fmt.Printf("SOA nameserver not recognized: %s\n", soa.Ns)
		os.Exit(1)
	}

	parts := strings.Split(soa.Ns, ".")
	if len(parts[0]) != 40 {
		fmt.Println("SOA nameserver name must start with a 40 character hex address")
	}

	registryAddress := common.HexToAddress(parts[0])

	if *uploadKeystoreFlag == "" {
		fmt.Println("--keystore is required")
		os.Exit(1)
	}

	accman, account, err := getAccount()
	if err != nil {
		fmt.Printf("Error getting account: %s\n", err)
		os.Exit(1)
	}

	txopts := bind.TransactOpts{
		From: account.Address,
		Signer: (Signer{accman}).Sign,
	}

	registry, err := ens.New(client, registryAddress, txopts)
	if err != nil {
		fmt.Printf("Error constructing ENS instance: %v\n", err)
		os.Exit(1)
	}

	resolver, err := registry.GetResolver(soa.Hdr.Name)
	if err != nil {
		fmt.Printf("Error getting resolver: %s\n", err)
	}

	fmt.Printf("Setting %d RRs for name %s at resolver %s\n", len(rrs), soa.Hdr.Name, resolver.Address.Hex())
	if err := resolver.SetRRs(rrs); err != nil {
		fmt.Printf("Error setting RRs: %s\n", err)
	}
}

type ENSDNS struct {
	client *ethclient.Client
}

func (ed *ENSDNS) getZone(name string) (*Zone, error) {
	client := &dns.Client{
		ReadTimeout: 5 * time.Second,
	}

	ns, err := utils.FindNS(client, rootServers, name, *nsDomainFlag)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(ns.Ns, ".")
	if len(parts[0]) != 40 {
		return nil, fmt.Errorf("SOA nameserver name '%s' does not start with a 40 character hex address", ns.Ns)
	}

	registryAddress := common.HexToAddress(parts[0])
	registry, err := ens.New(ed.client, registryAddress, bind.TransactOpts{})
	if err != nil {
		return nil, fmt.Errorf("Error constructing ENS instance: %v", err)
	}

	resolver, err := registry.GetResolver(ns.Hdr.Name)
	if err != nil {
		return nil, fmt.Errorf("Error getting resolver: %s", err)
	}

	rrs, err := resolver.GetRRs()
	if err != nil {
		return nil, fmt.Errorf("Error getting records from resolver: %s", err)
	}

	return NewZone(rrs), nil
}

type Zone struct {
	rrs []dns.RR
	subdomains map[string]*Zone
}

func NewZone(rrs []dns.RR) *Zone {
	root := &Zone{
		subdomains: make(map[string]*Zone),
	}

	for _, rr := range rrs {
		labels := strings.Split(rr.Header().Name, ".")
		z := root
		for i := len(labels) - 1; i >= 0; i-- {
			if len(labels[i]) == 0 {
				continue
			}

			sz, ok := z.subdomains[labels[i]]
			if !ok {
				sz = &Zone{
					subdomains: make(map[string]*Zone),
				}
				z.subdomains[labels[i]] = sz
			}
			z = sz
		}

		z.rrs = append(z.rrs, rr)
	}

	return root
}

func (z *Zone) findSubzone(question dns.Question) (rrs []dns.RR) {
	labels := strings.Split(question.Name, ".")
	zone := z
	for i := len(labels) - 1; i >= 0; i-- {
		if len(labels[i]) == 0 {
			continue
		}
		sz, ok := zone.subdomains[labels[i]]
		if !ok {
			sz, ok = zone.subdomains["*"]
			if !ok {
				return nil
			}
			return sz.rrs
		}
		zone = sz
	}
	return zone.rrs
}

func (z *Zone) Resolve(question dns.Question) (rrs []dns.RR, err error) {
	for _, rr := range z.findSubzone(question) {
		if question.Qtype == rr.Header().Rrtype || question.Qtype == dns.TypeANY {
			rr.Header().Name = question.Name
			rrs = append(rrs, rr)
		}
	}

	// If no answer is found, and this wasn't a CNAME or * query, try looking for CNAMEs
	if len(rrs) == 0 && question.Qtype != dns.TypeCNAME && question.Qtype != dns.TypeANY {
		question.Qtype = dns.TypeCNAME
		return z.Resolve(question)
	}

	return rrs, nil
}

func (ed *ENSDNS) Handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	for _, question := range r.Question {
		zone, err := ed.getZone(question.Name)
		if err != nil {
			log.Printf("Zone %v not found: %v", question.Name, err)
			break
		}

		rrs, err := zone.Resolve(question)
		if err != nil {
			log.Printf("Error resolving query %v: %v", question, err)
			m.Rcode = dns.RcodeServerFailure
			break
		}
		m.Answer = append(m.Answer, rrs...)
		m.Authoritative = true
	}

	w.WriteMsg(m)
}


func runServer(addr, proto string) {
	server := &dns.Server{Addr: addr, Net: proto, TsigSecret: nil}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("DNS server failed: %v", err)
	}
}

func serve(client *ethclient.Client, args []string) {
	serveFlagSet.Parse(args)
	args = serveFlagSet.Args()

	if len(args) > 0 {
		fmt.Printf("Usage: ensdns serve [flags]")
		os.Exit(1)
	}

	ensdns := &ENSDNS{
		client: client,
	}
	dns.HandleFunc(".", ensdns.Handle)

	go runServer(*listenAddressFlag, "tcp")
	go runServer(*listenAddressFlag, "udp")

	log.Printf("Listening on %s", *listenAddressFlag)

	select {}
}
