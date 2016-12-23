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

//go:generate abigen --sol contract/ens.sol --pkg contract --out contract/ens.go

package ens

import (
    "strings"

    "github.com/arachnid/ensdns/ens/contract"
    "github.com/miekg/dns"
    "github.com/ethereum/go-ethereum/accounts/abi/bind"
    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/crypto"
)

func NameHash(name string) common.Hash {
    if name == "" {
        return common.Hash{}
    }

    parts := strings.SplitN(name, ".", 2)
    label := crypto.Keccak256Hash([]byte(parts[0]))
    parent := common.Hash{}
    if len(parts) > 1 {
        parent = NameHash(parts[1])
    }
    return crypto.Keccak256Hash(parent[:], label[:])
}

type Registry struct {
    backend bind.ContractBackend
    ens *contract.ENSSession
}

func New(backend bind.ContractBackend, registryAddress common.Address, opts bind.TransactOpts) (*Registry, error) {
    ens, err := contract.NewENS(registryAddress, backend)
    if err != nil {
        return nil, err
    }

    return &Registry{
        backend: backend,
        ens: &contract.ENSSession{
            Contract:     ens,
            TransactOpts: opts,
        },
    }, nil
}


func (reg *Registry) GetResolver(name string) (*Resolver, error) {
    node := NameHash(name)
    resolverAddr, err := reg.ens.Resolver(node)
    if err != nil {
        return nil, err
    }

    resolver, err := contract.NewResolver(resolverAddr, reg.backend)
    if err != nil {
        return nil, err
    }

    return &Resolver{
        Address: resolverAddr,
        node: node,
        registry: reg,
        resolver: &contract.ResolverSession{
            Contract:     resolver,
            TransactOpts: reg.ens.TransactOpts,
        },
    }, nil
}

type Resolver struct {
    Address common.Address
    node common.Hash
    registry *Registry
    resolver *contract.ResolverSession
}

func (res *Resolver) GetRRs() (rrs []dns.RR, err error) {
    rdata, err := res.resolver.Dnsrr(res.node)
    if err != nil {
        return nil, err
    }

    for off := 0; off < len(rdata); {
        r, off1, err := dns.UnpackRR(rdata, off)
        if err != nil {
            return nil, err
        }
        if off1 == off {
            break
        }
        off = off1
        rrs = append(rrs, r)
    }
    return rrs, nil
/*
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

    return records, nil*/
}

func packRRs(rrs []dns.RR) (rdata []byte, err error) {
    len := (&dns.Msg{Answer: rrs}).Len()

    rdata = make([]byte, len)
    off := 0
    compression := make(map[string]int)
    for _, rr := range rrs {
        off, err = dns.PackRR(rr, rdata, off, compression, true)
        if err != nil {
            return nil, err
        }
    }

    return rdata[:off], nil
}

func (res *Resolver) SetRRs(rrs []dns.RR) error {
    rdata, err := packRRs(rrs)
    if err != nil {
        return err
    }

    _, err = res.resolver.SetDnsrr(res.node, rdata)
    return err
}

func (res *Resolver) GetTTL() (uint64, error) {
    return res.registry.ens.Ttl(res.node)
}
