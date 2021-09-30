package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-routeros/routeros"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type DnsResolver struct {
	cfg *ConfMap
}

func (d *DnsResolver) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {

	msg := dns.Msg{}
	msg.SetReply(r)

	switch r.Question[0].Qtype {
	case dns.TypeA:

		msg.Authoritative = true
		domain := msg.Question[0].Name
		logrus.WithField("domain", domain).Info("Resolving domain")

		r := Resolve{cfg: d.cfg, Name: domain}
		if !r.IsVPNListDomain() {

			if err := r.AskUpstr(d.cfg.Dns[0]); err != nil {
				logrus.WithField("dns-server", d.cfg.Dns[0]).
					Info(fmt.Sprintf("dns ask err: %v", err.Error()))
				if err := r.AskUpstr(d.cfg.Dns[1]); err != nil {
					logrus.WithField("dns-server", d.cfg.Dns[1]).
						Info(fmt.Sprintf("dns ask err: %v", err.Error()))
				}
			}

		} else {

			// If the domain is listed under whilelisted domains
			// we should get the dns results from a dns server
			// thats under VPN interface itself
			if err := r.AskUpstr(d.cfg.RouterOS.VPN.Dns[0]); err != nil {
				logrus.WithField("dns-server", "9.9.9.9").
					Info("dns ask err: %v", err.Error())
			}

			go func() {

				// adding domain ip addresses to mikrotik vpn interface
				if err := r.SetToMikritik(); err != nil {
					logrus.WithField("mikrotik", "").
						Info(fmt.Sprintf("mikrotik ip firewall add err: %v", err.Error()))
				}

			}()

		}

		msg.Answer = r.Answer
	}

	w.WriteMsg(&msg)
}

type Resolve struct {
	cfg       *ConfMap
	Name      string
	Addresses []string
	CNames    []string
	Answer    []dns.RR
}

func (rr *Resolve) IsVPNListDomain() bool {
	for _, d := range rr.cfg.RouterOS.VPN.WhitelistedDomains {
		if strings.Contains(rr.Name, d) {
			return true
		}
	}
	return false
}

func RouterOSDialer(useTLS bool, address, username, password string) (*routeros.Client, error) {
	if useTLS {
		return routeros.DialTLS(address, username, password, nil)
	}
	return routeros.Dial(address, username, password)
}

func (rr *Resolve) SetToMikritik() error {

	args := []string{
		"/ip/firewall/address-list/add",
		fmt.Sprintf("=list=%s", rr.cfg.RouterOS.VPN.Interface),
	}

	for _, addr := range rr.Addresses {
		logrus.WithField("mikrotik", "").
			Info(fmt.Sprintf("putting the domain ip addresses to mikrotik: %s", addr))
		address := fmt.Sprintf("=address=%s", addr)
		if _, err := mikrotik.RunArgs(append(args, []string{address}...)); err != nil {
			if !strings.Contains(err.Error(), "already") {
				logrus.WithField("mikrotik", "").
					Info(fmt.Sprintf("err ip firewall add to mikrotik: %v", err.Error()))
			}
		}
	}

	return nil
}

func (rr *Resolve) AskUpstr(upStrdns string) error {

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second * 5,
			}
			return d.DialContext(ctx, "udp", fmt.Sprintf("%s:%d", upStrdns, 53))
		},
	}

	cname, err := r.LookupCNAME(context.Background(), rr.Name)
	if err != nil {
		return err
	}

	rr.Answer = append(rr.Answer, &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   rr.Name,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
		},
		Target: cname,
	})

	ips, err := r.LookupHost(context.Background(), rr.Name)
	if err != nil {
		return err
	}

	for _, ip := range ips {

		if !IsIPv4(ip) {
			continue
		}

		rr.Addresses = append(rr.Addresses, ip)
		rr.Answer = append(rr.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   cname,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			A: net.ParseIP(ip),
		})
	}

	return nil

}

func IsIPv4(address string) bool {
	return strings.Count(address, ":") < 2
}

var (
	err      error
	mikrotik *routeros.Client
)

func main() {

	// Log as JSON instead of the default ASCII formatter.
	logrus.SetFormatter(&logrus.JSONFormatter{})

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	logrus.SetOutput(os.Stdout)

	configFile := flag.String("config-file", "config.yaml", "Config file path")
	flag.Parse()

	cfg, err := Load(*configFile)
	if err != nil {
		logrus.WithError(err).Info("Error on loading config")
		return
	}

	logrus.Info(
		"Connecting to mikrotik",
		fmt.Sprintf("%s:%d", cfg.RouterOS.Address, cfg.RouterOS.Port),
	)
	rand.Seed(time.Now().UnixNano())
	mikrotik, err = RouterOSDialer(
		cfg.RouterOS.UseTLS,
		fmt.Sprintf("%s:%d", cfg.RouterOS.Address, cfg.RouterOS.Port),
		cfg.RouterOS.Username,
		cfg.RouterOS.Password,
	)
	if err != nil {
		logrus.WithError(err).Info("Error on connecting to RouterOS")
		return
	}

	mikrotik.Async()
	defer mikrotik.Close()

	srv := &dns.Server{Addr: "0.0.0.0:53", Net: "udp"}
	srv.Handler = &DnsResolver{cfg: cfg}
	logrus.Info("dns listen on: ", "udp/0.0.0.0:53")

	if err := srv.ListenAndServe(); err != nil {
		logrus.WithError(err).Info("Error on ListenAndServe")
		return
	}

}
