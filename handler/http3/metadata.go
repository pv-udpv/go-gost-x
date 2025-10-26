package http3

import (
	"net/http"
	"strings"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	probeResistance *probeResistance
	header          http.Header
	hash            string
	ja4             string
	ja4Hash         string
	clientHelloFile string
	browserProfile  string
}

func (h *http3Handler) parseMetadata(md mdata.Metadata) error {
	if m := mdutil.GetStringMapString(md, "header"); len(m) > 0 {
		hd := http.Header{}
		for k, v := range m {
			hd.Add(k, v)
		}
		h.md.header = hd
	}

	pr := mdutil.GetString(md, "probeResistance", "probe_resist")
	if pr != "" {
		if ss := strings.SplitN(pr, ":", 2); len(ss) == 2 {
			h.md.probeResistance = &probeResistance{
				Type:  ss[0],
				Value: ss[1],
				Knock: mdutil.GetString(md, "knock"),
			}
		}
	}
	h.md.hash = mdutil.GetString(md, "hash")

	// Parse JA4 fingerprinting configuration
	h.md.ja4 = mdutil.GetString(md, "ja4")
	h.md.ja4Hash = mdutil.GetString(md, "ja4Hash")
	h.md.clientHelloFile = mdutil.GetString(md, "clientHelloSpecFile")
	h.md.browserProfile = mdutil.GetString(md, "browserProfile")

	return nil
}

type probeResistance struct {
	Type  string
	Value string
	Knock string
}
