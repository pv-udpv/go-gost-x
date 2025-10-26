package forwarder

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	dissector "github.com/go-gost/tls-dissector"
	xbypass "github.com/go-gost/x/bypass"
	"github.com/go-gost/x/config"
	xctx "github.com/go-gost/x/ctx"
	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	xhttp "github.com/go-gost/x/internal/net/http"
	"github.com/go-gost/x/internal/util/ja3"
	"github.com/go-gost/x/internal/util/sniffing"
	tls_util "github.com/go-gost/x/internal/util/tls"
	ws_util "github.com/go-gost/x/internal/util/ws"
	xstats "github.com/go-gost/x/observer/stats"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
	"golang.org/x/time/rate"
)

const (
	DefaultReadTimeout = 30 * time.Second
)

var (
	DefaultCertPool = tls_util.NewMemoryCertPool()
)

type HandleOptions struct {
	service        string
	dial           func(ctx context.Context, network, address string) (net.Conn, error)
	httpKeepalive  bool
	node           *chain.Node
	hop            hop.Hop
	bypass         bypass.Bypass
	recorderObject *xrecorder.HandlerRecorderObject
	log            logger.Logger
}

type HandleOption func(opts *HandleOptions)

func WithService(service string) HandleOption {
	return func(opts *HandleOptions) {
		opts.service = service
	}
}

func WithDial(dial func(ctx context.Context, network, address string) (net.Conn, error)) HandleOption {
	return func(opts *HandleOptions) {
		opts.dial = dial
	}
}

func WithHTTPKeepalive(keepalive bool) HandleOption {
	return func(opts *HandleOptions) {
		opts.httpKeepalive = keepalive
	}
}

func WithNode(node *chain.Node) HandleOption {
	return func(opts *HandleOptions) {
		opts.node = node
	}
}

func WithHop(hop hop.Hop) HandleOption {
	return func(opts *HandleOptions) {
		opts.hop = hop
	}
}

func WithBypass(bypass bypass.Bypass) HandleOption {
	return func(opts *HandleOptions) {
		opts.bypass = bypass
	}
}

func WithRecorderObject(ro *xrecorder.HandlerRecorderObject) HandleOption {
	return func(opts *HandleOptions) {
		opts.recorderObject = ro
	}
}

func WithLog(log logger.Logger) HandleOption {
	return func(opts *HandleOptions) {
		opts.log = log
	}
}

type Sniffer struct {
	Websocket           bool
	WebsocketSampleRate float64

	Recorder        recorder.Recorder
	RecorderOptions *recorder.Options

	// MITM TLS termination
	Certificate        *x509.Certificate
	PrivateKey         crypto.PrivateKey
	NegotiatedProtocol string
	CertPool           tls_util.CertPool
	MitmBypass         bypass.Bypass

	// JA3/JA4 fingerprint spoofing
	JA3                 string
	JA4                 string
	ClientHelloSpecFile string
	BrowserProfile      string

	ReadTimeout time.Duration
}

func (h *Sniffer) HandleHTTP(ctx context.Context, conn net.Conn, opts ...HandleOption) error {
	var ho HandleOptions
	for _, opt := range opts {
		opt(&ho)
	}

	if h.ReadTimeout <= 0 {
		h.ReadTimeout = DefaultReadTimeout
	}

	pStats := xstats.Stats{}
	conn = stats_wrapper.WrapConn(conn, &pStats)

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return err
	}

	if ho.log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		ho.log.Trace(string(dump))
	}

	ro := ho.recorderObject
	ro.HTTP = &xrecorder.HTTPRecorderObject{
		Host:   req.Host,
		Proto:  req.Proto,
		Scheme: req.URL.Scheme,
		Method: req.Method,
		URI:    req.RequestURI,
		Request: xrecorder.HTTPRequestRecorderObject{
			ContentLength: req.ContentLength,
			Header:        req.Header.Clone(),
		},
	}

	if clientIP := xhttp.GetClientIP(req); clientIP != nil {
		clientAddr := &net.TCPAddr{IP: clientIP}
		ro.ClientAddr = clientAddr.String()
		ctx = xctx.ContextWithSrcAddr(ctx, clientAddr)
	}

	// http/2
	if req.Method == "PRI" && len(req.Header) == 0 && req.URL.Path == "*" && req.Proto == "HTTP/2.0" {
		return h.serveH2(ctx, xnet.NewReadWriteConn(br, conn, conn), &ho)
	}

	node, cc, err := h.dial(ctx, conn, req, &ho)
	if err != nil {
		return err
	}
	defer cc.Close()

	ho.log = ho.log.WithFields(map[string]any{"src": cc.LocalAddr().String(), "dst": cc.RemoteAddr().String()})
	log := ho.log
	log.Debugf("connected to node %s(%s)", node.Name, node.Addr)

	ro.SrcAddr = cc.LocalAddr().String()
	ro.DstAddr = cc.RemoteAddr().String()
	ro.Time = time.Time{}

	shouldClose, err := h.httpRoundTrip(ctx, xio.NewReadWriteCloser(br, conn, conn), cc, node, req, &pStats, &ho)
	if err != nil || shouldClose {
		return err
	}

	for {
		pStats.Reset()

		req, err := http.ReadRequest(br)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		if log.IsLevelEnabled(logger.TraceLevel) {
			dump, _ := httputil.DumpRequest(req, false)
			log.Trace(string(dump))
		}

		if shouldClose, err := h.httpRoundTrip(ctx, xio.NewReadWriteCloser(br, conn, conn), cc, node, req, &pStats, &ho); err != nil || shouldClose {
			return err
		}
	}
}

func (h *Sniffer) dial(ctx context.Context, conn net.Conn, req *http.Request, ho *HandleOptions) (node *chain.Node, cc net.Conn, err error) {
	dial := ho.dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}

	if node = ho.node; node != nil {
		cc, err = dial(ctx, "tcp", node.Addr)
		return
	}

	ro := ho.recorderObject

	res := &http.Response{
		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
		Header:     http.Header{},
		StatusCode: http.StatusServiceUnavailable,
	}

	host := req.Host
	if host != "" {
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(strings.Trim(host, "[]"), "80")
		}
		ro.Host = host
		ho.log = ho.log.WithFields(map[string]any{
			"host": host,
		})

		if ho.bypass != nil &&
			ho.bypass.Contains(ctx, "tcp", host,
				bypass.WithService(ho.service),
				bypass.WithPathOption(req.RequestURI)) {
			ho.log.Debugf("bypass: %s %s", host, req.RequestURI)
			res.StatusCode = http.StatusForbidden
			ro.HTTP.StatusCode = res.StatusCode
			res.Write(conn)
			return nil, nil, xbypass.ErrBypass
		}
	}

	node = &chain.Node{}
	if ho.hop != nil {
		var clientIP net.IP
		if clientAddr, _ := net.ResolveTCPAddr("tcp", ro.ClientAddr); clientAddr != nil {
			clientIP = clientAddr.IP
		}

		node = ho.hop.Select(ctx,
			hop.ClientIPSelectOption(clientIP),
			hop.ProtocolSelectOption(sniffing.ProtoHTTP),
			hop.HostSelectOption(host),
			hop.MethodSelectOption(req.Method),
			hop.PathSelectOption(req.URL.Path),
			hop.QuerySelectOption(req.URL.Query()),
			hop.HeaderSelectOption(req.Header),
		)
	}
	if node == nil {
		ho.log.Warnf("node for %s not found", host)
		res.StatusCode = http.StatusBadGateway
		ro.HTTP.StatusCode = res.StatusCode
		res.Write(conn)
		return nil, nil, errors.New("node not available")
	}
	if node.Addr == "" {
		node = &chain.Node{
			Name: node.Name,
			Addr: host,
		}
	}

	ro.Host = node.Addr
	ho.log = ho.log.WithFields(map[string]any{
		"node": node.Name,
		"dst":  node.Addr,
	})
	ho.log.Debugf("find node for host %s -> %s(%s)", host, node.Name, node.Addr)

	cc, err = dial(ctx, "tcp", node.Addr)
	if err != nil {
		// TODO: the router itself may be failed due to the failed node in the router,
		// the dead marker may be a wrong operation.
		if marker := node.Marker(); marker != nil {
			marker.Mark()
		}
		ho.log.Warnf("connect to node %s(%s) failed: %v", node.Name, node.Addr, err)
		res.Write(conn)
		return
	}
	if marker := node.Marker(); marker != nil {
		marker.Reset()
	}

	if tlsSettings := node.Options().TLS; tlsSettings != nil {
		cfg := &tls.Config{
			ServerName:         tlsSettings.ServerName,
			InsecureSkipVerify: !tlsSettings.Secure,
		}
		tls_util.SetTLSOptions(cfg, &config.TLSOptions{
			MinVersion:   tlsSettings.Options.MinVersion,
			MaxVersion:   tlsSettings.Options.MaxVersion,
			CipherSuites: tlsSettings.Options.CipherSuites,
			ALPN:         tlsSettings.Options.ALPN,
		})
		cc = tls.Client(cc, cfg)
	}
	return
}

func (h *Sniffer) serveH2(ctx context.Context, conn net.Conn, ho *HandleOptions) error {
	const expectedBody = "SM\r\n\r\n"

	buf := make([]byte, len(expectedBody))
	n, err := io.ReadFull(conn, buf)
	if err != nil {
		return fmt.Errorf("h2: error reading client preface: %s", err)
	}
	if string(buf[:n]) != expectedBody {
		return errors.New("h2: invalid client preface")
	}

	ro := ho.recorderObject
	log := ho.log

	ro.Time = time.Time{}

	tr := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			node, cc, err := h.dialTLS(ctx, addr, ho)
			if err != nil {
				return nil, err
			}

			log = log.WithFields(map[string]any{"src": cc.LocalAddr().String(), "dst": cc.RemoteAddr().String()})
			ro.SrcAddr = cc.LocalAddr().String()
			ro.DstAddr = cc.RemoteAddr().String()
			log.Debugf("connected to node %s(%s)", node.Name, node.Addr)
			return cc, nil
		},
	}
	defer tr.CloseIdleConnections()

	(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{
		Context:          ctx,
		SawClientPreface: true,
		Handler: &h2Handler{
			transport:       tr,
			recorder:        h.Recorder,
			recorderOptions: h.RecorderOptions,
			recorderObject:  ro,
			log:             log,
		},
	})
	return nil
}

func (h *Sniffer) httpRoundTrip(ctx context.Context, rw, cc io.ReadWriteCloser, node *chain.Node, req *http.Request, pStats stats.Stats, ho *HandleOptions) (close bool, err error) {
	close = true

	log := ho.log
	ro := &xrecorder.HandlerRecorderObject{}
	*ro = *ho.recorderObject

	ro.Time = time.Now()
	log.Infof("%s <-> %s", ro.RemoteAddr, req.Host)
	defer func() {
		if err != nil {
			ro.Err = err.Error()
		}
		ro.InputBytes = pStats.Get(stats.KindInputBytes)
		ro.OutputBytes = pStats.Get(stats.KindOutputBytes)
		ro.Duration = time.Since(ro.Time)
		if err := ro.Record(ctx, h.Recorder); err != nil {
			log.Errorf("record: %v", err)
		}

		log.WithFields(map[string]any{
			"duration":    time.Since(ro.Time),
			"inputBytes":  ro.InputBytes,
			"outputBytes": ro.OutputBytes,
		}).Infof("%s >-< %s", ro.RemoteAddr, req.Host)
	}()

	ro.HTTP = &xrecorder.HTTPRecorderObject{
		Host:   req.Host,
		Proto:  req.Proto,
		Scheme: req.URL.Scheme,
		Method: req.Method,
		URI:    req.RequestURI,
		Request: xrecorder.HTTPRequestRecorderObject{
			ContentLength: req.ContentLength,
			Header:        req.Header.Clone(),
		},
	}

	res := &http.Response{
		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
		Header:     http.Header{},
		StatusCode: http.StatusServiceUnavailable,
	}

	// HTTP/1.0
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		if strings.ToLower(req.Header.Get("Connection")) == "keep-alive" {
			req.Header.Del("Connection")
		} else {
			req.Header.Set("Connection", "close")
		}
	}

	var responseHeader map[string]string
	var respBodyRewrites []chain.HTTPBodyRewriteSettings
	if httpSettings := node.Options().HTTP; httpSettings != nil {
		if auther := httpSettings.Auther; auther != nil {
			username, password, _ := req.BasicAuth()
			id, ok := auther.Authenticate(ctx, username, password, auth.WithService(ho.service))
			if !ok {
				res.StatusCode = http.StatusUnauthorized
				ro.HTTP.StatusCode = res.StatusCode
				res.Header.Set("WWW-Authenticate", "Basic")
				log.Warnf("node %s(%s) 401 unauthorized", node.Name, node.Addr)
				res.Write(rw)
				err = errors.New("unauthorized")
				return
			}
			ctx = xctx.ContextWithClientID(ctx, xctx.ClientID(id))
		}

		if httpSettings.Host != "" {
			req.Host = httpSettings.Host
		}
		for k, v := range httpSettings.RequestHeader {
			req.Header.Set(k, v)
		}

		for _, re := range httpSettings.RewriteURL {
			if re.Pattern.MatchString(req.URL.Path) {
				if s := re.Pattern.ReplaceAllString(req.URL.Path, re.Replacement); s != "" {
					req.URL.Path = s
					break
				}
			}
		}

		responseHeader = httpSettings.ResponseHeader
		respBodyRewrites = httpSettings.RewriteResponseBody
	}

	var reqBody *xhttp.Body
	if opts := h.RecorderOptions; opts != nil && opts.HTTPBody {
		if req.Body != nil {
			bodySize := opts.MaxBodySize
			if bodySize <= 0 {
				bodySize = sniffing.DefaultBodySize
			}
			if bodySize > sniffing.MaxBodySize {
				bodySize = sniffing.MaxBodySize
			}
			reqBody = xhttp.NewBody(req.Body, bodySize)
			req.Body = reqBody
		}
	}

	err = req.Write(cc)

	if reqBody != nil {
		ro.HTTP.Request.Body = reqBody.Content()
		ro.HTTP.Request.ContentLength = reqBody.Length()
	}

	if err != nil {
		res.Write(rw)
		return
	}

	br := bufio.NewReader(cc)
	var resp *http.Response
	for {
		xio.SetReadDeadline(cc, time.Now().Add(h.ReadTimeout))
		resp, err = http.ReadResponse(br, req)
		if err != nil {
			log.Errorf("read response: %v", err)
			res.Write(rw)
			return
		}
		if resp.StatusCode == http.StatusContinue {
			resp.Write(rw)
			resp.Body.Close()
			continue
		}

		break
	}
	defer resp.Body.Close()
	xio.SetReadDeadline(cc, time.Time{})

	if len(responseHeader) > 0 {
		if resp.Header == nil {
			resp.Header = http.Header{}
		}
		for k, v := range responseHeader {
			resp.Header.Set(k, v)
		}
	}

	ro.HTTP.StatusCode = resp.StatusCode
	ro.HTTP.Response.Header = resp.Header
	ro.HTTP.Response.ContentLength = resp.ContentLength

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Trace(string(dump))
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		h.handleUpgradeResponse(ctx, rw, cc, req, resp, ro, log)
		return
	}

	// HTTP/1.0
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		if !resp.Close {
			resp.Header.Set("Connection", "keep-alive")
		}
		resp.ProtoMajor = req.ProtoMajor
		resp.ProtoMinor = req.ProtoMinor
	}

	if !ho.httpKeepalive {
		resp.Header.Set("Connection", "close")
	}

	if err = h.rewriteRespBody(resp, respBodyRewrites...); err != nil {
		log.Errorf("rewrite body: %v", err)
		return
	}

	var respBody *xhttp.Body
	if opts := h.RecorderOptions; opts != nil && opts.HTTPBody {
		bodySize := opts.MaxBodySize
		if bodySize <= 0 {
			bodySize = sniffing.DefaultBodySize
		}
		if bodySize > sniffing.MaxBodySize {
			bodySize = sniffing.MaxBodySize
		}
		respBody = xhttp.NewBody(resp.Body, bodySize)
		resp.Body = respBody
	}

	err = resp.Write(rw)

	if respBody != nil {
		ro.HTTP.Response.Body = respBody.Content()
		ro.HTTP.Response.ContentLength = respBody.Length()
	}

	if err != nil {
		log.Errorf("write response: %v", err)
		return
	}

	if resp.ContentLength >= 0 {
		close = resp.Close
	}

	return
}

func upgradeType(h http.Header) string {
	if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") {
		return ""
	}
	return h.Get("Upgrade")
}

func (h *Sniffer) handleUpgradeResponse(ctx context.Context, rw, cc io.ReadWriteCloser, req *http.Request, res *http.Response, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	reqUpType := upgradeType(req.Header)
	resUpType := upgradeType(res.Header)
	if !strings.EqualFold(reqUpType, resUpType) {
		return fmt.Errorf("backend tried to switch protocol %q when %q was requested", resUpType, reqUpType)
	}

	res.Body = nil
	if err := res.Write(rw); err != nil {
		return fmt.Errorf("response write: %v", err)
	}

	if reqUpType == "websocket" && h.Websocket {
		return h.sniffingWebsocketFrame(ctx, rw, cc, ro, log)
	}

	// return xnet.Transport(rw, cc)
	return xnet.Pipe(ctx, rw, cc)
}

func (h *Sniffer) sniffingWebsocketFrame(ctx context.Context, rw, cc io.ReadWriter, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	errc := make(chan error, 1)

	sampleRate := h.WebsocketSampleRate
	if sampleRate == 0 {
		sampleRate = sniffing.DefaultSampleRate
	}
	if sampleRate < 0 {
		sampleRate = math.MaxFloat64
	}

	go func() {
		ro2 := &xrecorder.HandlerRecorderObject{}
		*ro2 = *ro
		ro := ro2

		limiter := rate.NewLimiter(rate.Limit(sampleRate), int(sampleRate))

		buf := &bytes.Buffer{}
		for {
			start := time.Now()

			if err := h.copyWebsocketFrame(cc, rw, buf, "client", ro); err != nil {
				errc <- err
				return
			}

			if limiter.Allow() {
				ro.Duration = time.Since(start)
				ro.Time = time.Now()
				if err := ro.Record(ctx, h.Recorder); err != nil {
					log.Errorf("record: %v", err)
				}
			}
		}
	}()

	go func() {
		ro2 := &xrecorder.HandlerRecorderObject{}
		*ro2 = *ro
		ro := ro2

		limiter := rate.NewLimiter(rate.Limit(sampleRate), int(sampleRate))

		buf := &bytes.Buffer{}
		for {
			start := time.Now()

			if err := h.copyWebsocketFrame(rw, cc, buf, "server", ro); err != nil {
				errc <- err
				return
			}

			if limiter.Allow() {
				ro.Duration = time.Since(start)
				ro.Time = time.Now()
				if err := ro.Record(ctx, h.Recorder); err != nil {
					log.Errorf("record: %v", err)
				}
			}
		}
	}()

	<-errc
	return nil
}

func (h *Sniffer) copyWebsocketFrame(w io.Writer, r io.Reader, buf *bytes.Buffer, from string, ro *xrecorder.HandlerRecorderObject) (err error) {
	fr := ws_util.Frame{}
	if _, err = fr.ReadFrom(r); err != nil {
		return err
	}

	ws := &xrecorder.WebsocketRecorderObject{
		From:    from,
		Fin:     fr.Header.Fin,
		Rsv1:    fr.Header.Rsv1,
		Rsv2:    fr.Header.Rsv2,
		Rsv3:    fr.Header.Rsv3,
		OpCode:  int(fr.Header.OpCode),
		Masked:  fr.Header.Masked,
		MaskKey: fr.Header.MaskKey,
		Length:  fr.Header.PayloadLength,
	}
	if opts := h.RecorderOptions; opts != nil && opts.HTTPBody {
		bodySize := opts.MaxBodySize
		if bodySize <= 0 {
			bodySize = sniffing.DefaultBodySize
		}
		if bodySize > sniffing.MaxBodySize {
			bodySize = sniffing.MaxBodySize
		}

		buf.Reset()
		if _, err := io.Copy(buf, io.LimitReader(fr.Data, int64(bodySize))); err != nil {
			return err
		}
		ws.Payload = buf.Bytes()
	}

	ro.Websocket = ws
	length := uint64(fr.Header.Length()) + uint64(fr.Header.PayloadLength)
	if from == "client" {
		ro.InputBytes = length
		ro.OutputBytes = 0
	} else {
		ro.InputBytes = 0
		ro.OutputBytes = length
	}

	fr.Data = io.MultiReader(bytes.NewReader(buf.Bytes()), fr.Data)
	if _, err := fr.WriteTo(w); err != nil {
		return err
	}

	return nil
}

func (h *Sniffer) rewriteRespBody(resp *http.Response, rewrites ...chain.HTTPBodyRewriteSettings) error {
	if resp == nil || len(rewrites) == 0 || resp.ContentLength <= 0 {
		return nil
	}

	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" {
		return nil
	}

	body, err := drainBody(resp.Body)
	if err != nil || body == nil {
		return err
	}

	contentType, _, _ := strings.Cut(resp.Header.Get("Content-Type"), ";")
	for _, rewrite := range rewrites {
		rewriteType := rewrite.Type
		if rewriteType == "" {
			rewriteType = "text/html"
		}
		if rewriteType != "*" && !strings.Contains(rewriteType, contentType) {
			continue
		}

		body = rewrite.Pattern.ReplaceAll(body, rewrite.Replacement)
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))

	return nil
}

func drainBody(b io.ReadCloser) (body []byte, err error) {
	if b == nil || b == http.NoBody {
		// No copying needed. Preserve the magic sentinel meaning of NoBody.
		return nil, nil
	}
	var buf bytes.Buffer
	if _, err = buf.ReadFrom(b); err != nil {
		return nil, err
	}
	if err = b.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (h *Sniffer) HandleTLS(ctx context.Context, conn net.Conn, opts ...HandleOption) error {
	var ho HandleOptions
	for _, opt := range opts {
		opt(&ho)
	}

	if h.ReadTimeout <= 0 {
		h.ReadTimeout = DefaultReadTimeout
	}

	buf := new(bytes.Buffer)
	clientHello, err := dissector.ParseClientHello(io.TeeReader(conn, buf))
	if err != nil {
		return err
	}

	ro := ho.recorderObject
	ro.TLS = &xrecorder.TLSRecorderObject{
		ServerName:  clientHello.ServerName,
		ClientHello: hex.EncodeToString(buf.Bytes()),
	}
	if len(clientHello.SupportedProtos) > 0 {
		ro.TLS.Proto = clientHello.SupportedProtos[0]
	}

	// ctx = xctx.ContextWithClientAddr(ctx, xctx.ClientAddr(ro.RemoteAddr))

	host := clientHello.ServerName
	if host != "" {
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(strings.Trim(host, "[]"), "443")
		}
		ro.Host = host

		if ho.bypass != nil && ho.bypass.Contains(ctx, "tcp", host, bypass.WithService(ho.service)) {
			return xbypass.ErrBypass
		}
	}

	node, cc, err := h.dialTLS(ctx, host, &ho)
	if err != nil {
		return err
	}
	defer cc.Close()
	ho.node = node

	log := ho.log.WithFields(map[string]any{"src": cc.LocalAddr().String(), "dst": cc.RemoteAddr().String()})
	log.Debugf("connected to node %s(%s)", node.Name, node.Addr)

	ro.SrcAddr = cc.LocalAddr().String()
	ro.DstAddr = cc.RemoteAddr().String()

	if h.Certificate != nil && h.PrivateKey != nil &&
		len(clientHello.SupportedProtos) > 0 && (clientHello.SupportedProtos[0] == "h2" || clientHello.SupportedProtos[0] == "http/1.1") {
		if host == "" {
			host = ro.Host
		}
		if h.MitmBypass == nil || !h.MitmBypass.Contains(ctx, "tcp", host) {
			return h.terminateTLS(ctx, xnet.NewReadWriteConn(io.MultiReader(buf, conn), conn, conn), cc, clientHello, &ho)
		}
	}

	if _, err := buf.WriteTo(cc); err != nil {
		return err
	}

	xio.SetReadDeadline(cc, time.Now().Add(h.ReadTimeout))
	serverHello, err := dissector.ParseServerHello(io.TeeReader(cc, buf))
	xio.SetReadDeadline(cc, time.Time{})

	if serverHello != nil {
		ro.TLS.CipherSuite = tls_util.CipherSuite(serverHello.CipherSuite).String()
		ro.TLS.CompressionMethod = serverHello.CompressionMethod
		if serverHello.Proto != "" {
			ro.TLS.Proto = serverHello.Proto
		}
		if serverHello.Version > 0 {
			ro.TLS.Version = tls_util.Version(serverHello.Version).String()
		}
	}

	if buf.Len() > 0 {
		ro.TLS.ServerHello = hex.EncodeToString(buf.Bytes())
	}

	if _, err := buf.WriteTo(conn); err != nil {
		return err
	}

	log.Infof("%s <-> %s", ro.RemoteAddr, ro.Host)
	// xnet.Transport(conn, cc)
	xnet.Pipe(ctx, conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(ro.Time),
	}).Infof("%s >-< %s", ro.RemoteAddr, ro.Host)

	return err
}

func (h *Sniffer) dialTLS(ctx context.Context, host string, ho *HandleOptions) (node *chain.Node, cc net.Conn, err error) {
	dial := ho.dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}

	if node = ho.node; node != nil {
		cc, err = dial(ctx, "tcp", node.Addr)
		return
	}

	node = &chain.Node{}

	ro := ho.recorderObject
	if ho.hop != nil {
		var clientIP net.IP
		if clientAddr, _ := net.ResolveTCPAddr("tcp", ro.ClientAddr); clientAddr != nil {
			clientIP = clientAddr.IP
		}

		node = ho.hop.Select(ctx,
			hop.ClientIPSelectOption(clientIP),
			hop.HostSelectOption(host),
			hop.ProtocolSelectOption(sniffing.ProtoTLS),
		)
	}
	if node == nil {
		err = errors.New("node not available")
		return
	}
	if node.Addr == "" {
		node = &chain.Node{
			Name: node.Name,
			Addr: host,
		}
	}

	addr := node.Addr
	if opts := node.Options(); opts != nil {
		switch opts.Network {
		case "unix":
			ro.Network = opts.Network
		default:
			if _, _, err := net.SplitHostPort(addr); err != nil {
				addr += ":443"
			}
		}
	}
	ro.Host = addr

	ho.log = ho.log.WithFields(map[string]any{
		"host": host,
		"node": node.Name,
		"dst":  fmt.Sprintf("%s/%s", addr, ro.Network),
	})
	ho.log.Debugf("find node for host %s -> %s(%s)", host, node.Name, addr)

	cc, err = dial(ctx, ro.Network, addr)
	if err != nil {
		// TODO: the router itself may be failed due to the failed node in the router,
		// the dead marker may be a wrong operation.
		if marker := node.Marker(); marker != nil {
			marker.Mark()
		}
		ho.log.Warnf("connect to node %s(%s) failed: %v", node.Name, node.Addr, err)
		return
	}

	if marker := node.Marker(); marker != nil {
		marker.Reset()
	}

	if tlsSettings := node.Options().TLS; tlsSettings != nil {
		cfg := &tls.Config{
			ServerName:         tlsSettings.ServerName,
			InsecureSkipVerify: !tlsSettings.Secure,
		}
		tls_util.SetTLSOptions(cfg, &config.TLSOptions{
			MinVersion:   tlsSettings.Options.MinVersion,
			MaxVersion:   tlsSettings.Options.MaxVersion,
			CipherSuites: tlsSettings.Options.CipherSuites,
			ALPN:         tlsSettings.Options.ALPN,
		})
		cc = tls.Client(cc, cfg)
	}
	return
}

func (h *Sniffer) terminateTLS(ctx context.Context, conn, cc net.Conn, clientHello *dissector.ClientHelloInfo, ho *HandleOptions) error {
	ro := ho.recorderObject
	log := ho.log

	nextProtos := clientHello.SupportedProtos
	if h.NegotiatedProtocol != "" {
		nextProtos = []string{h.NegotiatedProtocol}
	}

	cfg := &tls.Config{
		ServerName:   clientHello.ServerName,
		NextProtos:   nextProtos,
		CipherSuites: clientHello.CipherSuites,
	}
	if cfg.ServerName == "" {
		cfg.InsecureSkipVerify = true
	}

	var clientConn net.Conn
	var err error

	// Use custom JA3/JA4 fingerprint if configured
	if h.JA3 != "" || h.ClientHelloSpecFile != "" || h.BrowserProfile != "" {
		log.Debugf("using custom TLS fingerprint for upstream connection to %s", clientHello.ServerName)

		ja3Config := &ja3.TLSDialerConfig{
			JA3:                 h.JA3,
			ClientHelloSpecFile: h.ClientHelloSpecFile,
			BrowserProfile:      h.BrowserProfile,
			ServerName:          clientHello.ServerName,
			ALPNProtocols:       nextProtos,
			TLSConfig:           cfg,
		}

		// cc is already the TCP connection to upstream
		// We need to upgrade it to TLS with custom fingerprint
		clientConn, err = ja3.UpgradeConnWithFingerprint(ctx, cc, ja3Config)
		if err != nil {
			return fmt.Errorf("failed to establish TLS with custom fingerprint: %w", err)
		}
	} else {
		// Standard TLS handshake
		clientConn = tls.Client(cc, cfg)
		if err = clientConn.(*tls.Conn).HandshakeContext(ctx); err != nil {
			return err
		}
	}

	// Extract connection state
	var cs tls.ConnectionState
	if tlsConn, ok := clientConn.(*tls.Conn); ok {
		cs = tlsConn.ConnectionState()
	} else {
		// For uTLS connection, we need to get the state differently
		cs = clientConn.(interface{ ConnectionState() tls.ConnectionState }).ConnectionState()
	}

	ro.TLS.CipherSuite = tls_util.CipherSuite(cs.CipherSuite).String()
	ro.TLS.Proto = cs.NegotiatedProtocol
	ro.TLS.Version = tls_util.Version(cs.Version).String()

	host := cfg.ServerName
	if host == "" {
		if host = cs.PeerCertificates[0].Subject.CommonName; host == "" {
			host = ro.Host
		}
	}
	if h, _, _ := net.SplitHostPort(host); h != "" {
		host = h
	}

	negotiatedProtocol := cs.NegotiatedProtocol
	if h.NegotiatedProtocol != "" {
		negotiatedProtocol = h.NegotiatedProtocol
	}
	nextProtos = nil
	if negotiatedProtocol != "" {
		nextProtos = []string{negotiatedProtocol}
	}

	// cache the tls server handshake record.
	wb := &bytes.Buffer{}
	conn = xnet.NewReadWriteConn(conn, io.MultiWriter(wb, conn), conn)

	serverConn := tls.Server(conn, &tls.Config{
		NextProtos: nextProtos,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			certPool := h.CertPool
			if certPool == nil {
				certPool = DefaultCertPool
			}
			serverName := chi.ServerName
			if serverName == "" {
				serverName = host
			}
			cert, err := certPool.Get(serverName)
			if cert != nil {
				pool := x509.NewCertPool()
				pool.AddCert(h.Certificate)
				if _, err = cert.Verify(x509.VerifyOptions{
					DNSName: serverName,
					Roots:   pool,
				}); err != nil {
					log.Warnf("verify cached certificate for %s: %v", serverName, err)
					cert = nil
				}
			}
			if cert == nil {
				cert, err = tls_util.GenerateCertificate(serverName, 7*24*time.Hour, h.Certificate, h.PrivateKey)
				certPool.Put(serverName, cert)
			}
			if err != nil {
				return nil, err
			}

			return &tls.Certificate{
				Certificate: [][]byte{cert.Raw},
				PrivateKey:  h.PrivateKey,
			}, nil
		},
	})
	handshakeErr := serverConn.HandshakeContext(ctx)
	if record, _ := dissector.ReadRecord(wb); record != nil {
		wb.Reset()
		record.WriteTo(wb)
		ro.TLS.ServerHello = hex.EncodeToString(wb.Bytes())
	}
	if handshakeErr != nil {
		return handshakeErr
	}

	opts := []HandleOption{
		WithDial(func(ctx context.Context, network, address string) (net.Conn, error) {
			return clientConn, nil
		}),
		WithHTTPKeepalive(true),
		WithNode(ho.node),
		WithRecorderObject(ro),
		WithLog(log),
	}
	return h.HandleHTTP(ctx, serverConn, opts...)
}

type h2Handler struct {
	transport       http.RoundTripper
	recorder        recorder.Recorder
	recorderOptions *recorder.Options
	recorderObject  *xrecorder.HandlerRecorderObject
	log             logger.Logger
}

func (h *h2Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := h.log

	ro := &xrecorder.HandlerRecorderObject{}
	*ro = *h.recorderObject
	ro.Time = time.Now()

	var err error
	log.Infof("%s <-> %s", ro.RemoteAddr, r.Host)
	defer func() {
		ro.Duration = time.Since(ro.Time)
		if err != nil {
			ro.Err = err.Error()
		}
		if err := ro.Record(r.Context(), h.recorder); err != nil {
			log.Errorf("record: %v", err)
		}

		log.WithFields(map[string]any{
			"duration": time.Since(ro.Time),
		}).Infof("%s >-< %s", ro.RemoteAddr, r.Host)
	}()

	if clientIP := xhttp.GetClientIP(r); clientIP != nil {
		ro.ClientIP = clientIP.String()
	}
	ro.HTTP = &xrecorder.HTTPRecorderObject{
		Host:   r.Host,
		Proto:  r.Proto,
		Scheme: "https",
		Method: r.Method,
		URI:    r.RequestURI,
		Request: xrecorder.HTTPRequestRecorderObject{
			ContentLength: r.ContentLength,
			Header:        r.Header.Clone(),
		},
	}

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(r, false)
		log.Trace(string(dump))
	}

	url := r.URL
	url.Scheme = "https"
	url.Host = r.Host
	req := &http.Request{
		Method:        r.Method,
		URL:           url,
		Host:          r.Host,
		Header:        r.Header,
		Body:          r.Body,
		ContentLength: r.ContentLength,
		Trailer:       r.Trailer,
	}

	var reqBody *xhttp.Body
	if opts := h.recorderOptions; opts != nil && opts.HTTPBody {
		if req.Body != nil {
			bodySize := opts.MaxBodySize
			if bodySize <= 0 {
				bodySize = sniffing.DefaultBodySize
			}
			if bodySize > sniffing.MaxBodySize {
				bodySize = sniffing.MaxBodySize
			}
			reqBody = xhttp.NewBody(req.Body, bodySize)
			req.Body = reqBody
		}
	}

	resp, err := h.transport.RoundTrip(req.WithContext(r.Context()))
	if reqBody != nil {
		ro.HTTP.Request.Body = reqBody.Content()
		ro.HTTP.Request.ContentLength = reqBody.Length()
	}
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	ro.HTTP.StatusCode = resp.StatusCode
	ro.HTTP.Response.Header = resp.Header
	ro.HTTP.Response.ContentLength = resp.ContentLength

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Trace(string(dump))
	}

	h.setHeader(w, resp.Header)
	w.WriteHeader(resp.StatusCode)

	var respBody *xhttp.Body
	if opts := h.recorderOptions; opts != nil && opts.HTTPBody {
		bodySize := opts.MaxBodySize
		if bodySize <= 0 {
			bodySize = sniffing.DefaultBodySize
		}
		if bodySize > sniffing.MaxBodySize {
			bodySize = sniffing.MaxBodySize
		}
		respBody = xhttp.NewBody(resp.Body, bodySize)
		resp.Body = respBody
	}

	io.Copy(w, resp.Body)

	if respBody != nil {
		ro.HTTP.Response.Body = respBody.Content()
		ro.HTTP.Response.ContentLength = respBody.Length()
	}
}

func (h *h2Handler) setHeader(w http.ResponseWriter, header http.Header) {
	for k, v := range header {
		for i := range v {
			w.Header().Add(k, v[i])
		}
	}
}
