package aws

import (
	"fmt"
	"net/http"

	"github.com/golang/glog"
	"github.com/heptiolabs/kubernetes-aws-authenticator/pkg/token"
	"k8s.io/apimachinery/pkg/util/net"
	restclient "k8s.io/client-go/rest"
)

func init() {
	if err := restclient.RegisterAuthProviderPlugin("aws", newAWSAuthProvider); err != nil {
		glog.Fatalf("Failed to register aws auth plugin: %v", err)
	}
}

type awsAuthProvider struct {
	source tokenSource
}

func (g *awsAuthProvider) Login() error { return nil }

func (p *awsAuthProvider) WrapTransport(rt http.RoundTripper) http.RoundTripper {
	return &awsRoundTripper{
		tokenSource:  p.source,
		roundTripper: rt,
	}
}

type awsRoundTripper struct {
	tokenSource  tokenSource
	roundTripper http.RoundTripper
}

func newAWSAuthProvider(_ string, cfg map[string]string, persister restclient.AuthProviderConfigPersister) (restclient.AuthProvider, error) {
	var ts tokenSource

	ts, err := newAWSTokenSource(cfg)
	if err != nil {
		return nil, fmt.Errorf("")
	}

	return &awsAuthProvider{
		source: ts,
	}, nil
}

var _ net.RoundTripperWrapper = &awsRoundTripper{}

func (r *awsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {

	if len(req.Header.Get("Authorization")) != 0 {
		return r.roundTripper.RoundTrip(req)
	}

	token, err := r.tokenSource.Token()
	if err != nil {
		glog.Errorf("Failed to acquire a token: %v", err)
		return nil, fmt.Errorf("acquiring a token for authorization header: %v", err)
	}

	// clone the request in order to avoid modifying the headers of the original request
	req2 := new(http.Request)
	*req2 = *req
	req2.Header = make(http.Header, len(req.Header))
	for k, s := range req.Header {
		req2.Header[k] = append([]string(nil), s...)
	}

	req2.Header.Set("Authorization", fmt.Sprintf("%s %s", "Bearer", token))

	res, err := r.roundTripper.RoundTrip(req2)
	if err != nil {
		return nil, err
	}

	// Do we want to empty stored creds on 401?
	if res.StatusCode == 401 {
		glog.V(4).Infof("The credentials that were supplied are invalid for the target cluster")
		// TO DO empty cache
	}

	return res, nil
}

func (r *awsRoundTripper) WrappedRoundTripper() http.RoundTripper { return r.roundTripper }

type tokenSource interface {
	Token() (string, error)
}

type awsTokenSource struct {
	source    tokenSource
	cfg       map[string]string
	persister restclient.AuthProviderConfigPersister
}

func newAWSTokenSource(cfg map[string]string) (*awsTokenSource, error) {
	return &awsTokenSource{
		cfg: cfg,
	}, nil
}

func (ts *awsTokenSource) Token() (string, error) {
	return token.Get(ts.cfg["cluster-id"])
}
