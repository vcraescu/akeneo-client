package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/vcraescu/akeneo-client/client"
	"github.com/vcraescu/akeneo-client/internal/runtime"
)

type config struct {
	clientID     *string
	secret       *string
	username     *string
	password     *string
	token        *string
	refreshToken *string
	baseURI      string
	context      context.Context
	debug        bool
	client       *http.Client
}

type Option func(cfg *config)

func WithClientID(clientID string) Option {
	return func(cfg *config) {
		cfg.clientID = &clientID
	}
}

func WithSecret(secret string) Option {
	return func(cfg *config) {
		cfg.secret = &secret
	}
}

func WithUsername(username string) Option {
	return func(cfg *config) {
		cfg.username = &username
	}
}

func WithPassword(password string) Option {
	return func(cfg *config) {
		cfg.password = &password
	}
}

func WithToken(token string) Option {
	return func(cfg *config) {
		cfg.token = &token
	}
}

func WithRefreshToken(refreshToken string) Option {
	return func(cfg *config) {
		cfg.refreshToken = &refreshToken
	}
}

func WithDebug(debug bool) Option {
	return func(cfg *config) {
		cfg.debug = debug
	}
}

func WithContext(ctx context.Context) Option {
	return func(cfg *config) {
		cfg.context = ctx
	}
}

func WithBaseURI(baseURI string) Option {
	return func(cfg *config) {
		cfg.baseURI = baseURI
	}
}

func WithClient(client *http.Client) Option {
	return func(cfg *config) {
		cfg.client = client
	}
}

func NewAuthenticatedByPassword(options ...Option) (*client.Akeneo, error) {
	cfg := &config{
		context: context.Background(),
	}

	for _, option := range options {
		option(cfg)
	}

	transCfg, err := configToTransportConfig(cfg)
	if err != nil {
		return nil, err
	}

	var transport *runtime.AuthenticatedRuntime
	if cfg.client == nil {
		transport = runtime.NewAuthenticated(
			transCfg,
			runtime.NewAuthenticationWithPassword(*cfg.clientID, *cfg.secret, *cfg.username, *cfg.password),
		)
	} else {
		transport = runtime.NewAuthenticatedWithClient(
			transCfg,
			runtime.NewAuthenticationWithPassword(*cfg.clientID, *cfg.secret, *cfg.username, *cfg.password),
			cfg.client,
		)
	}

	if cfg.context != nil {
		transport.Context = cfg.context
	}

	transport.SetDebug(cfg.debug)

	return client.New(transport, nil), nil
}

func NewAuthenticatedByToken(options ...Option) (*client.Akeneo, error) {
	cfg := &config{
		context: context.Background(),
	}
	for _, option := range options {
		option(cfg)
	}

	transCfg, err := configToTransportConfig(cfg)
	if err != nil {
		return nil, err
	}

	transport := runtime.NewAuthenticated(
		transCfg,
		runtime.NewAuthenticationWithToken(*cfg.clientID, *cfg.secret, *cfg.token, *cfg.refreshToken),
	)
	transport.SetDebug(cfg.debug)

	return client.New(transport, nil), nil
}

func configToTransportConfig(cfg *config) (*client.TransportConfig, error) {
	uri, err := url.Parse(cfg.baseURI)
	if err != nil {
		return nil, fmt.Errorf("failed parsing base URI '%s': %w", cfg.baseURI, err)
	}

	if uri.Host == "" {
		return nil, fmt.Errorf("invalid base URI; host is missing: %s", cfg.baseURI)
	}

	scheme := "https"
	if uri.Scheme != "" {
		scheme = uri.Scheme
	}

	basePath := "/"
	if uri.Path != "" {
		basePath = uri.Path
	}

	return &client.TransportConfig{
		Host:     uri.Host,
		BasePath: basePath,
		Schemes:  []string{scheme},
	}, nil
}
