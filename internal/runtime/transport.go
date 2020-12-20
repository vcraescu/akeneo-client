package runtime

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/vcraescu/akeneo-client/client"
	"github.com/vcraescu/akeneo-client/client/authentication"
)

type Authentication struct {
	clientID     *string
	secret       *string
	username     *string
	password     *string
	accessToken  *string
	refreshToken *string
}

func NewAuthenticationWithPassword(clientID, secret, username, password string) Authentication {
	return Authentication{
		clientID: &clientID,
		secret:   &secret,
		username: &username,
		password: &password,
	}
}

func NewAuthenticationWithToken(clientID, secret, accessToken, refreshToken string) Authentication {
	return Authentication{
		clientID:     &clientID,
		secret:       &secret,
		accessToken:  &accessToken,
		refreshToken: &refreshToken,
	}
}

type AuthenticatedRuntime struct {
	*httptransport.Runtime
}

type ClientAuth struct {
	host           string
	basePath       string
	schemes        []string
	authentication Authentication
	context        context.Context
}

func NewClientAuth(
	ctx context.Context,
	host, basePath string,
	schemes []string,
	authentication Authentication,
) *ClientAuth {
	return &ClientAuth{
		host:           host,
		basePath:       basePath,
		schemes:        schemes,
		authentication: authentication,
		context:        ctx,
	}
}

func (a *ClientAuth) requestToken(formats strfmt.Registry) error {
	grantType := "password"
	token := base64.StdEncoding.EncodeToString(
		[]byte(fmt.Sprintf(
			"%s:%s",
			*a.authentication.clientID,
			*a.authentication.secret,
		)),
	)

	postTokenParams := authentication.NewPostTokenParamsWithContext(a.context).
		WithAuthorization(fmt.Sprintf("Basic %s", token)).
		WithBody(
			authentication.PostTokenBody{
				GrantType: &grantType,
				Password:  a.authentication.password,
				Username:  a.authentication.username,
			},
		)

	authService := authentication.New(
		httptransport.New(a.host, a.basePath, a.schemes),
		formats,
	)
	res, err := authService.PostToken(postTokenParams)
	if err != nil {
		return err
	}

	a.authentication.accessToken = &res.GetPayload().AccessToken
	a.authentication.refreshToken = &res.GetPayload().RefreshToken

	return nil
}

func (a *ClientAuth) AuthenticateRequest(req runtime.ClientRequest, formats strfmt.Registry) error {
	if a.authentication.accessToken == nil {
		if err := a.requestToken(formats); err != nil {
			return err
		}
	}

	w := httptransport.BearerToken(*a.authentication.accessToken)
	if err := w.AuthenticateRequest(req, formats); err != nil {
		if err, ok := err.(errors.Error); ok {
			if err.Code() == http.StatusUnauthorized {
			}
		}
		return err
	}

	return nil
}

func NewAuthenticated(
	config *client.TransportConfig,
	auth Authentication,
) *AuthenticatedRuntime {
	ctx := context.Background()
	transport := httptransport.New(config.Host, config.BasePath, config.Schemes)
	transport.Context = ctx
	transport.DefaultAuthentication = NewClientAuth(ctx, config.Host, config.BasePath, config.Schemes, auth)

	return &AuthenticatedRuntime{
		transport,
	}
}

func NewAuthenticatedWithClient(
	config *client.TransportConfig,
	auth Authentication,
	client *http.Client,
) *AuthenticatedRuntime {
	ctx := context.Background()
	transport := httptransport.NewWithClient(config.Host, config.BasePath, config.Schemes, client)
	transport.Context = ctx
	transport.DefaultAuthentication = NewClientAuth(ctx, config.Host, config.BasePath, config.Schemes, auth)

	return &AuthenticatedRuntime{
		Runtime: transport,
	}
}
