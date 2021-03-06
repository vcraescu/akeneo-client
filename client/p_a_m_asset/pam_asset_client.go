// Code generated by go-swagger; DO NOT EDIT.

package p_a_m_asset

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new p a m asset API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for p a m asset API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientService is the interface for Client methods
type ClientService interface {
	GetPamAssets(params *GetPamAssetsParams) (*GetPamAssetsOK, error)

	GetPamAssetsCode(params *GetPamAssetsCodeParams) (*GetPamAssetsCodeOK, error)

	PatchPamAssets(params *PatchPamAssetsParams) (*PatchPamAssetsOK, error)

	PatchPamAssetsCode(params *PatchPamAssetsCodeParams) (*PatchPamAssetsCodeCreated, *PatchPamAssetsCodeNoContent, error)

	PostPamAssets(params *PostPamAssetsParams) (*PostPamAssetsCreated, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  GetPamAssets gets list of p a m assets

  This endpoint allows you to get a list of PAM assets. PAM assets are paginated.
*/
func (a *Client) GetPamAssets(params *GetPamAssetsParams) (*GetPamAssetsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetPamAssetsParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "get_pam_assets",
		Method:             "GET",
		PathPattern:        "/api/rest/v1/assets",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetPamAssetsReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetPamAssetsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for get_pam_assets: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetPamAssetsCode gets a p a m asset

  This endpoint allows you to get the information about a given PAM asset.
*/
func (a *Client) GetPamAssetsCode(params *GetPamAssetsCodeParams) (*GetPamAssetsCodeOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetPamAssetsCodeParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "get_pam_assets__code_",
		Method:             "GET",
		PathPattern:        "/api/rest/v1/assets/{code}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetPamAssetsCodeReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetPamAssetsCodeOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for get_pam_assets__code_: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  PatchPamAssets updates create several p a m assets

  This endpoint allows you to update several PAM assets at once.
*/
func (a *Client) PatchPamAssets(params *PatchPamAssetsParams) (*PatchPamAssetsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPatchPamAssetsParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "patch_pam_assets",
		Method:             "PATCH",
		PathPattern:        "/api/rest/v1/assets",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &PatchPamAssetsReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*PatchPamAssetsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for patch_pam_assets: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  PatchPamAssetsCode updates create a p a m asset

  This endpoint allows you to update a given PAM asset. Know more about <a href="/documentation/update.html#update-behavior">Update behavior</a>. Note that if no asset exists for the given code, it creates it.
*/
func (a *Client) PatchPamAssetsCode(params *PatchPamAssetsCodeParams) (*PatchPamAssetsCodeCreated, *PatchPamAssetsCodeNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPatchPamAssetsCodeParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "patch_pam_assets__code_",
		Method:             "PATCH",
		PathPattern:        "/api/rest/v1/assets/{code}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &PatchPamAssetsCodeReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *PatchPamAssetsCodeCreated:
		return value, nil, nil
	case *PatchPamAssetsCodeNoContent:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for p_a_m_asset: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  PostPamAssets creates a new p a m asset

  This endpoint allows you to create a new PAM asset.
*/
func (a *Client) PostPamAssets(params *PostPamAssetsParams) (*PostPamAssetsCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPostPamAssetsParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "post_pam_assets",
		Method:             "POST",
		PathPattern:        "/api/rest/v1/assets",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &PostPamAssetsReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*PostPamAssetsCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for post_pam_assets: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
