// Code generated by go-swagger; DO NOT EDIT.

package family

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new family API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for family API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientService is the interface for Client methods
type ClientService interface {
	GetFamilies(params *GetFamiliesParams) (*GetFamiliesOK, error)

	GetFamiliesCode(params *GetFamiliesCodeParams) (*GetFamiliesCodeOK, error)

	PatchFamilies(params *PatchFamiliesParams) (*PatchFamiliesOK, error)

	PatchFamiliesCode(params *PatchFamiliesCodeParams) (*PatchFamiliesCodeCreated, *PatchFamiliesCodeNoContent, error)

	PostFamilies(params *PostFamiliesParams) (*PostFamiliesCreated, error)

	PostFamiliesFamilyCodeVariants(params *PostFamiliesFamilyCodeVariantsParams) (*PostFamiliesFamilyCodeVariantsCreated, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  GetFamilies gets list of families

  This endpoint allows you to get a list of families. Families are paginated and sorted by code.
*/
func (a *Client) GetFamilies(params *GetFamiliesParams) (*GetFamiliesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetFamiliesParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "get_families",
		Method:             "GET",
		PathPattern:        "/api/rest/v1/families",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetFamiliesReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetFamiliesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for get_families: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetFamiliesCode gets a family

  This endpoint allows you to get the information about a given family.
*/
func (a *Client) GetFamiliesCode(params *GetFamiliesCodeParams) (*GetFamiliesCodeOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetFamiliesCodeParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "get_families__code_",
		Method:             "GET",
		PathPattern:        "/api/rest/v1/families/{code}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetFamiliesCodeReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetFamiliesCodeOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for get_families__code_: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  PatchFamilies updates create several families

  This endpoint allows you to update and/or create several families at once.
*/
func (a *Client) PatchFamilies(params *PatchFamiliesParams) (*PatchFamiliesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPatchFamiliesParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "patch_families",
		Method:             "PATCH",
		PathPattern:        "/api/rest/v1/families",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &PatchFamiliesReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*PatchFamiliesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for patch_families: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  PatchFamiliesCode updates create a family

  This endpoint allows you to update a given family. Know more about <a href="/documentation/update.html#update-behavior">Update behavior</a>. Note that if no family exists for the given code, it creates it.
*/
func (a *Client) PatchFamiliesCode(params *PatchFamiliesCodeParams) (*PatchFamiliesCodeCreated, *PatchFamiliesCodeNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPatchFamiliesCodeParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "patch_families__code_",
		Method:             "PATCH",
		PathPattern:        "/api/rest/v1/families/{code}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &PatchFamiliesCodeReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *PatchFamiliesCodeCreated:
		return value, nil, nil
	case *PatchFamiliesCodeNoContent:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for family: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  PostFamilies creates a new family

  This endpoint allows you to create a new family.
*/
func (a *Client) PostFamilies(params *PostFamiliesParams) (*PostFamiliesCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPostFamiliesParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "post_families",
		Method:             "POST",
		PathPattern:        "/api/rest/v1/families",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &PostFamiliesReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*PostFamiliesCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for post_families: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  PostFamiliesFamilyCodeVariants creates a new family variant

  This endpoint allows you to create a family variant.
*/
func (a *Client) PostFamiliesFamilyCodeVariants(params *PostFamiliesFamilyCodeVariantsParams) (*PostFamiliesFamilyCodeVariantsCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPostFamiliesFamilyCodeVariantsParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "post_families__family_code__variants",
		Method:             "POST",
		PathPattern:        "/api/rest/v1/families/{family_code}/variants",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &PostFamiliesFamilyCodeVariantsReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*PostFamiliesFamilyCodeVariantsCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for post_families__family_code__variants: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
