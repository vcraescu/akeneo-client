// Code generated by go-swagger; DO NOT EDIT.

package category

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new category API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for category API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientService is the interface for Client methods
type ClientService interface {
	GetCategories(params *GetCategoriesParams) (*GetCategoriesOK, error)

	GetCategoriesCode(params *GetCategoriesCodeParams) (*GetCategoriesCodeOK, error)

	PatchCategories(params *PatchCategoriesParams) (*PatchCategoriesOK, error)

	PatchCategoriesCode(params *PatchCategoriesCodeParams) (*PatchCategoriesCodeCreated, *PatchCategoriesCodeNoContent, error)

	PostCategories(params *PostCategoriesParams) (*PostCategoriesCreated, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  GetCategories gets list of categories

  This endpoint allows you to get a list of categories. Categories are paginated and sorted by `root/left`.
*/
func (a *Client) GetCategories(params *GetCategoriesParams) (*GetCategoriesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetCategoriesParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "get_categories",
		Method:             "GET",
		PathPattern:        "/api/rest/v1/categories",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetCategoriesReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetCategoriesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for get_categories: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetCategoriesCode gets a category

  This endpoint allows you to get the information about a given category.
*/
func (a *Client) GetCategoriesCode(params *GetCategoriesCodeParams) (*GetCategoriesCodeOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetCategoriesCodeParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "get_categories__code_",
		Method:             "GET",
		PathPattern:        "/api/rest/v1/categories/{code}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetCategoriesCodeReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetCategoriesCodeOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for get_categories__code_: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  PatchCategories updates create several categories

  This endpoint allows you to update several categories at once.
*/
func (a *Client) PatchCategories(params *PatchCategoriesParams) (*PatchCategoriesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPatchCategoriesParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "patch_categories",
		Method:             "PATCH",
		PathPattern:        "/api/rest/v1/categories",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &PatchCategoriesReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*PatchCategoriesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for patch_categories: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  PatchCategoriesCode updates create a category

  This endpoint allows you to update a given category. Know more about <a href="/documentation/update.html#update-behavior">Update behavior</a>. Note that if no category exists for the given code, it creates it.
*/
func (a *Client) PatchCategoriesCode(params *PatchCategoriesCodeParams) (*PatchCategoriesCodeCreated, *PatchCategoriesCodeNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPatchCategoriesCodeParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "patch_categories__code_",
		Method:             "PATCH",
		PathPattern:        "/api/rest/v1/categories/{code}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &PatchCategoriesCodeReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *PatchCategoriesCodeCreated:
		return value, nil, nil
	case *PatchCategoriesCodeNoContent:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for category: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  PostCategories creates a new category

  This endpoint allows you to create a new category.
*/
func (a *Client) PostCategories(params *PostCategoriesParams) (*PostCategoriesCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPostCategoriesParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "post_categories",
		Method:             "POST",
		PathPattern:        "/api/rest/v1/categories",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &PostCategoriesReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*PostCategoriesCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for post_categories: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
