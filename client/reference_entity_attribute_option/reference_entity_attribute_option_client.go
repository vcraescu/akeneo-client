// Code generated by go-swagger; DO NOT EDIT.

package reference_entity_attribute_option

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new reference entity attribute option API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for reference entity attribute option API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientService is the interface for Client methods
type ClientService interface {
	GetReferenceEntityAttributesAttributeCodeOptions(params *GetReferenceEntityAttributesAttributeCodeOptionsParams) (*GetReferenceEntityAttributesAttributeCodeOptionsOK, error)

	GetReferenceEntityAttributesAttributeCodeOptionsCode(params *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams) (*GetReferenceEntityAttributesAttributeCodeOptionsCodeOK, error)

	PatchReferenceEntityAttributesAttributeCodeOptionsCode(params *PatchReferenceEntityAttributesAttributeCodeOptionsCodeParams) (*PatchReferenceEntityAttributesAttributeCodeOptionsCodeCreated, *PatchReferenceEntityAttributesAttributeCodeOptionsCodeNoContent, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  GetReferenceEntityAttributesAttributeCodeOptions gets a list of attribute options of a given attribute for a given reference entity

  This endpoint allows you to get a list of attribute options for a given reference entity.
*/
func (a *Client) GetReferenceEntityAttributesAttributeCodeOptions(params *GetReferenceEntityAttributesAttributeCodeOptionsParams) (*GetReferenceEntityAttributesAttributeCodeOptionsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetReferenceEntityAttributesAttributeCodeOptionsParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "get_reference_entity_attributes__attribute_code__options",
		Method:             "GET",
		PathPattern:        "/api/rest/v1/reference-entities/{reference_entity_code}/attributes/{attribute_code}/options",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetReferenceEntityAttributesAttributeCodeOptionsReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetReferenceEntityAttributesAttributeCodeOptionsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for get_reference_entity_attributes__attribute_code__options: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetReferenceEntityAttributesAttributeCodeOptionsCode gets an attribute option for a given attribute of a given reference entity

  This endpoint allows you to get the information about a given attribute option.
*/
func (a *Client) GetReferenceEntityAttributesAttributeCodeOptionsCode(params *GetReferenceEntityAttributesAttributeCodeOptionsCodeParams) (*GetReferenceEntityAttributesAttributeCodeOptionsCodeOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetReferenceEntityAttributesAttributeCodeOptionsCodeParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "get_reference_entity_attributes__attribute_code__options__code_",
		Method:             "GET",
		PathPattern:        "/api/rest/v1/reference-entities/{reference_entity_code}/attributes/{attribute_code}/options/{code}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetReferenceEntityAttributesAttributeCodeOptionsCodeReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetReferenceEntityAttributesAttributeCodeOptionsCodeOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for get_reference_entity_attributes__attribute_code__options__code_: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  PatchReferenceEntityAttributesAttributeCodeOptionsCode updates create a reference entity attribute option

  This endpoint allows you to update a given option for a given attribute and a given reference entity. Learn more about <a href="/documentation/update.html#patch-reference-entity-record-values">Update behavior</a>. Note that if the option does not already exist for the given attribute of the given reference entity, it creates it.
*/
func (a *Client) PatchReferenceEntityAttributesAttributeCodeOptionsCode(params *PatchReferenceEntityAttributesAttributeCodeOptionsCodeParams) (*PatchReferenceEntityAttributesAttributeCodeOptionsCodeCreated, *PatchReferenceEntityAttributesAttributeCodeOptionsCodeNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPatchReferenceEntityAttributesAttributeCodeOptionsCodeParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "patch_reference_entity_attributes__attribute_code__options__code_",
		Method:             "PATCH",
		PathPattern:        "/api/rest/v1/reference-entities/{reference_entity_code}/attributes/{attribute_code}/options/{code}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &PatchReferenceEntityAttributesAttributeCodeOptionsCodeReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, nil, err
	}
	switch value := result.(type) {
	case *PatchReferenceEntityAttributesAttributeCodeOptionsCodeCreated:
		return value, nil, nil
	case *PatchReferenceEntityAttributesAttributeCodeOptionsCodeNoContent:
		return nil, value, nil
	}
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for reference_entity_attribute_option: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}