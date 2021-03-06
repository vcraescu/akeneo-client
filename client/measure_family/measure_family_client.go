// Code generated by go-swagger; DO NOT EDIT.

package measure_family

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new measure family API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for measure family API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientService is the interface for Client methods
type ClientService interface {
	MeasureFamiliesGet(params *MeasureFamiliesGetParams) (*MeasureFamiliesGetOK, error)

	MeasureFamiliesGetList(params *MeasureFamiliesGetListParams) (*MeasureFamiliesGetListOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  MeasureFamiliesGet gets a measure family

  This endpoint allows you to get the information about a given measure family.
*/
func (a *Client) MeasureFamiliesGet(params *MeasureFamiliesGetParams) (*MeasureFamiliesGetOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewMeasureFamiliesGetParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "measure_families_get",
		Method:             "GET",
		PathPattern:        "/api/rest/v1/measure-families/{code}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &MeasureFamiliesGetReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*MeasureFamiliesGetOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for measure_families_get: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  MeasureFamiliesGetList gets list of measure familiy

  This endpoint allows you to get a list of measure families. Measure families are paginated and sorted by code.
*/
func (a *Client) MeasureFamiliesGetList(params *MeasureFamiliesGetListParams) (*MeasureFamiliesGetListOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewMeasureFamiliesGetListParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "measure_families_get_list",
		Method:             "GET",
		PathPattern:        "/api/rest/v1/measure-families",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &MeasureFamiliesGetListReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*MeasureFamiliesGetListOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for measure_families_get_list: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
