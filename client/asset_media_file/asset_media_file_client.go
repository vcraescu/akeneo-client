// Code generated by go-swagger; DO NOT EDIT.

package asset_media_file

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new asset media file API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for asset media file API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientService is the interface for Client methods
type ClientService interface {
	GetAssetMediaFilesCode(params *GetAssetMediaFilesCodeParams) (*GetAssetMediaFilesCodeOK, error)

	PostAssetMediaFiles(params *PostAssetMediaFilesParams) (*PostAssetMediaFilesCreated, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  GetAssetMediaFilesCode downloads the media file associated to an asset

  This endpoint allows you to download a given media file that is associated with an asset.
*/
func (a *Client) GetAssetMediaFilesCode(params *GetAssetMediaFilesCodeParams) (*GetAssetMediaFilesCodeOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAssetMediaFilesCodeParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "get_asset_media_files__code",
		Method:             "GET",
		PathPattern:        "/api/rest/v1/asset-media-files/{code}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetAssetMediaFilesCodeReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetAssetMediaFilesCodeOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for get_asset_media_files__code: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  PostAssetMediaFiles creates a new media file for an asset

  This endpoint allows you to create a new media file and associate it to a media file attribute value of an asset.
*/
func (a *Client) PostAssetMediaFiles(params *PostAssetMediaFilesParams) (*PostAssetMediaFilesCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPostAssetMediaFilesParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "post_asset_media_files",
		Method:             "POST",
		PathPattern:        "/api/rest/v1/asset-media-files",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &PostAssetMediaFilesReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*PostAssetMediaFilesCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for post_asset_media_files: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
