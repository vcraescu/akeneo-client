// Code generated by go-swagger; DO NOT EDIT.

package asset_attribute

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewGetAssetFamiliesCodeAttributesParams creates a new GetAssetFamiliesCodeAttributesParams object
// with the default values initialized.
func NewGetAssetFamiliesCodeAttributesParams() *GetAssetFamiliesCodeAttributesParams {
	var ()
	return &GetAssetFamiliesCodeAttributesParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetAssetFamiliesCodeAttributesParamsWithTimeout creates a new GetAssetFamiliesCodeAttributesParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetAssetFamiliesCodeAttributesParamsWithTimeout(timeout time.Duration) *GetAssetFamiliesCodeAttributesParams {
	var ()
	return &GetAssetFamiliesCodeAttributesParams{

		timeout: timeout,
	}
}

// NewGetAssetFamiliesCodeAttributesParamsWithContext creates a new GetAssetFamiliesCodeAttributesParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetAssetFamiliesCodeAttributesParamsWithContext(ctx context.Context) *GetAssetFamiliesCodeAttributesParams {
	var ()
	return &GetAssetFamiliesCodeAttributesParams{

		Context: ctx,
	}
}

// NewGetAssetFamiliesCodeAttributesParamsWithHTTPClient creates a new GetAssetFamiliesCodeAttributesParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetAssetFamiliesCodeAttributesParamsWithHTTPClient(client *http.Client) *GetAssetFamiliesCodeAttributesParams {
	var ()
	return &GetAssetFamiliesCodeAttributesParams{
		HTTPClient: client,
	}
}

/*GetAssetFamiliesCodeAttributesParams contains all the parameters to send to the API endpoint
for the get asset families code attributes operation typically these are written to a http.Request
*/
type GetAssetFamiliesCodeAttributesParams struct {

	/*AssetFamilyCode
	  Code of the asset family

	*/
	AssetFamilyCode string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get asset families code attributes params
func (o *GetAssetFamiliesCodeAttributesParams) WithTimeout(timeout time.Duration) *GetAssetFamiliesCodeAttributesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get asset families code attributes params
func (o *GetAssetFamiliesCodeAttributesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get asset families code attributes params
func (o *GetAssetFamiliesCodeAttributesParams) WithContext(ctx context.Context) *GetAssetFamiliesCodeAttributesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get asset families code attributes params
func (o *GetAssetFamiliesCodeAttributesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get asset families code attributes params
func (o *GetAssetFamiliesCodeAttributesParams) WithHTTPClient(client *http.Client) *GetAssetFamiliesCodeAttributesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get asset families code attributes params
func (o *GetAssetFamiliesCodeAttributesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAssetFamilyCode adds the assetFamilyCode to the get asset families code attributes params
func (o *GetAssetFamiliesCodeAttributesParams) WithAssetFamilyCode(assetFamilyCode string) *GetAssetFamiliesCodeAttributesParams {
	o.SetAssetFamilyCode(assetFamilyCode)
	return o
}

// SetAssetFamilyCode adds the assetFamilyCode to the get asset families code attributes params
func (o *GetAssetFamiliesCodeAttributesParams) SetAssetFamilyCode(assetFamilyCode string) {
	o.AssetFamilyCode = assetFamilyCode
}

// WriteToRequest writes these params to a swagger request
func (o *GetAssetFamiliesCodeAttributesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param asset_family_code
	if err := r.SetPathParam("asset_family_code", o.AssetFamilyCode); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
