// Code generated by go-swagger; DO NOT EDIT.

package asset

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

// NewPatchAssetsParams creates a new PatchAssetsParams object
// with the default values initialized.
func NewPatchAssetsParams() *PatchAssetsParams {
	var ()
	return &PatchAssetsParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewPatchAssetsParamsWithTimeout creates a new PatchAssetsParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewPatchAssetsParamsWithTimeout(timeout time.Duration) *PatchAssetsParams {
	var ()
	return &PatchAssetsParams{

		timeout: timeout,
	}
}

// NewPatchAssetsParamsWithContext creates a new PatchAssetsParams object
// with the default values initialized, and the ability to set a context for a request
func NewPatchAssetsParamsWithContext(ctx context.Context) *PatchAssetsParams {
	var ()
	return &PatchAssetsParams{

		Context: ctx,
	}
}

// NewPatchAssetsParamsWithHTTPClient creates a new PatchAssetsParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewPatchAssetsParamsWithHTTPClient(client *http.Client) *PatchAssetsParams {
	var ()
	return &PatchAssetsParams{
		HTTPClient: client,
	}
}

/*PatchAssetsParams contains all the parameters to send to the API endpoint
for the patch assets operation typically these are written to a http.Request
*/
type PatchAssetsParams struct {

	/*AssetFamilyCode
	  Code of the asset family

	*/
	AssetFamilyCode string
	/*Body*/
	Body []*PatchAssetsParamsBodyItems0

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the patch assets params
func (o *PatchAssetsParams) WithTimeout(timeout time.Duration) *PatchAssetsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the patch assets params
func (o *PatchAssetsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the patch assets params
func (o *PatchAssetsParams) WithContext(ctx context.Context) *PatchAssetsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the patch assets params
func (o *PatchAssetsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the patch assets params
func (o *PatchAssetsParams) WithHTTPClient(client *http.Client) *PatchAssetsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the patch assets params
func (o *PatchAssetsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAssetFamilyCode adds the assetFamilyCode to the patch assets params
func (o *PatchAssetsParams) WithAssetFamilyCode(assetFamilyCode string) *PatchAssetsParams {
	o.SetAssetFamilyCode(assetFamilyCode)
	return o
}

// SetAssetFamilyCode adds the assetFamilyCode to the patch assets params
func (o *PatchAssetsParams) SetAssetFamilyCode(assetFamilyCode string) {
	o.AssetFamilyCode = assetFamilyCode
}

// WithBody adds the body to the patch assets params
func (o *PatchAssetsParams) WithBody(body []*PatchAssetsParamsBodyItems0) *PatchAssetsParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the patch assets params
func (o *PatchAssetsParams) SetBody(body []*PatchAssetsParamsBodyItems0) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *PatchAssetsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param asset_family_code
	if err := r.SetPathParam("asset_family_code", o.AssetFamilyCode); err != nil {
		return err
	}

	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}