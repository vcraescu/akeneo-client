// Code generated by go-swagger; DO NOT EDIT.

package asset_media_file

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

// NewGetAssetMediaFilesCodeParams creates a new GetAssetMediaFilesCodeParams object
// with the default values initialized.
func NewGetAssetMediaFilesCodeParams() *GetAssetMediaFilesCodeParams {
	var ()
	return &GetAssetMediaFilesCodeParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetAssetMediaFilesCodeParamsWithTimeout creates a new GetAssetMediaFilesCodeParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetAssetMediaFilesCodeParamsWithTimeout(timeout time.Duration) *GetAssetMediaFilesCodeParams {
	var ()
	return &GetAssetMediaFilesCodeParams{

		timeout: timeout,
	}
}

// NewGetAssetMediaFilesCodeParamsWithContext creates a new GetAssetMediaFilesCodeParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetAssetMediaFilesCodeParamsWithContext(ctx context.Context) *GetAssetMediaFilesCodeParams {
	var ()
	return &GetAssetMediaFilesCodeParams{

		Context: ctx,
	}
}

// NewGetAssetMediaFilesCodeParamsWithHTTPClient creates a new GetAssetMediaFilesCodeParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetAssetMediaFilesCodeParamsWithHTTPClient(client *http.Client) *GetAssetMediaFilesCodeParams {
	var ()
	return &GetAssetMediaFilesCodeParams{
		HTTPClient: client,
	}
}

/*GetAssetMediaFilesCodeParams contains all the parameters to send to the API endpoint
for the get asset media files code operation typically these are written to a http.Request
*/
type GetAssetMediaFilesCodeParams struct {

	/*Code
	  Code of the resource

	*/
	Code string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get asset media files code params
func (o *GetAssetMediaFilesCodeParams) WithTimeout(timeout time.Duration) *GetAssetMediaFilesCodeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get asset media files code params
func (o *GetAssetMediaFilesCodeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get asset media files code params
func (o *GetAssetMediaFilesCodeParams) WithContext(ctx context.Context) *GetAssetMediaFilesCodeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get asset media files code params
func (o *GetAssetMediaFilesCodeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get asset media files code params
func (o *GetAssetMediaFilesCodeParams) WithHTTPClient(client *http.Client) *GetAssetMediaFilesCodeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get asset media files code params
func (o *GetAssetMediaFilesCodeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCode adds the code to the get asset media files code params
func (o *GetAssetMediaFilesCodeParams) WithCode(code string) *GetAssetMediaFilesCodeParams {
	o.SetCode(code)
	return o
}

// SetCode adds the code to the get asset media files code params
func (o *GetAssetMediaFilesCodeParams) SetCode(code string) {
	o.Code = code
}

// WriteToRequest writes these params to a swagger request
func (o *GetAssetMediaFilesCodeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param code
	if err := r.SetPathParam("code", o.Code); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
