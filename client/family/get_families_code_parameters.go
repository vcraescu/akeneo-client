// Code generated by go-swagger; DO NOT EDIT.

package family

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

// NewGetFamiliesCodeParams creates a new GetFamiliesCodeParams object
// with the default values initialized.
func NewGetFamiliesCodeParams() *GetFamiliesCodeParams {
	var ()
	return &GetFamiliesCodeParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetFamiliesCodeParamsWithTimeout creates a new GetFamiliesCodeParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetFamiliesCodeParamsWithTimeout(timeout time.Duration) *GetFamiliesCodeParams {
	var ()
	return &GetFamiliesCodeParams{

		timeout: timeout,
	}
}

// NewGetFamiliesCodeParamsWithContext creates a new GetFamiliesCodeParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetFamiliesCodeParamsWithContext(ctx context.Context) *GetFamiliesCodeParams {
	var ()
	return &GetFamiliesCodeParams{

		Context: ctx,
	}
}

// NewGetFamiliesCodeParamsWithHTTPClient creates a new GetFamiliesCodeParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetFamiliesCodeParamsWithHTTPClient(client *http.Client) *GetFamiliesCodeParams {
	var ()
	return &GetFamiliesCodeParams{
		HTTPClient: client,
	}
}

/*GetFamiliesCodeParams contains all the parameters to send to the API endpoint
for the get families code operation typically these are written to a http.Request
*/
type GetFamiliesCodeParams struct {

	/*Code
	  Code of the resource

	*/
	Code string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get families code params
func (o *GetFamiliesCodeParams) WithTimeout(timeout time.Duration) *GetFamiliesCodeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get families code params
func (o *GetFamiliesCodeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get families code params
func (o *GetFamiliesCodeParams) WithContext(ctx context.Context) *GetFamiliesCodeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get families code params
func (o *GetFamiliesCodeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get families code params
func (o *GetFamiliesCodeParams) WithHTTPClient(client *http.Client) *GetFamiliesCodeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get families code params
func (o *GetFamiliesCodeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCode adds the code to the get families code params
func (o *GetFamiliesCodeParams) WithCode(code string) *GetFamiliesCodeParams {
	o.SetCode(code)
	return o
}

// SetCode adds the code to the get families code params
func (o *GetFamiliesCodeParams) SetCode(code string) {
	o.Code = code
}

// WriteToRequest writes these params to a swagger request
func (o *GetFamiliesCodeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
