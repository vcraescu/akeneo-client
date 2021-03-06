// Code generated by go-swagger; DO NOT EDIT.

package channel

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

// NewGetChannelsCodeParams creates a new GetChannelsCodeParams object
// with the default values initialized.
func NewGetChannelsCodeParams() *GetChannelsCodeParams {
	var ()
	return &GetChannelsCodeParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetChannelsCodeParamsWithTimeout creates a new GetChannelsCodeParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetChannelsCodeParamsWithTimeout(timeout time.Duration) *GetChannelsCodeParams {
	var ()
	return &GetChannelsCodeParams{

		timeout: timeout,
	}
}

// NewGetChannelsCodeParamsWithContext creates a new GetChannelsCodeParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetChannelsCodeParamsWithContext(ctx context.Context) *GetChannelsCodeParams {
	var ()
	return &GetChannelsCodeParams{

		Context: ctx,
	}
}

// NewGetChannelsCodeParamsWithHTTPClient creates a new GetChannelsCodeParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetChannelsCodeParamsWithHTTPClient(client *http.Client) *GetChannelsCodeParams {
	var ()
	return &GetChannelsCodeParams{
		HTTPClient: client,
	}
}

/*GetChannelsCodeParams contains all the parameters to send to the API endpoint
for the get channels code operation typically these are written to a http.Request
*/
type GetChannelsCodeParams struct {

	/*Code
	  Code of the resource

	*/
	Code string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get channels code params
func (o *GetChannelsCodeParams) WithTimeout(timeout time.Duration) *GetChannelsCodeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get channels code params
func (o *GetChannelsCodeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get channels code params
func (o *GetChannelsCodeParams) WithContext(ctx context.Context) *GetChannelsCodeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get channels code params
func (o *GetChannelsCodeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get channels code params
func (o *GetChannelsCodeParams) WithHTTPClient(client *http.Client) *GetChannelsCodeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get channels code params
func (o *GetChannelsCodeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCode adds the code to the get channels code params
func (o *GetChannelsCodeParams) WithCode(code string) *GetChannelsCodeParams {
	o.SetCode(code)
	return o
}

// SetCode adds the code to the get channels code params
func (o *GetChannelsCodeParams) SetCode(code string) {
	o.Code = code
}

// WriteToRequest writes these params to a swagger request
func (o *GetChannelsCodeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
