// Code generated by go-swagger; DO NOT EDIT.

package published_product

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

// NewGetPublishedProductsCodeParams creates a new GetPublishedProductsCodeParams object
// with the default values initialized.
func NewGetPublishedProductsCodeParams() *GetPublishedProductsCodeParams {
	var ()
	return &GetPublishedProductsCodeParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetPublishedProductsCodeParamsWithTimeout creates a new GetPublishedProductsCodeParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetPublishedProductsCodeParamsWithTimeout(timeout time.Duration) *GetPublishedProductsCodeParams {
	var ()
	return &GetPublishedProductsCodeParams{

		timeout: timeout,
	}
}

// NewGetPublishedProductsCodeParamsWithContext creates a new GetPublishedProductsCodeParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetPublishedProductsCodeParamsWithContext(ctx context.Context) *GetPublishedProductsCodeParams {
	var ()
	return &GetPublishedProductsCodeParams{

		Context: ctx,
	}
}

// NewGetPublishedProductsCodeParamsWithHTTPClient creates a new GetPublishedProductsCodeParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetPublishedProductsCodeParamsWithHTTPClient(client *http.Client) *GetPublishedProductsCodeParams {
	var ()
	return &GetPublishedProductsCodeParams{
		HTTPClient: client,
	}
}

/*GetPublishedProductsCodeParams contains all the parameters to send to the API endpoint
for the get published products code operation typically these are written to a http.Request
*/
type GetPublishedProductsCodeParams struct {

	/*Code
	  Code of the resource

	*/
	Code string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get published products code params
func (o *GetPublishedProductsCodeParams) WithTimeout(timeout time.Duration) *GetPublishedProductsCodeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get published products code params
func (o *GetPublishedProductsCodeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get published products code params
func (o *GetPublishedProductsCodeParams) WithContext(ctx context.Context) *GetPublishedProductsCodeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get published products code params
func (o *GetPublishedProductsCodeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get published products code params
func (o *GetPublishedProductsCodeParams) WithHTTPClient(client *http.Client) *GetPublishedProductsCodeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get published products code params
func (o *GetPublishedProductsCodeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCode adds the code to the get published products code params
func (o *GetPublishedProductsCodeParams) WithCode(code string) *GetPublishedProductsCodeParams {
	o.SetCode(code)
	return o
}

// SetCode adds the code to the get published products code params
func (o *GetPublishedProductsCodeParams) SetCode(code string) {
	o.Code = code
}

// WriteToRequest writes these params to a swagger request
func (o *GetPublishedProductsCodeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
