// Code generated by go-swagger; DO NOT EDIT.

package association_type

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

// NewAssociationTypesPatchParams creates a new AssociationTypesPatchParams object
// with the default values initialized.
func NewAssociationTypesPatchParams() *AssociationTypesPatchParams {
	var ()
	return &AssociationTypesPatchParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewAssociationTypesPatchParamsWithTimeout creates a new AssociationTypesPatchParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewAssociationTypesPatchParamsWithTimeout(timeout time.Duration) *AssociationTypesPatchParams {
	var ()
	return &AssociationTypesPatchParams{

		timeout: timeout,
	}
}

// NewAssociationTypesPatchParamsWithContext creates a new AssociationTypesPatchParams object
// with the default values initialized, and the ability to set a context for a request
func NewAssociationTypesPatchParamsWithContext(ctx context.Context) *AssociationTypesPatchParams {
	var ()
	return &AssociationTypesPatchParams{

		Context: ctx,
	}
}

// NewAssociationTypesPatchParamsWithHTTPClient creates a new AssociationTypesPatchParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewAssociationTypesPatchParamsWithHTTPClient(client *http.Client) *AssociationTypesPatchParams {
	var ()
	return &AssociationTypesPatchParams{
		HTTPClient: client,
	}
}

/*AssociationTypesPatchParams contains all the parameters to send to the API endpoint
for the association types patch operation typically these are written to a http.Request
*/
type AssociationTypesPatchParams struct {

	/*Body*/
	Body AssociationTypesPatchBody
	/*Code
	  Code of the resource

	*/
	Code string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the association types patch params
func (o *AssociationTypesPatchParams) WithTimeout(timeout time.Duration) *AssociationTypesPatchParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the association types patch params
func (o *AssociationTypesPatchParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the association types patch params
func (o *AssociationTypesPatchParams) WithContext(ctx context.Context) *AssociationTypesPatchParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the association types patch params
func (o *AssociationTypesPatchParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the association types patch params
func (o *AssociationTypesPatchParams) WithHTTPClient(client *http.Client) *AssociationTypesPatchParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the association types patch params
func (o *AssociationTypesPatchParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the association types patch params
func (o *AssociationTypesPatchParams) WithBody(body AssociationTypesPatchBody) *AssociationTypesPatchParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the association types patch params
func (o *AssociationTypesPatchParams) SetBody(body AssociationTypesPatchBody) {
	o.Body = body
}

// WithCode adds the code to the association types patch params
func (o *AssociationTypesPatchParams) WithCode(code string) *AssociationTypesPatchParams {
	o.SetCode(code)
	return o
}

// SetCode adds the code to the association types patch params
func (o *AssociationTypesPatchParams) SetCode(code string) {
	o.Code = code
}

// WriteToRequest writes these params to a swagger request
func (o *AssociationTypesPatchParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if err := r.SetBodyParam(o.Body); err != nil {
		return err
	}

	// path param code
	if err := r.SetPathParam("code", o.Code); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
