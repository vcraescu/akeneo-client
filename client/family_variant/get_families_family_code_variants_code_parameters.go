// Code generated by go-swagger; DO NOT EDIT.

package family_variant

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

// NewGetFamiliesFamilyCodeVariantsCodeParams creates a new GetFamiliesFamilyCodeVariantsCodeParams object
// with the default values initialized.
func NewGetFamiliesFamilyCodeVariantsCodeParams() *GetFamiliesFamilyCodeVariantsCodeParams {
	var ()
	return &GetFamiliesFamilyCodeVariantsCodeParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetFamiliesFamilyCodeVariantsCodeParamsWithTimeout creates a new GetFamiliesFamilyCodeVariantsCodeParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetFamiliesFamilyCodeVariantsCodeParamsWithTimeout(timeout time.Duration) *GetFamiliesFamilyCodeVariantsCodeParams {
	var ()
	return &GetFamiliesFamilyCodeVariantsCodeParams{

		timeout: timeout,
	}
}

// NewGetFamiliesFamilyCodeVariantsCodeParamsWithContext creates a new GetFamiliesFamilyCodeVariantsCodeParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetFamiliesFamilyCodeVariantsCodeParamsWithContext(ctx context.Context) *GetFamiliesFamilyCodeVariantsCodeParams {
	var ()
	return &GetFamiliesFamilyCodeVariantsCodeParams{

		Context: ctx,
	}
}

// NewGetFamiliesFamilyCodeVariantsCodeParamsWithHTTPClient creates a new GetFamiliesFamilyCodeVariantsCodeParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetFamiliesFamilyCodeVariantsCodeParamsWithHTTPClient(client *http.Client) *GetFamiliesFamilyCodeVariantsCodeParams {
	var ()
	return &GetFamiliesFamilyCodeVariantsCodeParams{
		HTTPClient: client,
	}
}

/*GetFamiliesFamilyCodeVariantsCodeParams contains all the parameters to send to the API endpoint
for the get families family code variants code operation typically these are written to a http.Request
*/
type GetFamiliesFamilyCodeVariantsCodeParams struct {

	/*Code
	  Code of the resource

	*/
	Code string
	/*FamilyCode
	  Code of the family

	*/
	FamilyCode string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get families family code variants code params
func (o *GetFamiliesFamilyCodeVariantsCodeParams) WithTimeout(timeout time.Duration) *GetFamiliesFamilyCodeVariantsCodeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get families family code variants code params
func (o *GetFamiliesFamilyCodeVariantsCodeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get families family code variants code params
func (o *GetFamiliesFamilyCodeVariantsCodeParams) WithContext(ctx context.Context) *GetFamiliesFamilyCodeVariantsCodeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get families family code variants code params
func (o *GetFamiliesFamilyCodeVariantsCodeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get families family code variants code params
func (o *GetFamiliesFamilyCodeVariantsCodeParams) WithHTTPClient(client *http.Client) *GetFamiliesFamilyCodeVariantsCodeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get families family code variants code params
func (o *GetFamiliesFamilyCodeVariantsCodeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCode adds the code to the get families family code variants code params
func (o *GetFamiliesFamilyCodeVariantsCodeParams) WithCode(code string) *GetFamiliesFamilyCodeVariantsCodeParams {
	o.SetCode(code)
	return o
}

// SetCode adds the code to the get families family code variants code params
func (o *GetFamiliesFamilyCodeVariantsCodeParams) SetCode(code string) {
	o.Code = code
}

// WithFamilyCode adds the familyCode to the get families family code variants code params
func (o *GetFamiliesFamilyCodeVariantsCodeParams) WithFamilyCode(familyCode string) *GetFamiliesFamilyCodeVariantsCodeParams {
	o.SetFamilyCode(familyCode)
	return o
}

// SetFamilyCode adds the familyCode to the get families family code variants code params
func (o *GetFamiliesFamilyCodeVariantsCodeParams) SetFamilyCode(familyCode string) {
	o.FamilyCode = familyCode
}

// WriteToRequest writes these params to a swagger request
func (o *GetFamiliesFamilyCodeVariantsCodeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param code
	if err := r.SetPathParam("code", o.Code); err != nil {
		return err
	}

	// path param family_code
	if err := r.SetPathParam("family_code", o.FamilyCode); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
