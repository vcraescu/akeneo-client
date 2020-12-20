// Code generated by go-swagger; DO NOT EDIT.

package asset_attribute_option

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

// NewPatchAssetAttributesAttributeCodeOptionsCodeParams creates a new PatchAssetAttributesAttributeCodeOptionsCodeParams object
// with the default values initialized.
func NewPatchAssetAttributesAttributeCodeOptionsCodeParams() *PatchAssetAttributesAttributeCodeOptionsCodeParams {
	var ()
	return &PatchAssetAttributesAttributeCodeOptionsCodeParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewPatchAssetAttributesAttributeCodeOptionsCodeParamsWithTimeout creates a new PatchAssetAttributesAttributeCodeOptionsCodeParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewPatchAssetAttributesAttributeCodeOptionsCodeParamsWithTimeout(timeout time.Duration) *PatchAssetAttributesAttributeCodeOptionsCodeParams {
	var ()
	return &PatchAssetAttributesAttributeCodeOptionsCodeParams{

		timeout: timeout,
	}
}

// NewPatchAssetAttributesAttributeCodeOptionsCodeParamsWithContext creates a new PatchAssetAttributesAttributeCodeOptionsCodeParams object
// with the default values initialized, and the ability to set a context for a request
func NewPatchAssetAttributesAttributeCodeOptionsCodeParamsWithContext(ctx context.Context) *PatchAssetAttributesAttributeCodeOptionsCodeParams {
	var ()
	return &PatchAssetAttributesAttributeCodeOptionsCodeParams{

		Context: ctx,
	}
}

// NewPatchAssetAttributesAttributeCodeOptionsCodeParamsWithHTTPClient creates a new PatchAssetAttributesAttributeCodeOptionsCodeParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewPatchAssetAttributesAttributeCodeOptionsCodeParamsWithHTTPClient(client *http.Client) *PatchAssetAttributesAttributeCodeOptionsCodeParams {
	var ()
	return &PatchAssetAttributesAttributeCodeOptionsCodeParams{
		HTTPClient: client,
	}
}

/*PatchAssetAttributesAttributeCodeOptionsCodeParams contains all the parameters to send to the API endpoint
for the patch asset attributes attribute code options code operation typically these are written to a http.Request
*/
type PatchAssetAttributesAttributeCodeOptionsCodeParams struct {

	/*AssetFamilyCode
	  Code of the asset family

	*/
	AssetFamilyCode string
	/*AttributeCode
	  Code of the attribute

	*/
	AttributeCode string
	/*Body*/
	Body PatchAssetAttributesAttributeCodeOptionsCodeBody
	/*Code
	  Code of the resource

	*/
	Code string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the patch asset attributes attribute code options code params
func (o *PatchAssetAttributesAttributeCodeOptionsCodeParams) WithTimeout(timeout time.Duration) *PatchAssetAttributesAttributeCodeOptionsCodeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the patch asset attributes attribute code options code params
func (o *PatchAssetAttributesAttributeCodeOptionsCodeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the patch asset attributes attribute code options code params
func (o *PatchAssetAttributesAttributeCodeOptionsCodeParams) WithContext(ctx context.Context) *PatchAssetAttributesAttributeCodeOptionsCodeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the patch asset attributes attribute code options code params
func (o *PatchAssetAttributesAttributeCodeOptionsCodeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the patch asset attributes attribute code options code params
func (o *PatchAssetAttributesAttributeCodeOptionsCodeParams) WithHTTPClient(client *http.Client) *PatchAssetAttributesAttributeCodeOptionsCodeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the patch asset attributes attribute code options code params
func (o *PatchAssetAttributesAttributeCodeOptionsCodeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAssetFamilyCode adds the assetFamilyCode to the patch asset attributes attribute code options code params
func (o *PatchAssetAttributesAttributeCodeOptionsCodeParams) WithAssetFamilyCode(assetFamilyCode string) *PatchAssetAttributesAttributeCodeOptionsCodeParams {
	o.SetAssetFamilyCode(assetFamilyCode)
	return o
}

// SetAssetFamilyCode adds the assetFamilyCode to the patch asset attributes attribute code options code params
func (o *PatchAssetAttributesAttributeCodeOptionsCodeParams) SetAssetFamilyCode(assetFamilyCode string) {
	o.AssetFamilyCode = assetFamilyCode
}

// WithAttributeCode adds the attributeCode to the patch asset attributes attribute code options code params
func (o *PatchAssetAttributesAttributeCodeOptionsCodeParams) WithAttributeCode(attributeCode string) *PatchAssetAttributesAttributeCodeOptionsCodeParams {
	o.SetAttributeCode(attributeCode)
	return o
}

// SetAttributeCode adds the attributeCode to the patch asset attributes attribute code options code params
func (o *PatchAssetAttributesAttributeCodeOptionsCodeParams) SetAttributeCode(attributeCode string) {
	o.AttributeCode = attributeCode
}

// WithBody adds the body to the patch asset attributes attribute code options code params
func (o *PatchAssetAttributesAttributeCodeOptionsCodeParams) WithBody(body PatchAssetAttributesAttributeCodeOptionsCodeBody) *PatchAssetAttributesAttributeCodeOptionsCodeParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the patch asset attributes attribute code options code params
func (o *PatchAssetAttributesAttributeCodeOptionsCodeParams) SetBody(body PatchAssetAttributesAttributeCodeOptionsCodeBody) {
	o.Body = body
}

// WithCode adds the code to the patch asset attributes attribute code options code params
func (o *PatchAssetAttributesAttributeCodeOptionsCodeParams) WithCode(code string) *PatchAssetAttributesAttributeCodeOptionsCodeParams {
	o.SetCode(code)
	return o
}

// SetCode adds the code to the patch asset attributes attribute code options code params
func (o *PatchAssetAttributesAttributeCodeOptionsCodeParams) SetCode(code string) {
	o.Code = code
}

// WriteToRequest writes these params to a swagger request
func (o *PatchAssetAttributesAttributeCodeOptionsCodeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param asset_family_code
	if err := r.SetPathParam("asset_family_code", o.AssetFamilyCode); err != nil {
		return err
	}

	// path param attribute_code
	if err := r.SetPathParam("attribute_code", o.AttributeCode); err != nil {
		return err
	}

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
