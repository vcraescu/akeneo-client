// Code generated by go-swagger; DO NOT EDIT.

package p_a_m_asset_variation_file

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

// NewGetVariationFilesChannelCodeLocaleCodeParams creates a new GetVariationFilesChannelCodeLocaleCodeParams object
// with the default values initialized.
func NewGetVariationFilesChannelCodeLocaleCodeParams() *GetVariationFilesChannelCodeLocaleCodeParams {
	var ()
	return &GetVariationFilesChannelCodeLocaleCodeParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetVariationFilesChannelCodeLocaleCodeParamsWithTimeout creates a new GetVariationFilesChannelCodeLocaleCodeParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetVariationFilesChannelCodeLocaleCodeParamsWithTimeout(timeout time.Duration) *GetVariationFilesChannelCodeLocaleCodeParams {
	var ()
	return &GetVariationFilesChannelCodeLocaleCodeParams{

		timeout: timeout,
	}
}

// NewGetVariationFilesChannelCodeLocaleCodeParamsWithContext creates a new GetVariationFilesChannelCodeLocaleCodeParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetVariationFilesChannelCodeLocaleCodeParamsWithContext(ctx context.Context) *GetVariationFilesChannelCodeLocaleCodeParams {
	var ()
	return &GetVariationFilesChannelCodeLocaleCodeParams{

		Context: ctx,
	}
}

// NewGetVariationFilesChannelCodeLocaleCodeParamsWithHTTPClient creates a new GetVariationFilesChannelCodeLocaleCodeParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetVariationFilesChannelCodeLocaleCodeParamsWithHTTPClient(client *http.Client) *GetVariationFilesChannelCodeLocaleCodeParams {
	var ()
	return &GetVariationFilesChannelCodeLocaleCodeParams{
		HTTPClient: client,
	}
}

/*GetVariationFilesChannelCodeLocaleCodeParams contains all the parameters to send to the API endpoint
for the get variation files channel code locale code operation typically these are written to a http.Request
*/
type GetVariationFilesChannelCodeLocaleCodeParams struct {

	/*AssetCode
	  Code of the asset

	*/
	AssetCode string
	/*ChannelCode
	  Code of the channel

	*/
	ChannelCode string
	/*LocaleCode
	  Code of the locale if the asset is localizable or equal to `no-locale` if the asset is not localizable

	*/
	LocaleCode string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get variation files channel code locale code params
func (o *GetVariationFilesChannelCodeLocaleCodeParams) WithTimeout(timeout time.Duration) *GetVariationFilesChannelCodeLocaleCodeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get variation files channel code locale code params
func (o *GetVariationFilesChannelCodeLocaleCodeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get variation files channel code locale code params
func (o *GetVariationFilesChannelCodeLocaleCodeParams) WithContext(ctx context.Context) *GetVariationFilesChannelCodeLocaleCodeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get variation files channel code locale code params
func (o *GetVariationFilesChannelCodeLocaleCodeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get variation files channel code locale code params
func (o *GetVariationFilesChannelCodeLocaleCodeParams) WithHTTPClient(client *http.Client) *GetVariationFilesChannelCodeLocaleCodeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get variation files channel code locale code params
func (o *GetVariationFilesChannelCodeLocaleCodeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAssetCode adds the assetCode to the get variation files channel code locale code params
func (o *GetVariationFilesChannelCodeLocaleCodeParams) WithAssetCode(assetCode string) *GetVariationFilesChannelCodeLocaleCodeParams {
	o.SetAssetCode(assetCode)
	return o
}

// SetAssetCode adds the assetCode to the get variation files channel code locale code params
func (o *GetVariationFilesChannelCodeLocaleCodeParams) SetAssetCode(assetCode string) {
	o.AssetCode = assetCode
}

// WithChannelCode adds the channelCode to the get variation files channel code locale code params
func (o *GetVariationFilesChannelCodeLocaleCodeParams) WithChannelCode(channelCode string) *GetVariationFilesChannelCodeLocaleCodeParams {
	o.SetChannelCode(channelCode)
	return o
}

// SetChannelCode adds the channelCode to the get variation files channel code locale code params
func (o *GetVariationFilesChannelCodeLocaleCodeParams) SetChannelCode(channelCode string) {
	o.ChannelCode = channelCode
}

// WithLocaleCode adds the localeCode to the get variation files channel code locale code params
func (o *GetVariationFilesChannelCodeLocaleCodeParams) WithLocaleCode(localeCode string) *GetVariationFilesChannelCodeLocaleCodeParams {
	o.SetLocaleCode(localeCode)
	return o
}

// SetLocaleCode adds the localeCode to the get variation files channel code locale code params
func (o *GetVariationFilesChannelCodeLocaleCodeParams) SetLocaleCode(localeCode string) {
	o.LocaleCode = localeCode
}

// WriteToRequest writes these params to a swagger request
func (o *GetVariationFilesChannelCodeLocaleCodeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param asset_code
	if err := r.SetPathParam("asset_code", o.AssetCode); err != nil {
		return err
	}

	// path param channel_code
	if err := r.SetPathParam("channel_code", o.ChannelCode); err != nil {
		return err
	}

	// path param locale_code
	if err := r.SetPathParam("locale_code", o.LocaleCode); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
