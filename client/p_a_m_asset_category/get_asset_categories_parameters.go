// Code generated by go-swagger; DO NOT EDIT.

package p_a_m_asset_category

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
	"github.com/go-openapi/swag"
)

// NewGetAssetCategoriesParams creates a new GetAssetCategoriesParams object
// with the default values initialized.
func NewGetAssetCategoriesParams() *GetAssetCategoriesParams {
	var (
		limitDefault     = int64(10)
		pageDefault      = int64(1)
		withCountDefault = bool(false)
	)
	return &GetAssetCategoriesParams{
		Limit:     &limitDefault,
		Page:      &pageDefault,
		WithCount: &withCountDefault,

		timeout: cr.DefaultTimeout,
	}
}

// NewGetAssetCategoriesParamsWithTimeout creates a new GetAssetCategoriesParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetAssetCategoriesParamsWithTimeout(timeout time.Duration) *GetAssetCategoriesParams {
	var (
		limitDefault     = int64(10)
		pageDefault      = int64(1)
		withCountDefault = bool(false)
	)
	return &GetAssetCategoriesParams{
		Limit:     &limitDefault,
		Page:      &pageDefault,
		WithCount: &withCountDefault,

		timeout: timeout,
	}
}

// NewGetAssetCategoriesParamsWithContext creates a new GetAssetCategoriesParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetAssetCategoriesParamsWithContext(ctx context.Context) *GetAssetCategoriesParams {
	var (
		limitDefault     = int64(10)
		pageDefault      = int64(1)
		withCountDefault = bool(false)
	)
	return &GetAssetCategoriesParams{
		Limit:     &limitDefault,
		Page:      &pageDefault,
		WithCount: &withCountDefault,

		Context: ctx,
	}
}

// NewGetAssetCategoriesParamsWithHTTPClient creates a new GetAssetCategoriesParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetAssetCategoriesParamsWithHTTPClient(client *http.Client) *GetAssetCategoriesParams {
	var (
		limitDefault     = int64(10)
		pageDefault      = int64(1)
		withCountDefault = bool(false)
	)
	return &GetAssetCategoriesParams{
		Limit:      &limitDefault,
		Page:       &pageDefault,
		WithCount:  &withCountDefault,
		HTTPClient: client,
	}
}

/*GetAssetCategoriesParams contains all the parameters to send to the API endpoint
for the get asset categories operation typically these are written to a http.Request
*/
type GetAssetCategoriesParams struct {

	/*Limit
	  Number of results by page, see <a href="/documentation/pagination.html">Pagination</a> section

	*/
	Limit *int64
	/*Page
	  Number of the page to retrieve when using the `page` pagination method type. <strong>Should never be set manually</strong>, see <a href="/documentation/pagination.html#pagination">Pagination</a> section

	*/
	Page *int64
	/*WithCount
	  Return the count of products in the response. Be carefull with that, on a big catalog, it can decrease performance in a significative way

	*/
	WithCount *bool

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get asset categories params
func (o *GetAssetCategoriesParams) WithTimeout(timeout time.Duration) *GetAssetCategoriesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get asset categories params
func (o *GetAssetCategoriesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get asset categories params
func (o *GetAssetCategoriesParams) WithContext(ctx context.Context) *GetAssetCategoriesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get asset categories params
func (o *GetAssetCategoriesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get asset categories params
func (o *GetAssetCategoriesParams) WithHTTPClient(client *http.Client) *GetAssetCategoriesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get asset categories params
func (o *GetAssetCategoriesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithLimit adds the limit to the get asset categories params
func (o *GetAssetCategoriesParams) WithLimit(limit *int64) *GetAssetCategoriesParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the get asset categories params
func (o *GetAssetCategoriesParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithPage adds the page to the get asset categories params
func (o *GetAssetCategoriesParams) WithPage(page *int64) *GetAssetCategoriesParams {
	o.SetPage(page)
	return o
}

// SetPage adds the page to the get asset categories params
func (o *GetAssetCategoriesParams) SetPage(page *int64) {
	o.Page = page
}

// WithWithCount adds the withCount to the get asset categories params
func (o *GetAssetCategoriesParams) WithWithCount(withCount *bool) *GetAssetCategoriesParams {
	o.SetWithCount(withCount)
	return o
}

// SetWithCount adds the withCount to the get asset categories params
func (o *GetAssetCategoriesParams) SetWithCount(withCount *bool) {
	o.WithCount = withCount
}

// WriteToRequest writes these params to a swagger request
func (o *GetAssetCategoriesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Limit != nil {

		// query param limit
		var qrLimit int64
		if o.Limit != nil {
			qrLimit = *o.Limit
		}
		qLimit := swag.FormatInt64(qrLimit)
		if qLimit != "" {
			if err := r.SetQueryParam("limit", qLimit); err != nil {
				return err
			}
		}

	}

	if o.Page != nil {

		// query param page
		var qrPage int64
		if o.Page != nil {
			qrPage = *o.Page
		}
		qPage := swag.FormatInt64(qrPage)
		if qPage != "" {
			if err := r.SetQueryParam("page", qPage); err != nil {
				return err
			}
		}

	}

	if o.WithCount != nil {

		// query param with_count
		var qrWithCount bool
		if o.WithCount != nil {
			qrWithCount = *o.WithCount
		}
		qWithCount := swag.FormatBool(qrWithCount)
		if qWithCount != "" {
			if err := r.SetQueryParam("with_count", qWithCount); err != nil {
				return err
			}
		}

	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
