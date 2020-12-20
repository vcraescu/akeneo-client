// Code generated by go-swagger; DO NOT EDIT.

package attribute_group

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

// NewAttributeGroupsGetListParams creates a new AttributeGroupsGetListParams object
// with the default values initialized.
func NewAttributeGroupsGetListParams() *AttributeGroupsGetListParams {
	var (
		limitDefault     = int64(10)
		pageDefault      = int64(1)
		withCountDefault = bool(false)
	)
	return &AttributeGroupsGetListParams{
		Limit:     &limitDefault,
		Page:      &pageDefault,
		WithCount: &withCountDefault,

		timeout: cr.DefaultTimeout,
	}
}

// NewAttributeGroupsGetListParamsWithTimeout creates a new AttributeGroupsGetListParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewAttributeGroupsGetListParamsWithTimeout(timeout time.Duration) *AttributeGroupsGetListParams {
	var (
		limitDefault     = int64(10)
		pageDefault      = int64(1)
		withCountDefault = bool(false)
	)
	return &AttributeGroupsGetListParams{
		Limit:     &limitDefault,
		Page:      &pageDefault,
		WithCount: &withCountDefault,

		timeout: timeout,
	}
}

// NewAttributeGroupsGetListParamsWithContext creates a new AttributeGroupsGetListParams object
// with the default values initialized, and the ability to set a context for a request
func NewAttributeGroupsGetListParamsWithContext(ctx context.Context) *AttributeGroupsGetListParams {
	var (
		limitDefault     = int64(10)
		pageDefault      = int64(1)
		withCountDefault = bool(false)
	)
	return &AttributeGroupsGetListParams{
		Limit:     &limitDefault,
		Page:      &pageDefault,
		WithCount: &withCountDefault,

		Context: ctx,
	}
}

// NewAttributeGroupsGetListParamsWithHTTPClient creates a new AttributeGroupsGetListParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewAttributeGroupsGetListParamsWithHTTPClient(client *http.Client) *AttributeGroupsGetListParams {
	var (
		limitDefault     = int64(10)
		pageDefault      = int64(1)
		withCountDefault = bool(false)
	)
	return &AttributeGroupsGetListParams{
		Limit:      &limitDefault,
		Page:       &pageDefault,
		WithCount:  &withCountDefault,
		HTTPClient: client,
	}
}

/*AttributeGroupsGetListParams contains all the parameters to send to the API endpoint
for the attribute groups get list operation typically these are written to a http.Request
*/
type AttributeGroupsGetListParams struct {

	/*Limit
	  Number of results by page, see <a href="/documentation/pagination.html">Pagination</a> section

	*/
	Limit *int64
	/*Page
	  Number of the page to retrieve when using the `page` pagination method type. <strong>Should never be set manually</strong>, see <a href="/documentation/pagination.html#pagination">Pagination</a> section

	*/
	Page *int64
	/*Search
	  Filter attribute groups, for more details see the <a href="/documentation/filter.html#filter-attribute-groups">Filters</a> section.

	*/
	Search *string
	/*WithCount
	  Return the count of products in the response. Be carefull with that, on a big catalog, it can decrease performance in a significative way

	*/
	WithCount *bool

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the attribute groups get list params
func (o *AttributeGroupsGetListParams) WithTimeout(timeout time.Duration) *AttributeGroupsGetListParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the attribute groups get list params
func (o *AttributeGroupsGetListParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the attribute groups get list params
func (o *AttributeGroupsGetListParams) WithContext(ctx context.Context) *AttributeGroupsGetListParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the attribute groups get list params
func (o *AttributeGroupsGetListParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the attribute groups get list params
func (o *AttributeGroupsGetListParams) WithHTTPClient(client *http.Client) *AttributeGroupsGetListParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the attribute groups get list params
func (o *AttributeGroupsGetListParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithLimit adds the limit to the attribute groups get list params
func (o *AttributeGroupsGetListParams) WithLimit(limit *int64) *AttributeGroupsGetListParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the attribute groups get list params
func (o *AttributeGroupsGetListParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithPage adds the page to the attribute groups get list params
func (o *AttributeGroupsGetListParams) WithPage(page *int64) *AttributeGroupsGetListParams {
	o.SetPage(page)
	return o
}

// SetPage adds the page to the attribute groups get list params
func (o *AttributeGroupsGetListParams) SetPage(page *int64) {
	o.Page = page
}

// WithSearch adds the search to the attribute groups get list params
func (o *AttributeGroupsGetListParams) WithSearch(search *string) *AttributeGroupsGetListParams {
	o.SetSearch(search)
	return o
}

// SetSearch adds the search to the attribute groups get list params
func (o *AttributeGroupsGetListParams) SetSearch(search *string) {
	o.Search = search
}

// WithWithCount adds the withCount to the attribute groups get list params
func (o *AttributeGroupsGetListParams) WithWithCount(withCount *bool) *AttributeGroupsGetListParams {
	o.SetWithCount(withCount)
	return o
}

// SetWithCount adds the withCount to the attribute groups get list params
func (o *AttributeGroupsGetListParams) SetWithCount(withCount *bool) {
	o.WithCount = withCount
}

// WriteToRequest writes these params to a swagger request
func (o *AttributeGroupsGetListParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	if o.Search != nil {

		// query param search
		var qrSearch string
		if o.Search != nil {
			qrSearch = *o.Search
		}
		qSearch := qrSearch
		if qSearch != "" {
			if err := r.SetQueryParam("search", qSearch); err != nil {
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