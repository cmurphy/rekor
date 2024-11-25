// Code generated by go-swagger; DO NOT EDIT.

//
// Copyright 2024 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package entries

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

	"github.com/sigstore/rekor/pkg/generated/models"
)

// NewCreateLogEntryParams creates a new CreateLogEntryParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateLogEntryParams() *CreateLogEntryParams {
	return &CreateLogEntryParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateLogEntryParamsWithTimeout creates a new CreateLogEntryParams object
// with the ability to set a timeout on a request.
func NewCreateLogEntryParamsWithTimeout(timeout time.Duration) *CreateLogEntryParams {
	return &CreateLogEntryParams{
		timeout: timeout,
	}
}

// NewCreateLogEntryParamsWithContext creates a new CreateLogEntryParams object
// with the ability to set a context for a request.
func NewCreateLogEntryParamsWithContext(ctx context.Context) *CreateLogEntryParams {
	return &CreateLogEntryParams{
		Context: ctx,
	}
}

// NewCreateLogEntryParamsWithHTTPClient creates a new CreateLogEntryParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateLogEntryParamsWithHTTPClient(client *http.Client) *CreateLogEntryParams {
	return &CreateLogEntryParams{
		HTTPClient: client,
	}
}

/*
CreateLogEntryParams contains all the parameters to send to the API endpoint

	for the create log entry operation.

	Typically these are written to a http.Request.
*/
type CreateLogEntryParams struct {

	// ProposedEntry.
	ProposedEntry models.ProposedEntry

	/* TreeID.

	   The tree ID of the tree in which you wish to create an entry
	*/
	TreeID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create log entry params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateLogEntryParams) WithDefaults() *CreateLogEntryParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create log entry params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateLogEntryParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the create log entry params
func (o *CreateLogEntryParams) WithTimeout(timeout time.Duration) *CreateLogEntryParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create log entry params
func (o *CreateLogEntryParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create log entry params
func (o *CreateLogEntryParams) WithContext(ctx context.Context) *CreateLogEntryParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create log entry params
func (o *CreateLogEntryParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create log entry params
func (o *CreateLogEntryParams) WithHTTPClient(client *http.Client) *CreateLogEntryParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create log entry params
func (o *CreateLogEntryParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithProposedEntry adds the proposedEntry to the create log entry params
func (o *CreateLogEntryParams) WithProposedEntry(proposedEntry models.ProposedEntry) *CreateLogEntryParams {
	o.SetProposedEntry(proposedEntry)
	return o
}

// SetProposedEntry adds the proposedEntry to the create log entry params
func (o *CreateLogEntryParams) SetProposedEntry(proposedEntry models.ProposedEntry) {
	o.ProposedEntry = proposedEntry
}

// WithTreeID adds the treeID to the create log entry params
func (o *CreateLogEntryParams) WithTreeID(treeID string) *CreateLogEntryParams {
	o.SetTreeID(treeID)
	return o
}

// SetTreeID adds the treeId to the create log entry params
func (o *CreateLogEntryParams) SetTreeID(treeID string) {
	o.TreeID = treeID
}

// WriteToRequest writes these params to a swagger request
func (o *CreateLogEntryParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if err := r.SetBodyParam(o.ProposedEntry); err != nil {
		return err
	}

	// path param treeID
	if err := r.SetPathParam("treeID", o.TreeID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
