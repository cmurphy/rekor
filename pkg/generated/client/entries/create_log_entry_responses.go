// Code generated by go-swagger; DO NOT EDIT.

//
// Copyright 2025 The Sigstore Authors.
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
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/sigstore/rekor/pkg/generated/models"
)

// CreateLogEntryReader is a Reader for the CreateLogEntry structure.
type CreateLogEntryReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateLogEntryReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateLogEntryCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateLogEntryBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewCreateLogEntryConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		result := NewCreateLogEntryDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewCreateLogEntryCreated creates a CreateLogEntryCreated with default headers values
func NewCreateLogEntryCreated() *CreateLogEntryCreated {
	return &CreateLogEntryCreated{}
}

/*
CreateLogEntryCreated describes a response with status code 201, with default header values.

Returns the entry created in the transparency log
*/
type CreateLogEntryCreated struct {

	/* UUID of log entry
	 */
	ETag string

	/* URI location of log entry

	   Format: uri
	*/
	Location strfmt.URI

	Payload models.LogEntry
}

// IsSuccess returns true when this create log entry created response has a 2xx status code
func (o *CreateLogEntryCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create log entry created response has a 3xx status code
func (o *CreateLogEntryCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create log entry created response has a 4xx status code
func (o *CreateLogEntryCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create log entry created response has a 5xx status code
func (o *CreateLogEntryCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create log entry created response a status code equal to that given
func (o *CreateLogEntryCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create log entry created response
func (o *CreateLogEntryCreated) Code() int {
	return 201
}

func (o *CreateLogEntryCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/log/entries][%d] createLogEntryCreated %s", 201, payload)
}

func (o *CreateLogEntryCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/log/entries][%d] createLogEntryCreated %s", 201, payload)
}

func (o *CreateLogEntryCreated) GetPayload() models.LogEntry {
	return o.Payload
}

func (o *CreateLogEntryCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header ETag
	hdrETag := response.GetHeader("ETag")

	if hdrETag != "" {
		o.ETag = hdrETag
	}

	// hydrates response header Location
	hdrLocation := response.GetHeader("Location")

	if hdrLocation != "" {
		vallocation, err := formats.Parse("uri", hdrLocation)
		if err != nil {
			return errors.InvalidType("Location", "header", "strfmt.URI", hdrLocation)
		}
		o.Location = *(vallocation.(*strfmt.URI))
	}

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateLogEntryBadRequest creates a CreateLogEntryBadRequest with default headers values
func NewCreateLogEntryBadRequest() *CreateLogEntryBadRequest {
	return &CreateLogEntryBadRequest{}
}

/*
CreateLogEntryBadRequest describes a response with status code 400, with default header values.

The content supplied to the server was invalid
*/
type CreateLogEntryBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this create log entry bad request response has a 2xx status code
func (o *CreateLogEntryBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create log entry bad request response has a 3xx status code
func (o *CreateLogEntryBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create log entry bad request response has a 4xx status code
func (o *CreateLogEntryBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create log entry bad request response has a 5xx status code
func (o *CreateLogEntryBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create log entry bad request response a status code equal to that given
func (o *CreateLogEntryBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create log entry bad request response
func (o *CreateLogEntryBadRequest) Code() int {
	return 400
}

func (o *CreateLogEntryBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/log/entries][%d] createLogEntryBadRequest %s", 400, payload)
}

func (o *CreateLogEntryBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/log/entries][%d] createLogEntryBadRequest %s", 400, payload)
}

func (o *CreateLogEntryBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateLogEntryBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateLogEntryConflict creates a CreateLogEntryConflict with default headers values
func NewCreateLogEntryConflict() *CreateLogEntryConflict {
	return &CreateLogEntryConflict{}
}

/*
CreateLogEntryConflict describes a response with status code 409, with default header values.

The request conflicts with the current state of the transparency log
*/
type CreateLogEntryConflict struct {
	Location strfmt.URI

	Payload *models.Error
}

// IsSuccess returns true when this create log entry conflict response has a 2xx status code
func (o *CreateLogEntryConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create log entry conflict response has a 3xx status code
func (o *CreateLogEntryConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create log entry conflict response has a 4xx status code
func (o *CreateLogEntryConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this create log entry conflict response has a 5xx status code
func (o *CreateLogEntryConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this create log entry conflict response a status code equal to that given
func (o *CreateLogEntryConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the create log entry conflict response
func (o *CreateLogEntryConflict) Code() int {
	return 409
}

func (o *CreateLogEntryConflict) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/log/entries][%d] createLogEntryConflict %s", 409, payload)
}

func (o *CreateLogEntryConflict) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/log/entries][%d] createLogEntryConflict %s", 409, payload)
}

func (o *CreateLogEntryConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateLogEntryConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header Location
	hdrLocation := response.GetHeader("Location")

	if hdrLocation != "" {
		vallocation, err := formats.Parse("uri", hdrLocation)
		if err != nil {
			return errors.InvalidType("Location", "header", "strfmt.URI", hdrLocation)
		}
		o.Location = *(vallocation.(*strfmt.URI))
	}

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateLogEntryDefault creates a CreateLogEntryDefault with default headers values
func NewCreateLogEntryDefault(code int) *CreateLogEntryDefault {
	return &CreateLogEntryDefault{
		_statusCode: code,
	}
}

/*
CreateLogEntryDefault describes a response with status code -1, with default header values.

There was an internal error in the server while processing the request
*/
type CreateLogEntryDefault struct {
	_statusCode int

	Payload *models.Error
}

// IsSuccess returns true when this create log entry default response has a 2xx status code
func (o *CreateLogEntryDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this create log entry default response has a 3xx status code
func (o *CreateLogEntryDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this create log entry default response has a 4xx status code
func (o *CreateLogEntryDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this create log entry default response has a 5xx status code
func (o *CreateLogEntryDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this create log entry default response a status code equal to that given
func (o *CreateLogEntryDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the create log entry default response
func (o *CreateLogEntryDefault) Code() int {
	return o._statusCode
}

func (o *CreateLogEntryDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/log/entries][%d] createLogEntry default %s", o._statusCode, payload)
}

func (o *CreateLogEntryDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/log/entries][%d] createLogEntry default %s", o._statusCode, payload)
}

func (o *CreateLogEntryDefault) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateLogEntryDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
