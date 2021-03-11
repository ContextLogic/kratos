/*
 * Ory Kratos API
 *
 * Documentation for all public and administrative Ory Kratos APIs. Public and administrative APIs are exposed on different ports. Public APIs can face the public internet without any protection while administrative APIs should never be exposed without prior authorization. To protect the administative API port you should use something like Nginx, Ory Oathkeeper, or any other technology capable of authorizing incoming requests.
 *
 * API version: 1.0.0
 * Contact: hi@ory.sh
 */

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package kratos

import (
	"encoding/json"
)

// ImageDeleteResponseItem ImageDeleteResponseItem image delete response item
type ImageDeleteResponseItem struct {
	// The image ID of an image that was deleted
	Deleted *string `json:"Deleted,omitempty"`
	// The image ID of an image that was untagged
	Untagged *string `json:"Untagged,omitempty"`
}

// NewImageDeleteResponseItem instantiates a new ImageDeleteResponseItem object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewImageDeleteResponseItem() *ImageDeleteResponseItem {
	this := ImageDeleteResponseItem{}
	return &this
}

// NewImageDeleteResponseItemWithDefaults instantiates a new ImageDeleteResponseItem object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewImageDeleteResponseItemWithDefaults() *ImageDeleteResponseItem {
	this := ImageDeleteResponseItem{}
	return &this
}

// GetDeleted returns the Deleted field value if set, zero value otherwise.
func (o *ImageDeleteResponseItem) GetDeleted() string {
	if o == nil || o.Deleted == nil {
		var ret string
		return ret
	}
	return *o.Deleted
}

// GetDeletedOk returns a tuple with the Deleted field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ImageDeleteResponseItem) GetDeletedOk() (*string, bool) {
	if o == nil || o.Deleted == nil {
		return nil, false
	}
	return o.Deleted, true
}

// HasDeleted returns a boolean if a field has been set.
func (o *ImageDeleteResponseItem) HasDeleted() bool {
	if o != nil && o.Deleted != nil {
		return true
	}

	return false
}

// SetDeleted gets a reference to the given string and assigns it to the Deleted field.
func (o *ImageDeleteResponseItem) SetDeleted(v string) {
	o.Deleted = &v
}

// GetUntagged returns the Untagged field value if set, zero value otherwise.
func (o *ImageDeleteResponseItem) GetUntagged() string {
	if o == nil || o.Untagged == nil {
		var ret string
		return ret
	}
	return *o.Untagged
}

// GetUntaggedOk returns a tuple with the Untagged field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ImageDeleteResponseItem) GetUntaggedOk() (*string, bool) {
	if o == nil || o.Untagged == nil {
		return nil, false
	}
	return o.Untagged, true
}

// HasUntagged returns a boolean if a field has been set.
func (o *ImageDeleteResponseItem) HasUntagged() bool {
	if o != nil && o.Untagged != nil {
		return true
	}

	return false
}

// SetUntagged gets a reference to the given string and assigns it to the Untagged field.
func (o *ImageDeleteResponseItem) SetUntagged(v string) {
	o.Untagged = &v
}

func (o ImageDeleteResponseItem) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Deleted != nil {
		toSerialize["Deleted"] = o.Deleted
	}
	if o.Untagged != nil {
		toSerialize["Untagged"] = o.Untagged
	}
	return json.Marshal(toSerialize)
}

type NullableImageDeleteResponseItem struct {
	value *ImageDeleteResponseItem
	isSet bool
}

func (v NullableImageDeleteResponseItem) Get() *ImageDeleteResponseItem {
	return v.value
}

func (v *NullableImageDeleteResponseItem) Set(val *ImageDeleteResponseItem) {
	v.value = val
	v.isSet = true
}

func (v NullableImageDeleteResponseItem) IsSet() bool {
	return v.isSet
}

func (v *NullableImageDeleteResponseItem) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableImageDeleteResponseItem(val *ImageDeleteResponseItem) *NullableImageDeleteResponseItem {
	return &NullableImageDeleteResponseItem{value: val, isSet: true}
}

func (v NullableImageDeleteResponseItem) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableImageDeleteResponseItem) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
