package dscvr

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"

	"go.yaml.in/yaml/v4"
)

type checkHealthResponse struct {
	Status      string  `json:"status"`
	Description *string `json:"description,omitempty"`
}

type listSupportedFunctionsResponse []supportedFunction

type listAttributeDefinitionsResponse []attrCodeblock

type discoverCertificateRequest struct {
	Name       string          `json:"name"`
	Kind       string          `json:"kind"`
	Attributes []attrCodeblock `json:"attributes"`
}

type discoverCertificateResponse struct {
	UUID            string `json:"uuid"`
	Name            string `json:"name"`
	Status          string `json:"status"`
	CertificateData []any  `json:"certificateData"`
	Meta            []any  `json:"meta"`
}

type getDiscoveryRequest struct {
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	PageNumber   int    `json:"pageNumber"`
	ItemsPerPage int    `json:"itemsPerPage"`
}

type getDiscoveryResponse struct {
	UUID                        string                 `json:"uuid"`
	Name                        string                 `json:"name"`
	Status                      string                 `json:"status"`
	CertificateData             []any                  `json:"certificateData"`
	TotalCertificatesDiscovered int                    `json:"totalCertificatesDiscovered"`
	Meta                        []getDiscoveryMetaItem `json:"meta"`
}

type getDiscoveryMetaItem struct {
	Version     int    `json:"version"`
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	Description string `json:"description"`

	Content     []any          `json:"content"`
	Type        string         `json:"type"`
	ContentType string         `json:"contentType"`
	Properties  metaProperties `json:"properties"`
}

type generalErrMsgResp struct {
	Message string `json:"message"`
}

type registerConnectorRequest struct {
	Name             string `json:"name"`
	Url              string `json:"url"`
	AuthType         string `json:"authType"`
	AuthAttributes   []any  `json:"authAttributes"`
	CustomAttributes []any  `json:"customAttributes"`
}

type metaItemContentString struct {
	Data string `json:"data"`
}

type metaItemContentCodeblock struct {
	Data metaItemContentCodeblockItem `json:"data"`
}

type metaItemContentCodeblockItem struct {
	Language string `json:"language"`
	Code     string `json:"code"`
}

type metaProperties struct {
	Label   string `json:"label"`
	Visible bool   `json:"visible"`
}

type supportedFunction struct {
	FuncGroupCode string                      `json:"functionGroupCode"`
	Kinds         []string                    `json:"kinds"`
	Endpoints     []supportedFunctionEndpoint `json:"endPoints"`
}

type supportedFunctionEndpoint struct {
	UUID     *string `json:"uuid"`
	Name     string  `json:"name"`
	Context  string  `json:"context"`
	Method   string  `json:"method"`
	Required bool    `json:"required"`
}

type attrCodeblock struct {
	Version     *int                   `json:"version,omitempty"`
	UUID        string                 `json:"uuid"`
	Name        string                 `json:"name"`
	Description *string                `json:"description,omitempty"`
	Type        *string                `json:"type,omitempty"`
	ContentType *string                `json:"contentType,omitempty"`
	Content     []attrCodeblockContent `json:"content"`
	Properties  *attrProperties        `json:"properties,omitempty"`
}

type attrCodeblockContent struct {
	Reference *string         `json:"reference,omitempty"`
	RawData   json.RawMessage `json:"data"`
	Data      any             `json:"-"`
}

type attrCodeblockContentData struct {
	Code     string `json:"code"`
	Language string `json:"language"`
}

type attrProperties struct {
	Label   string `json:"label"`
	Visible bool   `json:"visible"`
}

func (a *attrCodeblock) UnmarshalJSON(b []byte) error {
	type auxBlock attrCodeblock
	var aux auxBlock
	err := json.Unmarshal(b, &aux)
	if err != nil {
		return err
	}

	var typ string
	if aux.Type == nil {
		typ = "data"
	} else {
		typ = *aux.Type
	}

	switch typ {
	case "", "data":
		for i, content := range aux.Content {
			var data attrCodeblockContentData
			err := json.Unmarshal(content.RawData, &data)
			if err != nil {
				return err
			}
			aux.Content[i].Data = data
		}
	case "info":
		for i, content := range aux.Content {
			var data string
			err := json.Unmarshal(content.RawData, &data)
			if err != nil {
				return err
			}
			aux.Content[i].Data = data
		}
	default:
		return fmt.Errorf("unsupported attribute type %s: expected \"data\" or \"info\"", *aux.Type)
	}

	a.Version = aux.Version
	a.UUID = aux.UUID
	a.Name = aux.Name
	a.Description = aux.Description
	a.Type = aux.Type
	a.ContentType = aux.ContentType
	a.Content = aux.Content
	a.Properties = aux.Properties
	return nil
}

func (a attrCodeblock) MarshalJSON() ([]byte, error) {
	type auxBlock attrCodeblock
	var aux = auxBlock(a)

	for i, content := range a.Content {
		raw, err := json.Marshal(content.Data)
		if err != nil {
			return nil, err
		}
		aux.Content[i].RawData = raw
	}
	return json.Marshal(aux)
}

func (a *attrCodeblockContent) UnmarshalJSON(b []byte) error {
	type auxContent struct {
		Reference *string         `json:"reference,omitempty"`
		RawData   json.RawMessage `json:"data"`
	}
	var aux auxContent
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	a.Reference = aux.Reference
	a.RawData = aux.RawData

	// Attempt to unmarshal as CodeBlockAttributeContentData first
	var codeData attrCodeblockContentData
	if err := json.Unmarshal(aux.RawData, &codeData); err == nil && codeData.Language != "" && codeData.Code != "" {
		a.Data = codeData
		return nil
	}

	// Fallback to string (TextAttributeContent)
	var strData string
	if err := json.Unmarshal(aux.RawData, &strData); err == nil {
		a.Data = strData
		return nil
	}

	// Final fallback to generic map if nested structure is unknown
	var genericData any
	if err := json.Unmarshal(aux.RawData, &genericData); err != nil {
		return err
	}
	a.Data = genericData
	return nil
}

func (a attrCodeblockContent) MarshalJSON() ([]byte, error) {
	type auxContent struct {
		Reference *string `json:"reference,omitempty"`
		Data      any     `json:"data"`
	}
	return json.Marshal(auxContent{
		Reference: a.Reference,
		Data:      a.Data,
	})
}

func validateAttr(attrs []RequestAttributeDto) error {
	if len(attrs) == 0 {
		return nil
	}

	for _, attr := range attrs {
		switch attr.UUID {
		case lensConfigurationAttrUUID:
			if attr.Name == "" {
				return errors.New("attribute name cannot be empty")
			}
			if attr.ContentType == "" {
				return errors.New("attribute contentType cannot be empty")
			}
			if attr.ContentType != lensConfigurationAttrContentType {
				return fmt.Errorf("attribute uuid: %q, name: %q does not have expected 'ContentType' property defined, expected: %q, actual, %q",
					attr.UUID, attr.Name, lensConfigurationAttrContentType, attr.ContentType)
			}
			if len(attr.Content) != 1 {
				return fmt.Errorf("attribute uuid: %q, name: %q has unexpected number of items in `Content` array, expected: 1, actual: %d",
					attr.UUID, attr.Name, len(attr.Content))
			}
			data, ok := attr.Content[0].Data.(attrCodeblockContentData)
			if !ok {
				return fmt.Errorf("attribute uuid: %q, name: %q wrong type of `Content[0].Data` array, expected: attrCodeblockContent, actual: %T",
					attr.UUID, attr.Name, attr.Content[0].Data)
			}
			if data.Language != "yaml" {
				return fmt.Errorf("attribute uuid: %q, name: %q defines unexpected language, expected: 'yaml', actual: %q", attr.UUID, attr.Name, data.Language)
			}

			dd, err := base64.StdEncoding.DecodeString(data.Code)
			if err != nil {
				return fmt.Errorf("attribute uuid: %q, name: %q contains an unexpected base64 encoded value: %q: %s", attr.UUID, attr.Name, data.Code, err)
			}
			var m model.Scan
			err = yaml.Unmarshal(dd, &m)
			if err != nil {
				return fmt.Errorf("attribute uuid: %q, name: %q is not a valid yaml cbom-lens scan configuration: %s", attr.UUID, attr.Name, err)
			}
		case lensConfigurationInfoAttrUUID:
			return nil
		default:
			return fmt.Errorf("unknown attribute uuid: %q name: %q", attr.UUID, attr.Name)
		}
	}

	return nil
}

type AttributeContentType string

const (
	AttributeContentTypeString     AttributeContentType = "string"
	AttributeContentTypeText       AttributeContentType = "text"
	AttributeContentTypeInteger    AttributeContentType = "integer"
	AttributeContentTypeBoolean    AttributeContentType = "boolean"
	AttributeContentTypeFloat      AttributeContentType = "float"
	AttributeContentTypeDate       AttributeContentType = "date"
	AttributeContentTypeTime       AttributeContentType = "time"
	AttributeContentTypeDatetime   AttributeContentType = "datetime"
	AttributeContentTypeSecret     AttributeContentType = "secret"
	AttributeContentTypeFile       AttributeContentType = "file"
	AttributeContentTypeCredential AttributeContentType = "credential"
	AttributeContentTypeCodeblock  AttributeContentType = "codeblock"
	AttributeContentTypeObject     AttributeContentType = "object"
)

type RequestAttributeDto struct {
	UUID        string                 `json:"uuid"`
	Name        string                 `json:"name"`
	ContentType AttributeContentType   `json:"contentType"`
	Content     []attrCodeblockContent `json:"content"`
	Version     string                 `json:"version,omitempty"`
}

func ptrString(v string) *string {
	return &v
}

func ptrInt(v int) *int {
	return &v
}
