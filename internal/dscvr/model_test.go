package dscvr

import (
	"encoding/base64"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"
)

func TestValidateAttr(t *testing.T) {
	// Helper function to create valid scan config
	validScanConfig := model.Scan{
		Version: 0,
		Filesystem: model.Filesystem{
			Enabled: true,
			Paths:   []string{"/tmp"},
		},
		Containers: model.Containers{
			Enabled: false,
		},
		Ports: model.Ports{
			Enabled: false,
		},
		Service: model.ServiceFields{
			Verbose: false,
			Log:     "stderr",
		},
	}

	validYAML, err := yaml.Marshal(validScanConfig)
	require.NoError(t, err)
	validBase64 := base64.StdEncoding.EncodeToString(validYAML)

	tests := []struct {
		name    string
		attrs   []RequestAttributeDto
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid attribute",
			attrs: []RequestAttributeDto{
				{
					UUID:        lensConfigurationAttrUUID,
					Name:        lensConfigurationAttrName,
					ContentType: AttributeContentTypeCodeblock,
					Content: []attrCodeblockContent{
						{
							Data: attrCodeblockContentData{
								Code:     validBase64,
								Language: "yaml",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "empty UUID",
			attrs: []RequestAttributeDto{
				{
					UUID:        "",
					Name:        lensConfigurationAttrName,
					ContentType: AttributeContentTypeCodeblock,
					Content: []attrCodeblockContent{
						{
							Data: attrCodeblockContentData{
								Code:     validBase64,
								Language: "yaml",
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "UUID cannot be empty",
		},
		{
			name: "empty name",
			attrs: []RequestAttributeDto{
				{
					UUID:        lensConfigurationAttrUUID,
					Name:        "",
					ContentType: AttributeContentTypeCodeblock,
					Content: []attrCodeblockContent{
						{
							Data: attrCodeblockContentData{
								Code:     validBase64,
								Language: "yaml",
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "name cannot be empty",
		},
		{
			name: "empty contentType",
			attrs: []RequestAttributeDto{
				{
					UUID:        lensConfigurationAttrUUID,
					Name:        lensConfigurationAttrName,
					ContentType: "",
					Content: []attrCodeblockContent{
						{
							Data: attrCodeblockContentData{
								Code:     validBase64,
								Language: "yaml",
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "contentType cannot be empty",
		},
		{
			name: "invalid ContentType value",
			attrs: []RequestAttributeDto{
				{
					UUID:        lensConfigurationAttrUUID,
					Name:        lensConfigurationAttrName,
					ContentType: "invalid",
					Content: []attrCodeblockContent{
						{
							Data: attrCodeblockContentData{
								Code:     validBase64,
								Language: "yaml",
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid contentType",
		},
		{
			name: "empty Content array",
			attrs: []RequestAttributeDto{
				{
					UUID:        lensConfigurationAttrUUID,
					Name:        lensConfigurationAttrName,
					ContentType: AttributeContentTypeCodeblock,
					Content:     []attrCodeblockContent{},
				},
			},
			wantErr: true,
			errMsg:  "content cannot be empty",
		},
		{
			name: "multiple Content items",
			attrs: []RequestAttributeDto{
				{
					UUID:        lensConfigurationAttrUUID,
					Name:        lensConfigurationAttrName,
					ContentType: AttributeContentTypeCodeblock,
					Content: []attrCodeblockContent{
						{
							Data: attrCodeblockContentData{
								Code:     validBase64,
								Language: "yaml",
							},
						},
						{
							Data: attrCodeblockContentData{
								Code:     validBase64,
								Language: "yaml",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "empty attributes slice",
			attrs:   []RequestAttributeDto{},
			wantErr: true,
			errMsg:  "cannot be empty",
		},
		{
			name: "multiple valid attributes",
			attrs: []RequestAttributeDto{
				{
					UUID:        lensConfigurationAttrUUID,
					Name:        lensConfigurationAttrName,
					ContentType: AttributeContentTypeCodeblock,
					Content: []attrCodeblockContent{
						{
							Data: attrCodeblockContentData{
								Code:     validBase64,
								Language: "yaml",
							},
						},
					},
				},
				{
					UUID:        lensConfigurationAttrUUID,
					Name:        lensConfigurationAttrName,
					ContentType: AttributeContentTypeCodeblock,
					Content: []attrCodeblockContent{
						{
							Data: attrCodeblockContentData{
								Code:     validBase64,
								Language: "yaml",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "nil attributes slice",
			attrs:   nil,
			wantErr: true,
			errMsg:  "cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAttr(tt.attrs)
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
