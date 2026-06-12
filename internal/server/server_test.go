/*
** OCI Secrets Store CSI Driver Provider
**
** Copyright (c) 2022 Oracle America, Inc. and its affiliates.
** Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
 */
package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/oracle-samples/oci-secrets-store-csi-driver-provider/internal/service"
	"github.com/oracle-samples/oci-secrets-store-csi-driver-provider/internal/testutils"
	"github.com/oracle-samples/oci-secrets-store-csi-driver-provider/internal/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	provider "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

func TestMain(m *testing.M) {
	testutils.RunTestCase(m)
}

const readOnlyFilePermission = "292" // Octal 0444 in decimal
const readOnlyPermission = 0444

// Note that real-life Secrets Store CSI Driver sends more detailed and complicated MountRequest
// than we use for testing purposes.

type cachedK8sClient struct{}

func (cachedK8sClient) CoreV1() corev1client.CoreV1Interface {
	return nil
}

func TestGetK8sClientSet_ReturnsCachedClientSet(t *testing.T) {
	cachedClientSet := cachedK8sClient{}
	providerServer := &ProviderServer{k8sClientSet: cachedClientSet}

	firstClientSet, err := providerServer.getK8sClientSet()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	secondClientSet, err := providerServer.getK8sClientSet()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if firstClientSet != cachedClientSet {
		t.Fatalf("Expected cached clientset, got a different clientset")
	}
	if secondClientSet != cachedClientSet {
		t.Fatalf("Expected cached clientset on repeated call, got a different clientset")
	}
}

func TestMount_RequestTwoExistingSecrets_ReturnTwoSecrets(t *testing.T) {
	secretBundleRequests := []*types.SecretBundleRequest{
		{Name: "foo", VersionNumber: 2},
		{Name: "hello", VersionNumber: 1},
	}
	mockBundles := []*types.SecretBundle{
		{
			ID: "uid1", Name: "foo", VersionNumber: 2,
			Stages:        []types.Stage{types.Current, types.Latest},
			BundleContent: &types.SecretBundleContent{Content: "YmFyMQ==", ContentType: types.Base64},
		},
		{
			ID: "uid2", Name: "hello", VersionNumber: 1,
			Stages:        []types.Stage{types.Current, types.Latest},
			BundleContent: &types.SecretBundleContent{Content: "d29ybGQ=", ContentType: types.Base64},
		},
	}

	var mockService service.SecretService = &mockSecretService{
		requestsMock: secretBundleRequests,
		bundlesMock:  mockBundles,
	}
	providerServer := &ProviderServer{secretService: mockService}

	var auth *types.Auth = &types.Auth{Type: types.Instance}
	var vaultID = "vault1"
	attributes, err := marshalRequestAttributes(secretBundleRequests, auth, vaultID)
	if err != nil {
		t.Fatalf("Precondition failed: unable to serialize request attributes")
	}
	request := provider.MountRequest{
		Attributes: attributes,
		TargetPath: "/some/path",
		Permission: readOnlyFilePermission,
	}

	mountResponse, err := providerServer.Mount(context.Background(), &request)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expectedMountResponse := &provider.MountResponse{
		Files: []*provider.File{
			{Path: "foo", Contents: []byte("bar1"), Mode: readOnlyPermission},
			{Path: "hello", Contents: []byte("world"), Mode: readOnlyPermission},
		},
		ObjectVersion: []*provider.ObjectVersion{
			{Id: "uid1", Version: "2"},
			{Id: "uid2", Version: "1"},
		},
	}

	assertMountResponse(t, mountResponse, expectedMountResponse)
}

func TestMount_RequestOneExistingSecretAndOneAbsent_ReturnError(t *testing.T) {
	secretBundleRequests := []*types.SecretBundleRequest{
		{Name: "foo", VersionNumber: 2},
		{Name: "hello", VersionNumber: 2},
	}

	var mockService service.SecretService = &mockSecretService{}
	providerServer := &ProviderServer{secretService: mockService}

	var auth *types.Auth = &types.Auth{Type: types.Instance}
	var vaultID = "vault1"
	attributes, err := marshalRequestAttributes(secretBundleRequests, auth, vaultID)
	if err != nil {
		t.Fatalf("Precondition failed: unable to serialize request attributes")
	}
	request := provider.MountRequest{
		Attributes: attributes,
		TargetPath: "/some/path",
		Permission: readOnlyFilePermission,
	}

	_, err = providerServer.Mount(context.Background(), &request)
	if err == nil {
		t.Fatalf("Missed expected error")
	}
	if status.Code(err) != codes.NotFound {
		t.Errorf("Invalid gRPC code: %v", status.Code(err))
	}
	if !strings.Contains(err.Error(), "unable to retrieve secrets:") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestMount_InvalidFormatAttributes_ReturnError(t *testing.T) {
	var mockService service.SecretService = &mockSecretService{}
	providerServer := &ProviderServer{secretService: mockService}

	request := provider.MountRequest{
		Attributes: "invalid-value",
		TargetPath: "/some/path",
		Permission: readOnlyFilePermission,
	}

	_, err := providerServer.Mount(context.Background(), &request)
	if err == nil {
		t.Fatalf("Missed expected error")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("Invalid gRPC code: %v", status.Code(err))
	}
	if !strings.Contains(
		err.Error(), "failed to unmarshal SecretProviderClass parameters or attributes provided by driver") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestMount_InvalidSecretsAttribute_ReturnError(t *testing.T) {
	var mockService service.SecretService = &mockSecretService{}
	providerServer := &ProviderServer{secretService: mockService}

	invalidMountRequests, err := prepareInvalidMountRequests()
	if err != nil {
		t.Fatalf("Precondition failed: unable to prepare requests: %v", err)
	}

	for _, request := range invalidMountRequests {
		_, err := providerServer.Mount(context.Background(), request)
		if err == nil {
			t.Errorf("Missed expected error")
			continue
		}
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("Invalid gRPC code: %v", status.Code(err))
		}
		if !strings.Contains(err.Error(), "unable to handle SecretProviderClass secrets:") {
			t.Errorf("Unexpected error message: %v", err)
		}
	}
}

func TestMount_RequestTwoSecretsWithAliasForOnlyOne_ReturnTwoSecretsWithOnePathOverwriitenWithAlias(t *testing.T) {
	secretBundleRequests := []*types.SecretBundleRequest{
		{Name: "foo", VersionNumber: 2, FileName: "fooAlias"},
		{Name: "hello", VersionNumber: 1},
	}
	mockBundles := []*types.SecretBundle{
		{
			ID: "uid1", Name: "foo", VersionNumber: 2, FileName: "fooAlias",
			Stages:        []types.Stage{types.Current, types.Latest},
			BundleContent: &types.SecretBundleContent{Content: "YmFyMQ==", ContentType: types.Base64},
		},
		{
			ID: "uid2", Name: "hello", VersionNumber: 1,
			Stages:        []types.Stage{types.Current, types.Latest},
			BundleContent: &types.SecretBundleContent{Content: "d29ybGQ=", ContentType: types.Base64},
		},
	}

	var mockService service.SecretService = &mockSecretService{
		requestsMock: secretBundleRequests,
		bundlesMock:  mockBundles,
	}
	providerServer := &ProviderServer{secretService: mockService}

	var auth *types.Auth = &types.Auth{Type: types.Instance}
	var vaultID = "vault1"
	attributes, err := marshalRequestAttributes(secretBundleRequests, auth, vaultID)
	if err != nil {
		t.Fatalf("Precondition failed: unable to serialize request attributes")
	}
	request := provider.MountRequest{
		Attributes: attributes,
		TargetPath: "/some/path",
		Permission: readOnlyFilePermission,
	}

	mountResponse, err := providerServer.Mount(context.Background(), &request)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expectedMountResponse := &provider.MountResponse{
		Files: []*provider.File{
			{Path: "fooAlias", Contents: []byte("bar1"), Mode: readOnlyPermission},
			{Path: "hello", Contents: []byte("world"), Mode: readOnlyPermission},
		},
		ObjectVersion: []*provider.ObjectVersion{
			{Id: "uid1", Version: "2"},
			{Id: "uid2", Version: "1"},
		},
	}

	assertMountResponse(t, mountResponse, expectedMountResponse)
}

func TestMount_RequestTwoSecretsWithAliases_ReturnTwoSecretsWithAliases(t *testing.T) {
	secretBundleRequests := []*types.SecretBundleRequest{
		{Name: "foo", VersionNumber: 2, FileName: "fooAlias"},
		{Name: "hello", VersionNumber: 1, FileName: "helloAlias"},
	}
	mockBundles := []*types.SecretBundle{
		{
			ID: "uid1", Name: "foo", VersionNumber: 2, FileName: "fooAlias",
			Stages:        []types.Stage{types.Current, types.Latest},
			BundleContent: &types.SecretBundleContent{Content: "YmFyMQ==", ContentType: types.Base64},
		},
		{
			ID: "uid2", Name: "hello", VersionNumber: 1, FileName: "helloAlias",
			Stages:        []types.Stage{types.Current, types.Latest},
			BundleContent: &types.SecretBundleContent{Content: "d29ybGQ=", ContentType: types.Base64},
		},
	}

	var mockService service.SecretService = &mockSecretService{
		requestsMock: secretBundleRequests,
		bundlesMock:  mockBundles,
	}
	providerServer := &ProviderServer{secretService: mockService}

	var auth *types.Auth = &types.Auth{Type: types.Instance}
	var vaultID = "vault1"
	attributes, err := marshalRequestAttributes(secretBundleRequests, auth, vaultID)
	if err != nil {
		t.Fatalf("Precondition failed: unable to serialize request attributes")
	}
	request := provider.MountRequest{
		Attributes: attributes,
		TargetPath: "/some/path",
		Permission: readOnlyFilePermission,
	}

	mountResponse, err := providerServer.Mount(context.Background(), &request)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expectedMountResponse := &provider.MountResponse{
		Files: []*provider.File{
			{Path: "fooAlias", Contents: []byte("bar1"), Mode: readOnlyPermission},
			{Path: "helloAlias", Contents: []byte("world"), Mode: readOnlyPermission},
		},
		ObjectVersion: []*provider.ObjectVersion{
			{Id: "uid1", Version: "2"},
			{Id: "uid2", Version: "1"},
		},
	}

	assertMountResponse(t, mountResponse, expectedMountResponse)
}

func prepareInvalidMountRequests() ([]*provider.MountRequest, error) {
	invalidParameters := []map[string]string{
		{"someField": "someValue"},   // missed 'secrets' attribute
		{"secrets": ""},              // empty 'secrets' attribute
		{"secrets": "invalid-value"}, // plain string instead of expected YAML
		{"secrets": "- name: foo\n  versionNumber: 2\n  redundantField: test\n"}, // redundant secret field
		{"secrets": "- name: foo\n  versionNumber: 0\n"},                         // non-positive version number
	}
	var mountRequests []*provider.MountRequest

	for _, parameters := range invalidParameters {
		parametersJSONBytes, err := json.Marshal(parameters)
		if err != nil {
			return nil, err
		}
		request := &provider.MountRequest{
			Attributes: string(parametersJSONBytes),
			TargetPath: "/some/path",
			Permission: readOnlyFilePermission,
		}
		mountRequests = append(mountRequests, request)
	}
	return mountRequests, nil
}
