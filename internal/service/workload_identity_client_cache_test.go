/*
** OCI Secrets Store CSI Driver Provider
**
** Copyright (c) 2022 Oracle America, Inc. and its affiliates.
** Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
 */
package service

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/oracle-samples/oci-secrets-store-csi-driver-provider/internal/types"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	apiMachineryTypes "k8s.io/apimachinery/pkg/types"
)

type fakeServiceAccountTokenSource struct {
	mu        sync.Mutex
	calls     int
	expiresAt func(time.Duration) time.Time
	started   chan struct{}
	startOnce sync.Once
	block     chan struct{}
}

func (source *fakeServiceAccountTokenSource) TokenForPod(
	ctx context.Context, _ types.PodInfo, ttl time.Duration) (*ServiceAccountToken, error) {

	source.mu.Lock()
	source.calls++
	callNumber := source.calls
	source.mu.Unlock()

	if source.started != nil {
		source.startOnce.Do(func() {
			close(source.started)
		})
	}
	if source.block != nil {
		select {
		case <-source.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	expiresAt := time.Now().Add(ttl)
	if source.expiresAt != nil {
		expiresAt = source.expiresAt(ttl)
	}

	return &ServiceAccountToken{
		Token:     fmt.Sprintf("token-%d", callNumber),
		ExpiresAt: expiresAt,
	}, nil
}

func (source *fakeServiceAccountTokenSource) Calls() int {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.calls
}

type fakeWorkloadIdentityFactory struct {
	mu                     sync.Mutex
	configProvidersCreated int
	secretClientsCreated   int
}

func (factory *fakeWorkloadIdentityFactory) createSecretClient(
	_ common.ConfigurationProvider) (OCISecretClient, error) {

	factory.mu.Lock()
	defer factory.mu.Unlock()

	factory.secretClientsCreated++
	return &fakeWorkloadIdentitySecretClient{id: factory.secretClientsCreated}, nil
}

func (factory *fakeWorkloadIdentityFactory) createConfigProvider(
	_ *types.Auth) (common.ConfigurationProvider, error) {

	return common.NewRawConfigurationProvider("tenancy", "user", "region", "fingerprint", "privatekey", nil), nil
}

func (factory *fakeWorkloadIdentityFactory) createWorkloadIdentityConfigProvider(
	serviceAccountToken string) (common.ConfigurationProvider, error) {

	factory.mu.Lock()
	defer factory.mu.Unlock()

	factory.configProvidersCreated++
	return common.NewRawConfigurationProvider(
		"tenancy", "user", "region", "fingerprint", serviceAccountToken, nil), nil
}

func (factory *fakeWorkloadIdentityFactory) ConfigProvidersCreated() int {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	return factory.configProvidersCreated
}

func (factory *fakeWorkloadIdentityFactory) SecretClientsCreated() int {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	return factory.secretClientsCreated
}

type fakeWorkloadIdentitySecretClient struct {
	id int
}

func (*fakeWorkloadIdentitySecretClient) GetSecretBundleByName(
	context.Context, secrets.GetSecretBundleByNameRequest) (secrets.GetSecretBundleByNameResponse, error) {

	return secrets.GetSecretBundleByNameResponse{}, nil
}

func newTestWorkloadIdentityClientCache(
	now *time.Time,
	tokenSource *fakeServiceAccountTokenSource,
	factory *fakeWorkloadIdentityFactory) *workloadIdentityClientCache {

	cache := newWorkloadIdentityClientCache(tokenSource, factory)
	cache.now = func() time.Time {
		return *now
	}
	cache.maxEntries = 10
	return cache
}

func newWorkloadIdentityAuth(podUID string) *types.Auth {
	return &types.Auth{
		Type: types.Workload,
		WorkloadIdentityCfg: types.WorkloadIdentityConfig{
			PodInfo: types.PodInfo{
				Namespace:          "test-namespace",
				Name:               "test-pod",
				UID:                apiMachineryTypes.UID(podUID),
				ServiceAccountName: "test-service-account",
			},
		},
	}
}

func TestWorkloadIdentityClientCache_SamePodBeforeTTLReusesClient(t *testing.T) {
	now := time.Date(2026, time.June, 16, 12, 0, 0, 0, time.UTC)
	tokenSource := &fakeServiceAccountTokenSource{expiresAt: func(ttl time.Duration) time.Time {
		return now.Add(ttl)
	}}
	factory := &fakeWorkloadIdentityFactory{}
	cache := newTestWorkloadIdentityClientCache(&now, tokenSource, factory)
	auth := newWorkloadIdentityAuth("pod-uid-1")

	firstLease, err := cache.GetOrCreate(context.Background(), auth)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	firstClient := firstLease.SecretClient()
	firstLease.Release()

	secondLease, err := cache.GetOrCreate(context.Background(), auth)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	secondClient := secondLease.SecretClient()
	secondLease.Release()

	if firstClient != secondClient {
		t.Fatalf("Expected same cached client before TTL expiry")
	}
	if tokenSource.Calls() != 1 {
		t.Fatalf("Expected one token request, got %d", tokenSource.Calls())
	}
	if factory.ConfigProvidersCreated() != 1 {
		t.Fatalf("Expected one config provider, got %d", factory.ConfigProvidersCreated())
	}
	if factory.SecretClientsCreated() != 1 {
		t.Fatalf("Expected one Secrets client, got %d", factory.SecretClientsCreated())
	}
}

func TestWorkloadIdentityClientCache_DifferentPodUIDCreatesDifferentClient(t *testing.T) {
	now := time.Date(2026, time.June, 16, 12, 0, 0, 0, time.UTC)
	tokenSource := &fakeServiceAccountTokenSource{expiresAt: func(ttl time.Duration) time.Time {
		return now.Add(ttl)
	}}
	factory := &fakeWorkloadIdentityFactory{}
	cache := newTestWorkloadIdentityClientCache(&now, tokenSource, factory)

	firstLease, err := cache.GetOrCreate(context.Background(), newWorkloadIdentityAuth("pod-uid-1"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	firstClient := firstLease.SecretClient()
	firstLease.Release()

	secondLease, err := cache.GetOrCreate(context.Background(), newWorkloadIdentityAuth("pod-uid-2"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	secondClient := secondLease.SecretClient()
	secondLease.Release()

	if firstClient == secondClient {
		t.Fatalf("Expected different clients for different pod UIDs")
	}
	if tokenSource.Calls() != 2 {
		t.Fatalf("Expected two token requests, got %d", tokenSource.Calls())
	}
}

func TestWorkloadIdentityClientCache_ExpiredEntryIsReplaced(t *testing.T) {
	now := time.Date(2026, time.June, 16, 12, 0, 0, 0, time.UTC)
	tokenSource := &fakeServiceAccountTokenSource{expiresAt: func(ttl time.Duration) time.Time {
		return now.Add(ttl)
	}}
	factory := &fakeWorkloadIdentityFactory{}
	cache := newTestWorkloadIdentityClientCache(&now, tokenSource, factory)
	auth := newWorkloadIdentityAuth("pod-uid-1")

	firstLease, err := cache.GetOrCreate(context.Background(), auth)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	firstClient := firstLease.SecretClient()
	firstLease.Release()

	now = now.Add(workloadIdentityTokenTTL)

	secondLease, err := cache.GetOrCreate(context.Background(), auth)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	secondClient := secondLease.SecretClient()
	secondLease.Release()

	if firstClient == secondClient {
		t.Fatalf("Expected a new client after cache entry expiry")
	}
	if tokenSource.Calls() != 2 {
		t.Fatalf("Expected two token requests, got %d", tokenSource.Calls())
	}
}

func TestWorkloadIdentityClientCache_ReaperRetiresExpiredEntry(t *testing.T) {
	now := time.Date(2026, time.June, 16, 12, 0, 0, 0, time.UTC)
	tokenSource := &fakeServiceAccountTokenSource{expiresAt: func(ttl time.Duration) time.Time {
		return now.Add(ttl)
	}}
	factory := &fakeWorkloadIdentityFactory{}
	cache := newTestWorkloadIdentityClientCache(&now, tokenSource, factory)
	auth := newWorkloadIdentityAuth("pod-uid-1")

	lease, err := cache.GetOrCreate(context.Background(), auth)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	lease.Release()

	now = now.Add(workloadIdentityTokenTTL)
	cache.reapExpired(now)

	if len(cache.entries) != 0 {
		t.Fatalf("Expected expired entry to be removed by reaper, got %d entries", len(cache.entries))
	}
}

func TestWorkloadIdentityClientCache_ConcurrentMissesCreateOneClient(t *testing.T) {
	now := time.Date(2026, time.June, 16, 12, 0, 0, 0, time.UTC)
	tokenSource := &fakeServiceAccountTokenSource{
		expiresAt: func(ttl time.Duration) time.Time {
			return now.Add(ttl)
		},
		started: make(chan struct{}),
		block:   make(chan struct{}),
	}
	factory := &fakeWorkloadIdentityFactory{}
	cache := newTestWorkloadIdentityClientCache(&now, tokenSource, factory)
	auth := newWorkloadIdentityAuth("pod-uid-1")

	const goroutines = 20
	errCh := make(chan error, goroutines)
	startCh := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			<-startCh
			lease, err := cache.GetOrCreate(context.Background(), auth)
			if err != nil {
				errCh <- err
				return
			}
			lease.Release()
			errCh <- nil
		}()
	}

	close(startCh)
	select {
	case <-tokenSource.started:
	case <-time.After(5 * time.Second):
		t.Fatalf("Timed out waiting for first token request")
	}
	close(tokenSource.block)

	for i := 0; i < goroutines; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	}

	if tokenSource.Calls() != 1 {
		t.Fatalf("Expected one token request for concurrent misses, got %d", tokenSource.Calls())
	}
	if factory.ConfigProvidersCreated() != 1 {
		t.Fatalf("Expected one config provider for concurrent misses, got %d", factory.ConfigProvidersCreated())
	}
	if factory.SecretClientsCreated() != 1 {
		t.Fatalf("Expected one Secrets client for concurrent misses, got %d", factory.SecretClientsCreated())
	}
}
