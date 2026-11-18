package kagent

import (
	"context"
	"fmt"
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

const (
	kagentGroup   = "api.kagent.dev"
	kagentVersion = "v1alpha3"

	kindRemoteMCPServer = "RemoteMCPServer"

	// managedByLabel marks the Kagent resources the registry created.
	managedByLabel = "app.kubernetes.io/managed-by"
	managedByValue = "agentregistry"
)

var (
	agentsResource           = schema.GroupVersionResource{Group: kagentGroup, Version: kagentVersion, Resource: "agents"}
	remoteMCPServersResource = schema.GroupVersionResource{Group: kagentGroup, Version: kagentVersion, Resource: "remotemcpservers"}
)

// kagentClient is the part of the Kubernetes API the adapter uses.
type kagentClient interface {
	listAgents(ctx context.Context, namespace string) ([]string, error)
	listRemoteMCPServers(ctx context.Context, namespace string) ([]string, error)
	ensureRemoteMCPServer(ctx context.Context, server *unstructured.Unstructured) error
	deleteRemoteMCPServer(ctx context.Context, namespace, name string) error
}

type dynamicClient struct {
	client dynamic.Interface
}

func newDynamicClient(client dynamic.Interface) kagentClient {
	return &dynamicClient{client: client}
}

// inClusterClient builds one client from the registry's in-cluster
// ServiceAccount and reuses it.
func inClusterClient() func() (kagentClient, error) {
	var (
		once   sync.Once
		client kagentClient
		err    error
	)
	return func() (kagentClient, error) {
		once.Do(func() {
			var config *rest.Config
			config, err = rest.InClusterConfig()
			if err != nil {
				err = fmt.Errorf("load in-cluster Kubernetes config: %w", err)
				return
			}
			var dyn dynamic.Interface
			dyn, err = dynamic.NewForConfig(config)
			if err != nil {
				err = fmt.Errorf("create Kubernetes client: %w", err)
				return
			}
			client = newDynamicClient(dyn)
		})
		return client, err
	}
}

func (c *dynamicClient) listAgents(ctx context.Context, namespace string) ([]string, error) {
	return c.listNames(ctx, agentsResource, namespace)
}

func (c *dynamicClient) listRemoteMCPServers(ctx context.Context, namespace string) ([]string, error) {
	return c.listNames(ctx, remoteMCPServersResource, namespace)
}

func (c *dynamicClient) listNames(
	ctx context.Context,
	resource schema.GroupVersionResource,
	namespace string,
) ([]string, error) {
	list, err := c.client.Resource(resource).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list kagent %s in %s: %w", resource.Resource, namespace, err)
	}
	names := make([]string, 0, len(list.Items))
	for _, item := range list.Items {
		names = append(names, item.GetName())
	}
	return names, nil
}

// ensureRemoteMCPServer creates the RemoteMCPServer, or replaces the spec and
// labels of an existing one with the same name.
func (c *dynamicClient) ensureRemoteMCPServer(ctx context.Context, server *unstructured.Unstructured) error {
	resource := c.client.Resource(remoteMCPServersResource).Namespace(server.GetNamespace())
	_, err := resource.Create(ctx, server, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create kagent RemoteMCPServer %s/%s: %w", server.GetNamespace(), server.GetName(), err)
	}
	existing, err := resource.Get(ctx, server.GetName(), metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get kagent RemoteMCPServer %s/%s: %w", server.GetNamespace(), server.GetName(), err)
	}
	existing.SetLabels(server.GetLabels())
	existing.Object["spec"] = server.Object["spec"]
	if _, err := resource.Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update kagent RemoteMCPServer %s/%s: %w", server.GetNamespace(), server.GetName(), err)
	}
	return nil
}

func (c *dynamicClient) deleteRemoteMCPServer(ctx context.Context, namespace, name string) error {
	err := c.client.Resource(remoteMCPServersResource).Namespace(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete kagent RemoteMCPServer %s/%s: %w", namespace, name, err)
	}
	return nil
}
