package agentgateway

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// ObjectClient is the part of the Kubernetes API the reconciler uses.
type ObjectClient interface {
	// List returns the objects of kind gvk in namespace matching selector.
	List(ctx context.Context, gvk schema.GroupVersionKind, namespace, selector string) ([]unstructured.Unstructured, error)
	// Apply creates obj, or replaces the labels, annotations and spec of the
	// existing object of that name, which must be one this package manages.
	Apply(ctx context.Context, obj *unstructured.Unstructured) error
	// Delete removes an object; a missing one is fine.
	Delete(ctx context.Context, gvk schema.GroupVersionKind, namespace, name string) error
}

type dynamicClient struct {
	client dynamic.Interface
}

// NewDynamicClient returns an ObjectClient over a dynamic client.
func NewDynamicClient(client dynamic.Interface) ObjectClient {
	return &dynamicClient{client: client}
}

// resources are the plural resource names of Kinds.
var resources = map[schema.GroupVersionKind]string{
	BackendGVK:   "agentgatewaybackends",
	PolicyGVK:    "agentgatewaypolicies",
	HTTPRouteGVK: "httproutes",
}

func resource(gvk schema.GroupVersionKind) schema.GroupVersionResource {
	return gvk.GroupVersion().WithResource(resources[gvk])
}

func (c *dynamicClient) List(ctx context.Context, gvk schema.GroupVersionKind, namespace, selector string) ([]unstructured.Unstructured, error) {
	var out []unstructured.Unstructured
	options := metav1.ListOptions{LabelSelector: selector}
	for {
		list, err := c.client.Resource(resource(gvk)).Namespace(namespace).List(ctx, options)
		if err != nil {
			return nil, fmt.Errorf("list %s in %s: %w", gvk.Kind, namespace, err)
		}
		out = append(out, list.Items...)
		if options.Continue = list.GetContinue(); options.Continue == "" {
			return out, nil
		}
	}
}

func (c *dynamicClient) Apply(ctx context.Context, obj *unstructured.Unstructured) error {
	gvk := obj.GroupVersionKind()
	objects := c.client.Resource(resource(gvk)).Namespace(obj.GetNamespace())
	if _, err := objects.Create(ctx, obj, metav1.CreateOptions{}); err == nil {
		return nil
	} else if !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create %s %s/%s: %w", gvk.Kind, obj.GetNamespace(), obj.GetName(), err)
	}
	existing, err := objects.Get(ctx, obj.GetName(), metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get %s %s/%s: %w", gvk.Kind, obj.GetNamespace(), obj.GetName(), err)
	}
	if !managed(existing) {
		return fmt.Errorf("%s %s/%s exists and is not managed by the registry; not replacing it",
			gvk.Kind, obj.GetNamespace(), obj.GetName())
	}
	existing.SetLabels(obj.GetLabels())
	existing.SetAnnotations(obj.GetAnnotations())
	existing.Object["spec"] = obj.Object["spec"]
	if _, err := objects.Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update %s %s/%s: %w", gvk.Kind, obj.GetNamespace(), obj.GetName(), err)
	}
	return nil
}

func (c *dynamicClient) Delete(ctx context.Context, gvk schema.GroupVersionKind, namespace, name string) error {
	err := c.client.Resource(resource(gvk)).Namespace(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete %s %s/%s: %w", gvk.Kind, namespace, name, err)
	}
	return nil
}

func managed(obj *unstructured.Unstructured) bool {
	labels := obj.GetLabels()
	return labels[managedByLabel] == managedByValue && labels[componentLabel] == componentValue
}
