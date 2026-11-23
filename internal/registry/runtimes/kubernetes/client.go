package kubernetes

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

// workloadClient is the part of the Kubernetes API the adapter uses.
type workloadClient interface {
	apply(ctx context.Context, w *workload) error
	remove(ctx context.Context, namespace, name string) error
	getDeployment(ctx context.Context, namespace, name string) (*appsv1.Deployment, error)
	logs(ctx context.Context, namespace, name string, in types.LogsInput, out chan<- types.LogLine) error
}

type clientsetClient struct {
	client kubernetes.Interface
}

func newClientsetClient(client kubernetes.Interface) workloadClient {
	return &clientsetClient{client: client}
}

// inClusterClient builds one client from the registry's in-cluster
// ServiceAccount and reuses it.
func inClusterClient() func() (workloadClient, error) {
	var (
		once   sync.Once
		client workloadClient
		err    error
	)
	return func() (workloadClient, error) {
		once.Do(func() {
			var config *rest.Config
			config, err = rest.InClusterConfig()
			if err != nil {
				err = fmt.Errorf("load in-cluster Kubernetes config: %w", err)
				return
			}
			var clientset kubernetes.Interface
			clientset, err = kubernetes.NewForConfig(config)
			if err != nil {
				err = fmt.Errorf("create Kubernetes client: %w", err)
				return
			}
			client = newClientsetClient(clientset)
		})
		return client, err
	}
}

// apply creates the workload's objects, or replaces the spec and labels of
// existing ones. The NetworkPolicy goes first, so pods never run without it.
func (c *clientsetClient) apply(ctx context.Context, w *workload) error {
	policies := c.client.NetworkingV1().NetworkPolicies(w.namespace)
	if _, err := policies.Create(ctx, w.networkPolicy, metav1.CreateOptions{}); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("create NetworkPolicy %s/%s: %w", w.namespace, w.name, err)
		}
		existing, err := policies.Get(ctx, w.name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get NetworkPolicy %s/%s: %w", w.namespace, w.name, err)
		}
		existing.Labels, existing.Spec = w.networkPolicy.Labels, w.networkPolicy.Spec
		if _, err := policies.Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("update NetworkPolicy %s/%s: %w", w.namespace, w.name, err)
		}
	}

	accounts := c.client.CoreV1().ServiceAccounts(w.namespace)
	if _, err := accounts.Create(ctx, w.serviceAccount, metav1.CreateOptions{}); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("create ServiceAccount %s/%s: %w", w.namespace, w.name, err)
		}
		existing, err := accounts.Get(ctx, w.name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get ServiceAccount %s/%s: %w", w.namespace, w.name, err)
		}
		existing.Labels, existing.AutomountServiceAccountToken = w.serviceAccount.Labels, w.serviceAccount.AutomountServiceAccountToken
		if _, err := accounts.Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("update ServiceAccount %s/%s: %w", w.namespace, w.name, err)
		}
	}

	deployments := c.client.AppsV1().Deployments(w.namespace)
	if _, err := deployments.Create(ctx, w.deployment, metav1.CreateOptions{}); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("create Deployment %s/%s: %w", w.namespace, w.name, err)
		}
		existing, err := deployments.Get(ctx, w.name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get Deployment %s/%s: %w", w.namespace, w.name, err)
		}
		existing.Labels, existing.Spec = w.deployment.Labels, w.deployment.Spec
		if _, err := deployments.Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("update Deployment %s/%s: %w", w.namespace, w.name, err)
		}
	}
	return nil
}

// remove deletes the workload's objects; missing ones are fine. The
// NetworkPolicy goes last, so no pod outlives it.
func (c *clientsetClient) remove(ctx context.Context, namespace, name string) error {
	background := metav1.DeletePropagationBackground
	options := metav1.DeleteOptions{PropagationPolicy: &background}
	if err := c.client.AppsV1().Deployments(namespace).Delete(ctx, name, options); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete Deployment %s/%s: %w", namespace, name, err)
	}
	if err := c.client.CoreV1().ServiceAccounts(namespace).Delete(ctx, name, options); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete ServiceAccount %s/%s: %w", namespace, name, err)
	}
	pods, err := c.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{workloadLabel: name}).String(),
	})
	if err != nil {
		return fmt.Errorf("list pods of %s/%s: %w", namespace, name, err)
	}
	if len(pods.Items) > 0 {
		return fmt.Errorf("%d pods of %s/%s are still terminating", len(pods.Items), namespace, name)
	}
	if err := c.client.NetworkingV1().NetworkPolicies(namespace).Delete(ctx, name, options); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete NetworkPolicy %s/%s: %w", namespace, name, err)
	}
	return nil
}

func (c *clientsetClient) getDeployment(ctx context.Context, namespace, name string) (*appsv1.Deployment, error) {
	deployment, err := c.client.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get Deployment %s/%s: %w", namespace, name, err)
	}
	return deployment, nil
}

// logs sends the log lines of every pod of the workload, one pod after
// another.
func (c *clientsetClient) logs(ctx context.Context, namespace, name string, in types.LogsInput, out chan<- types.LogLine) error {
	pods, err := c.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{workloadLabel: name}).String(),
	})
	if err != nil {
		return fmt.Errorf("list pods of %s/%s: %w", namespace, name, err)
	}
	options := &corev1.PodLogOptions{Container: containerName, Follow: in.Follow, Timestamps: true}
	if in.TailLines > 0 {
		tail := int64(in.TailLines)
		options.TailLines = &tail
	}
	for _, pod := range pods.Items {
		stream, err := c.client.CoreV1().Pods(namespace).GetLogs(pod.Name, options).Stream(ctx)
		if err != nil {
			return fmt.Errorf("stream logs of pod %s/%s: %w", namespace, pod.Name, err)
		}
		err = sendLines(ctx, stream, pod.Name, out)
		_ = stream.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// sendLines parses "<RFC3339 timestamp> <line>" records (Timestamps: true).
func sendLines(ctx context.Context, stream io.Reader, pod string, out chan<- types.LogLine) error {
	scanner := bufio.NewScanner(stream)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := types.LogLine{Stream: pod, Line: scanner.Text()}
		if stamp, rest, ok := strings.Cut(line.Line, " "); ok {
			if ts, err := time.Parse(time.RFC3339Nano, stamp); err == nil {
				line.Timestamp, line.Line = ts, rest
			}
		}
		select {
		case out <- line:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read logs of pod %s: %w", pod, err)
	}
	return nil
}
