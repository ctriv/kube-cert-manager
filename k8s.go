// Copyright 2016 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/flowcontrol"

	"github.com/pkg/errors"
)

func (k K8sClient) createEvent(ev v1.Event) {
	now := metav1.Now()
	ev.Name = fmt.Sprintf("%s.%x", ev.InvolvedObject.Name, now.UnixNano())
	if ev.Kind == "" {
		ev.Kind = "Event"
	}
	if ev.APIVersion == "" {
		ev.APIVersion = "v1"
	}
	if ev.FirstTimestamp.IsZero() {
		ev.FirstTimestamp = now
	}
	if ev.LastTimestamp.IsZero() {
		ev.LastTimestamp = now
	}
	if ev.Count == 0 {
		ev.Count = 1
	}
	_, err := k.c.Core().Events(ev.Namespace).Create(&ev)
	if err != nil {
		log.Printf("Error posting event: %v\n", err)
		return
	}
}

func (k K8sClient) updateCertStatus(namespace string, name string, status CertificateStatus) {
	update := make(map[string]CertificateStatus)

	update["status"] = status

	patch_err := k._doCertPatch(namespace, name, update)

	if patch_err != nil {
		log.Printf("ERROR updating status: %v\n", patch_err)
	} else {
		log.Printf("UPDATED status for %s/%s: %#v\n", namespace, name, status)
	}
}

func (k K8sClient) _doCertPatch(namespace string, name string, obj interface{}) error {
	raw_patch, json_error := json.Marshal(obj)

	if json_error != nil {
		return errors.Wrapf(json_error, "could not marshall update into json")
	}

	patch_err := k.certClient.Patch("application/merge-patch+json").
		Namespace(namespace).
		Resource("certificates").
		Name(name).
		Body(raw_patch).
		Do().
		Error()

	return patch_err
}

func (k K8sClient) getSecret(namespace string, key string) (*v1.Secret, error) {
	secret, err := k.c.CoreV1().Secrets(namespace).Get(key, metav1.GetOptions{})
	if err != nil {
		switch kerr := err.(type) {
		case kerrors.APIStatus:
			if kerr.Status().Code == http.StatusNotFound {
				return nil, nil
			} else {
				return nil, errors.Wrapf(err, "Unexpected status code  whle fetching secret %q: %v", key, kerr.Status())
			}
		}
		return nil, errors.Wrapf(err, "Unexpected error while fetching secret %q", key)
	}
	return secret, nil
}

func (k K8sClient) saveSecret(namespace string, secret *v1.Secret, isUpdate bool) error {
	if secret.Name == "" {
		return errors.New("Secret name must be specified in metadata")
	}

	if isUpdate {
		_, err := k.c.CoreV1().Secrets(namespace).Update(secret)
		return err
	} else {
		_, err := k.c.CoreV1().Secrets(namespace).Create(secret)
		return err
	}
}

func (k K8sClient) deleteSecret(namespace string, key string) error {
	return k.c.CoreV1().Secrets(namespace).Delete(key, nil)
}

func (k K8sClient) deleteCertificate(c Certificate, namespace string) error {
	log.Printf("About to delete certificate %s in namespace %s ", c.Metadata.Name, namespace)
	deleteError := k.certClient.Delete().
		Namespace(namespace).
		Resource("certificates").
		Name(c.Metadata.Name).Do().Error()
	return deleteError
}

func (k K8sClient) getSecrets(namespace string) ([]v1.Secret, error) {
	listOpts := metav1.ListOptions{}
	listOpts.LabelSelector = "creator=kube-cert-manager"

	list, err := k.c.CoreV1().Secrets(namespace).List(listOpts)
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (k K8sClient) getCertificates(namespace string) ([]Certificate, error) {
	rl := flowcontrol.NewTokenBucketRateLimiter(0.2, 3)
	for {
		rl.Accept()
		req := k.certClient.Get().Resource("certificates").Namespace(namespace)

		var certList CertificateList

		err := req.Do().Into(&certList)

		if err != nil {
			log.Printf("Error while retrieving certificate: %v. Retrying", err)
		} else {
			return certList.Items, nil
		}
	}
}

// Copied from cache.NewListWatchFromClient since that constructor doesn't
// allow labelselectors, but labelselectors should be preferred over field
// selectors.
func newListWatchFromClient(c cache.Getter, resource string, namespace string) *cache.ListWatch {
	listFunc := func(options metav1.ListOptions) (runtime.Object, error) {
		return c.Get().
			Namespace(namespace).
			Resource(resource).
			VersionedParams(&options, metav1.ParameterCodec).
			Do().
			Get()
	}
	watchFunc := func(options metav1.ListOptions) (watch.Interface, error) {
		return c.Get().
			Prefix("watch").
			Namespace(namespace).
			Resource(resource).
			VersionedParams(&options, metav1.ParameterCodec).
			Watch()
	}
	return &cache.ListWatch{ListFunc: listFunc, WatchFunc: watchFunc}
}

func (k K8sClient) monitorCertificateEvents(namespace string, done <-chan struct{}) <-chan CertificateEvent {
	events := make(chan CertificateEvent)

	evFunc := func(evType watch.EventType, obj interface{}) {
		cert, ok := obj.(*Certificate)
		if !ok {
			log.Printf("could not convert %v (%T) into Certificate", obj, obj)
			return
		}
		events <- CertificateEvent{
			Type:   string(evType),
			Object: *cert,
		}
	}

	source := newListWatchFromClient(k.certClient, "certificates", namespace)

	store, ctrl := cache.NewInformer(source, &Certificate{}, 0, cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			evFunc(watch.Added, obj)
		},
		UpdateFunc: func(old, new interface{}) {
			evFunc(watch.Modified, new)
		},
		DeleteFunc: func(obj interface{}) {
			evFunc(watch.Deleted, obj)
		},
	})

	go func() {
		for _, initObj := range store.List() {
			evFunc(watch.Added, initObj)
		}

		go ctrl.Run(done)
	}()

	return events
}

func namespacedEndpoint(endpoint, namespace string) string {
	return fmt.Sprintf(endpoint, namespace)
}

func namespacedAllCertEndpoint(endpoint, certNamespace string) string {
	return fmt.Sprintf(endpoint, certNamespace)
}

func namespacedCertEndpoint(endpoint, certNamespace, namespace string) string {
	return fmt.Sprintf(endpoint, certNamespace, namespace)
}

func addURLArgument(urlString string, key string, value string) (string, error) {
	u, err := url.Parse(urlString)
	if err != nil {
		return "", errors.Wrapf(err, "Error parsing URL: %v", err)
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func getDomainFromLabel(s *v1.Secret, tagPrefix string) string {
	domain := s.Labels[addTagPrefix(tagPrefix, "domain")]
	if domain == "" {
		// deprecated plain "domain" label
		// check for it in case people have the plain label in secrets when upgrading
		// will be updated to the prefixed label when the Secret is next updated
		domain = s.Labels["domain"]
	}
	return domain
}

func addTagPrefix(prefix, tag string) string {
	if prefix == "" {
		return tag
	} else if strings.HasSuffix(prefix, ".") {
		// Support the deprecated "stable.liquidweb.com/kcm." prefix
		return prefix + tag
	}

	return prefix + "/" + tag
}
