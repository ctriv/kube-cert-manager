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

package k8s

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/pkg/errors"
	"k8s.io/client-go/pkg/api"
	kerrors "k8s.io/client-go/pkg/api/errors"
	"k8s.io/client-go/pkg/api/unversioned"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/runtime"
	"k8s.io/client-go/pkg/util/flowcontrol"
	"k8s.io/client-go/pkg/watch"
	"k8s.io/client-go/tools/cache"
)

func (k K8sClient) CreateEvent(ev v1.Event) {
	now := unversioned.Now()
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

func (k K8sClient) UpdateCertStatus(namespace string, name string, status CertificateStatus) {
	update := make(map[string]CertificateStatus)

	update["status"] = status

	patch_err := k.doCertPatch(namespace, name, update)

	if patch_err != nil {
		log.Printf("ERROR updating status: %v\n", patch_err)
	} else {
		log.Printf("UPDATED status for %s/%s: %#v\n", namespace, name, status)
	}
}

func (k K8sClient) UpdateCertSpec(namespace string, name string, spec CertificateSpec) error {
	update := make(map[string]CertificateSpec)

	update["spec"] = spec

	err := k.doCertPatch(namespace, name, update)

	if err != nil {
		return errors.Wrapf(err, "ERROR updating spec for %s/%s: %#v\n", namespace, name, spec)
	}

	log.Printf("UPDATED spec for %s/%s: %#v\n", namespace, name, spec)
	return nil
}

func (k K8sClient) doCertPatch(namespace string, name string, obj interface{}) error {
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

func (k K8sClient) GetSecret(namespace string, key string) (*v1.Secret, error) {
	secret, err := k.c.Core().Secrets(namespace).Get(key)
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

func (k K8sClient) SaveSecret(namespace string, secret *v1.Secret, isUpdate bool) error {
	if secret.Name == "" {
		return errors.New("Secret name must be specified in metadata")
	}

	if isUpdate {
		_, err := k.c.Secrets(namespace).Update(secret)
		return err
	} else {
		_, err := k.c.Secrets(namespace).Create(secret)
		return err
	}
}

func (k K8sClient) DeleteSecret(namespace string, key string) error {
	return k.c.Secrets(namespace).Delete(key, nil)
}

func (k K8sClient) DeleteCertificate(c Certificate, namespace string) error {
	log.Printf("About to delete certificate %s in namespace %s ", c.Metadata.Name, namespace)
	deleteError := k.certClient.Delete().
		Namespace(namespace).
		Resource("certificates").
		Name(c.Metadata.Name).Do().Error()
	return deleteError
}

func (k K8sClient) GetSecrets(namespace string) ([]v1.Secret, error) {
	listOpts := v1.ListOptions{}
	listOpts.LabelSelector = "creator=kube-cert-manager"

	list, err := k.c.Secrets(namespace).List(listOpts)
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (k K8sClient) GetCertificates(namespace string) ([]Certificate, error) {
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
	listFunc := func(options api.ListOptions) (runtime.Object, error) {
		return c.Get().
			Namespace(namespace).
			Resource(resource).
			VersionedParams(&options, api.ParameterCodec).
			Do().
			Get()
	}
	watchFunc := func(options api.ListOptions) (watch.Interface, error) {
		return c.Get().
			Prefix("watch").
			Namespace(namespace).
			Resource(resource).
			VersionedParams(&options, api.ParameterCodec).
			Watch()
	}
	return &cache.ListWatch{ListFunc: listFunc, WatchFunc: watchFunc}
}

func (k K8sClient) MonitorCertificateEvents(namespace string, done <-chan struct{}) <-chan CertificateEvent {
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
