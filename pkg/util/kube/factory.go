/*
Copyright 2017 Jetstack Ltd.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package kube

import (
	sync "sync"

	"github.com/golang/glog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	cache "k8s.io/client-go/tools/cache"
)

type SharedInformerFactory interface {
	InformerFor(string, metav1.GroupVersionKind, cache.SharedIndexInformer) cache.SharedIndexInformer
	Start(<-chan struct{})
}

var DefaultSharedInformerFactory = NewSharedInformerFactory()

type sharedInformerFactory struct {
	lock             sync.Mutex
	informers        map[string]map[metav1.GroupVersionKind]cache.SharedIndexInformer
	startedInformers map[string]map[metav1.GroupVersionKind]bool
}

var _ SharedInformerFactory = &sharedInformerFactory{}

func NewSharedInformerFactory() SharedInformerFactory {
	return &sharedInformerFactory{
		informers:        make(map[string]map[metav1.GroupVersionKind]cache.SharedIndexInformer),
		startedInformers: make(map[string]map[metav1.GroupVersionKind]bool),
	}
}

func (s *sharedInformerFactory) InformerFor(namespace string, gvk metav1.GroupVersionKind, i cache.SharedIndexInformer) cache.SharedIndexInformer {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.informers == nil {
		glog.Infof("Init map on lookup for %s - %#v", namespace, gvk)
		s.informers = make(map[string]map[metav1.GroupVersionKind]cache.SharedIndexInformer)
	}
	informerMap, nsExists := s.informers[namespace]
	if !nsExists {
		glog.Infof("NS does not exist on lookup for %s - %#v", namespace, gvk)
		s.informers[namespace] = map[metav1.GroupVersionKind]cache.SharedIndexInformer{
			gvk: i,
		}
		return i
	}
	informer, exists := informerMap[gvk]
	if !exists {
		glog.Infof("existing informer does not exist on lookup for %s - %#v", namespace, gvk)
		informerMap[gvk] = i
		return i
	}
	glog.Infof("existing informer found for %s - %#v", namespace, gvk)
	return informer
}

// Start initializes all requested informers.
func (f *sharedInformerFactory) Start(stopCh <-chan struct{}) {
	f.lock.Lock()
	defer f.lock.Unlock()

	for namespace, informerMap := range f.informers {
		startedMap, exists := f.startedInformers[namespace]
		if !exists {
			startedMap = make(map[metav1.GroupVersionKind]bool)
			f.startedInformers[namespace] = startedMap
		}
		for informerType, informer := range informerMap {
			if !startedMap[informerType] {
				go informer.Run(stopCh)
				startedMap[informerType] = true
			}
		}
	}
}
