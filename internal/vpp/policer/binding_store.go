package policer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type InterfaceBinding struct {
	SwIfIndex uint32 `json:"sw_if_index"`
	Direction string `json:"direction"`
}

type bindingStore struct {
	mu       sync.RWMutex
	path     string
	bindings map[string][]InterfaceBinding // policer name -> bindings
}

func newBindingStore(path string) *bindingStore {
	bs := &bindingStore{
		path:     path,
		bindings: map[string][]InterfaceBinding{},
	}
	_ = bs.load()
	return bs
}

func (bs *bindingStore) load() error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	b, err := os.ReadFile(bs.path)
	if err != nil {
		return nil
	}

	var data map[string][]InterfaceBinding
	if err := json.Unmarshal(b, &data); err != nil {
		return nil
	}

	bs.bindings = data
	return nil
}

func (bs *bindingStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(bs.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(bs.bindings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(bs.path, b, 0o644)
}

func (bs *bindingStore) get(name string) []InterfaceBinding {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	src := bs.bindings[name]
	out := make([]InterfaceBinding, 0, len(src))
	out = append(out, src...)
	return out
}

func (bs *bindingStore) add(name string, swIfIndex uint32, direction string) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	list := bs.bindings[name]
	for _, b := range list {
		if b.SwIfIndex == swIfIndex && b.Direction == direction {
			return nil
		}
	}

	bs.bindings[name] = append(bs.bindings[name], InterfaceBinding{SwIfIndex: swIfIndex, Direction: direction})
	return bs.saveLocked()
}

func (bs *bindingStore) remove(name string, swIfIndex uint32, direction string) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	list := bs.bindings[name]
	if len(list) == 0 {
		return nil
	}

	out := list[:0]
	for _, b := range list {
		if b.SwIfIndex == swIfIndex && b.Direction == direction {
			continue
		}
		out = append(out, b)
	}
	if len(out) == 0 {
		delete(bs.bindings, name)
	} else {
		bs.bindings[name] = out
	}
	return bs.saveLocked()
}
