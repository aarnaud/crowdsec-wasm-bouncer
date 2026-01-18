package main

import (
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/types"
)

func main() {
	// Unused due to -buildmode=c-shared
}

func init() {
	proxywasm.SetVMContext(&vmContext{})
}

type vmContext struct {
	types.DefaultVMContext
}

func (vm *vmContext) OnVMStart(vmConfigurationSize int) types.OnVMStartStatus {
	proxywasm.SetPluginContext(vm.NewPluginContext)
	return types.OnVMStartStatusOK
}

// NewPluginContext is called BY ENVOY for each filter configuration
// You cannot control how many times - Envoy does based on its config
func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	proxywasm.LogInfof("Creating new plugin context with ID: %d", contextID)
	return &pluginContext{
		contextID: contextID,
	}
}
