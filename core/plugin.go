package core

type Plugin interface {
	Name() string
	OnPassiveScan(req, resp string) []Finding
	OnActiveScan(req *RawRequest) []Finding
}

var plugins []Plugin

func RegisterPlugin(p Plugin) {
	plugins = append(plugins, p)
}

func GetPlugins() []Plugin {
	return plugins
}
