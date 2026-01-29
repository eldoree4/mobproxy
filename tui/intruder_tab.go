package tui

import (
	"github.com/rivo/tview"
)

func NewIntruderTab() tview.Primitive {
	text := tview.NewTextView().
		SetText("Intruder: use Proxy tab, select request, press 'i' to send here.").
		SetBorder(true)

	return text
}
