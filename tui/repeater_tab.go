package tui

import "github.com/rivo/tview"

func NewRepeaterTab() tview.Primitive {
	text := tview.NewTextView().
		SetText("Repeater: from Proxy tab press 'r' to send here.").
		SetBorder(true)

	return text
}
