package tui

import (
	"fmt"

	"mobproxy/core"

	"github.com/rivo/tview"
)

func NewScannerTab() tview.Primitive {
	list := tview.NewList().SetBorder(true).SetTitle(" Findings ")
	detail := tview.NewTextView().SetBorder(true).SetTitle(" Detail ")

	refresh := func() {
		list.Clear()
		for i, f := range core.Findings {
			title := fmt.Sprintf("[%d] %s", i+1, f.Type)
			list.AddItem(title, "", 0, nil)
		}
	}

	refresh()

	list.SetSelectedFunc(func(i int, main, sec string, r rune) {
		if i < len(core.Findings) {
			f := core.Findings[i]
			detail.SetText(f.Type + "\n\n" + f.Detail + "\n\nRequest:\n" + f.Request)
		}
	})

	flex := tview.NewFlex().
		AddItem(list, 30, 1, true).
		AddItem(detail, 0, 3, false)

	return flex
}
