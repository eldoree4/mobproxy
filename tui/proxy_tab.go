package tui

import (
	"os"
	"path/filepath"

	"github.com/rivo/tview"
)

func NewProxyTab() tview.Primitive {
	list := tview.NewList().SetBorder(true).SetTitle(" History ")
	viewer := tview.NewTextView().SetBorder(true).SetTitle(" Viewer ").SetWrap(false)

	files, _ := os.ReadDir("history")
	for _, f := range files {
		list.AddItem(f.Name(), "", 0, nil)
	}

	list.SetSelectedFunc(func(i int, main, sec string, r rune) {
		b, _ := os.ReadFile(filepath.Join("history", main))
		viewer.SetText(string(b))
	})

	flex := tview.NewFlex().
		AddItem(list, 30, 1, true).
		AddItem(viewer, 0, 3, false)

	return flex
}
