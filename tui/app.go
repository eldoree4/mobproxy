package tui

import (
	"github.com/rivo/tview"
)

var (
	app       *tview.Application
	pages     *tview.Pages
	tabHeader *tview.TextView
)

func Run() {
	app = tview.NewApplication()
	pages = tview.NewPages()

	tabHeader = tview.NewTextView().
		SetText("[::b][Proxy] [Repeater] [Intruder] [Scanner]").
		SetDynamicColors(true)

	proxy := NewProxyTab()
	repeater := NewRepeaterTab()
	intruder := NewIntruderTab()
	scanner := NewScannerTab()

	pages.AddPage("proxy", proxy, true, true)
	pages.AddPage("repeater", repeater, true, false)
	pages.AddPage("intruder", intruder, true, false)
	pages.AddPage("scanner", scanner, true, false)

	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tabHeader, 1, 1, false).
		AddItem(pages, 0, 1, true)

	app.SetRoot(root, true)
	bindKeys()
	app.Run()
}

func bindKeys() {
	app.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Rune() {
		case '1':
			switchTab("proxy")
		case '2':
			switchTab("repeater")
		case '3':
			switchTab("intruder")
		case '4':
			switchTab("scanner")
		}
		return ev
	})
}

func switchTab(name string) {
	pages.SwitchToPage(name)
}

case 's':
    core.SaveProject("project1")
case 'l':
    core.LoadProject("project1")
case 'c':
    go core.StartCrawler()
