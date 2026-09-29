package common

import (
	"image/color"
	"sync"
	"testing"

	"charm.land/lipgloss/v2"
)

func TestNewPaletteRendersDistinctThemes(t *testing.T) {
	dark := NewPalette(true)
	light := NewPalette(false)

	darkRender := lipgloss.NewStyle().
		Foreground(dark.Text).
		Background(dark.Background).
		Render("ior")
	lightRender := lipgloss.NewStyle().
		Foreground(light.Text).
		Background(light.Background).
		Render("ior")

	if darkRender == lightRender {
		t.Fatalf("expected dark and light palettes to render differently")
	}
}

func TestApplyPaletteUpdatesSharedStyles(t *testing.T) {
	t.Cleanup(func() { ApplyPalette(true) })

	ApplyPalette(true)
	dark := Current().ScreenStyle.Render("ior")

	ApplyPalette(false)
	light := Current().ScreenStyle.Render("ior")

	if dark == light {
		t.Fatalf("expected ScreenStyle render to differ between dark and light palettes")
	}
}

func TestCurrentReturnsPopulatedTheme(t *testing.T) {
	t.Cleanup(func() { ApplyPalette(true) })

	wantBackground := map[bool]color.Color{
		true:  lipgloss.Color("235"),
		false: lipgloss.Color("255"),
	}
	for _, isDark := range []bool{true, false} {
		ApplyPalette(isDark)
		theme := Current()
		if theme == nil {
			t.Fatalf("Current() returned nil theme for isDark=%v", isDark)
		}
		if theme.Text == nil || theme.Panel == nil || theme.Danger == nil {
			t.Fatalf("theme palette colors not populated for isDark=%v", isDark)
		}
		if got := theme.Background; got != wantBackground[isDark] {
			t.Fatalf("Background for isDark=%v: got %v, want %v", isDark, got, wantBackground[isDark])
		}
		if got := theme.ScreenStyle.Render("ior"); got == "" {
			t.Fatalf("ScreenStyle rendered empty output for isDark=%v", isDark)
		}
		if got := theme.PanelStyle.Render("panel"); got == "" {
			t.Fatalf("PanelStyle rendered empty output for isDark=%v", isDark)
		}
	}
}

// TestApplyPaletteConcurrentWithReaders exercises concurrent ApplyPalette
// writers and theme readers (the pattern that previously raced on package-level
// style globals). Run under -race to verify the atomic snapshot publication.
func TestApplyPaletteConcurrentWithReaders(t *testing.T) {
	t.Cleanup(func() { ApplyPalette(true) })

	const goroutines = 4
	const iterations = 250

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if g%2 == 0 {
					ApplyPalette((i+g)%2 == 0)
					continue
				}
				theme := Current()
				if theme == nil {
					t.Error("Current() returned nil theme")
					return
				}
				if theme.Text == nil || theme.Panel == nil {
					t.Error("theme palette colors not populated")
					return
				}
				_ = theme.ScreenStyle.Render("ior")
				_ = theme.PanelStyle.Render("panel")
				_ = theme.TableSelectedCellStyle.Render("cell")
			}
		}(g)
	}
	wg.Wait()
}
