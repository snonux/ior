package common

import (
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
	dark := ScreenStyle.Render("ior")

	ApplyPalette(false)
	light := ScreenStyle.Render("ior")

	if dark == light {
		t.Fatalf("expected ScreenStyle render to differ between dark and light palettes")
	}
}
