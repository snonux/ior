package dashboard

const panelHorizontalChrome = 4

// Keep a small guard so sparkline rows never soft-wrap in panel cells.
const sparklineSafetyMargin = 3

// Stats engine currently provides 120 time-series slots; cap rendering width
// so wide terminals don't introduce wrap/placement artifacts.
const sparklineMaxWidth = 120
