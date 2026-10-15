// tipShift returns how far (px) to move a tip that starts at left and is
// width wide so it stays margin px inside a viewport of the given width; a
// tip wider than the screen keeps its left edge at the margin.
export function tipShift(left: number, width: number, viewport: number, margin = 8): number {
  if (left < margin) return margin - left
  const over = left + width - (viewport - margin)
  if (over <= 0) return 0
  return Math.max(-over, margin - left)
}
