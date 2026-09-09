//go:build !windows

package web

import "net/http"

// handleImportFromApp: hanya tersedia di Windows (baca auth.json app AutoClaw
// + DPAPI). Di Linux/macOS app AutoClaw tidak ada — tombol ini disembunyikan
// di template, handler ini cuma pengaman.
func (s *Server) handleImportFromApp(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, "import.html", "accounts", map[string]any{
		"Error": "Import dari App hanya tersedia di Windows (butuh app AutoClaw + DPAPI). Gunakan Login Z.ai atau Import Token.",
	})
}
