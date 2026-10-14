package rest

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/controlplane/backup"
)

// SetBackups enables the panel's manual backups (P8).
func (s *Server) SetBackups(b *backup.Service) { s.backups = b }

// BackupListResponse lists the backups, newest first.
type BackupListResponse struct {
	Backups []backup.Info `json:"backups"`
}

func (s *Server) registerBackupRoutes(api *mux.Router) {
	api.HandleFunc("/backups", s.handleListBackups).Methods("GET")
	api.HandleFunc("/backups", s.handleCreateBackup).Methods("POST")
	api.HandleFunc("/backups/{name}", s.handleDownloadBackup).Methods("GET")
	api.HandleFunc("/backups/{name}", s.handleDeleteBackup).Methods("DELETE")
}

func (s *Server) backupsReady(w http.ResponseWriter) bool {
	if s.backups == nil {
		errorWithCode(w, http.StatusServiceUnavailable, "backups_disabled", "backups are not configured on this server")
		return false
	}
	return true
}

func (s *Server) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	if !s.backupsReady(w) {
		return
	}
	info, err := s.backups.Create(r.Context())
	if errors.Is(err, backup.ErrBusy) {
		errorWithCode(w, http.StatusConflict, "backup_running", err.Error())
		return
	}
	if err != nil {
		// pg_dump's message stays in the log: it can name hosts and users.
		slog.Error("backup failed", "error", err)
		errorResponse(w, http.StatusInternalServerError, "failed to create the backup; see the control-plane log")
		return
	}
	slog.Info("backup created", "name", info.Name, "size", info.Size, "user", sessionUserID(r))
	jsonResponse(w, http.StatusCreated, info)
}

func (s *Server) handleListBackups(w http.ResponseWriter, r *http.Request) {
	if !s.backupsReady(w) {
		return
	}
	list, err := s.backups.List()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to list backups")
		return
	}
	jsonResponse(w, http.StatusOK, BackupListResponse{Backups: list})
}

func (s *Server) handleDownloadBackup(w http.ResponseWriter, r *http.Request) {
	if !s.backupsReady(w) {
		return
	}
	f, info, err := s.backups.Open(mux.Vars(r)["name"])
	if errors.Is(err, backup.ErrNotFound) {
		errorResponse(w, http.StatusNotFound, "backup not found")
		return
	}
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to open the backup")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", info.Name))
	w.Header().Set("Content-Length", fmt.Sprint(info.Size))
	if _, err := io.Copy(w, f); err != nil {
		slog.Warn("backup download interrupted", "name", info.Name, "error", err)
	}
}

func (s *Server) handleDeleteBackup(w http.ResponseWriter, r *http.Request) {
	if !s.backupsReady(w) {
		return
	}
	name := mux.Vars(r)["name"]
	err := s.backups.Delete(name)
	if errors.Is(err, backup.ErrNotFound) {
		errorResponse(w, http.StatusNotFound, "backup not found")
		return
	}
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to delete the backup")
		return
	}
	slog.Info("backup deleted", "name", name, "user", sessionUserID(r))
	w.WriteHeader(http.StatusNoContent)
}
