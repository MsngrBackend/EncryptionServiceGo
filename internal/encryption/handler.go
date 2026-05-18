package encryption

import (
	"encoding/json"
	"errors"
	"net/http"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", h.health)
	mux.HandleFunc("GET /health/", h.health)
	mux.HandleFunc("POST /keys/", h.registerPublicKey)
	mux.HandleFunc("GET /keys/{user_id}/", h.getPublicKey)
	mux.HandleFunc("POST /keys/lookup/", h.lookupPublicKeys)
	mux.HandleFunc("POST /messages/encrypt/", h.encryptMessage)
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"service": "EncryptionService",
		"status":  "ok",
	})
}

func (h *Handler) registerPublicKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UserID    string `json:"user_id"`
		PublicKey string `json:"public_key"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, detail("invalid json"))
		return
	}

	key, err := h.svc.RegisterPublicKey(r.Context(), body.UserID, body.PublicKey)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, key)
}

func (h *Handler) getPublicKey(w http.ResponseWriter, r *http.Request) {
	key, err := h.svc.GetPublicKey(r.Context(), r.PathValue("user_id"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, key)
}

func (h *Handler) lookupPublicKeys(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UserIDs []string `json:"user_ids"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, detail("invalid json"))
		return
	}

	keys, err := h.svc.LookupPublicKeys(r.Context(), body.UserIDs)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

func (h *Handler) encryptMessage(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Content    string      `json:"content"`
		Recipients []Recipient `json:"recipients"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, detail("invalid json"))
		return
	}

	envelopes, err := h.svc.EncryptMessage(r.Context(), body.Content, body.Recipients)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":   Algorithm,
		"envelopes": envelopes,
	})
}

func writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidInput):
		writeJSON(w, http.StatusBadRequest, detail(err.Error()))
	case errors.Is(err, ErrNotFound):
		writeJSON(w, http.StatusNotFound, detail(err.Error()))
	default:
		writeJSON(w, http.StatusInternalServerError, detail("internal error"))
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func detail(msg string) map[string]string {
	return map[string]string{"detail": msg}
}

func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}
