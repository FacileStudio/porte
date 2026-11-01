package magiclink

import (
	"net"
	"net/http"
	"strconv"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/tronc/httpjson"

	"github.com/go-chi/chi/v5"
)

// Mount registers POST /auth/magic-link and POST /auth/magic-link/consume with
// porte's own bodies.
//
// An app whose frontend expects a richer response calls [Kit.Request] and
// [Kit.Consume] from its own handlers instead, as with porte/local. Behind a
// proxy, put chi's RealIP middleware in front of these routes, and only when
// the proxy is trusted: the per-source limit counts whatever RemoteAddr says.
func (k *Kit) Mount(router chi.Router) {
	router.Post(porte.RouteMagicLink, k.handleRequest)
	router.Post(porte.RouteMagicLinkConsume, k.handleConsume)
}

func (k *Kit) handleRequest(w http.ResponseWriter, r *http.Request) {
	var request porte.MagicLinkRequest
	if err := httpjson.DecodeJSON(w, r, &request); err != nil {
		httpjson.WriteError(w, err)
		return
	}
	if err := k.Request(r.Context(), request.Email, sourceIP(r)); err != nil {
		httpjson.WriteError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpjson.WriteJSON(w, http.StatusAccepted, porte.MagicLinkRequestResponse{OK: true})
}

func (k *Kit) handleConsume(w http.ResponseWriter, r *http.Request) {
	var request porte.MagicLinkConsumeRequest
	if err := httpjson.DecodeJSON(w, r, &request); err != nil {
		httpjson.WriteError(w, err)
		return
	}
	userID, token, err := k.Consume(r.Context(), w, r, request.Token)
	if err != nil {
		httpjson.WriteError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpjson.WriteJSON(w, http.StatusOK, porte.ExchangeResponse{
		UserID: strconv.FormatInt(userID, 10),
		Token:  token,
	})
}

func sourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
