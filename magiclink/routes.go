package magiclink

import (
	"net"
	"net/http"
	"strconv"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/tronc/errors"
	"github.com/FacileStudio/tronc/httpjson"

	"github.com/go-chi/chi/v5"
)

// Mount registers POST /auth/magic-link and POST /auth/magic-link/consume with
// porte's own bodies.
//
// An app whose frontend expects a richer response calls [Kit.Request] and
// [Kit.Consume] from its own handlers instead, as with porte/local.
//
// The consume route requires the X-Facile-CSRF header, like every other route
// that acts on a cookie. It is public, so no ambient credential is abused, but
// it sets one: a cross-site form post carrying an attacker's own link would
// otherwise sign the victim's browser in as the attacker. The header is
// checked before the token is touched, so a forged request cannot spend a link
// either. The request route needs none: it acts on nothing the caller holds.
//
// The source address is RemoteAddr, and porte never reads X-Forwarded-For
// anywhere else. Behind a proxy every caller then shares the proxy's address
// and the per-source limit becomes a global one, so an app behind a proxy it
// controls sets [Config.ClientIP].
func (k *Kit) Mount(router chi.Router) {
	router.Post(porte.RouteMagicLink, k.handleRequest)
	router.Post(porte.RouteMagicLinkConsume, k.handleConsume)
}

func (k *Kit) handleRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var request porte.MagicLinkRequest
	if err := httpjson.DecodeJSON(w, r, &request); err != nil {
		httpjson.WriteError(w, err)
		return
	}
	if err := k.Request(r.Context(), request.Email, k.sourceIP(r)); err != nil {
		httpjson.WriteError(w, err)
		return
	}
	httpjson.WriteJSON(w, http.StatusAccepted, porte.MagicLinkRequestResponse{OK: true})
}

func (k *Kit) handleConsume(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get(porte.CSRFHeaderName) == "" {
		httpjson.WriteError(w, errors.Forbidden("missing "+porte.CSRFHeaderName+" header"))
		return
	}
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
	httpjson.WriteJSON(w, http.StatusOK, porte.ExchangeResponse{
		UserID: strconv.FormatInt(userID, 10),
		Token:  token,
	})
}

func (k *Kit) sourceIP(r *http.Request) string {
	if k.cfg.ClientIP != nil {
		return k.cfg.ClientIP(r)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
