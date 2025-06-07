package handlers

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/NissesSenap/spffie-ambient-auth/pkg/oidc"
	"github.com/NissesSenap/spffie-ambient-auth/service-a/auth"
	"github.com/NissesSenap/spffie-ambient-auth/service-a/config"
)

type OIDCHandler struct {
	OIDCClient *oidc.Client
	Templates  *template.Template
	Config     *config.Config
}

type LoginData struct {
	AuthURL string
	State   string
}

func NewOIDCHandler(oidcClient *oidc.Client, cfg *config.Config) *OIDCHandler {
	var tmpl *template.Template
	var err error
	
	// Try to load templates from files first
	tmpl, err = template.ParseGlob(filepath.Join("templates", "*.html"))
	if err != nil {
		log.Printf("[warning] Failed to load templates from files: %v, using fallback", err)
		// Fallback to embedded template if file not found
		tmpl = template.New("login.html")
		fallbackHTML := `<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h1>Login to Service A</h1>
    <p>Click the link below to authenticate:</p>
    <a href="{{.AuthURL}}">Login with OIDC Provider</a>
    <p>State: {{.State}}</p>
</body>
</html>`
		tmpl, _ = tmpl.Parse(fallbackHTML)
	} else {
		log.Printf("[startup] Successfully loaded templates from files")
	}

	return &OIDCHandler{
		OIDCClient: oidcClient,
		Templates:  tmpl,
		Config:     cfg,
	}
}

func (h *OIDCHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	authURL, state, err := auth.GenerateAuthURL(w, r, h.OIDCClient, h.Config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Check if request wants JSON response
	if r.Header.Get("Accept") == "application/json" {
		// Return JSON response with auth URL for API clients
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"auth_url": authURL,
			"state":    state,
		})
		return
	}

	// Return HTML response with template
	w.Header().Set("Content-Type", "text/html")
	data := LoginData{
		AuthURL: authURL,
		State:   state,
	}

	// Use the template file (template name is just "login.html" when loaded from file)
	templateName := "login.html"
	if err := h.Templates.ExecuteTemplate(w, templateName, data); err != nil {
		// Simple fallback if template fails
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *OIDCHandler) LoginURLHandler(w http.ResponseWriter, r *http.Request) {
	authURL, _, err := auth.GenerateAuthURL(w, r, h.OIDCClient, h.Config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return just the raw URL as plain text
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, authURL)
}

func (h *OIDCHandler) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	if h.OIDCClient == nil {
		http.Error(w, "OIDC not initialized", http.StatusInternalServerError)
		return
	}

	// Get state from cookie
	cookie, err := r.Cookie("oidc_state")
	if err != nil {
		http.Error(w, "Missing state cookie", http.StatusBadRequest)
		return
	}

	// Parse state JWT
	pkce, err := oidc.ParseStateJWT(cookie.Value, h.Config.OIDCSecret)
	if err != nil {
		http.Error(w, "Invalid state token", http.StatusBadRequest)
		return
	}

	// Verify state parameter
	if r.URL.Query().Get("state") != pkce.State {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	oauth2Token, rawIDToken, err := h.OIDCClient.ExchangeCodeForToken(
		r.Context(),
		r.URL.Query().Get("code"),
		pkce.CodeVerifier,
		pkce.RedirectURI,
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to exchange token: %v", err), http.StatusInternalServerError)
		return
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	// Return tokens
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": oauth2Token.AccessToken,
		"id_token":     rawIDToken,
		"token_type":   "Bearer",
		"expires_in":   int(time.Until(oauth2Token.Expiry).Seconds()),
	})
}

func (h *OIDCHandler) UserinfoHandler(w http.ResponseWriter, r *http.Request) {
	// Extract JWT token from Authorization header
	tokenString, err := auth.ExtractBearerToken(r)
	if err != nil {
		http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}

	// Parse JWT without verification (we'll verify in service-b)
	userInfo, err := oidc.ParseTokenUnsafe(tokenString)
	if err != nil {
		http.Error(w, "Invalid token format", http.StatusBadRequest)
		return
	}

	// Return user info
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}

func HelloHandler(w http.ResponseWriter, r *http.Request) {
	token := ""
	if tokenString, err := auth.ExtractBearerToken(r); err == nil {
		token = tokenString
	}

	fmt.Fprintf(w, "Hello from service-a!\n")
	if token != "" {
		fmt.Fprintf(w, "Received Bearer token: %s\n", token)
	} else {
		fmt.Fprintf(w, "No Bearer token received.\n")
	}
}
