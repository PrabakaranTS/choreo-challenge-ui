package main

import (
    "fmt"
    "html/template"
    "net/http"
	
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

var (
	clientID     = "axRa3MPnlwZVgdufyfoW8rVwds4a"
	clientSecret = "UEopsEiUtXrLy7L4Yk979WSjuloyx4xyDcBSxr1OpL4a"
)

func SignupPage(w http.ResponseWriter, r *http.Request) {
 if r.Method == http.MethodPost {
  // Retrieve signup form data.
  username := r.FormValue("username")
  password := r.FormValue("password")

  // Perform signup logic here (e.g., store user data in a database).
  // For simplicity, we'll just print the data for demonstration.
  fmt.Printf("New user signup: Username - %s, Password - %s\n", username, password)

  // Redirect to a welcome or login page after signup.
  http.Redirect(w, r, "/welcome", http.StatusSeeOther)
  return
 }

 // If not a POST request, serve the signup page template.
 tmpl, err := template.ParseFiles("templates/signup.html")
 if err != nil {
  http.Error(w, err.Error(), http.StatusInternalServerError)
  return
 }
 tmpl.Execute(w, nil)
}


// LoginPage is the handler for the login page.
func LoginPage(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        username := r.FormValue("username")
        password := r.FormValue("password")

        // Perform authentication logic here (e.g., check against a database).
        // For simplicity, we'll just check if the username and password are both "admin".
        if username == "admin" && password == "admin" {
            // Successful login, redirect to a welcome page.
            http.Redirect(w, r, "/welcome", http.StatusSeeOther)
            return
        }

        // Invalid credentials, show the login page with an error message.
        fmt.Fprintf(w, "Invalid credentials. Please try again.")
        return
    }

    // If not a POST request, serve the login page template.
    tmpl, err := template.ParseFiles("templates/login.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    tmpl.Execute(w, nil)
}

// WelcomePage is the handler for the welcome page.
func WelcomePage(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Welcome, you have successfully logged in!")
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}

func main() {

	http.HandleFunc("/", LoginPage)
    http.HandleFunc("/login", LoginPage)
    http.HandleFunc("/welcome", WelcomePage)

    // Serve static files from the "static" directory.
    http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

    // Start the server on port 8080.
    fmt.Println("Server started on http://localhost:8080")
    http.ListenAndServe(":8080", nil)

	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, "https://api.asgardeo.io/t/prabakaran/oauth2/token")
	if err != nil {
		log.Fatal(err)
	}
	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}
	verifier := provider.Verifier(oidcConfig)

	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "https://79310b66-1338-4bb0-bf68-6715ade81613.e1-us-east-azure.choreoapps.dev/auth/login/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		state, err := randString(16)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		nonce, err := randString(16)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		setCallbackCookie(w, r, "state", state)
		setCallbackCookie(w, r, "nonce", nonce)

		http.Redirect(w, r, config.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
	})

	http.HandleFunc("/auth/google/callback", func(w http.ResponseWriter, r *http.Request) {
		state, err := r.Cookie("state")
		if err != nil {
			http.Error(w, "state not found", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("state") != state.Value {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		nonce, err := r.Cookie("nonce")
		if err != nil {
			http.Error(w, "nonce not found", http.StatusBadRequest)
			return
		}
		if idToken.Nonce != nonce.Value {
			http.Error(w, "nonce did not match", http.StatusBadRequest)
			return
		}

		oauth2Token.AccessToken = "*REDACTED*"

		resp := struct {
			OAuth2Token   *oauth2.Token
			IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
		}{oauth2Token, new(json.RawMessage)}

		if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data, err := json.MarshalIndent(resp, "", "    ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})

	log.Printf("listening on http://%s/", "127.0.0.1:5556")
	log.Fatal(http.ListenAndServe("127.0.0.1:5556", nil))
}