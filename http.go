package mafate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// httpClient is the internal HTTP transport. It is not exported; callers use
// the high-level methods on Client instead.
type httpClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

func newHTTPClient(baseURL, apiKey string, transport http.RoundTripper, timeout time.Duration) *httpClient {
	return &httpClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   timeout,

			// Aucune redirection n'est suivie.
			//
			// Par défaut Go en suit jusqu'à 10, et sur un 307/308 il REJOUE le corps
			// vers l'hôte de Location. Ce corps porte aujourd'hui le base64 du clair ;
			// en mode enveloppe il portera la DEK. Le serveur MAFATE n'émet aucun 3xx :
			// une redirection sur un appel d'API est donc soit une mauvaise
			// configuration, soit une attaque, jamais un fonctionnement normal.
			//
			// Second défaut fermé au passage : shouldCopyHeaderOnRedirect ne compare que
			// le DOMAINE, pas le schéma. Une redirection vers un sous-domaine en http://
			// conservait l'en-tête Authorization, envoyant le Bearer eaas_sk_ en clair.
			//
			// ErrUseLastResponse ne produit pas d'erreur : il RETOURNE la réponse 3xx,
			// que le contrôle de statut de do() transforme ensuite en ApiError.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// pathSegment échappe un identifiant destiné à un segment de chemin.
//
// url.PathEscape échappe `/`, ce qui empêche un identifiant comme `../../v1/keys`
// de sortir du chemin prévu et de frapper une autre route. Les identifiants
// légitimes (UUID) ne contiennent que des caractères non réservés et traversent
// cette fonction inchangés.
func pathSegment(value string) string {
	return url.PathEscape(value)
}

// buildURL constructs the full request URL, appending any query parameters.
func (c *httpClient) buildURL(path string, params map[string]string) (string, error) {
	full := c.baseURL + path
	if len(params) == 0 {
		return full, nil
	}
	u, err := url.Parse(full)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// do executes an HTTP request and decodes the JSON response into out.
// If out is nil the response body is discarded (used for 204 endpoints).
func (c *httpClient) do(ctx context.Context, method, path string, params map[string]string, body, out interface{}) error {
	rawURL, err := c.buildURL(path, params)
	if err != nil {
		return &MafateError{Message: fmt.Sprintf("build url: %s", err)}
	}

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return &MafateError{Message: fmt.Sprintf("marshal request: %s", err)}
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if err != nil {
		return &MafateError{Message: fmt.Sprintf("create request: %s", err)}
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return translateTransportError(err, c.httpClient.Timeout)
	}
	defer resp.Body.Close()

	// Les 3xx sont traités AVANT le cas général : le corps d'une redirection est
	// vide ou sans intérêt, et le message par défaut ("301 Moved Permanently")
	// n'orienterait vers rien.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return &ApiError{
			Status: resp.StatusCode,
			Title:  "redirection refusée",
			Detail: fmt.Sprintf(
				"l'API a répondu %d vers %q. Le SDK ne suit aucune redirection : sur un 307/308 "+
					"le corps de la requête serait rejoué vers cet hôte. Cause la plus fréquente : "+
					"une baseURL en http:// — mais la clé d'API et le corps sont alors DÉJÀ partis "+
					"en clair, la redirection arrivant après. Utilisez https://.",
				resp.StatusCode, resp.Header.Get("Location"),
			),
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return c.decodeError(resp)
	}

	if resp.StatusCode == http.StatusNoContent || out == nil {
		return nil
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return &MafateError{Message: fmt.Sprintf("decode response: %s", err)}
	}
	return nil
}

// translateTransportError distingue un dépassement de délai d'un échec de
// connexion, et enveloppe les deux dans la hiérarchie du SDK.
//
// Auparavant tout ressortait en MafateError générique avec « execute request: »
// en préfixe : l'appelant ne pouvait pas distinguer « le serveur est lent »
// (réessayer a du sens) de « l'hôte est faux » (réessayer ne sert à rien).
// Node et Python exposent désormais TimeoutError et ConnectionError ; Go fait de
// même, avec ses propres idiomes (errors.As plutôt que instanceof).
func translateTransportError(err error, timeout time.Duration) error {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return &TimeoutError{
			MafateError:    MafateError{Message: fmt.Sprintf("la requête a dépassé le délai imparti de %s", timeout)},
			TimeoutSeconds: timeout.Seconds(),
		}
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return &TimeoutError{
			MafateError:    MafateError{Message: fmt.Sprintf("la requête a dépassé le délai imparti de %s", timeout)},
			TimeoutSeconds: timeout.Seconds(),
		}
	}

	return &ConnectionError{
		MafateError: MafateError{Message: fmt.Sprintf("l'API MAFATE n'a pas pu être jointe : %s", err)},
		Cause:       err,
	}
}

// decodeError reads the response body and attempts to parse an RFC 7807
// problem detail. Falls back to the HTTP status text on parse failure.
func (c *httpClient) decodeError(resp *http.Response) error {
	apiErr := &ApiError{
		Status: resp.StatusCode,
		Title:  resp.Status,
	}

	raw, err := io.ReadAll(resp.Body)
	if err == nil && len(raw) > 0 {
		var pd problemDetail
		if json.Unmarshal(raw, &pd) == nil {
			if pd.Title != "" {
				apiErr.Title = pd.Title
			}
			apiErr.Detail = pd.Detail
		}
	}

	return apiErr
}

// get performs a GET request with optional query parameters.
func (c *httpClient) get(ctx context.Context, path string, params map[string]string, out interface{}) error {
	return c.do(ctx, http.MethodGet, path, params, nil, out)
}

// post performs a POST request with an optional JSON body.
func (c *httpClient) post(ctx context.Context, path string, body, out interface{}) error {
	return c.do(ctx, http.MethodPost, path, nil, body, out)
}

// patch performs a PATCH request with an optional JSON body.
func (c *httpClient) patch(ctx context.Context, path string, body, out interface{}) error {
	return c.do(ctx, http.MethodPatch, path, nil, body, out)
}

// delete performs a DELETE request (no response body expected).
func (c *httpClient) delete(ctx context.Context, path string) error {
	return c.do(ctx, http.MethodDelete, path, nil, nil, nil)
}
