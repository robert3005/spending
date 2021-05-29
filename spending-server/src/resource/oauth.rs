use http::{header, StatusCode};
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenUrl,
};
use serde::Deserialize;
use std::sync::Arc;
use warp::filters::BoxedFilter;
use warp::http::Response;
use warp::Filter;
use warp::Rejection;
use warp::Reply;

static PREFIX: &str = "oauth";
static REDIRECT_URL: &str = "redirect";
static LOGIN_URL: &str = "login";
static CSRF_TOKEN_COOKIE: &str = "csrf_token";

#[derive(Deserialize)]
struct RedirectParams {
    code: String,
    state: String,
}

pub struct Oauth2Config<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    auth_url: &'a str,
    token_url: &'a str,
    scopes: &'a Vec<&'a str>,
    extra_params: &'a Vec<(&'a str, &'a str)>,
}

impl<'a> Oauth2Config<'a> {
    pub fn new(
        client_id: &'a str,
        client_secret: &'a str,
        auth_url: &'a str,
        token_url: &'a str,
        scopes: &'a Vec<&'a str>,
        extra_params: &'a Vec<(&'a str, &'a str)>,
    ) -> Oauth2Config<'a> {
        Oauth2Config {
            client_id: client_id,
            client_secret: client_secret,
            auth_url: auth_url,
            token_url: token_url,
            scopes: scopes,
            extra_params: extra_params,
        }
    }

    fn oauth2_client(&self) -> BasicClient {
        return BasicClient::new(
            ClientId::new(self.client_id.to_string()),
            Some(ClientSecret::new(self.client_secret.to_string())),
            AuthUrl::new(self.auth_url.to_string()).unwrap(),
            Some(TokenUrl::new(self.token_url.to_string()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new("http://172.18.60.171:3000/oauth/redirect".to_string()).unwrap());
    }
}

pub struct Oauth2Resource {
    oauth2_client: Arc<BasicClient>,
    scopes: Arc<Vec<Scope>>,
    extra_params: Arc<Vec<(String, String)>>,
}

impl Oauth2Resource {
    pub fn new(config: Oauth2Config<'_>) -> Oauth2Resource {
        return Oauth2Resource {
            oauth2_client: Arc::new(config.oauth2_client()),
            scopes: Arc::new(
                config
                    .scopes
                    .iter()
                    .map(|&s| Scope::new(s.to_string()))
                    .collect(),
            ),
            extra_params: Arc::new(
                config
                    .extra_params
                    .iter()
                    .map(|(name, value)| (name.to_string(), value.to_string()))
                    .collect(),
            ),
        };
    }

    async fn login(self: Arc<Self>) -> Result<Response<Vec<u8>>, Rejection> {
        // let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let authorization_request = self
            .oauth2_client
            .authorize_url(CsrfToken::new_random);
            // .set_pkce_challenge(pkce_challenge);

        let request_with_scopes = self
            .scopes
            .iter()
            .fold(authorization_request, |req, s| req.add_scope(s.to_owned()));
        let request_with_params = self
            .extra_params
            .iter()
            .fold(request_with_scopes, |req, (name, value)| {
                req.add_extra_param(name, value)
            });

        let (auth_url, csrf_token) = request_with_params.url();

        let mut csrf_cookie = CSRF_TOKEN_COOKIE.to_string();
        csrf_cookie.push('=');
        csrf_cookie.push_str(csrf_token.secret());

        return Response::builder()
            .header(header::SET_COOKIE, csrf_cookie)
            .header(header::LOCATION, auth_url.as_str())
            .status(StatusCode::FOUND)
            .body(vec![])
            .map_err(|_err| warp::reject::reject());
    }

    async fn redirect(
        self: Arc<Self>,
        query_state: String,
        cookie_state: String,
        auth_code: String,
    ) -> Result<Response<Vec<u8>>, Rejection> {
        if !query_state.eq(&cookie_state) {
            return Err(warp::reject::reject());
        }

        let token_result = self
            .oauth2_client
            .exchange_code(AuthorizationCode::new(auth_code))
            // // Set the PKCE code verifier.
            // .set_pkce_verifier(pkce_verifier)
            .request_async(async_http_client)
            .await
            .unwrap();

        return Response::builder()
            .status(StatusCode::OK)
            .body(vec![])
            .map_err(|_err| warp::reject::reject());
    }

    pub fn routes(self: Arc<Self>) -> BoxedFilter<(impl Reply,)> {
        let login_filter = warp::path(PREFIX)
            .and(warp::path(LOGIN_URL))
            .and(warp::path::end())
            .and_then({
                let resource = Arc::clone(&self);
                move || {
                    let resource = Arc::clone(&resource);
                    return resource.login();
                }
            })
            .boxed();

        let redirect = warp::path(PREFIX)
            .and(warp::path(REDIRECT_URL))
            .and(warp::path::end())
            .and(warp::filters::query::query())
            .and(warp::filters::cookie::cookie(CSRF_TOKEN_COOKIE))
            .and_then({
                let resource = Arc::clone(&self);
                move |query_params: RedirectParams, state_cookie: String| {
                    let resource = Arc::clone(&resource);
                    return resource.redirect(query_params.state, state_cookie, query_params.code);
                }
            })
            .boxed();

        return login_filter.or(redirect).boxed();
    }
}
