use warp::Filter;
use warp::filters::BoxedFilter;
use warp::Rejection;
use std::future::Future;
use oauth2::{
    AuthorizationCode,
    AuthUrl,
    ClientId,
    ClientSecret,
    CsrfToken,
    PkceCodeChallenge,
    RedirectUrl,
    Scope,
    TokenResponse,
    TokenUrl
};
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use warp::http::Uri;
use warp::http::Response;
use warp::http::Error;
use http::{header, StatusCode};

pub trait Oauth2 {
    fn build_routes(&self) -> BoxedFilter<(Result<Response<()>, Error>,)>;
}

pub struct Oauth2Config<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    auth_url: &'a str,
    token_url: &'a str,
}

impl<'a> Oauth2Config<'a> {
    pub fn new(client_id: &'a str, client_secret: &'a str, auth_url: &'a str, token_url: &'a str) -> Oauth2Config<'a> {
        Oauth2Config {
            client_id: client_id,
            client_secret: client_secret,
            auth_url: auth_url,
            token_url: token_url,
        }
    }

    fn oauth2_client(config: &Oauth2Config) -> BasicClient {
        return BasicClient::new(
            ClientId::new(config.client_id.to_string()),
            Some(ClientSecret::new(config.client_secret.to_string())),
            AuthUrl::new(config.auth_url.to_string()).unwrap(),
            Some(TokenUrl::new(config.token_url.to_string()).unwrap())
        )
        .set_redirect_uri(RedirectUrl::new("oauth2/redirect".to_string()).unwrap());
    }
}

pub struct Oauth2Resource<'a> {
    config: Oauth2Config<'a>,
}

impl<'a> Oauth2 for Oauth2Resource<'a> {
    fn build_routes(&self) -> BoxedFilter<(Result<Response<()>, Error>,)> {
        let client = Oauth2Config::oauth2_client(&self.config);
        let login_filter = warp::path("oauth2/login")
            .map(|| {
                let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

                // Generate the full authorization URL.
                let (auth_url, csrf_token) = client
                .authorize_url(CsrfToken::new_random)
                // Set the desired scopes.
                .add_scope(Scope::new("read".to_string()))
                .add_scope(Scope::new("write".to_string()))
                // Set the PKCE code challenge.
                .set_pkce_challenge(pkce_challenge)
                .url();
                
                let mut csrf_cookie = String::from("csrf_token=");
                csrf_cookie.push_str(csrf_token.secret());
                
                return Response::builder()
                    .header(header::SET_COOKIE, csrf_cookie)
                    .header(header::LOCATION, auth_url.as_str())
                    .status(StatusCode::MOVED_PERMANENTLY)
                    .body(());
            })
            .boxed();

        let redirect = warp::path("oauth2/redirect")
            .and_then(async || {
                // Once the user has been redirected to the redirect URL, you'll have access to the
                // authorization code. For security reasons, your code should verify that the `state`
                // parameter returned by the server matches `csrf_state`.

                // Now you can trade it for an access token.
                let token_result = client
                    .exchange_code(AuthorizationCode::new("some authorization code".to_string()))
                    // // Set the PKCE code verifier.
                    // .set_pkce_verifier(pkce_verifier)
                    .request_async(async_http_client)
                    .await
                    .unwrap();

                return Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .map_err(|_err| { warp::reject::reject() });
            })
            .boxed();

        return login_filter;//.or(redirect).boxed();
    }
}
