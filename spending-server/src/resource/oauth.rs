use http::{header, StatusCode};
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenUrl,
};
use warp::filters::BoxedFilter;
use warp::http::Response;
use warp::Filter;
use warp::Rejection;
use warp::Reply;
use std::sync::Arc;

pub struct Oauth2Config<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    auth_url: &'a str,
    token_url: &'a str,
}

impl<'a> Oauth2Config<'a> {
    pub fn new(
        client_id: &'a str,
        client_secret: &'a str,
        auth_url: &'a str,
        token_url: &'a str,
    ) -> Oauth2Config<'a> {
        Oauth2Config {
            client_id: client_id,
            client_secret: client_secret,
            auth_url: auth_url,
            token_url: token_url,
        }
    }

    fn oauth2_client(&self) -> BasicClient {
        return BasicClient::new(
            ClientId::new(self.client_id.to_string()),
            Some(ClientSecret::new(self.client_secret.to_string())),
            AuthUrl::new(self.auth_url.to_string()).unwrap(),
            Some(TokenUrl::new(self.token_url.to_string()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new("oauth2/redirect".to_string()).unwrap());
    }
}

pub struct Oauth2Resource {
    oauth2_client: Arc<BasicClient>,
}

impl Oauth2Resource {
    pub fn new(config: Oauth2Config<'_>) -> Oauth2Resource {
        return Oauth2Resource {
            oauth2_client: Arc::new(config.oauth2_client()),
        };
    }
}

pub fn routes(oauth2_resource: &Arc<Oauth2Resource>) -> BoxedFilter<(impl Reply,)> {
    let login_filter = warp::path("oauth2/login")
        .and(warp::path::end())
        .and_then({
            let client = Arc::clone(&oauth2_resource.oauth2_client);
            move || {
                let client = Arc::clone(&client);
                return login(client);
            }
        })
        .boxed();

    let redirect = warp::path("oauth2/redirect")
        .and(warp::path::end())
        .and_then(
            
            {
                let client = Arc::clone(&oauth2_resource.oauth2_client);
                move || {
                    let client = Arc::clone(&client);
                    return redirect(client);
                }
            }
        )
        .boxed();

    return login_filter.or(redirect).boxed();
}

async fn login(oauth2_client: Arc<BasicClient>) -> Result<Response<Vec<u8>>, Rejection> {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, csrf_token) = oauth2_client
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
        .body(vec![])
        .map_err(|_err| warp::reject::reject());
}

async fn redirect(oauth2_client: Arc<BasicClient>) -> Result<Response<Vec<u8>>, Rejection> {
    // Once the user has been redirected to the redirect URL, you'll have access to the
    // authorization code. For security reasons, your code should verify that the `state`
    // parameter returned by the server matches `csrf_state`.

    // Now you can trade it for an access token.
    let token_result = oauth2_client
        .exchange_code(AuthorizationCode::new(
            "some authorization code".to_string(),
        ))
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
