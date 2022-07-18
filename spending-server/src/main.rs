#![feature(async_closure)]

use warp::Filter;

mod resource;

use resource::oauth;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // GET /hello/warp => 200 OK with body "Hello, warp!"
    let hello = warp::path("hello")
        .and(warp::path::param())
        .and(warp::path::end())
        .map(|name: String| format!("Hello, {}!", name));

    let oauth2 = Arc::new(oauth::Oauth2Resource::new(
        resource::oauth::Oauth2Config::new("", "", "https://auth.truelayer.com/", "https://auth.truelayer.com/connect/token", &vec!["info", "balance", "cards", "transactions", "offline_access"], &vec![("providers", "uk-ob-all uk-oauth-all")]),
    ));

    warp::serve(hello.or(oauth2.routes()))
        .run(([0, 0, 0, 0], 3000))
        .await;
}
