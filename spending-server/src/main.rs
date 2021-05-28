#![feature(async_closure)]

use warp::Filter;

mod resource;

#[tokio::main]
async fn main() {
    // GET /hello/warp => 200 OK with body "Hello, warp!"
    let hello = warp::path("hello")
        .and(warp::path::param())
        .map(|name: String| format!("Hello, {}!", name));

    let oauth2 =
        resource::oauth::Oauth2Resource::new(resource::oauth::Oauth2Config::new("", "", "", ""));

    warp::serve(hello.or(oauth2.build_routes()))
        .run(([127, 0, 0, 1], 3030))
        .await;
}
