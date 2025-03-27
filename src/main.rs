// the imports
use axum::{Router, extract::Query, response::IntoResponse, routing::get}; // web server
use serde_json::Value;
use std::fs; // to read file sys
use std::net::SocketAddr;

/// the struct to accept the URL query params, in order to hold wesbite addrs
#[derive(Debug, serde::Deserialize)]
struct UrlQuery {
    url: String,
}

// flow: open the json file -> read -> looks for the section in json file -> takes action!
// checking if a URL exists in the phishing filters
fn checking_url(url: &str) -> bool {
    // read the JSON file for the filtering
    let data =
        fs::read_to_string("filters/caught.json").expect("Error: Unable to read the JSON file");

    // parsing the JSON file
    let json: Value = serde_json::from_str(&data).expect("error: invalid JSON format");

    // extracts the list of phishing websites
    // gets the flagged_sites key from the json file
    if let Some(Value::Array(blacklist)) = json.get("flagged_sites") {
        //
        // checks if the URL is available in the list
        // iterates in the array and check the urls present in it to blacklist them
        return blacklist.iter().any(|site| site.as_str() == Some(url));
    }

    // retuning false if no matches
    false
}

// flow: goes to the struct UrlQuery -> validates with checking_url fn and outputs the message
//
//
async fn checking_url_handler(Query(query): Query<UrlQuery>) -> impl IntoResponse {
    let is_phishing = checking_url(&query.url);

    if is_phishing {
        format!("Warning: {} is a known phishing site", query.url)
    } else {
        format!("URL {} is not in our phishing database", query.url)
    }
}

// The main function
#[tokio::main]
// to handle more than one visitors at the same time!
async fn main() {
    // setting up the listener
    let addr = "127.0.0.1:3000".parse::<SocketAddr>().unwrap();

    // containing all the routes and handlers
    let app = Router::new().route("/checking", get(checking_url_handler));

    println!("Listening on http://{}", addr);

    // answer  calls
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    // serve
    axum::serve(listener, app).await.unwrap();
}
