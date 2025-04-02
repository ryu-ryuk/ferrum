use axum::extract::State;
use axum::{
    Router,
    extract::Query,
    routing::get,
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::SocketAddr;
use std::collections::{HashMap, HashSet};
use std::fs;
use reqwest::Client;
use std::time::Duration;
use url::Url;
use std::sync::Arc;

#[derive(Deserialize)]
struct UrlQuery {
    url: String,
}

#[derive(Serialize)]
struct AnalysisResponse {
    url: String,
    status: String,
    data: Option<UrlAnalysis>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct UrlAnalysis {
    url: String,
    is_shortened: bool,
    is_phishing: bool,
    risk_score: f32,
    analysis: HashMap<String, String>,
}

#[derive(Debug)]
pub struct UrlCheckResult {
    pub is_phishing: bool,
    pub is_shortened: bool,
}

#[derive(Debug, Deserialize)]
pub struct PhishingList {
    pub flagged_sites: Vec<String>,
}


fn is_valid_url(url: &str) -> bool {
    if url.len() > 2048 {
        log::warn!("URL exceeds 2048 characters: {}", url);
        return false;
    }
    let normalized_url = normalize_url(url);
    match Url::parse(&normalized_url) {  // Use normalized_url here
        Ok(parsed_url) => {
            let valid = parsed_url.scheme() == "http" || parsed_url.scheme() == "https";
            if !valid {
                log::debug!("Invalid scheme for URL: {}", normalized_url);            }
            valid
        }
        Err(e) => {
            log::debug!("Failed to parse URL '{}': {}", normalized_url, e);            false
        }
    }
}

fn normalize_url(url: &str) -> String {
    // If the URL parses as-is, return it; otherwise, prepend "https://"
    match Url::parse(url) {
        Ok(_) => url.to_string(),
        Err(_) => format!("https://{}", url),
    }
}

fn is_known_shortener(url: &str) -> bool {
    let normalized_url = normalize_url(url);
    let shorteners: HashSet<&str> = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cli.gs", "pic.gd",
        "DwarfURL.com", "ow.ly", "snipurl.com", "short.to", "BudURL.com",
        "ping.fm", "post.ly", "Just.as", "bkite.com", "snipr.com", "fic.kr",
        "loopt.us", "doiop.com", "twitthis.com", "htxt.it", "AltURL.com",
        "RedirX.com", "DigBig.com", "tiny.cc", "u.nu", "u.to", "ln-s.net",
        "twurl.nl", "zi.ma", "urlx.ie", "adjix.com", "cutt.ly", "tr.im",
        "tiny.pl", "url4.eu", "fave.co", "hurl.ws", "ur1.ca", "x.co",
        "prettylinkpro.com", "scrnch.me", "filoops.info", "vzturl.com",
        "qr.net", "1url.com", "tweez.me", "v.gd", "tr.im", "link.zip.net",
        "tinyarrows.com", "shrinkster.com", "go2.me", "go2l.ink", "youtu.be",
        "amzn.to",
    ].iter().copied().collect();

    let parsed_url = match Url::parse(&normalized_url) {
        Ok(url) => url,
        Err(_e) => {
            return false;
        }
    };

    if let Some(host) = parsed_url.host_str() {
        shorteners.contains(host) || shorteners.iter().any(|s| host.ends_with(&format!(".{}", s)))
    } else {
        false
    }
}

async fn fetch_phishing_list() -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    const URL: &str = "https://raw.githubusercontent.com/polkadot-js/phishing/master/all.json";
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let response = client.get(URL).send().await?;
    let json: Value = response.json().await?;
    Ok(json)
}

async fn check_online_phishing_db(url: &str, phishing_list: &Result<Value, String>) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let json = match phishing_list {
        Ok(json) => json,
        Err(e) => {
            log::warn!("Failed to load phishing list: {}", e);
            return Ok(false);
        }
    };
    if let Some(Value::Array(blacklist)) = json.get("deny") {
        let url_lower = url.to_lowercase();
        Ok(blacklist.iter().any(|site| {
            site.as_str().map_or(false, |s| url_lower.contains(&s.to_lowercase()))
        }))
    } else {
        Ok(false)
    }
}

fn check_local_phishing_db(url: &str) -> bool {
    let content = match fs::read_to_string("filters/caught.json") {
        Ok(content) => content,
        Err(e) => {
            log::warn!("Failed to read local phishing DB: {}", e);
            return false;
        }
    };
    let json: PhishingList = match serde_json::from_str(&content) {
        Ok(json) => json,
        Err(e) => {
            log::warn!("Failed to parse local phishing DB: {}", e);
            return false;
        }
    };
    json.flagged_sites.iter().any(|s| url == s)
}

async fn checking_url_enhanced(url: &str, phishing_list: &Result<Value, String>) -> UrlCheckResult {
    let normalized_url = normalize_url(url);
    let is_phishing_local = check_local_phishing_db(&normalized_url);
    let is_phishing_online = check_online_phishing_db(&normalized_url, phishing_list).await.unwrap_or_else(|e| {
        log::warn!("Online phishing check failed: {}", e);
        false
    });
    let is_shortened = is_known_shortener(&normalized_url);
    UrlCheckResult {
        is_phishing: is_phishing_local || is_phishing_online,
        is_shortened,
    }
}


struct RiskWeights {
    shortened: f32,
    // redirects: f32,
    phishing: f32,
    suspicious_tld: f32,
    ip_address: f32,
    at_symbol: f32,
    double_slash: f32,
    dash_in_domain: f32,
    multiple_subdomains: f32,
}

const WEIGHTS: RiskWeights = RiskWeights {
    shortened: 0.3,
    // redirects: 0.2,
    phishing: 0.9,
    suspicious_tld: 0.2,
    ip_address: 0.3,
    at_symbol: 0.3,
    double_slash: 0.2,
    dash_in_domain: 0.1,
    multiple_subdomains: 0.1,
};

fn calculate_risk_score(
    is_shortened: bool,
    // redirects: bool,
    in_phishing_db: bool,
    url_features: &HashMap<String, bool>,
) -> f32 {
    let mut score = 0.0;
    if is_shortened { score += WEIGHTS.shortened; }
    // if redirects { score += WEIGHTS.redirects; }
    if in_phishing_db { score += WEIGHTS.phishing; }
    if *url_features.get("has_suspicious_tld").unwrap_or(&false) { score += WEIGHTS.suspicious_tld; }
    if *url_features.get("has_ip_address").unwrap_or(&false) { score += WEIGHTS.ip_address; }
    if *url_features.get("has_at_symbol").unwrap_or(&false) { score += WEIGHTS.at_symbol; }
    if *url_features.get("has_double_slash").unwrap_or(&false) { score += WEIGHTS.double_slash; }
    if *url_features.get("has_dash_in_domain").unwrap_or(&false) { score += WEIGHTS.dash_in_domain; }
    if *url_features.get("has_multiple_subdomains").unwrap_or(&false) { score += WEIGHTS.multiple_subdomains; }
    score.min(1.0)
}

fn extract_url_features(url: &str) -> HashMap<String, bool> {
    let normalized_url = normalize_url(url);
    let mut features = HashMap::new();
    let suspicious_tlds = ["xyz", "top", "club", "online", "site", "info", "biz"];
    let parsed_url = match Url::parse(&normalized_url) {
        Ok(url) => url,
        Err(_) => return features,
    };

    if let Some(domain) = parsed_url.domain() {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() > 1 {
            let tld = parts[parts.len() - 1];
            features.insert("has_suspicious_tld".to_string(), suspicious_tlds.contains(&tld));
        }
        features.insert("has_dash_in_domain".to_string(), domain.contains('-'));
        features.insert("has_multiple_subdomains".to_string(), domain.matches('.').count() > 2);
    }

    features.insert("has_ip_address".to_string(), normalized_url.parse::<std::net::IpAddr>().is_ok());
    features.insert("has_at_symbol".to_string(), normalized_url.contains('@'));
    features.insert("has_double_slash".to_string(), normalized_url[8..].contains("//"));
    features
}


// async fn check_redirect(url: &str) -> Result<(bool, String, bool), Box<dyn std::error::Error + Send + Sync>> {
//     let normalized_url = normalize_url(url);
//     let client = Client::builder()
//         .timeout(Duration::from_secs(10))  // Increased timeout to 10s
//         .redirect(reqwest::redirect::Policy::limited(5))
//         .build()?;
//     let response = client.get(&normalized_url).send().await.map_err(|e| {
//         log::warn!("Redirect check failed for {}: {}", normalized_url, e);
//         e
//     })?;
//     let final_url = response.url().to_string();
//     let redirects = final_url != normalized_url;
//     let is_cross_domain = if redirects {
//         let original_domain = Url::parse(&normalized_url)?.host_str().unwrap_or("").to_string();
//         let final_domain = Url::parse(&final_url)?.host_str().unwrap_or("").to_string();
//         log::debug!("Redirect: {} -> {}, cross-domain: {}", normalized_url, final_url, original_domain != final_domain);
//         original_domain != final_domain
//     } else {
//         false
//     };
//     Ok((redirects, final_url, is_cross_domain))
// }
// async fn checking_url_enhanced(url: &str, phishing_list: &Result<Value, String>) -> UrlCheckResult {
    
//     let normalized_url = normalize_url(url);
//     let is_phishing_local = check_local_phishing_db(&normalized_url);
//     let is_phishing_online = check_online_phishing_db(&normalized_url, phishing_list).await.unwrap_or_else(|e| {
//         log::warn!("Online phishing check failed: {}", e);
//         false
//     });
//     let redirect_result = check_redirect(&normalized_url).await.unwrap_or_else(|e| {
//         log::warn!("Redirect check failed: {}", e);
//         (false, normalized_url.clone(), false)
//     });
//     let is_shortened = if is_known_shortener(&normalized_url) {
//         true
//     } else {
//         check_redirect(&normalized_url).await.map_or(false, |(redirects, _, is_cross_domain)| redirects && is_cross_domain)
//     };
//     UrlCheckResult {
//         is_phishing: is_phishing_local || is_phishing_online,
//         is_shortened,
//     }
// }

async fn analyze_url(url: &str, phishing_list: Arc<Result<Value, String>>) -> Result<UrlAnalysis, Box<dyn std::error::Error + Send + Sync>> {
    let normalized_url = normalize_url(url);
    let mut analysis = HashMap::new();
    let check_result = checking_url_enhanced(&normalized_url, &phishing_list).await;
    // let (redirects, final_url, is_cross_domain) = check_redirect(&normalized_url).await.unwrap_or_else(|e| {
        // log::warn!("Redirect check failed: {}", e);
        // (false, normalized_url.clone(), false)
    // });

    // analysis.insert("redirect".to_string(), if redirects {
    //     format!("URL redirects to: {}", final_url)
    // } else {
    //     "No redirection".to_string()
    // });

    if check_result.is_phishing {
        analysis.insert("phishing_detected".to_string(), "URL found in phishing database".to_string());
    }

    let url_features = extract_url_features(&normalized_url);
    for (feature, value) in &url_features {
        if *value {
            analysis.insert(feature.clone(), "Suspicious feature detected".to_string());
        }
    } //is_cross_domain
    let risk_score = calculate_risk_score(check_result.is_shortened, check_result.is_phishing, &url_features);
    let risk_assessment = if risk_score >= 0.7 {
        "High risk - Likely phishing"
    } else if risk_score >= 0.4 {
        "Medium risk - Suspicious"
    } else {
        "Low risk - Likely safe"
    }.to_string();
    analysis.insert("risk_assessment".to_string(), risk_assessment);

    Ok(UrlAnalysis {
        url: normalized_url,
        is_shortened: check_result.is_shortened,
        is_phishing: check_result.is_phishing,
        risk_score,
        analysis,
    })
}

#[axum::debug_handler]
async fn analyze_url_handler(Query(params): Query<UrlQuery>, State(phishing_list): State<Arc<Result<Value, String>>>) -> (StatusCode, Json<AnalysisResponse>) {
    if !is_valid_url(&params.url) {  
        return (
            StatusCode::BAD_REQUEST,
            Json(AnalysisResponse {
                url: params.url.clone(),
                status: "error".to_string(),
                data: None,
                error: Some("Invalid URL".to_string()),
            }),
        );
    }

    match analyze_url(&params.url, phishing_list).await { 
        Ok(analysis) => (
            StatusCode::OK,
            Json(AnalysisResponse {
                url: params.url.clone(),
                status: "success".to_string(),
                data: Some(analysis),
                error: None,
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AnalysisResponse {
                url: params.url.clone(),
                status: "error".to_string(),
                data: None,
                error: Some(format!("Analysis failed: {}", e)),
            }),
        ),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();
    let phishing_list = Arc::new(fetch_phishing_list().await.map(|v| Ok(v)).unwrap_or_else(|e| Err(e.to_string())));
    let app = Router::new()
        .route("/analyze", get(analyze_url_handler))
        .with_state(phishing_list.clone());

    let addr: SocketAddr = "127.0.0.1:3000".parse()?;
    println!("URL Analysis Service running on http://{}", addr);

    axum_server::bind(addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}