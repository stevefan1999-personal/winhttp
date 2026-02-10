use winhttp::Session;

fn main() {
    let session = Session::new().expect("Failed to create session");
    let connection = session
        .connect("httpbin.org", 80)
        .expect("Failed to connect");

    let request = connection
        .request("GET", "/get")
        .build()
        .expect("Failed to build request");

    request.send().expect("Failed to send");
    request.receive_response().expect("Failed to receive");

    let body = request.read_all().expect("Failed to read body");
    assert!(!body.is_empty(), "Response should not be empty");

    let body_str = String::from_utf8_lossy(&body);
    println!("Response body:\n{}", body_str);
}
