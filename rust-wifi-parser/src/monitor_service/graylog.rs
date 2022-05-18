use reqwest::blocking::{Client, Response};
use reqwest::Error;
use crate::packets::management_packets::ManagementFrame;

// converts the management frame into a json and sends it to the provided url.
// if an error occurs we print it to stdout.
pub fn send_management_frame_to_log(management_frame: &Box<dyn ManagementFrame>, greylog_url: &str) {
    let json: String = management_frame.get_json();
    let client: Client = reqwest::blocking::Client::new();
    let result: Result<Response, Error> = client
        .post(greylog_url)
        .body(json)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .send();

    // for graylog we want a status code 202 per documentation
    match result {
        Ok(r) => {
            if r.status().as_u16() != 202 {
                println!("GRAYLOG ERROR [STATUS CODE: {}]", r.status())
            }
        }
        Err(e) => println!("ERROR: [{}]", e),
    }
}