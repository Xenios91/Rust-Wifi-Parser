use reqwest::blocking::{Client, Response};
use reqwest::Error;
use crate::packets::management_packets::ManagementFrame;

pub fn send_to_monitor(management_frame: Box<dyn ManagementFrame>, monitor_url: &String) {
    let json: String = management_frame.get_json();
    let client: Client = reqwest::blocking::Client::new();
    let _result: Result<Response, Error> = client
        .post(monitor_url)
        .body(json)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .send();
}