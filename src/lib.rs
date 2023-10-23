pub mod app;
pub mod auth;
pub mod ldap;
pub mod utils;

pub mod schema {
    pub mod api;
    pub mod db;
}

pub mod api {
    pub mod db;
    pub mod endpoints;
}
