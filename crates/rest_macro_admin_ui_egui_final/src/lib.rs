
use eframe::egui;
use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};
use gloo_net::http::Request;

#[wasm_bindgen(start)]
pub fn start() -> Result<(), JsValue> {
    let web_options = eframe::WebOptions::default();
    eframe::start_web(
        "admin-ui",
        web_options,
        Box::new(|_cc| Box::<AdminApp>::default()),
    )
}

#[derive(Default)]
struct AdminApp {
    page: Page,
    email: String,
    password: String,
    token: Option<String>,
    login_error: Option<String>,
    posts: Vec<Post>,
    posts_loaded: bool,
}

#[derive(Default, PartialEq, Clone)]
enum Page {
    #[default]
    Login,
    Dashboard,
}

#[derive(Serialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginResponse {
    token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Post {
    id: Option<i64>,
    title: String,
    content: String,
    created_at: Option<String>,
    updated_at: Option<String>,
}

impl eframe::App for AdminApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        match self.page {
            Page::Login => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.heading("Login");

                    ui.horizontal(|ui| {
                        ui.label("Email:");
                        ui.text_edit_singleline(&mut self.email);
                    });

                    ui.horizontal(|ui| {
                        ui.label("Password:");
                        ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                    });

                    if ui.button("Login").clicked() {
                        let req = LoginRequest {
                            email: self.email.clone(),
                            password: self.password.clone(),
                        };

                        let cb = ctx.clone();
                        let mut app = self.clone();

                        wasm_bindgen_futures::spawn_local(async move {
                            let result = Request::post("/auth/login")
                                .header("Content-Type", "application/json")
                                .body(serde_json::to_string(&req).unwrap())
                                .send()
                                .await;

                            if let Ok(response) = result {
                                if let Ok(data) = response.json::<LoginResponse>().await {
                                    app.token = Some(data.token);
                                    app.page = Page::Dashboard;
                                    app.login_error = None;
                                    cb.request_repaint();
                                } else {
                                    app.login_error = Some("Failed to parse response".into());
                                    cb.request_repaint();
                                }
                            } else {
                                app.login_error = Some("Login failed".into());
                                cb.request_repaint();
                            }
                        });
                    }

                    if let Some(err) = &self.login_error {
                        ui.colored_label(egui::Color32::RED, err);
                    }
                });
            }

            Page::Dashboard => {
                if !self.posts_loaded {
                    if let Some(token) = &self.token {
                        let token = token.clone();
                        let cb = ctx.clone();
                        let app_ptr = std::rc::Rc::new(std::cell::RefCell::new(self.clone()));
                        let app_clone = app_ptr.clone();

                        wasm_bindgen_futures::spawn_local(async move {
                            let response = Request::get("/post")
                                .header("Authorization", &format!("Bearer {}", token))
                                .send()
                                .await;

                            if let Ok(resp) = response {
                                if let Ok(posts) = resp.json::<Vec<Post>>().await {
                                    let mut app = app_clone.borrow_mut();
                                    app.posts = posts;
                                    app.posts_loaded = true;
                                    cb.request_repaint();
                                }
                            }
                        });
                    }
                }

                egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Admin Panel");
                        if ui.button("Logout").clicked() {
                            self.token = None;
                            self.page = Page::Login;
                            self.posts.clear();
                            self.posts_loaded = false;
                        }
                    });
                });

                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.heading("Posts");

                    for post in &self.posts {
                        ui.group(|ui| {
                            ui.label(format!("ID: {}", post.id.unwrap_or_default()));
                            ui.label(format!("Title: {}", post.title));
                            ui.label(format!("Content: {}", post.content));
                            if let Some(ts) = &post.updated_at {
                                ui.small(format!("Updated: {}", ts));
                            }
                        });
                        ui.separator();
                    }

                    if self.posts.is_empty() && self.posts_loaded {
                        ui.label("No posts found.");
                    }
                });
            }
        }
    }
}

impl Clone for AdminApp {
    fn clone(&self) -> Self {
        Self {
            page: self.page.clone(),
            email: self.email.clone(),
            password: self.password.clone(),
            token: self.token.clone(),
            login_error: self.login_error.clone(),
            posts: self.posts.clone(),
            posts_loaded: self.posts_loaded,
        }
    }
}


// --- Users tab logic ---

// [EXCERPT] Replace the `Tab::Users` match arm in CentralPanel with real implementation
Tab::Users => {
    if let Some(token) = &self.token {
        if !self.users_loaded {
            let token = token.clone();
            let cb = ctx.clone();
            let app_ptr = std::rc::Rc::new(std::cell::RefCell::new(self.clone()));
            let app_clone = app_ptr.clone();

            wasm_bindgen_futures::spawn_local(async move {
                if let Ok(resp) = Request::get("/user")
                    .header("Authorization", &format!("Bearer {}", token))
                    .send()
                    .await
                {
                    if let Ok(users) = resp.json::<Vec<User>>().await {
                        let mut app = app_clone.borrow_mut();
                        app.users = users;
                        app.users_loaded = true;
                        cb.request_repaint();
                    }
                }
            });
        }

        ui.heading("Users");
        for user in &self.users {
            ui.group(|ui| {
                ui.label(format!("Email: {}", user.email));
                ui.label(format!("Role: {}", user.role));

                if user.role != "admin" {
                    if ui.button("Promote to admin").clicked() {
                        if let Some(id) = user.id {
                            let token = token.clone();
                            let cb = ctx.clone();
                            let mut user_data = user.clone();
                            user_data.role = "admin".into();

                            wasm_bindgen_futures::spawn_local(async move {
                                let _ = Request::put(&format!("/user/{}", id))
                                    .header("Authorization", &format!("Bearer {}", token))
                                    .header("Content-Type", "application/json")
                                    .body(serde_json::to_string(&user_data).unwrap())
                                    .send()
                                    .await;
                                cb.request_repaint();
                            });
                            self.users_loaded = false;
                        }
                    }
                }

                if ui.button("Delete").clicked() {
                    if let Some(id) = user.id {
                        let token = token.clone();
                        let cb = ctx.clone();

                        wasm_bindgen_futures::spawn_local(async move {
                            let _ = Request::delete(&format!("/user/{}", id))
                                .header("Authorization", &format!("Bearer {}", token))
                                .send()
                                .await;
                            cb.request_repaint();
                        });
                        self.users_loaded = false;
                    }
                }
            });
            ui.separator();
        }
    } else {
        ui.label("Authentication required.");
    }
}
