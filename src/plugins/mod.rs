//! Extensible activity reporter plugins (e.g. Discord Rich Presence).

pub mod discord_rpc;

use crate::privacy::PluginsConfig;

#[derive(Debug, Clone, PartialEq)]
pub struct PluginActivity {
    pub app_name: String,
    pub window_title: String,
    pub category: String,
    pub started_at: f64,
    pub paused: bool,
    pub screen_locked: bool,
}

pub trait ActivityReporterPlugin: Send {
    #[allow(dead_code)]
    fn name(&self) -> &'static str;
    fn on_activity_update(&mut self, activity: Option<&PluginActivity>, cfg: &PluginsConfig);
    fn on_shutdown(&mut self);
}

pub struct PluginManager {
    plugins: Vec<Box<dyn ActivityReporterPlugin>>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: vec![Box::new(discord_rpc::DiscordRpcPlugin::new())],
        }
    }

    pub fn notify_update(&mut self, activity: Option<&PluginActivity>, cfg: &PluginsConfig) {
        for plugin in &mut self.plugins {
            plugin.on_activity_update(activity, cfg);
        }
    }

    pub fn shutdown(&mut self) {
        for plugin in &mut self.plugins {
            plugin.on_shutdown();
        }
    }
}
