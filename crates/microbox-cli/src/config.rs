use microbox_policy::{ConfigFile, PolicyError};
use std::path::{Path, PathBuf};

pub fn discover_config(path: Option<PathBuf>) -> Result<Option<ConfigFile>, PolicyError> {
    if let Some(path) = path {
        if path.exists() {
            return ConfigFile::load(&path).map(Some);
        }
        return Ok(None);
    }

    let default_path = Path::new("microbox.toml");
    if default_path.exists() {
        ConfigFile::load(default_path).map(Some)
    } else {
        Ok(None)
    }
}
