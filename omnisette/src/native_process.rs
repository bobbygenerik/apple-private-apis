//! App-owned IPC with the pinned official provider. No ADB, shell, or credential IPC.
use std::{collections::HashMap, path::PathBuf, process::Stdio, time::Duration};
use tokio::{io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader}, process::{Child, ChildStdin, ChildStdout, Command}};
use crate::{AnisetteError, LoginClientInfo};
struct Worker { child: Child, input: ChildStdin, output: BufReader<ChildStdout> }
pub struct NativeProvider { root: PathBuf, info: LoginClientInfo, worker: Option<Worker> }
impl NativeProvider {
    pub fn new(root: PathBuf, info: LoginClientInfo) -> Self { Self { root, info, worker: None } }
    async fn start(&mut self) -> Result<(), AnisetteError> {
        let runtime = self.root.join("native_provider_runtime");
        if !runtime.join("worker.jar").is_file() { return Err(AnisetteError::MissingLibraries); }
        let state = self.root.join("native_provider_state");
        tokio::fs::create_dir_all(&state).await?;
        // The official registry never writes the fork's hardware or keystore metadata.
        for name in ["hw_info.plist", "keystore.plist"] {
            tokio::fs::copy(self.root.join(name), state.join(name)).await?;
        }
        let mut child = Command::new("/system/bin/app_process")
            .arg(format!("-Djava.class.path={}", runtime.join("worker.jar").display()))
            .arg("/system/bin").arg("NativeAuthWorker").arg(&state).arg(&runtime)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
            .kill_on_drop(true).spawn()?;
        let input = child.stdin.take().ok_or(AnisetteError::Misc)?;
        let output = BufReader::new(child.stdout.take().ok_or(AnisetteError::Misc)?);
        self.worker = Some(Worker {child,input,output});
        Ok(())
    }
    pub async fn headers(&mut self) -> Result<HashMap<String,String>, AnisetteError> {
        let result = tokio::time::timeout(Duration::from_secs(100), self.request()).await;
        match result {
            Ok(Ok(headers)) => Ok(headers),
            other => {
                if let Some(mut worker) = self.worker.take() { let _ = worker.child.kill().await; }
                match other { Ok(Err(error)) => Err(error), _ => Err(AnisetteError::Misc) }
            }
        }
    }
    async fn request(&mut self) -> Result<HashMap<String,String>, AnisetteError> {
        if self.worker.is_none() { self.start().await?; }
        let worker = self.worker.as_mut().ok_or(AnisetteError::Misc)?;
        worker.input.write_all(b"headers\n").await?;
        worker.input.flush().await?;
        // Bound both the line and total noise; never expose raw stdout/error bodies.
        for _ in 0..8 {
            let mut line = Vec::new();
            (&mut worker.output).take(16385).read_until(b'\n', &mut line).await?;
            if line.is_empty() || line.len() > 16384 { return Err(AnisetteError::Misc); }
            if let Some(payload) = line.strip_prefix(b"OBIM_NATIVE_HEADERS=") {
                let mut headers: HashMap<String,String> = serde_json::from_slice(payload).map_err(|_| AnisetteError::Misc)?;
                for key in ["X-Apple-I-MD", "X-Apple-I-MD-M", "X-Mme-Device-Id"] {
                    if !headers.get(key).is_some_and(|v| !v.is_empty()) { return Err(AnisetteError::Misc); }
                }
                // The exported official wrapper describes FindMy. This client is AuthKit.
                headers.insert("X-Mme-Client-Info".into(), self.info.mme_client_info_akd.clone());
                return Ok(headers);
            }
        }
        Err(AnisetteError::Misc)
    }
}
