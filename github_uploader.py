#!/usr/bin/env python3
"""
GitHub Uploader - small graphical tool that pushes the CONTENTS OF A FOLDER (this whole Kivy
project, source + buildozer.spec) to a GitHub repo, creating the repo automatically if it does
not exist yet - and makes sure a GitHub Actions workflow is included that actually BUILDS the
Android APK on GitHub's own servers after the push, instead of just storing raw files.

Run on your desktop/CI machine (not on the phone):

    pip install requests
    python github_uploader.py

What it does, using the GitHub REST API with your personal access token:
  1. Verifies the token and reads your GitHub username (so you never have to type "repo owner").
  2. Creates the repo under your account if a repo with that name does not exist yet - you don't
     need to create anything on github.com first.
  3. If the folder doesn't already have .github/workflows/build-apk.yml, writes it in before
     uploading. That workflow runs `buildozer -v android debug` on a GitHub Actions runner on
     every push, then attaches the resulting .apk to a GitHub Release automatically - no local
     Android SDK/NDK needed on your machine at all.
  4. Walks the chosen folder and uploads every file into that repo (one Contents-API call per
     file: creates new files, updates existing ones by their current sha).
  5. Prints the repo's Actions URL at the end so you can watch the build and grab the APK.

Token scope needed: a classic PAT with the "repo" scope (public_repo is enough for public repos),
or a fine-grained PAT with "Contents: Read and write" + "Administration: Read and write" (the
second one only if you want it to create the repo for you). The token is only kept in memory for
this run unless you tick "Remember on this PC", which saves it in
~/.aminium_github_uploader.json (local file, not synced anywhere).
"""
import base64
import json
import os
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import requests

CFG_PATH = Path.home() / ".aminium_github_uploader.json"
API = "https://api.github.com"
TOKEN_PAGE = "https://github.com/settings/tokens/new?description=Aminium%20Uploader&scopes=repo"

# folders we never want to upload (build caches, VCS internals, virtualenvs...)
SKIP_DIRS = {".git", "__pycache__", ".buildozer", "bin", ".venv", "venv", ".idea", ".vscode", "node_modules"}
MAX_FILE_MB = 45  # GitHub's Contents API caps a single PUT around ~50 MB; stay safely under it

WORKFLOW_PATH = ".github/workflows/build-apk.yml"
WORKFLOW_YAML = """name: Build Android APK

on:
  push:
    branches: [ main ]
  workflow_dispatch: {}

permissions:
  contents: write

jobs:
  build:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install system dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y \\
            git zip unzip openjdk-17-jdk-headless python3-pip autoconf libtool pkg-config \\
            zlib1g-dev libncurses-dev cmake libffi-dev libssl-dev build-essential ccache

      - name: Install buildozer & Cython
        run: pip install --upgrade buildozer "cython<3.1"

      - name: Cache Android SDK/NDK (buildozer global dir)
        uses: actions/cache@v4
        with:
          path: ~/.buildozer
          key: buildozer-global-${{ hashFiles('buildozer.spec') }}

      - name: Cache project build dir
        uses: actions/cache@v4
        with:
          path: .buildozer
          key: buildozer-project-${{ hashFiles('buildozer.spec') }}

      - name: Build the debug APK
        run: yes | buildozer -v android debug

      - name: Upload APK as a workflow artifact
        uses: actions/upload-artifact@v4
        with:
          name: aminium-studio-apk
          path: bin/*.apk

      - name: Attach the APK to a GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          tag_name: build-${{ github.run_number }}
          name: "Aminium Studio build #${{ github.run_number }}"
          files: bin/*.apk
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
"""


def ensure_workflow_file(root: Path, log) -> None:
    """Writes the Actions workflow into the local folder if it isn't there yet, so the upload
    below picks it up like any other file and GitHub actually builds the APK after the push."""
    wf_path = root / WORKFLOW_PATH
    if wf_path.exists():
        log(f"{WORKFLOW_PATH} already present - using the project's own build workflow as-is.")
        return
    wf_path.parent.mkdir(parents=True, exist_ok=True)
    wf_path.write_text(WORKFLOW_YAML, encoding="utf-8")
    log(f"Added {WORKFLOW_PATH} - GitHub Actions will build the APK on every push from now on.")


def load_cfg() -> dict:
    try:
        return json.loads(CFG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_cfg(d: dict) -> None:
    try:
        CFG_PATH.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


class GitHubClient:
    def __init__(self, token: str):
        self.s = requests.Session()
        self.s.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })

    def whoami(self) -> str:
        r = self.s.get(f"{API}/user", timeout=20)
        r.raise_for_status()
        return r.json()["login"]

    def repo_exists(self, owner, repo) -> bool:
        r = self.s.get(f"{API}/repos/{owner}/{repo}", timeout=20)
        return r.status_code == 200

    def create_repo(self, name, private, description):
        r = self.s.post(f"{API}/user/repos", timeout=30, json={
            "name": name, "private": private, "description": description, "auto_init": True,
        })
        r.raise_for_status()
        return r.json()

    def get_file_sha(self, owner, repo, path, branch):
        r = self.s.get(f"{API}/repos/{owner}/{repo}/contents/{path}", params={"ref": branch}, timeout=20)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, dict):
                return data.get("sha")
        return None

    def put_file(self, owner, repo, path, content_bytes, branch, message, sha=None):
        body = {
            "message": message,
            "content": base64.b64encode(content_bytes).decode("ascii"),
            "branch": branch,
        }
        if sha:
            body["sha"] = sha
        r = self.s.put(f"{API}/repos/{owner}/{repo}/contents/{path}", timeout=60, json=body)
        if r.status_code not in (200, 201):
            raise RuntimeError(f"{path}: HTTP {r.status_code} {r.text[:200]}")
        return r.json()


def iter_folder_files(root: Path, skip_dirs: set):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs and d != ".git"]
        for fn in filenames:
            p = Path(dirpath) / fn
            yield p, p.relative_to(root).as_posix()


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Aminium - GitHub Uploader")
        self.geometry("600x600")
        self.resizable(False, False)
        self.cfg = load_cfg()
        self.owner = ""  # filled in once the token is verified - this IS the "repo owner", automatically
        self._build_ui()

    def _row(self, parent, label, show=None, default=""):
        f = ttk.Frame(parent)
        f.pack(fill="x", pady=4)
        ttk.Label(f, text=label, width=16).pack(side="left")
        e = ttk.Entry(f, show=show)
        e.insert(0, default)
        e.pack(side="left", fill="x", expand=True)
        return e

    def open_token_page(self):
        webbrowser.open(TOKEN_PAGE)
        self.log("Opened GitHub's 'New personal access token' page in your browser. "
                  "Create it with the 'repo' scope, then paste it back here.")

    def _build_ui(self):
        pad = {"padx": 14, "pady": 6}
        top = ttk.Frame(self)
        top.pack(fill="both", expand=True, **pad)

        ttk.Label(top, text="GitHub auto-uploader", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        ttk.Label(top, text="Uploads every file in a folder to a GitHub repo - creates the repo for you if needed.",
                  foreground="#555", wraplength=560, justify="left").pack(anchor="w", pady=(0, 8))

        f = ttk.Frame(top)
        f.pack(fill="x", pady=4)
        ttk.Label(f, text="Access token", width=16).pack(side="left")
        self.e_token = ttk.Entry(f, show="*")
        self.e_token.insert(0, self.cfg.get("token", ""))
        self.e_token.pack(side="left", fill="x", expand=True)
        ttk.Button(f, text="Get API token", command=self.open_token_page).pack(side="left", padx=(6, 0))

        f2 = ttk.Frame(top)
        f2.pack(fill="x", pady=4)
        ttk.Label(f2, text="GitHub account", width=16).pack(side="left")
        self.lbl_owner = ttk.Label(f2, text="(not verified yet)", foreground="#777")
        self.lbl_owner.pack(side="left", fill="x", expand=True)
        ttk.Button(f2, text="Verify token", command=self.on_verify).pack(side="left")

        self.e_repo = self._row(top, "Repo name", default=self.cfg.get("repo", ""))

        f = ttk.Frame(top)
        f.pack(fill="x", pady=4)
        ttk.Label(f, text="Folder to upload", width=16).pack(side="left")
        self.e_folder = ttk.Entry(f)
        self.e_folder.insert(0, self.cfg.get("last_folder", ""))
        self.e_folder.pack(side="left", fill="x", expand=True)
        ttk.Button(f, text="Browse", command=self.pick_folder).pack(side="left", padx=(6, 0))

        self.v_private = tk.BooleanVar(value=bool(self.cfg.get("private", False)))
        ttk.Checkbutton(top, text="Create the repo as private (only matters the first time it's created)",
                        variable=self.v_private).pack(anchor="w")
        self.v_skip = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Skip build/cache folders (.git, __pycache__, .buildozer, bin, venv ...)",
                        variable=self.v_skip).pack(anchor="w")
        self.v_remember = tk.BooleanVar(value=bool(self.cfg.get("remember", False)))
        ttk.Checkbutton(top, text="Remember these settings on this PC (saves the token locally)",
                        variable=self.v_remember).pack(anchor="w", pady=(0, 10))

        row = ttk.Frame(top)
        row.pack(fill="x")
        self.btn_upload = ttk.Button(row, text="Upload folder to GitHub", command=self.on_upload)
        self.btn_upload.pack(side="left")

        self.progress = ttk.Progressbar(top, mode="determinate")
        self.progress.pack(fill="x", pady=(10, 4))

        ttk.Label(top, text="Log", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(6, 0))
        self.log_box = tk.Text(top, height=14, state="disabled", bg="#0d1330", fg="#cfd6ff")
        self.log_box.pack(fill="both", expand=True)

    def pick_folder(self):
        p = filedialog.askdirectory()
        if p:
            self.e_folder.delete(0, "end")
            self.e_folder.insert(0, p)
            if not self.e_repo.get().strip():
                self.e_repo.insert(0, Path(p).name.lower().replace(" ", "-"))

    def log(self, msg):
        def ui():
            self.log_box.configure(state="normal")
            self.log_box.insert("end", str(msg) + "\n")
            self.log_box.see("end")
            self.log_box.configure(state="disabled")
        self.after(0, ui)

    def _save_if_wanted(self):
        if self.v_remember.get():
            save_cfg({
                "token": self.e_token.get().strip(), "repo": self.e_repo.get().strip(),
                "last_folder": self.e_folder.get().strip(), "private": self.v_private.get(),
                "remember": True,
            })
        else:
            save_cfg({"remember": False})

    def on_verify(self):
        token = self.e_token.get().strip()
        if not token:
            return messagebox.showwarning("Missing token", "Paste your GitHub access token first.")

        def work():
            try:
                gh = GitHubClient(token)
                who = gh.whoami()
                self.owner = who
                self.after(0, lambda: self.lbl_owner.configure(text=who, foreground="#2a8f4a"))
                self.log(f"Token OK - signed in as {who}. Repos will be created/updated under this account.")
            except Exception as e:
                self.after(0, lambda: self.lbl_owner.configure(text="(verification failed)", foreground="#b33"))
                self.log(f"Token check failed: {e}")
        threading.Thread(target=work, daemon=True).start()

    def on_upload(self):
        token = self.e_token.get().strip()
        repo = self.e_repo.get().strip()
        folder = self.e_folder.get().strip()
        if not (token and repo and folder):
            return messagebox.showwarning("Missing info", "Token, repo name and a folder are all required.")
        if not os.path.isdir(folder):
            return messagebox.showerror("Folder not found", folder)
        self._save_if_wanted()
        self.btn_upload.configure(state="disabled")
        self.progress["value"] = 0

        def work():
            try:
                gh = GitHubClient(token)
                owner = self.owner or gh.whoami()
                self.owner = owner
                self.after(0, lambda: self.lbl_owner.configure(text=owner, foreground="#2a8f4a"))
                self.log(f"Signed in as {owner}.")

                if gh.repo_exists(owner, repo):
                    self.log(f"Repo '{owner}/{repo}' already exists - uploading into it.")
                else:
                    self.log(f"Repo '{owner}/{repo}' does not exist yet - creating it automatically...")
                    gh.create_repo(repo, self.v_private.get(), "Uploaded by Aminium GitHub Uploader")
                    self.log("Repo created.")

                root = Path(folder)
                ensure_workflow_file(root, self.log)
                skip = SKIP_DIRS if self.v_skip.get() else set()
                files = list(iter_folder_files(root, skip))
                total = len(files)
                self.log(f"{total} file(s) to upload from {root}")
                self.after(0, lambda: self.progress.configure(maximum=max(1, total)))

                done = skipped = failed = 0
                for i, (full_path, rel_path) in enumerate(files, 1):
                    size_mb = full_path.stat().st_size / (1024 * 1024)
                    if size_mb > MAX_FILE_MB:
                        self.log(f"[skip] {rel_path} is {size_mb:.1f} MB (over the {MAX_FILE_MB} MB limit for this API)")
                        skipped += 1
                        self.after(0, lambda i=i: self.progress.configure(value=i))
                        continue
                    try:
                        content = full_path.read_bytes()
                        sha = gh.get_file_sha(owner, repo, rel_path, "main")
                        gh.put_file(owner, repo, rel_path, content, "main", f"Upload {rel_path}", sha=sha)
                        done += 1
                        self.log(f"[ok]   {rel_path}")
                    except Exception as e:
                        failed += 1
                        self.log(f"[fail] {rel_path}: {e}")
                    self.after(0, lambda i=i: self.progress.configure(value=i))

                self.log(f"Done: {done} uploaded, {skipped} skipped (too large), {failed} failed, out of {total}.")
                actions_url = f"https://github.com/{owner}/{repo}/actions"
                self.log(f"GitHub Actions should now be building the APK: {actions_url}")
                self.log("It takes a few minutes the first time (downloading the Android SDK/NDK). "
                          "When it finishes, the APK is attached to a new Release in that repo, and also "
                          "downloadable from the workflow run itself as an artifact.")
                self.after(0, lambda: webbrowser.open(actions_url))
                self.after(0, lambda: messagebox.showinfo(
                    "Done", f"Uploaded {done}/{total} file(s) to {owner}/{repo}.\n"
                            "GitHub Actions is now building the Android APK - its Actions tab just opened in your browser."
                    + (f"\n{failed} file(s) failed - see the log." if failed else "")))
            except Exception as e:
                self.log(f"ERROR: {e}")
                self.after(0, lambda: messagebox.showerror("Upload failed", str(e)))
            finally:
                self.after(0, lambda: self.btn_upload.configure(state="normal"))
        threading.Thread(target=work, daemon=True).start()


if __name__ == "__main__":
    App().mainloop()
