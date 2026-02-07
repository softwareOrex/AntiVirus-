import hashlib
import json
import os
import shutil
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_NAME = "PyAV (учебный)"
DB_FILE = "signatures.json"
DEFAULT_QUARANTINE = "quarantine"
LOG_FILE = "scan_log.txt"

SUSPICIOUS_EXT = {".exe", ".dll", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".jar"}
SUSPICIOUS_DIR_PARTS = {"temp", "appdata", "roaming", "startup", "downloads"}

CHUNK = 1024 * 1024  # 1MB


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def safe_rel(p: Path) -> str:
    try:
        return str(p.resolve())
    except Exception:
        return str(p)


def load_db(db_path: Path) -> dict:
    if not db_path.exists():
        # Пустая база по умолчанию
        return {
            "version": 1,
            "updated": now_str(),
            "sha256": [
                # Пример: добавляй сюда хэши тестовых "вредоносов"
                # "0123abcd...": "EICAR-like test"
            ],
        }
    with db_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_db(db_path: Path, db: dict):
    db["updated"] = now_str()
    with db_path.open("w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)


@dataclass
class Finding:
    path: Path
    reason: str
    severity: str  # "high"/"medium"/"low"


class Scanner:
    def __init__(self, signatures: dict, quarantine_dir: Path, log_path: Path, ui_cb=None):
        self.signatures = signatures
        self.quarantine_dir = quarantine_dir
        self.log_path = log_path
        self.ui_cb = ui_cb

        self._stop = False
        self.scanned = 0
        self.flagged = 0

    def stop(self):
        self._stop = True

    def log(self, line: str):
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(f"[{now_str()}] {line}\n")

    def heuristic(self, path: Path) -> list[Finding]:
        findings = []
        ext = path.suffix.lower()

        # Подозрительное расширение
        if ext in SUSPICIOUS_EXT:
            findings.append(Finding(path, f"Подозрительное расширение: {ext}", "low"))

        # Подозрительный путь
        parts = {p.lower() for p in path.parts}
        if any(x in parts for x in SUSPICIOUS_DIR_PARTS):
            findings.append(Finding(path, "Файл в потенциально рискованной директории", "low"))

        # Очень большой исполняемый в Temp/Downloads — чуть более “средне”
        try:
            size = path.stat().st_size
            if size > 50 * 1024 * 1024 and ext in {".exe", ".dll"} and any(x in parts for x in {"temp", "downloads"}):
                findings.append(Finding(path, "Крупный исполняемый файл в Temp/Downloads", "medium"))
        except Exception:
            pass

        return findings

    def signature_check(self, path: Path) -> Finding | None:
        try:
            h = sha256_file(path)
        except Exception as e:
            self.log(f"Не удалось прочитать {safe_rel(path)}: {e}")
            return None

        sig_db = self.signatures.get("sha256", [])
        # Поддержим формат как список или как dict
        if isinstance(sig_db, dict):
            if h in sig_db:
                return Finding(path, f"Сигнатура совпала (SHA256): {sig_db[h]}", "high")
        else:
            if h in set(sig_db):
                return Finding(path, "Сигнатура совпала (SHA256)", "high")
        return None

    def scan_path(self, target: Path, do_signatures=True, do_heuristics=True) -> list[Finding]:
        findings: list[Finding] = []
        self._stop = False
        self.scanned = 0
        self.flagged = 0

        def walk_files(p: Path):
            if p.is_file():
                yield p
                return
            for root, _, files in os.walk(p):
                if self._stop:
                    return
                for name in files:
                    yield Path(root) / name

        for f in walk_files(target):
            if self._stop:
                break

            self.scanned += 1
            if self.ui_cb:
                self.ui_cb(status=f"Сканирую: {safe_rel(f)}", scanned=self.scanned, flagged=self.flagged)

            # подписи
            if do_signatures:
                hit = self.signature_check(f)
                if hit:
                    findings.append(hit)
                    self.flagged += 1
                    self.log(f"ALERT(HIGH) {safe_rel(f)} :: {hit.reason}")

            # эвристика (не дублируем high, но всё равно можно)
            if do_heuristics:
                hs = self.heuristic(f)
                for h in hs:
                    findings.append(h)
                    self.flagged += 1
                    self.log(f"ALERT({h.severity.upper()}) {safe_rel(f)} :: {h.reason}")

        if self.ui_cb:
            self.ui_cb(status="Готово.", scanned=self.scanned, flagged=self.flagged)

        return findings

    def quarantine(self, item: Path) -> Path:
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest = self.quarantine_dir / f"{item.name}.{stamp}.q"
        shutil.move(str(item), str(dest))
        self.log(f"QUARANTINE {safe_rel(item)} -> {safe_rel(dest)}")
        return dest


class App(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        master.title(APP_NAME)
        master.geometry("880x560")
        self.pack(fill="both", expand=True)

        self.base_dir = Path(getattr(sys, "_MEIPASS", Path.cwd()))
        self.db_path = Path.cwd() / DB_FILE
        self.log_path = Path.cwd() / LOG_FILE
        self.quarantine_dir = Path.cwd() / DEFAULT_QUARANTINE

        self.db = load_db(self.db_path)

        self._scanner = None
        self._scan_thread = None

        self._build_ui()

    def _build_ui(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=10)

        ttk.Label(top, text="Цель:").pack(side="left")
        self.target_var = tk.StringVar(value=str(Path.home()))
        ttk.Entry(top, textvariable=self.target_var, width=60).pack(side="left", padx=8)

        ttk.Button(top, text="Файл…", command=self.pick_file).pack(side="left")
        ttk.Button(top, text="Папка…", command=self.pick_dir).pack(side="left", padx=(6, 0))

        opts = ttk.Frame(self)
        opts.pack(fill="x", padx=10)

        self.sig_var = tk.BooleanVar(value=True)
        self.heu_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text="Сигнатуры (SHA256)", variable=self.sig_var).pack(side="left")
        ttk.Checkbutton(opts, text="Эвристика (простая)", variable=self.heu_var).pack(side="left", padx=12)

        ttk.Label(opts, text=f"База: {DB_FILE} (обновлено: {self.db.get('updated','—')})").pack(side="right")

        btns = ttk.Frame(self)
        btns.pack(fill="x", padx=10, pady=10)

        self.scan_btn = ttk.Button(btns, text="Сканировать", command=self.start_scan)
        self.scan_btn.pack(side="left")

        self.stop_btn = ttk.Button(btns, text="Стоп", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=8)

        ttk.Button(btns, text="Добавить хэш в базу…", command=self.add_hash).pack(side="left", padx=8)
        ttk.Button(btns, text="Открыть карантин", command=self.open_quarantine).pack(side="left", padx=8)
        ttk.Button(btns, text="Открыть лог", command=self.open_log).pack(side="left", padx=8)

        self.status_var = tk.StringVar(value="Готов.")
        self.count_var = tk.StringVar(value="Проверено: 0 | Найдено: 0")

        status = ttk.Frame(self)
        status.pack(fill="x", padx=10)
        ttk.Label(status, textvariable=self.status_var).pack(side="left")
        ttk.Label(status, textvariable=self.count_var).pack(side="right")

        self.tree = ttk.Treeview(self, columns=("severity", "reason", "path"), show="headings")
        self.tree.heading("severity", text="Уровень")
        self.tree.heading("reason", text="Причина")
        self.tree.heading("path", text="Путь")
        self.tree.column("severity", width=90, anchor="center")
        self.tree.column("reason", width=360)
        self.tree.column("path", width=380)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

        actions = ttk.Frame(self)
        actions.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(actions, text="В карантин выбранное", command=self.quarantine_selected).pack(side="left")
        ttk.Button(actions, text="Удалить выбранное", command=self.delete_selected).pack(side="left", padx=8)
        ttk.Button(actions, text="Очистить список", command=self.clear_results).pack(side="right")

    def pick_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.target_var.set(p)

    def pick_dir(self):
        p = filedialog.askdirectory()
        if p:
            self.target_var.set(p)

    def ui_update(self, status=None, scanned=None, flagged=None):
        if status is not None:
            self.status_var.set(status)
        if scanned is not None or flagged is not None:
            s = scanned if scanned is not None else 0
            f = flagged if flagged is not None else 0
            self.count_var.set(f"Проверено: {s} | Найдено: {f}")

    def clear_results(self):
        for i in self.tree.get_children():
            self.tree.delete(i)

    def start_scan(self):
        target = Path(self.target_var.get()).expanduser()
        if not target.exists():
            messagebox.showerror("Ошибка", "Цель не существует.")
            return

        self.clear_results()

        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.ui_update(status="Запуск…", scanned=0, flagged=0)

        self._scanner = Scanner(self.db, self.quarantine_dir, self.log_path, ui_cb=self.ui_update)

        def run():
            try:
                findings = self._scanner.scan_path(
                    target,
                    do_signatures=self.sig_var.get(),
                    do_heuristics=self.heu_var.get()
                )
                # показать результаты в UI
                def show():
                    for f in findings:
                        self.tree.insert("", "end", values=(f.severity, f.reason, safe_rel(f.path)))
                    messagebox.showinfo("Сканирование завершено", f"Готово.\nПроверено: {self._scanner.scanned}\nНайдено: {len(findings)}")
            except Exception as e:
                def show():
                    messagebox.showerror("Ошибка", str(e))
            finally:
                def done():
                    self.scan_btn.config(state="normal")
                    self.stop_btn.config(state="disabled")
                    self.ui_update(status="Готов.")
                self.after(0, done)
                if 'show' in locals():
                    self.after(0, show)

        self._scan_thread = threading.Thread(target=run, daemon=True)
        self._scan_thread.start()

    def stop_scan(self):
        if self._scanner:
            self._scanner.stop()
            self.ui_update(status="Остановка…")

    def _get_selected_paths(self) -> list[Path]:
        items = self.tree.selection()
        paths = []
        for it in items:
            vals = self.tree.item(it, "values")
            if len(vals) >= 3:
                paths.append(Path(vals[2]))
        return paths

    def quarantine_selected(self):
        paths = self._get_selected_paths()
        if not paths:
            messagebox.showwarning("Нет выбора", "Выбери строки в списке.")
            return
        if messagebox.askyesno("Карантин", f"Переместить в карантин {len(paths)} файл(ов)?"):
            moved = 0
            for p in paths:
                try:
                    if p.exists() and p.is_file():
                        self._scanner = self._scanner or Scanner(self.db, self.quarantine_dir, self.log_path)
                        self._scanner.quarantine(p)
                        moved += 1
                except Exception as e:
                    messagebox.showerror("Ошибка", f"{p}\n{e}")
            messagebox.showinfo("Готово", f"В карантин: {moved}")

    def delete_selected(self):
        paths = self._get_selected_paths()
        if not paths:
            messagebox.showwarning("Нет выбора", "Выбери строки в списке.")
            return
        if messagebox.askyesno("Удаление", f"Удалить безвозвратно {len(paths)} файл(ов)?"):
            deleted = 0
            for p in paths:
                try:
                    if p.exists() and p.is_file():
                        p.unlink()
                        deleted += 1
                        with self.log_path.open("a", encoding="utf-8") as f:
                            f.write(f"[{now_str()}] DELETE {safe_rel(p)}\n")
                except Exception as e:
                    messagebox.showerror("Ошибка", f"{p}\n{e}")
            messagebox.showinfo("Готово", f"Удалено: {deleted}")

    def add_hash(self):
        p = filedialog.askopenfilename(title="Выбери файл для добавления SHA256 в базу")
        if not p:
            return
        path = Path(p)
        try:
            h = sha256_file(path)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось посчитать хэш:\n{e}")
            return

        # Запишем в базу как dict с описанием
        if not isinstance(self.db.get("sha256", None), dict):
            self.db["sha256"] = {}
        desc = f"Added from {path.name}"
        self.db["sha256"][h] = desc
        save_db(self.db_path, self.db)
        messagebox.showinfo("Добавлено", f"SHA256:\n{h}\n\nЗаписано в {DB_FILE}")

    def open_quarantine(self):
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        path = str(self.quarantine_dir.resolve())
        self._open_path(path)

    def open_log(self):
        self.log_path.touch(exist_ok=True)
        self._open_path(str(self.log_path.resolve()))

    def _open_path(self, path: str):
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)  # type: ignore
            elif sys.platform == "darwin":
                os.system(f'open "{path}"')
            else:
                os.system(f'xdg-open "{path}"')
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))


def main():
    root = tk.Tk()
    try:
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
