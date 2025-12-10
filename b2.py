import os, re, json, zipfile, hashlib, subprocess, sys
from pathlib import Path
from datetime import datetime
from tqdm import tqdm

# ---------------- DEPENDENCIES ----------------
try:
    from tqdm import tqdm
except ImportError:
    import subprocess, sys
    subprocess.run([sys.executable, "-m", "pip", "install", "tqdm"], check=True)
    from tqdm import tqdm

# Проверка git-lfs
try:
    subprocess.run(["git", "lfs", "version"], check=True, stdout=subprocess.DEVNULL)
except subprocess.CalledProcessError:
    print("[INFO] Git LFS не найден, устанавливаем...")
    subprocess.run(["git", "lfs", "install"], check=True)

# ---------------- CONFIG ----------------
REPORT_DIR = Path("deep_reports"); REPORT_DIR.mkdir(exist_ok=True)
FILES_TO_PROCESS = ["WS_STREAM.log", "RAW.zip", "DECODED.zip"]
GIT_COMMIT_MSG = "WS автоматический PF-отчёт"

# ---------------- HELPERS ----------------
def read_file(path):
    try:
        with open(path, "r", errors="ignore") as f: return f.read()
    except Exception as e:
        print(f"[ERROR] Не удалось прочитать {path}: {e}")
        return ""

def extract_zip(zip_path):
    files_content = []
    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            for name in z.namelist():
                with z.open(name) as f:
                    text = f.read().decode("utf-8", errors="ignore")
                    files_content.append(text)
    except Exception as e:
        print(f"[ERROR] Не удалось распаковать {zip_path}: {e}")
    return files_content

def hash_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

# ---------------- PARSE WS ----------------
def parse_ws_messages(texts):
    seen_hashes = set()
    rounds = []
    pf_events = {
        "early_crash": [],
        "early_hash": [],
        "early_salt": [],
        "early_seed": [],
        "early_serverSeed": []
    }
    
    crash_pattern = re.compile(r'(\d+\.\d{1,4})')
    hash_pattern = re.compile(r'\b[a-f0-9]{64}\b')
    hexlike_pattern = re.compile(r'\b[a-f0-9]{16,}\b')
    base64_pattern = re.compile(r'[A-Za-z0-9+/]{16,}={0,2}')

    for text in tqdm(texts, desc="Анализ сообщений"):
        messages = re.findall(r'\{.*?\}', text, re.DOTALL)
        seen_round_end = False
        for m in messages:
            h = hash_text(m)
            if h not in seen_hashes:
                seen_hashes.add(h)
                try:
                    obj = json.loads(m)
                except:
                    continue
                rounds.append(obj)
                
                # ----- PF ANALYSIS -----
                if any(x in m.lower() for x in ["end","finish","round_end","complete"]):
                    seen_round_end = True
                # Early crash
                for val in crash_pattern.findall(m):
                    try:
                        fval = float(val)
                        if fval > 1.0 and not seen_round_end:
                            pf_events["early_crash"].append({"value": fval, "payload": m[:500]})
                    except: pass
                # Early hash
                for hval in hash_pattern.findall(m):
                    if not seen_round_end:
                        pf_events["early_hash"].append({"hash": hval, "payload": m[:500]})
                # Salt/Seed/ServerSeed
                candidates = hexlike_pattern.findall(m) + base64_pattern.findall(m)
                for c in candidates:
                    L = len(c)
                    if not seen_round_end:
                        if 8 <= L <= 32: pf_events["early_salt"].append({"salt": c, "payload": m[:500]})
                        if 32 < L <= 64: pf_events["early_seed"].append({"seed": c, "payload": m[:500]})
                        if L > 64: pf_events["early_serverSeed"].append({"serverSeed": c, "payload": m[:500]})
    return rounds, pf_events

# ---------------- SAVE JSON ----------------
def save_json(data, suffix="ws_rounds"):
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    file_path = REPORT_DIR / f"{suffix}_{ts}.json"
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return file_path

# ---------------- GIT LFS PUSH ----------------
def git_lfs_push(file_path):
    try:
        subprocess.run(["git", "lfs", "track", str(file_path)], check=True)
        subprocess.run(["git", "add", str(file_path)], check=True)
        subprocess.run(["git", "commit", "-m", GIT_COMMIT_MSG], check=True)
        subprocess.run(["git", "pull", "--rebase"], check=True)
        subprocess.run(["git", "push"], check=True)
        print(f"[*] Файл успешно запушен через Git LFS: {file_path}")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Git ошибка: {e}")

# ---------------- MAIN ----------------
def main():
    all_texts = []
    for path in FILES_TO_PROCESS:
        if path.endswith(".zip"):
            all_texts.extend(extract_zip(path))
        else:
            all_texts.append(read_file(path))
    
    rounds, pf_events = parse_ws_messages(all_texts)
    
    combined_report = {
        "rounds": rounds,
        "pf_predictive_analysis": pf_events
    }
    
    json_file = save_json(combined_report, suffix="ws_pf_report")
    git_lfs_push(json_file)

if __name__=="__main__":
    main()
