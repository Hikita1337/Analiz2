import os, re, json, zipfile, hashlib, subprocess, sys
from pathlib import Path
from datetime import datetime

# ---------------- DEPENDENCIES ----------------
try:
    from tqdm import tqdm
except ImportError:
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
FILES_TO_PROCESS = ["WS_STREAM.log", "RAW.zip", "DECODED.zip", "bigdump.txt"]
GIT_COMMIT_MSG = "WS PF-автоотчёт"

BASE64_LIMIT = 100
HEX_LIMIT = 100

# ---------------- HELPERS ----------------
def read_file(path):
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read()
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

def save_json(data, name):
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    file_path = REPORT_DIR / f"{name}_{ts}.json"
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return file_path

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

# ---------------- PARSE ----------------
def parse_texts(texts):
    seen_hashes = set()
    unique_texts = []

    for t in tqdm(texts, desc="Удаляем дубликаты"):
        h = hash_text(t)
        if h not in seen_hashes:
            seen_hashes.add(h)
            unique_texts.append(t)
    return unique_texts

def extract_base64(texts, limit=BASE64_LIMIT):
    b64_regex = r'(?:[A-Za-z0-9+/]{20,}={0,2})'
    found = []
    for t in texts:
        found.extend(re.findall(b64_regex, t))
    unique_found = list(dict.fromkeys(found))[:limit]
    decoded = []
    for chunk in tqdm(unique_found, desc="Base64 декодирование"):
        try:
            val = base64.b64decode(chunk).decode("utf-8", errors="ignore")
            if val.strip():
                decoded.append({"encoded": chunk, "decoded": val})
        except: pass
    return decoded

def extract_hex(texts, limit=HEX_LIMIT):
    hex_regex = r'(?:[0-9a-fA-F]{2}){8,}'
    found = []
    for t in texts:
        found.extend(re.findall(hex_regex, t))
    unique_found = list(dict.fromkeys(found))[:limit]
    decoded = []
    for h in tqdm(unique_found, desc="HEX декодирование"):
        try:
            val = bytes.fromhex(h).decode("utf-8", errors="ignore")
            if val.strip():
                decoded.append({"hex": h, "decoded": val})
        except: pass
    return decoded

def pf_predictive_analysis(texts):
    result = {
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

    for text in tqdm(texts, desc="PF анализ"):
        seen_round_end = any(x in text.lower() for x in ["end","finish","round_end","complete"])
        for val in crash_pattern.findall(text):
            try:
                fval = float(val)
                if fval > 1.0 and not seen_round_end:
                    result["early_crash"].append({"value": fval, "payload": text[:500]})
            except: pass
        for hval in hash_pattern.findall(text):
            if not seen_round_end:
                result["early_hash"].append({"hash": hval, "payload": text[:500]})
        candidates = hexlike_pattern.findall(text) + base64_pattern.findall(text)
        for c in candidates:
            L = len(c)
            if not seen_round_end:
                if 8 <= L <= 32: result["early_salt"].append({"salt": c, "payload": text[:500]})
                if 32 < L <= 64: result["early_seed"].append({"seed": c, "payload": text[:500]})
                if L > 64: result["early_serverSeed"].append({"serverSeed": c, "payload": text[:500]})
    return result

# ---------------- MAIN ----------------
def main():
    all_texts = []

    for path in FILES_TO_PROCESS:
        if path.endswith(".zip"):
            all_texts.extend(extract_zip(path))
        else:
            all_texts.append(read_file(path))

    all_texts = parse_texts(all_texts)

    base64_data = extract_base64(all_texts)
    hex_data = extract_hex(all_texts)
    pf_data = pf_predictive_analysis(all_texts)

    # Сохраняем JSON по блокам
    json_files = []
    json_files.append(git_lfs_push(save_json(base64_data, "base64")))
    json_files.append(git_lfs_push(save_json(hex_data, "hex")))
    json_files.append(git_lfs_push(save_json(pf_data, "pf_predictive_analysis")))
    json_files.append(git_lfs_push(save_json(all_texts, "ws_raw_unique")))

if __name__=="__main__":
    main()