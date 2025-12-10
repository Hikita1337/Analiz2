import json
from pathlib import Path
from collections import defaultdict, Counter

# ---------------- CONFIG ----------------
DATA_DIR = Path("deep_reports_processed")
OUTPUT_DIR = Path("deep_reports_advanced_analysis")
OUTPUT_DIR.mkdir(exist_ok=True)

FILES = {
    "base64": DATA_DIR / "base64_2025-12-10_09-19-04_unique_2025-12-10_09-56-47.json",
    "hex": DATA_DIR / "hex_2025-12-10_09-19-05_unique_2025-12-10_09-56-47.json",
    "pf": DATA_DIR / "pf_predictive_analysis_2025-12-10_09-19-05_unique_2025-12-10_09-56-49.json",
    "ws": DATA_DIR / "ws_raw_unique_2025-12-10_09-19-06_unique_2025-12-10_09-56-56.json"
}

# ---------------- HELPERS ----------------
def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def correlate_pf(ws_list, pf_events):
    correlation = defaultdict(list)
    for key, events in pf_events.items():
        for event in events:
            payload = event.get("payload", "")
            for idx, ws_msg in enumerate(ws_list):
                ws_text = str(ws_msg)
                if payload in ws_text:
                    correlation[key].append({"ws_index": idx, **event})
                    break
    return correlation

def analyze_sequences(ws_list):
    sequence_counts = Counter()
    for msg in ws_list:
        key = tuple(sorted((k, str(v)) for k, v in msg.items())) if isinstance(msg, dict) else (str(msg),)
        sequence_counts[key] += 1
    return sequence_counts

# ---------------- MAIN ----------------
def main():
    base64_data = load_json(FILES["base64"])
    hex_data = load_json(FILES["hex"])
    pf_data = load_json(FILES["pf"])
    ws_data = load_json(FILES["ws"])
    
    # Корреляция PF-событий с WS
    pf_correlation = correlate_pf(ws_data, pf_data)
    
    # Анализ повторяющихся последовательностей сообщений WS
    sequence_stats = analyze_sequences(ws_data)
    
    # Сбор продвинутого отчёта с хронологической картой PF
    report = {
        "pf_summary": {k: len(v) for k, v in pf_data.items()},
        "ws_total_messages": len(ws_data),
        "pf_correlation": pf_correlation,
        "ws_sequence_patterns": {str(list(k)): v for k, v in sequence_stats.items() if v > 1}
    }
    
    output_file = OUTPUT_DIR / "advanced_pf_ws_analysis.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"[INFO] Хронологический PF-анализ завершён. Результат сохранён: {output_file}")

if __name__ == "__main__":
    main()