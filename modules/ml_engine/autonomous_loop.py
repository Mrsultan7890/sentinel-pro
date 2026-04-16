"""
Autonomous Learning Loop — Sentinel ML Engine
Yeh daemon background mein chalta rehta hai aur:
  1. Har SCHEDULE_INTERVAL seconds mein check karta hai ki retrain karna chahiye
  2. Drift detect karta hai — agar F1 gir raha hai toh alert karta hai
  3. Scheduled full retrain karta hai (default: har 24 ghante)
  4. CRL se naya data crawl karta hai agar data stale ho

Usage (main.py startup mein):
    from modules.ml_engine.autonomous_loop import AutonomousLearningLoop
    loop = AutonomousLearningLoop()
    loop.start()          # background daemon thread start
    loop.stop()           # graceful shutdown
"""

import json
import logging
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).resolve().parents[2] / 'models' / 'ml_engine'
DATA_DIR   = MODELS_DIR / 'training_data'
LOOP_STATE_FILE = DATA_DIR / 'autonomous_loop_state.json'

# Config
CHECK_INTERVAL      = 300    # har 5 min mein check karo
SCHEDULED_RETRAIN   = 86400  # har 24 ghante full retrain
DRIFT_CHECK_EVERY   = 3600   # har 1 ghante drift check
MIN_SAMPLES_FOR_CRL = 20     # agar itne se kam samples hain toh CRL crawl karo

# Global busy flag — RL ya brain chal raha ho to retrain mat karo
_BUSY = False

def set_busy(val: bool):
    global _BUSY
    _BUSY = val


class AutonomousLearningLoop:
    """
    Background daemon jo ML models ko autonomously improve karta rehta hai.

    Flow:
        Start
          ↓
        Har 5 min: pending samples check
          ↓ (agar >= threshold)
        Background retrain trigger
          ↓
        Har 1 ghante: drift check
          ↓ (agar drift detected)
        Alert log + aggressive retrain
          ↓
        Har 24 ghante: scheduled full retrain + CRL crawl
    """

    def __init__(self):
        self._stop_event  = threading.Event()
        self._thread      = None
        self._last_scheduled_retrain = self._load_state().get('last_scheduled_retrain', 0)
        self._last_drift_check       = 0

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Background daemon thread start karo."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop,
            daemon=True,
            name='sentinel-autonomous-loop'
        )
        self._thread.start()
        logger.info("Autonomous learning loop started")

    def stop(self) -> None:
        """Graceful shutdown."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("Autonomous learning loop stopped")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ── Main Loop ──────────────────────────────────────────────────────────────

    def _loop(self) -> None:
        """Main daemon loop."""
        logger.info("Autonomous loop running...")
        while not self._stop_event.is_set():
            try:
                now = time.time()

                # Busy check — RL ya brain chal raha ho to skip
                if _BUSY:
                    logger.debug("Autonomous loop: system busy — skipping")
                    self._stop_event.wait(timeout=CHECK_INTERVAL)
                    continue

                # 1. Pending samples check → background retrain
                self._check_and_retrain()

                # 2. Drift check (har 1 ghante)
                if now - self._last_drift_check >= DRIFT_CHECK_EVERY:
                    self._check_drift()
                    self._last_drift_check = now

                # 3. Scheduled full retrain (har 24 ghante)
                if now - self._last_scheduled_retrain >= SCHEDULED_RETRAIN:
                    self._scheduled_full_retrain()
                    self._last_scheduled_retrain = now
                    self._save_state()

            except Exception as e:
                logger.debug(f"Autonomous loop error: {e}")

            self._stop_event.wait(timeout=CHECK_INTERVAL)

    # ── Tasks ──────────────────────────────────────────────────────────────────

    def _check_and_retrain(self) -> None:
        """Pending samples check karo aur zaroorat ho toh background retrain trigger karo."""
        try:
            from modules.ml_engine.trainer import ModelTrainer
            if ModelTrainer.should_retrain():
                pending = ModelTrainer.pending_samples()
                logger.info(f"Autonomous: {pending} pending samples — triggering background retrain")
                ModelTrainer.auto_retrain_background()
        except Exception as e:
            logger.debug(f"_check_and_retrain error: {e}")

    def _check_drift(self) -> None:
        """Drift detect karo. Agar drift hai toh log karo aur aggressive retrain trigger karo."""
        try:
            from modules.ml_engine.trainer import ModelTrainer
            drift = ModelTrainer.detect_drift()
            if drift.get('drift_detected'):
                logger.warning(f"Model drift detected: {drift['flags']}")
                # Drift pe immediate retrain — threshold ignore karo
                self._force_retrain(reason='drift_detected')
            else:
                logger.debug("Drift check: no drift detected")
        except Exception as e:
            logger.debug(f"_check_drift error: {e}")

    def _scheduled_full_retrain(self) -> None:
        logger.info("Autonomous: scheduled 24h full retrain starting...")
        try:
            from modules.ml_engine.trainer import ModelTrainer
            trainer = ModelTrainer()

            # Best available data load karo
            import json as _json
            from pathlib import Path as _Path
            DATA_DIR_PATH = _Path('/home/kali/osints/models/ml_engine/training_data')
            LABEL_MAP = {'CRITICAL':'CRITICAL','HIGH':'HIGH','MEDIUM':'MEDIUM',
                         'MODERATE':'MEDIUM','LOW':'LOW'}

            best_files = [
                'threat_master_balanced.jsonl',
                'linux_kali_dataset.jsonl',
                'github_threat_data.jsonl',
                'threat_v4_clean.jsonl',
            ]
            all_samples = []
            seen = set()
            # CPU pe fast rehne ke liye max 15K samples
            MAX_AUTO = 15000
            for fname in best_files:
                fpath = DATA_DIR_PATH / fname
                if not fpath.exists():
                    continue
                count = 0
                with open(fpath, encoding='utf-8', errors='replace') as f:
                    for line in f:
                        if len(all_samples) >= MAX_AUTO:
                            break
                        try:
                            d = _json.loads(line.strip())
                            text  = str(d.get('text') or d.get('content') or '').strip()
                            label = LABEL_MAP.get(str(d.get('label','')).upper(), '')
                            if not text or not label or len(text) < 20:
                                continue
                            key = text[:80]
                            if key in seen:
                                continue
                            seen.add(key)
                            all_samples.append({'text': text[:1500], 'label': label})
                            count += 1
                        except Exception:
                            continue
                logger.info(f"Autonomous retrain: {fname} +{count}")

            if len(all_samples) < 100:
                logger.warning("Autonomous: not enough data for retrain")
                return

            trainer._threat_data = all_samples
            trainer._inject_synthetic_samples()
            trainer.merge_scan_data()

            results = trainer.train_all()
            report  = trainer.evaluate()
            trainer.save_all()
            ModelTrainer._log_performance(report, trigger='scheduled_24h')
            logger.info(f"Autonomous: retrain complete on {len(all_samples)} samples — {results}")

        except Exception as e:
            logger.warning(f"Scheduled retrain error: {e}")

    def _force_retrain(self, reason: str = 'manual') -> None:
        """Force retrain — threshold ignore karo."""
        def _run():
            try:
                from modules.ml_engine.trainer import ModelTrainer
                trainer = ModelTrainer()
                trainer.merge_scan_data()
                trainer._load_raw_data()
                trainer._inject_synthetic_samples()
                trainer.train_all()
                report = trainer.evaluate()
                trainer.save_all()
                ModelTrainer._log_performance(report, trigger=reason)
                logger.info(f"Force retrain complete (reason={reason})")
            except Exception as e:
                logger.debug(f"Force retrain error: {e}")
        threading.Thread(target=_run, daemon=True, name='sentinel-force-retrain').start()

    # ── State Persistence ──────────────────────────────────────────────────────

    def _save_state(self) -> None:
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            with open(LOOP_STATE_FILE, 'w') as f:
                json.dump({
                    'last_scheduled_retrain': self._last_scheduled_retrain,
                    'updated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                }, f)
        except Exception:
            pass

    def _load_state(self) -> dict:
        try:
            if LOOP_STATE_FILE.exists():
                with open(LOOP_STATE_FILE) as f:
                    return json.load(f)
        except Exception:
            pass
        return {}
