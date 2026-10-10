"""Central configuration for the Rakshak-AI cyber-range prototype.

All values can be overridden through environment variables (see .env.example).
Nothing here reaches outside the local machine except OLLAMA_BASE_URL, which
must always point at a locally running Ollama instance.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent          # backend/app
BACKEND_DIR = BASE_DIR.parent                        # backend
REPO_DIR = BACKEND_DIR.parent                        # repo root
DATA_DIR = BASE_DIR / "data"
POLICY_DIR = BASE_DIR / "policy"
KNOWLEDGE_DIR = REPO_DIR / "knowledge"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(REPO_DIR / ".env", BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- App ---
    app_name: str = "Rakshak-AI: Mission-Aware Cyber Defence SOC"
    app_env: str = "development"
    ocsf_schema_version: str = "1.3.0"  # documented target, OCSF-compatible (not certified)

    # --- Database ---
    database_url: str = f"sqlite:///{BACKEND_DIR / 'rakshak.db'}"

    # --- Ollama (local only) ---
    enable_llm_analysis: bool = False   # Part 1 defaults to False (deterministic only)
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen2.5:7b-instruct"
    ollama_timeout_seconds: int = 60

    # --- Vector search / RAG ---
    embedding_model_path: str = ""      # empty => keyword fallback
    faiss_index_path: str = str(BACKEND_DIR / "faiss.index")

    # --- Analytics ---
    use_isolation_forest: bool = False  # deterministic feature score is the default
    anomaly_incident_threshold: float = 0.55

    # --- Server ---
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    @property
    def cors_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
