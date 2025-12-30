"""Streamlit UI for Secure Mail Triage.

Usage notes:
- Manual input only (no Gmail ingestion).
- Uses a fixed model and requires OPENAI_API_KEY in the environment.
"""
from __future__ import annotations

import os
import sys

import streamlit as st

if __package__ is None:  # Allow running via `streamlit run secure_mail_triage/ui_app.py`.
    repo_root = os.path.dirname(os.path.dirname(__file__))
    sys.path.append(repo_root)

from secure_mail_triage.agents import Email
from secure_mail_triage.pipeline import create_llm_pipeline
from secure_mail_triage.storage import fetch_recent_results, save_result

FIXED_MODEL = "gpt-4o-mini"  # Single model used by the UI.


def _build_pipeline():
    return create_llm_pipeline(model=FIXED_MODEL)


def _render_result(result):
    st.subheader("Classification")
    st.json(
        {
            "verdict": result.features.get("verdict"),
            "risk_score": result.features.get("risk_score"),
            "rationale": result.features.get("rationale", []),
            "warnings": result.warnings,
        }
    )


def main() -> None:
    st.set_page_config(page_title="Secure Mail Triage", page_icon=":shield:")
    st.title("Secure Mail Triage")

    with st.sidebar:
        st.header("Settings")
        st.text_input("OpenAI model", value=FIXED_MODEL, disabled=True)
        if not os.getenv("OPENAI_API_KEY"):
            st.warning("OPENAI_API_KEY is not set in the environment.")
        db_path = st.text_input("SQLite DB path", value="triage.db")
        store_results = st.checkbox("Store results in DB", value=True)

    st.header("Classify Email")
    subject = st.text_input("Subject")
    sender = st.text_input("Sender")
    recipients_input = st.text_input("Recipients (comma-separated)")
    body = st.text_area("Body", height=200)

    if st.button("Classify"):
        recipients = [r.strip() for r in recipients_input.split(",") if r.strip()]
        email = Email(subject=subject, body=body, sender=sender, recipients=recipients)
        try:
            if not os.getenv("OPENAI_API_KEY"):
                raise ValueError("OPENAI_API_KEY is not set. Set it in your environment.")
            pipeline = _build_pipeline()
            classification, details = pipeline.run_with_details(email)
            _render_result(classification)
            if store_results:
                save_result(
                    db_path=db_path,
                    source="ui",
                    message_id=None,
                    thread_id=None,
                    email=email,
                    classification=classification,
                    details=details,
                )
        except Exception as exc:
            st.error(f"Classification failed: {exc}")

    st.header("Recent Results")
    if st.button("Refresh"):
        results = fetch_recent_results(db_path, limit=25)
        if results:
            st.dataframe(results, use_container_width=True)
        else:
            st.info("No results found.")


if __name__ == "__main__":
    main()
