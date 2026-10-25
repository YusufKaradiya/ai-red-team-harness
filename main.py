
import os

from fastapi import FastAPI, HTTPException, Request
from datetime import datetime, timezone
from pydantic import AliasChoices, BaseModel, ConfigDict, Field
from starlette.responses import JSONResponse

from src.core.orchestrator import ScenarioRunner
from src.core.local_agent import LocalAgent
app = FastAPI(
    title="MAI-24 Red-Team Harness",
    description="Agentic AI Security Testing Platform",
    version="0.1.0",
)


@app.get("/")
def root():
    return {
        "project": "MAI-24",
        "message": "Red-Team Harness API",
        "status": "running",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "redteam-api",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

from pathlib import Path

from src.corpus.loader import CorpusError, load_corpus

CORPUS_PATH = (
    Path(__file__).resolve().parent
    / "data"
    / "corpus"
    / "scenarios.jsonl"
)
PROJECT_ROOT = Path(__file__).resolve().parent
AGENT_ROLE = os.getenv("REDTEAM_AGENT_ROLE", "viewer")
LOCAL_AGENT = LocalAgent(
    role=AGENT_ROLE,
    policy_path=PROJECT_ROOT / "configs" / "policies.json",
    tool_policy_path=(
        PROJECT_ROOT / "configs" / "tool_permissions.json"
    ),
    canary_path=PROJECT_ROOT / "data" / "synthetic_documents" / "canary.txt",
    audit_path=PROJECT_ROOT / "experiments" / "day13-agent-audit.jsonl",
)


class AgentChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=20_000)


@app.post("/agent/chat")
def agent_chat(request: AgentChatRequest):
    try:
        return LOCAL_AGENT.respond(request.message)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Local agent request failed",
        ) from exc


@app.get("/scenarios")
def list_scenarios(
    category: str | None = None,
    enabled_only: bool = True,
):
    try:
        scenarios = load_corpus(CORPUS_PATH)
    except CorpusError as exc:
        raise HTTPException(
            status_code=500,
            detail="Corpus validation failed"
        ) from exc

    if enabled_only:
        scenarios = [s for s in scenarios if s.enabled]

    if category:
        scenarios = [
            s for s in scenarios if s.category == category
        ]

    return {
        "count": len(scenarios),
        "scenarios": [
            s.model_dump(mode="json") for s in scenarios
        ]
    }


@app.get("/scenarios/{scenario_id}")
def get_scenario(scenario_id: str):
    try:
        scenarios = load_corpus(CORPUS_PATH)
    except CorpusError as exc:
        raise HTTPException(
            status_code=500,
            detail="Corpus validation failed"
        ) from exc

    for scenario in scenarios:
        if scenario.id == scenario_id:
            return scenario.model_dump(mode="json")

    raise HTTPException(
        status_code=404,
        detail="Scenario not found"
    )

class CampaignRequest(BaseModel):
    scenario_ids: list[str] | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "selected_ids",
            "scenario_ids",
        ),
    )


@app.post("/campaigns/run")
def run_campaign(request: CampaignRequest):
    runner = ScenarioRunner(
        corpus_path=CORPUS_PATH,
        results_path=(
            Path(__file__).resolve().parent
            / "experiments"
            / "results.jsonl"
        ),
        audit_path=(
            Path(
                os.getenv(
                    "REDTEAM_AUDIT_PATH",
                    Path(__file__).resolve().parent
                    / "experiments"
                    / "day9-audit.jsonl",
                )
            )
        ),
    )

    try:
        summary = runner.run_campaign(
            request.scenario_ids
        )

        trials = []
        for result in summary["results"]:
            observed = result.get("observed", {})
            if not isinstance(observed, dict):
                observed = {}

            simulator_version = result.get(
                "simulator_version", ""
            )
            mode = result.get("mode") or (
                "baseline"
                if simulator_version.startswith("Baseline-")
                else "unknown"
            )

            trials.append({
                **result,
                "mode": mode,
                "reason_code": observed.get(
                    "reason_code",
                    result.get("error_type", "UNKNOWN"),
                ),
                "pass": result.get("passed", False),
                "latency_ms": result.get("latency_ms"),
            })

        completed = summary["completed"]
        scenario_count = summary["scenario_count"]

        return {
            **summary,
            "mode": (
                trials[0]["mode"]
                if trials and all(
                    trial["mode"] == trials[0]["mode"]
                    for trial in trials
                )
                else "mixed"
            ),
            "completed_count": completed,
            "error_count": summary["errors"],
            "pass_count": summary["passed"],
            "execution_pass_rate": (
                completed / scenario_count
                if scenario_count
                else 0
            ),
            "result_match_rate": (
                summary["passed"] / completed
                if completed
                else 0
            ),
            "trials": trials,
        }
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc)
        ) from exc
    except Exception as exc:
        # Avoid exposing internal exception details.
        raise HTTPException(
            status_code=500,
            detail="Campaign execution failed"
        ) from exc

MAX_BODY_BYTES = 256 * 1024  # 256 KiB


@app.middleware("http")
async def request_size_limit(request: Request, call_next):
    content_length = request.headers.get("content-length")

    if content_length:
        try:
            size = int(content_length)
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid content length"}
            )

        if size < 0:
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid content length"}
            )

        if size > MAX_BODY_BYTES:
            return JSONResponse(
                status_code=413,
                content={"detail": "Request too large"}
            )

    body = await request.body()

    if len(body) > MAX_BODY_BYTES:
        return JSONResponse(
            status_code=413,
            content={"detail": "Request too large"}
        )

    return await call_next(request)
