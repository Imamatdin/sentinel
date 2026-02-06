"""Report export API endpoints.

Endpoints:
- GET /api/export/pdf   Generate and download PDF report
- GET /api/export/json  Download raw engagement data as JSON

These are registered in app.py as:
    app.include_router(export_router, prefix="/api/export", tags=["export"])

The export_routes need access to the EngagementManager to get the result.
The manager is stored on app.state by the app.py lifespan.
"""

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

router = APIRouter()


@router.get("/pdf")
async def download_pdf_report(request: Request):
    """Generate and download the pentest report as PDF.

    Requires a completed engagement. Generates the PDF on-the-fly
    from the stored EngagementResult + genome patterns.
    """
    manager = request.app.state.manager

    if not manager._result:
        raise HTTPException(
            status_code=404,
            detail="No engagement result available. Run an engagement first.",
        )

    result = manager._result

    # Load genome patterns for the report
    genome_patterns = None
    try:
        from sentinel.genome.database import GenomeDB
        db = GenomeDB()
        genome_patterns = db.search(limit=100)
    except Exception:
        pass  # Genome DB may not exist yet

    # Generate PDF
    from sentinel.reporting.pdf_generator import PDFReportGenerator
    generator = PDFReportGenerator()

    session_id = getattr(result, "target_url", "report").replace(
        "://", "_"
    ).replace("/", "_")
    output_path = f"/tmp/sentinel_report_{session_id}.pdf"

    actual_path = generator.generate(result, genome_patterns, output_path)

    media_type = (
        "application/pdf"
        if actual_path.endswith(".pdf")
        else "text/html"
    )

    return FileResponse(
        actual_path,
        media_type=media_type,
        filename=f"sentinel_report.{actual_path.split('.')[-1]}",
    )


@router.get("/json")
async def download_json_report(request: Request):
    """Download raw engagement data as JSON.

    Returns the full EngagementResult serialized as JSON, including
    all agent results, speed stats, and reports.
    """
    manager = request.app.state.manager

    if not manager._result:
        raise HTTPException(
            status_code=404,
            detail="No engagement result available. Run an engagement first.",
        )

    result = manager._result

    # Serialize EngagementResult
    data = {
        "success": result.success,
        "target_url": result.target_url,
        "duration": result.duration,
        "event_count": result.event_count,
        "speed_stats": result.speed_stats,
        "red_report": result.red_report,
        "blue_report": result.blue_report,
        "agents": {
            name: {
                "success": ar.success,
                "duration": ar.duration,
                "tool_calls_made": ar.tool_calls_made,
                "output_tokens": getattr(ar.metrics, "output_tokens", 0),
                "error": ar.error,
            }
            for name, ar in result.agent_results.items()
        },
    }

    return JSONResponse(content=data)
