"""Burrow Python Web API wrapper (Proxies to Go Backend)"""
import os
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx

def create_app(config=None) -> FastAPI:
    app = FastAPI(title="Burrow MCP API Wrapper", version="1.0.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    GO_API_URL = os.getenv("BURROW_API_URL", "http://127.0.0.1:8080")
    GO_API_TOKEN = os.getenv("BURROW_API_TOKEN", "")

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def proxy_to_go(path: str, request: Request):
        url = f"{GO_API_URL}/{path}"
        headers = dict(request.headers)
        headers.pop("host", None)
        
        if GO_API_TOKEN:
            headers["Authorization"] = f"Bearer {GO_API_TOKEN}"

        async with httpx.AsyncClient() as client:
            try:
                body = await request.body()
                req = client.build_request(
                    method=request.method,
                    url=url,
                    headers=headers,
                    content=body,
                    params=request.query_params
                )
                response = await client.send(req, stream=True)
                
                async def stream_generator():
                    async for chunk in response.aiter_bytes():
                        yield chunk
                        
                # Forward the response from the Go backend, dropping chunking headers
                resp_headers = {k: v for k, v in response.headers.items() if k.lower() not in ("content-length", "content-encoding", "transfer-encoding")}
                return StreamingResponse(
                    stream_generator(), 
                    status_code=response.status_code, 
                    headers=resp_headers
                )
            except httpx.RequestError as exc:
                raise HTTPException(status_code=502, detail=f"Go backend unreachable at {GO_API_URL}: {exc}")

    return app
