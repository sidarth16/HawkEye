
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import os
import uvicorn
from dotenv import load_dotenv

from slither.slither import Slither

from src.detectors import IVC, AC, ACM, MCO
from src.response.IVC_response import build_detector_response
from src.response.AC_response import build_access_control_response
from src.response.ACM_response import build_mint_access_response
from src.response.MCO_response import build_override_response

from src.response.merge_response import merge_scan_responses

app = FastAPI()
load_dotenv()
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")

# serve static files
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

def detect_vulns(chain: str, address: str) -> dict:

    print("detecting Vulns")
    prefix=''
    if chain=="arbitrum": prefix = 'arbi:'
    if chain=="base": prefix = 'base:'
    if chain=='optimism': prefix = 'optim:'

    try:
        sl = Slither(prefix + address, etherscan_api_key=ETHERSCAN_API_KEY)
    except Exception as e :
        print(e)
        raise(e)

    info_IV = IVC.run(sl)
    info_AC = AC.run(sl)
    info_ACM = ACM.run(sl)
    info_MCO = MCO.run(sl)

    return {"info_AC": info_AC, "info_IV": info_IV, "info_ACM": info_ACM, "info_MCO" : info_MCO}


# -------------------------------------------

class ScanRequest(BaseModel):
    chain: str
    address: str

@app.get("/", response_class=HTMLResponse)
async def homepage(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/scan")
async def api_scan(req: ScanRequest):
    # Input normalization / basic validation
    chain = req.chain.strip()
    address = req.address.strip()

    # call detector
    
    try:
        raw = detect_vulns(chain, address)
        info_AC = raw.get("info_AC", {}) 
        info_IV = raw.get("info_IV", {}) 
        info_ACM = raw.get("info_ACM", {}) 
        info_MCO = raw.get("info_MCO", {})


        response_IV = build_detector_response(req.chain, req.address, info_IV)
        response_AC = build_access_control_response(req.chain, req.address, info_AC )
        response_ACM = build_mint_access_response(req.chain, req.address, info_ACM)
        response_MCO = build_override_response(req.chain, req.address, info_MCO)

        merged_response = merge_scan_responses(response_IV, response_AC, response_ACM, response_MCO)

        return JSONResponse(content=merged_response)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
