
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import uvicorn

from slither.slither import Slither

import input_validation, AC_admin_funcs, AC_mint, check_missing_override
from IVC_response import build_detector_response
from AC_response import build_access_control_response
from ACM_response import build_mint_access_response
from MCO_response import build_override_response

from merge_response import merge_scan_responses

app = FastAPI()

# serve static files
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

def detect_vulns(chain: str, address: str) -> dict:
    # Example response shape — change to your detector's output
    # This function should perform the heavy lifting of analyzing the contract

    print("detect")
    prefix=''
    if chain=="arbitrum": prefix = 'arbi:'
    if chain=="base": prefix = 'base:'
    if chain=='optimism': prefix = 'optim:'

    try:
        sl = Slither(prefix+address, etherscan_api_key="BK15VKTGEUVYXYXVRQ5H93HWUITNF6ZK8C")
    except Exception as e :
        print(e)
        raise(e)
    # sl = Slither('test-contracts/VulnerableMerkleTest.sol')
    # sl = Slither('test-contracts/hidden_mint_20.sol')
    print("slither done")


    info_IV = input_validation.run(sl)
    info_AC = AC_admin_funcs.run(sl)
    info_ACM = AC_mint.run(sl)
    info_MCO = check_missing_override.run(sl)

    # print(info_IV)

    # return {
    #     "chain": chain,
    #     "address": address,
    #     "issues_found": [
    #         {
    #             "id": "IV-001",
    #             "title": "Missing input validation on transfer",
    #             "severity": "HIGH",
    #             "description": "transfer() does not validate recipient address",
    #             "info":result
    #         }
    #     ],
    #     "summary": "1 potential input validation issue",
    #     # "result": result
    # }
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

    # call your detector

    # try:
    #     result = detect_vulns(chain, address)
    # except Exception as e:
    #     return JSONResponse(status_code=500, content={"error": str(e)})
    
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

    # return JSONResponse(content=result)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
