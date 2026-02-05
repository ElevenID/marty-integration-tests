"""
Mock Wallet Service for Integration Testing

This is a lightweight mock wallet service that implements the essential
wallet APIs needed for testing OpenID4VCI and OpenID4VP flows. It stores
credentials in-memory and provides REST API endpoints matching our test
client's expectations.

This is NOT a production wallet - it's specifically designed for automated
integration testing of credential issuance and verification flows.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Optional, Any
import uuid
from datetime import datetime

app = FastAPI(title="Mock Wallet Service for Testing")

# In-memory storage
wallets: Dict[str, Dict[str, Any]] = {}
dids: Dict[str, List[str]] = {}  # wallet_id -> list of DIDs
credentials: Dict[str, List[Dict[str, Any]]] = {}  # wallet_id -> list of credentials


class CreateWalletRequest(BaseModel):
    name: str


class CreateDIDRequest(BaseModel):
    method: str = "key"


class AcceptCredentialOfferRequest(BaseModel):
    offer: str
    did: Optional[str] = None


class PresentCredentialRequest(BaseModel):
    presentationRequest: str
    credentialIds: List[str]
    did: Optional[str] = None


@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "mock-wallet"}


@app.post("/wallet-api/wallet/create")
def create_wallet(request: CreateWalletRequest):
    """Create a new wallet"""
    wallet_id = f"wallet-{uuid.uuid4().hex[:8]}"
    
    wallets[wallet_id] = {
        "id": wallet_id,
        "walletId": wallet_id,
        "name": request.name,
        "created_at": datetime.utcnow().isoformat(),
    }
    
    # Initialize empty DID and credential lists
    dids[wallet_id] = []
    credentials[wallet_id] = []
    
    return wallets[wallet_id]


@app.post("/wallet-api/wallet/{wallet_id}/dids/create")
def create_did(wallet_id: str, request: CreateDIDRequest):
    """Create a new DID in the wallet"""
    if wallet_id not in wallets:
        raise HTTPException(status_code=404, detail="Wallet not found")
    
    # Generate mock DID based on method
    did_value = f"did:{request.method}:{uuid.uuid4().hex}"
    
    dids[wallet_id].append(did_value)
    
    return {
        "did": did_value,
        "method": request.method,
        "created_at": datetime.utcnow().isoformat(),
    }


@app.get("/wallet-api/wallet/{wallet_id}/dids")
def list_dids(wallet_id: str):
    """List all DIDs in the wallet"""
    if wallet_id not in wallets:
        raise HTTPException(status_code=404, detail="Wallet not found")
    
    return dids.get(wallet_id, [])


@app.post("/wallet-api/wallet/{wallet_id}/exchange/useOfferRequest")
def accept_credential_offer(wallet_id: str, offer: str, did: Optional[str] = None):
    """
    Accept a credential offer (OpenID4VCI)
    
    In a real wallet, this would:
    1. Parse the offer URL
    2. Contact the credential issuer
    3. Request and receive the credential
    4. Store it in the wallet
    
    For testing, we simulate successful acceptance and store a mock credential.
    """
    if wallet_id not in wallets:
        raise HTTPException(status_code=404, detail="Wallet not found")
    
    # Parse offer to extract credential info (simplified)
    credential_id = f"cred-{uuid.uuid4().hex[:12]}"
    
    # Store mock credential
    credential = {
        "id": credential_id,
        "credentialId": credential_id,
        "type": ["VerifiableCredential", "MockCredential"],
        "issuer": "mock-issuer",
        "issuanceDate": datetime.utcnow().isoformat(),
        "offer_url": offer,
        "holder_did": did,
        "status": "accepted",
    }
    
    credentials[wallet_id].append(credential)
    
    return {
        "success": True,
        "credential_id": credential_id,
        "status": "accepted",
    }


@app.get("/wallet-api/wallet/{wallet_id}/credentials")
def list_credentials(wallet_id: str):
    """List all credentials in the wallet"""
    if wallet_id not in wallets:
        raise HTTPException(status_code=404, detail="Wallet not found")
    
    return credentials.get(wallet_id, [])


@app.get("/wallet-api/wallet/{wallet_id}/credentials/{credential_id}")
def get_credential(wallet_id: str, credential_id: str):
    """Get a specific credential by ID"""
    if wallet_id not in wallets:
        raise HTTPException(status_code=404, detail="Wallet not found")
    
    wallet_creds = credentials.get(wallet_id, [])
    for cred in wallet_creds:
        if cred.get("id") == credential_id or cred.get("credentialId") == credential_id:
            return cred
    
    raise HTTPException(status_code=404, detail="Credential not found")


@app.post("/wallet-api/wallet/{wallet_id}/exchange/usePresentationRequest")
def present_credential(wallet_id: str, request: PresentCredentialRequest):
    """
    Present credentials in response to a verification request (OpenID4VP)
    
    In a real wallet, this would:
    1. Parse the presentation request
    2. Select matching credentials
    3. Create and sign a verifiable presentation
    4. Submit it to the verifier
    
    For testing, we simulate successful presentation.
    """
    if wallet_id not in wallets:
        raise HTTPException(status_code=404, detail="Wallet not found")
    
    # Verify credentials exist
    wallet_creds = credentials.get(wallet_id, [])
    found_creds = []
    
    for cred_id in request.credentialIds:
        for cred in wallet_creds:
            if cred.get("id") == cred_id or cred.get("credentialId") == cred_id:
                found_creds.append(cred)
                break
    
    if not found_creds:
        raise HTTPException(status_code=404, detail="No matching credentials found")
    
    return {
        "success": True,
        "presentation_id": f"vp-{uuid.uuid4().hex[:12]}",
        "status": "presented",
        "credential_count": len(found_creds),
    }


@app.post("/wallet-api/wallet/{wallet_id}/exchange/resolveCredentialOffer")
def resolve_credential_offer(wallet_id: str, offer: str):
    """Resolve a credential offer to see details before accepting"""
    if wallet_id not in wallets:
        raise HTTPException(status_code=404, detail="Wallet not found")
    
    return {
        "credential_issuer": "https://example.com/issuer",
        "credentials": ["VerifiableCredential"],
        "offer_url": offer,
    }


@app.post("/wallet-api/wallet/{wallet_id}/exchange/resolvePresentationRequest")
def resolve_presentation_request(wallet_id: str, request: str):
    """Resolve a presentation request to see what's being requested"""
    if wallet_id not in wallets:
        raise HTTPException(status_code=404, detail="Wallet not found")
    
    return {
        "presentation_definition": {
            "input_descriptors": []
        },
        "request_url": request,
    }


@app.delete("/wallet-api/wallet/{wallet_id}/credentials/{credential_id}")
def delete_credential(wallet_id: str, credential_id: str):
    """Delete a credential from the wallet"""
    if wallet_id not in wallets:
        raise HTTPException(status_code=404, detail="Wallet not found")
    
    wallet_creds = credentials.get(wallet_id, [])
    
    for i, cred in enumerate(wallet_creds):
        if cred.get("id") == credential_id or cred.get("credentialId") == credential_id:
            wallet_creds.pop(i)
            return {"success": True, "message": "Credential deleted"}
    
    raise HTTPException(status_code=404, detail="Credential not found")


@app.delete("/wallet-api/wallet/{wallet_id}")
def delete_wallet(wallet_id: str):
    """Delete a wallet"""
    if wallet_id not in wallets:
        raise HTTPException(status_code=404, detail="Wallet not found")
    
    # Clean up all data
    wallets.pop(wallet_id, None)
    dids.pop(wallet_id, None)
    credentials.pop(wallet_id, None)
    
    return {"success": True, "message": "Wallet deleted"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7001)
