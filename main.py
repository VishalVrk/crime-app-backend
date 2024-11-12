from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import List, Dict, Optional
from datetime import datetime
import json
import logging
from supabase import create_client
import os
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import re

# Load environment variables
load_dotenv()

# Initialize Supabase client
supabase_url = os.getenv("SUPABASE_URL")
supabase_key = os.getenv("SUPABASE_KEY")
supabase = create_client(supabase_url, supabase_key)


app = FastAPI(
    title="Forensic Text Analysis API",
    description="API for analyzing text content for suspicious patterns and behaviors",
    version="1.0.0"
)

# Define the origins that should be allowed
origins = [
    "http://localhost:3000",  # example frontend
    "https://crime-forensic.vercel.app/",  # production frontend domain
]

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=origins,  # allows these specific origins
    allow_methods=["*"],     # allows all HTTP methods
    allow_headers=["*"],     # allows all headers
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Models
class TextInput(BaseModel):
    text: str
    source: str  # "email", "file_activity", or "whatsapp"
    metadata: Optional[Dict] = Field(default_factory=dict)

class AnalysisResult(BaseModel):
    is_suspicious: bool
    content: str
    source: str
    timestamp: str
    reason: Optional[str] = None
    metadata: Optional[Dict] = Field(default_factory=dict)  # Add this line

# Initialize patterns
try:
    with open('suspicious_patterns.json', 'r') as f:
        suspicious_patterns = json.load(f)
except Exception as e:
    logger.error(f"Error loading suspicious patterns: {str(e)}")
    raise

class TextAnalyzer:
    def __init__(self, patterns: Dict):
        self.patterns = patterns

    def analyze_text(self, text: str, source: str, timestamp: str) -> AnalysisResult:
        reasons = []
        risk_score = 0

        # Step 1: Check keywords for each category
        for category, keywords in self.patterns.get('keywords', {}).items():
            for keyword in keywords:
                if keyword in text.lower():
                    reasons.append(f"Keyword match: '{keyword}' in category '{category}'")
                    risk_score += self.patterns['risk_scores'].get(category, 0)

        # Step 2: Check patterns
        for pattern_name, pattern in self.patterns.get('patterns', {}).items():
            if isinstance(pattern, list):  # For pattern lists like suspicious extensions
                for subpattern in pattern:
                    if re.search(subpattern, text):
                        reasons.append(f"Pattern match: '{subpattern}' in category '{pattern_name}'")
                        risk_score += self.patterns['risk_scores'].get(pattern_name, 0)
            else:
                if re.search(pattern, text):
                    reasons.append(f"Pattern match: '{pattern_name}'")
                    risk_score += self.patterns['risk_scores'].get(pattern_name, 0)

        # Step 3: Check whitelist/blacklist
        if any(domain in text.lower() for domain in self.patterns.get('whitelist', {}).get('domains', [])):
            risk_score *= 0.5  # Reduce score if whitelisted
        elif any(domain in text.lower() for domain in self.patterns.get('blacklist', {}).get('domains', [])):
            reasons.append("Blacklisted domain found")
            risk_score += 0.2  # Increase score for blacklisted domains

        # Step 4: Determine if event is suspicious based on risk score
        alert_threshold = self.patterns.get('alert_threshold', 0.7)
        is_suspicious = risk_score >= alert_threshold

        return AnalysisResult(
            is_suspicious=is_suspicious,
            content=text,
            source=source,
            timestamp=timestamp,
            reason="; ".join(reasons) if reasons else None
        )


# Initialize analyzer
text_analyzer = TextAnalyzer(suspicious_patterns)

async def store_analysis_result(result: AnalysisResult):
    try:
        response = await supabase.table("events").insert({
            "content": result.content,
            "is_suspicious": result.is_suspicious,  # Save the calculated flag
            "type": result.source,
            "timestamp": result.timestamp,
            "sender": result.metadata.get("sender") if result.metadata else None,
            "receiver": result.metadata.get("receiver") if result.metadata else None,
            "user": result.metadata.get("user") if result.metadata else None,
            "action": result.metadata.get("action") if result.metadata else None,
            "filepath": result.metadata.get("filepath") if result.metadata else None
        }).execute()
        if response.status_code != 200:
            raise Exception(f"Failed to insert data: {response}")
    except Exception as e:
        logger.error(f"Error storing analysis result: {str(e)}")


@app.post("/api/analyze-text", response_model=AnalysisResult)
async def analyze_text(input_data: TextInput, background_tasks: BackgroundTasks):
    try:
        timestamp = datetime.utcnow().isoformat()
        result = text_analyzer.analyze_text(input_data.text, input_data.source, timestamp)      
        background_tasks.add_task(store_analysis_result, result)        
        return result
    except Exception as e:
        logger.error(f"Error in analyze_text endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }
