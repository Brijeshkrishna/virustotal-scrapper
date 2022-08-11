from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel


class AnalysisResults(BaseModel):
    engine_name: str
    engine_version: Optional[str]
    result: Optional[str]
    category:str
    

class AnalysisStats(BaseModel):
    harmless: int
    type_unsupported: int
    suspicious: int
    confirmed_timeout: int
    timeout: int
    failure: int
    malicious: int
    undetected: int


class FileInfo(BaseModel):
    filename: str
    id: str
    magic:Optional[str]
    type_description: str
    file_type_info: Dict[str, str]
    first_submission_date: datetime
    last_modification_date: datetime
    times_submitted: int
    total_votes: Dict[str, int]
    size: int
    file_extension: str
    last_submission_date: datetime
    results: List[AnalysisResults]
    tags: List[str]
    last_analysis_date: datetime
    list_hash: Dict[str, Optional[str]]
    analysis_stats: AnalysisStats
    file_type: str


