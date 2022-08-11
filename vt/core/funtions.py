import random
import json
import string
from .module_class import *


def random_header_id():
    return ("".join(random.choice(string.ascii_letters) for _ in range(59))) + "=="


def file_info_fill(data: json,raw=0):
    if raw:
        return data
        
    data = data["data"]
    file_type_info = {}
    total_votes = {}
    last_analysis_results = []
    tags = []

    file_type = data["type"]
    id = data["id"]
    attributes = data["attributes"]
    type_description = attributes["type_description"]
    for i in attributes["trid"]:
        file_type_info.update(
            {"file_type": i["file_type"], "probability": i["probability"]}
        )
    try :
        filename = attributes["names"][0]
    except:
        filename=""

    last_modification_date = datetime.fromtimestamp(
        attributes["last_modification_date"]
    )
    times_submitted = attributes["times_submitted"]

    total_votes.update(
        {
            "harmless": attributes["total_votes"]["harmless"],
            "malicious": attributes["total_votes"]["malicious"],
        }
    )
    size = attributes["size"]
    file_extension = attributes["type_extension"]
    last_submission_date = datetime.fromtimestamp(attributes["last_modification_date"])

    for _, value in attributes["last_analysis_results"].items():

        temp = {
            "engine_name": value["engine_name"],
            "engine_version": value["engine_version"],
            "result": value["result"],
            "category":value["category"]
        }
        last_analysis_results.append(AnalysisResults(**temp))

    list_hash = {
        "sha256": attributes["sha256"],
        "md5": attributes["md5"],
        "sha1": attributes["sha1"],
        "vhash": attributes["vhash"] if "vhash" in attributes else None,
        "ssdeep": attributes["ssdeep"] if "ssdeep" in attributes else None,
        "tlsh": attributes["tlsh"] if "tlsh" in attributes else None,
    }
    magic= attributes["magic"] if "magic" in attributes else None
    first_submission_date = datetime.fromtimestamp(attributes["first_submission_date"])
    for i in attributes["tags"]:
        tags.append(i)
    last_analysis_date = datetime.fromtimestamp(attributes["last_analysis_date"])

    attributes = attributes["last_analysis_stats"]
    temp = {
        "harmless": attributes["harmless"],
        "type_unsupported": attributes["type-unsupported"],
        "suspicious": attributes["suspicious"],
        "confirmed_timeout": attributes["confirmed-timeout"],
        "timeout": attributes["timeout"],
        "failure": attributes["failure"],
        "malicious": attributes["malicious"],
        "undetected": attributes["undetected"],
    }
    last_analysis_stats = AnalysisStats(**temp)

    temp = {
        "filename": filename,
        "id": id,
        "type_description": type_description,
        "file_type_info": file_type_info,
        "first_submission_date": first_submission_date,
        "last_modification_date": last_modification_date,
        "times_submitted": times_submitted,
        "total_votes": total_votes,
        "size": size,
        "file_extension": file_extension,
        "last_submission_date": last_submission_date,
        "results": last_analysis_results,
        "tags": tags,
        "last_analysis_date": last_analysis_date,
        "list_hash": list_hash,
        "analysis_stats": last_analysis_stats,
        "file_type": file_type,
        "magic": magic,
    }

    return FileInfo(**temp)
