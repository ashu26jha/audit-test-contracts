import json
import os
from enum import Enum

from common import logger
from fastapi import HTTPException

# Define the path to the profiles directory
PROFILES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "profiles_data")


# Enum for profile names
class Profiles(Enum):
    NONE = "none"
    DEFAULT = "default"
    DAO = "dao"
    DEFI = "defi"
    IDENTITY = "identity"
    NFT = "nft"
    UTILITY = "utility"


# Function to load a profile from a file
def load_profile(profile_name: Profiles):
    if profile_name == Profiles.NONE:
        # Return an empty list if no profile is selected
        return []

    # Map profile enums to file names
    profile_file_map = {
        Profiles.DEFAULT: "profile_default.json",
        Profiles.DAO: "profile_dao.json",
        Profiles.DEFI: "profile_defi.json",
        Profiles.IDENTITY: "profile_identity.json",
        Profiles.NFT: "profile_nft.json",
        Profiles.UTILITY: "profile_utility.json",
    }

    # Get the profile file path
    profile_file = profile_file_map.get(profile_name)

    # Construct the full path to the profile file
    profile_path = os.path.join(PROFILES_DIR, profile_file)

    # Load and return the content of the profile file as a list of dicts
    try:
        with open(profile_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError as exc:
        message = f"Profile file for {profile_name} not found."
        logger.error(message)
        raise HTTPException(status_code=404, detail=message) from exc
    except json.JSONDecodeError as exc:
        message = f"Profile file for {profile_name} is not a valid JSON file."
        logger.error(message)
        raise HTTPException(status_code=500, detail="Internal Server Error") from exc
