import json
import os
from enum import Enum
from typing import Any, Dict, List

from core.utils.errors import ConfigurationError, ValidationError
from core.utils.logger import logger

# Define the path to the profiles directory
PROFILES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "config", "profiles_data"
)

if not os.path.exists(PROFILES_DIR):
    raise ConfigurationError("Profiles directory not found", details={"profiles_dir": PROFILES_DIR})


# Enum for profile names
class Profiles(Enum):
    NONE = "none"
    DEFAULT = "default"
    DEFAULT_2 = "default_2"
    CAIRO = "cairo"
    DAO = "dao"
    DEFI = "defi"
    IDENTITY = "identity"
    NFT = "nft"
    UTILITY = "utility"
    FUZZING = "fuzzing"


# Function to load a profile from a file
def load_profile(profile_name: Profiles) -> List[Dict[str, Any]]:
    """
    Load a profile configuration from a file.

    Args:
        profile_name: The profile to load.

    Returns:
        List[Dict[str, Any]]: The profile configuration.

    Raises:
        ValidationError: If the profile file is not found or is invalid.
    """
    if profile_name == Profiles.NONE:
        # Return an empty list if no profile is selected
        return []

    # Map profile enums to file names
    profile_file_map = {
        Profiles.DEFAULT: "profile_default.json",
        Profiles.DEFAULT_2: "profile_default_2.json",
        Profiles.CAIRO: "profile_cairo.json",
        Profiles.DAO: "profile_dao.json",
        Profiles.DEFI: "profile_defi.json",
        Profiles.IDENTITY: "profile_identity.json",
        Profiles.NFT: "profile_nft.json",
        Profiles.UTILITY: "profile_utility.json",
        Profiles.FUZZING: "profile_fuzzing.json",
    }

    # Get the profile file path
    profile_file = profile_file_map.get(profile_name)
    if not profile_file:
        raise ValidationError(
            "Invalid profile name",
            details={
                "profile_name": profile_name.value,
                "available_profiles": [p.value for p in Profiles],
            },
        )

    # Construct the full path to the profile file
    profile_path = os.path.join(PROFILES_DIR, profile_file)

    # Load and return the content of the profile file as a list of dicts
    try:
        with open(profile_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError as exc:
        logger.error(f"Profile file for {profile_name} not found.")
        raise ValidationError(
            "Profile file not found",
            details={"profile_name": profile_name.value, "profile_path": profile_path},
        ) from exc
    except json.JSONDecodeError as exc:
        logger.error(f"Profile file for {profile_name} is not a valid JSON file.")
        raise ValidationError(
            "Invalid profile file format",
            details={
                "profile_name": profile_name.value,
                "profile_path": profile_path,
                "error": str(exc),
            },
        ) from exc
