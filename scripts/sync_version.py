#!/usr/bin/env python3
import re


def main():
    # Read version from .version file
    with open(".version", "r") as f:
        version = f.read().strip()

    print(f"Syncing version {version}")

    # Update frontend package.json
    pkg_path = "./frontend/package.json"
    with open(pkg_path, "r") as f:
        pkg_content = f.read()

    pkg_new = re.sub(r'"version": "[0-9.]+"', f'"version": "{version}"', pkg_content)

    if pkg_new != pkg_content:
        print(f"Updating frontend version to {version}")
        with open(pkg_path, "w") as f:
            f.write(pkg_new)

    # Update backend settings.py
    settings_path = "./backend/config/settings.py"
    with open(settings_path, "r") as f:
        settings_content = f.read()

    settings_new = re.sub(
        r'VERSION = "[0-9.]+"  # Auto-updated by pre-commit hook',
        f'VERSION = "{version}"  # Auto-updated by pre-commit hook',
        settings_content,
    )

    if settings_new != settings_content:
        print(f"Updating backend version to {version}")
        with open(settings_path, "w") as f:
            f.write(settings_new)

    print("Version sync complete")


if __name__ == "__main__":
    main()
