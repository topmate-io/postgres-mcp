import os
import requests


class TopmateBuisnessLogic:

    def __init__(self):
        self.base_url = os.getenv("TOPMATE_LOGIC_HUB_BASE_URL")
        self.api_key = os.getenv("TOPMATE_LOGIC_HUB_API_KEY")

        # Validate configuration without making requests during init
        if not self.base_url or not self.api_key:
            raise ValueError(
                "TOPMATE_LOGIC_HUB_BASE_URL and TOPMATE_LOGIC_HUB_API_KEY environment variables must be set"
            )

    def get_rules(self):
        url = f"{self.base_url}/api/rules/json"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        response = requests.get(url, headers=headers, timeout=5)
        return response.json()

    def get_patterns(self):
        url = f"{self.base_url}/api/patterns/json"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        response = requests.get(url, headers=headers, timeout=5)
        return response.json()