import slack
from slack.errors import SlackApiError

from api.v1.utilities.stats.service import StatsService
from config.settings import SLACK_TOKEN
from core.utils.errors import EnvironmentError
from core.utils.logger import logger


async def send_slack_message():
    """
    Send a Slack message with the last 24-hour statistics.

    Raises:
        EnvironmentError: If there's an error sending the message to Slack
    """
    logger.info("[Slack] Sending message...")
    try:
        stats_24h = await StatsService.get_24h_stats()
        text = f"""
        *Last 24 Hour updates:*
        ─ Lines Scanned: {stats_24h.lines_of_code}
        ─ New Users: {stats_24h.new_users}
        ─ Total Scans: {stats_24h.total_scans_24h}
        ─ Vulnerabilities Found: {stats_24h.vulnerabilities_found}
        ─ Free Scans: {stats_24h.free_scans}
        ─ Pro Scans: {stats_24h.pro_scans}
        ─ Enterprise Scans: {stats_24h.enterprise_scans}
        """

        slack_client = slack.WebClient(token=SLACK_TOKEN)
        slack_client.chat_postMessage(
            channel="#project-ai-code-auditor",
            text=text,
            username="Audit Agent Updates",
        )
    except SlackApiError as e:
        raise EnvironmentError(
            "Failed to send Slack message",
            details={"error": str(e), "response_code": e.response.get("error", "unknown")},
        ) from e
    except Exception as e:
        raise EnvironmentError("Failed to send Slack message", details={"error": str(e)}) from e
