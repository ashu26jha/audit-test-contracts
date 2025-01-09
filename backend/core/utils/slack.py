import slack

from api.v1.utilities.stats.service import StatsService
from config.settings import SLACK_TOKEN
from core.utils.logger import logger


async def send_slack_message():
    logger.info("Sending Slack message")
    try:
        stats_24h = await StatsService.get_24h_stats()
        text = f"""
        *Last 24 Hour updates:*
        ─ Lines Scanned: {stats_24h.lines_of_code}
        ─ New Users: {stats_24h.new_users}
        ─ Total Scans: {stats_24h.total_scans_24h}
        ─ Vulnerabilities Found: {stats_24h.vulnerabilities_found}
        ─ External Scans: {stats_24h.paid_scans_24h}
        """

        slack_client = slack.WebClient(token=SLACK_TOKEN)
        slack_client.chat_postMessage(
            channel="#project-ai-code-auditor",
            text=text,
            username="Audit Agent Updates",
        )
    except Exception as e:
        logger.error(f"Failed to send Slack message: {e}")
