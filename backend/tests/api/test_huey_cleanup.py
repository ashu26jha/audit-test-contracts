from datetime import datetime

import pytest
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from huey.api import Task
from pytz import utc  # Add this import

from core.db.connection import cleanup_huey_tasks, huey


@pytest.mark.asyncio
async def test_cleanup_huey_tasks():
    # 0. Clear everything first to ensure clean state
    huey.storage.flush_all()

    # 1. Create some dummy tasks and results
    test_task = Task()
    huey.storage.enqueue(b"test_task_data", 0)  # Add task to queue
    huey.storage.add_to_schedule(b"test_scheduled_task", datetime.now())  # Add scheduled task
    huey.put_result(test_task.id, "test_result")  # Add result

    # 2. Verify data exists
    assert huey.storage.queue_size() > 0, "Queue should not be empty"
    assert huey.storage.schedule_size() > 0, "Schedule should not be empty"
    assert huey.storage.result_store_size() > 0, "Results should not be empty"

    # 3. Run cleanup
    await cleanup_huey_tasks()

    # 4. Verify cleanup worked
    assert huey.storage.queue_size() == 1, "We are not flushing the queue"
    assert huey.storage.schedule_size() == 0, "Schedule should be empty"
    assert huey.storage.result_store_size() == 0, "Results should be empty"


@pytest.mark.asyncio
async def test_cleanup_schedule():
    # Create a test scheduler with timezone
    scheduler = AsyncIOScheduler(timezone=utc)

    # Add our cleanup job
    scheduler.add_job(
        cleanup_huey_tasks,
        "cron",
        hour=0,
        minute=0,
        id="cleanup_huey_tasks",
        name="cleanup_huey_tasks",
        misfire_grace_time=3600,
    )

    try:
        # Start the scheduler
        scheduler.start()

        # Get the next run time for our job
        job = scheduler.get_job("cleanup_huey_tasks")
        assert job is not None, "Job should be registered"

        # Verify the cron trigger settings
        trigger = job.trigger
        assert trigger.fields[3].is_default, "Hours should be 0"  # hour field
        assert trigger.fields[2].is_default, "Minutes should be 0"  # minute field

        # Verify other job properties
        assert job.name == "cleanup_huey_tasks"
        assert job.misfire_grace_time == 3600
    finally:
        # Clean up
        scheduler.shutdown()


@pytest.mark.asyncio
async def test_cleanup_huey_tasks_empty():
    """Test cleanup function handles empty storage gracefully"""
    # 0. Ensure clean state
    huey.storage.flush_all()

    # 1. Run cleanup on empty storage
    await cleanup_huey_tasks()

    # 2. Verify no errors occurred
    assert huey.storage.queue_size() == 0
    assert huey.storage.schedule_size() == 0
    assert huey.storage.result_store_size() == 0
