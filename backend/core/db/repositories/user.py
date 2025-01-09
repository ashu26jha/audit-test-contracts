from datetime import datetime, timezone
from typing import List, Optional

from fastapi import HTTPException

from config.subscription_settings import SUBSCRIPTION_SETTINGS
from core.models.user import SubscriptionData, SubscriptionType, User
from core.utils.logger import logger


class UserRepository:
    """Repository for managing user records in the database."""

    @staticmethod
    async def get_by_username(username: str) -> Optional[User]:
        """Get a user by username."""
        return await User.find_one({"username": username})

    @staticmethod
    async def get_by_github_id(github_id: str) -> Optional[User]:
        """Get a user by GitHub ID."""
        return await User.find_one({"githubId": github_id})

    @staticmethod
    async def get_by_email(email: str) -> Optional[User]:
        """Get a user by email."""
        return await User.find_one({"email": email})

    @staticmethod
    async def get_by_customer_id(customer_id: str) -> Optional[User]:
        """Get a user by Stripe customer ID."""
        return await User.find_one({"subscription.stripeCustomerId": customer_id})

    @staticmethod
    async def get_by_subscription_id(subscription_id: str) -> Optional[User]:
        """Get a user by Stripe subscription ID."""
        return await User.find_one({"subscription.stripeSubscriptionId": subscription_id})

    @staticmethod
    async def get_by_access_token(access_token: str) -> Optional[User]:
        """Get a user by access token."""
        return await User.find_one({"accessToken": access_token})

    @staticmethod
    async def create_user(
        github_id: str,
        username: str,
        email: str,
        access_token: str,
        avatar_url: str,
        name: str,
        installation_ids: List[int],
    ) -> User:
        """
        Create a new user.

        Args:
            github_id: GitHub user ID
            username: GitHub username
            email: User's email
            access_token: GitHub access token
            avatar_url: GitHub avatar URL
            name: User's full name
            installation_ids: List of GitHub App installation IDs

        Returns:
            Created User object

        Raises:
            HTTPException: If user creation fails
        """
        try:
            user = User(
                githubId=github_id,
                username=username,
                email=email,
                accessToken=access_token,
                avatarUrl=avatar_url,
                name=name,
                installationId=installation_ids,
                token_version=0,
            )
            await user.create()
            return user
        except Exception as e:
            logger.error(f"Error creating user {username}: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to create user") from e

    @staticmethod
    async def update_user(
        user: User,
        access_token: str,
        installation_ids: List[int],
        avatar_url: str,
        name: str,
        email: str,
    ) -> User:
        """
        Update user information.

        Args:
            user: User object to update
            access_token: New GitHub access token
            installation_ids: New installation IDs
            avatar_url: New avatar URL
            name: New name
            email: New email

        Returns:
            Updated User object

        Raises:
            HTTPException: If update fails
        """
        try:
            await user.update(
                {
                    "$set": {
                        "accessToken": access_token,
                        "installationId": installation_ids,
                        "avatarUrl": avatar_url,
                        "name": name,
                        "email": email,
                        "updatedAt": datetime.now(timezone.utc),
                    }
                }
            )
            return await UserRepository.get_by_github_id(user.githubId)
        except Exception as e:
            logger.error(f"Error updating user {user.username}: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to update user") from e

    @staticmethod
    async def increment_token_version(user: User) -> None:
        """Increment user's token version to invalidate all existing tokens"""
        await user.update({"$inc": {"token_version": 1}})

    @staticmethod
    async def activate_subscription(
        user: User,
        subscription_id: str,
        subscription_type: SubscriptionType = SubscriptionType.PRO,
        customer_id: str = None,
    ) -> User:
        """
        Activate a user's subscription with full setup of credits and expiration.

        Args:
            user: User object to update
            subscription_id: Stripe subscription ID
            subscription_type: Type of subscription (defaults to 'pro')
            customer_id: Stripe customer ID

        Returns:
            Updated User object
        """
        try:
            subscription = SUBSCRIPTION_SETTINGS[subscription_type]
            now = datetime.now(timezone.utc)

            # Create a new SubscriptionData object with all the fields
            subscription_data = SubscriptionData(
                isActive=True,
                type=subscription_type,
                stripeSubscriptionId=subscription_id,
                stripeCustomerId=customer_id,
                credits=subscription["monthly_credits"],
                monthlyCredits=subscription["monthly_credits"],
                lastRenewalAt=now,
                expiresAt=now + subscription["credit_expiry_period"],
            )

            # Update using the model
            await user.update({"$set": {"subscription": subscription_data.model_dump()}})
            return await UserRepository.get_by_github_id(user.githubId)

        except Exception as e:
            logger.error(f"Error activating subscription for user {user.username}: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to activate subscription") from e

    @staticmethod
    async def deactivate_subscription(user: User) -> User:
        """
        Deactivate a user's subscription while preserving the Stripe customer ID.
        """
        try:
            now = datetime.now(timezone.utc)

            # Create update data preserving the customer ID
            subscription_update = {
                "subscription.isActive": False,
                "subscription.type": SubscriptionType.FREE,
                "subscription.credits": 0,
                "subscription.monthlyCredits": 0,
                "subscription.stripeSubscriptionId": None,
                "subscription.expiresAt": now,
                "subscription.lastRenewalAt": None,
                # Explicitly NOT updating stripeCustomerId to preserve it
            }

            await user.update({"$set": subscription_update})
            return await UserRepository.get_by_github_id(user.githubId)

        except Exception as e:
            logger.error(f"Error deactivating subscription for user {user.username}: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to deactivate subscription") from e

    @staticmethod
    async def renew_subscription_credits(user: User) -> User:
        """
        Renew subscription credits for the current billing period.
        """
        try:
            now = datetime.now(timezone.utc)
            subscription_type = user.subscription.type

            if subscription_type not in SUBSCRIPTION_SETTINGS:
                raise ValueError(f"Invalid subscription type: {subscription_type}")

            subscription = SUBSCRIPTION_SETTINGS[subscription_type]
            updates = {
                "$set": {
                    "subscription.credits": subscription["monthly_credits"],
                    "subscription.lastRenewalAt": now,
                    "subscription.expiresAt": now + subscription["credit_expiry_period"],
                }
            }

            await user.update(updates)
            return await UserRepository.get_by_github_id(user.githubId)

        except Exception as e:
            logger.error(f"Error renewing subscription credits for user {user.username}: {str(e)}")
            raise HTTPException(
                status_code=500, detail="Failed to renew subscription credits"
            ) from e

    async def ensure_user_subscription_data(user: User) -> User:
        """
        Ensure user has subscription data initialized.

        Args:
            user: User object to check/update

        Returns:
            Updated User object
        """
        if not user.subscription:
            user.subscription = SubscriptionData(
                isActive=False,
                type=SubscriptionType.FREE,
                credits=0,
                monthlyCredits=0,
                stripeSubscriptionId=None,
                stripeCustomerId=None,
                expiresAt=None,
                lastRenewalAt=None,
            )
            await user.save()
            logger.info(f"Initialized subscription data for user {user.githubId}")
        return user

    @staticmethod
    async def create_test_user(username: str) -> User:
        """Create a test user in the database."""
        test_user = User(
            username=username,
            email=f"{username}@example.com",
            githubId="1234567890",
            accessToken="test_access_token",
            avatarUrl="https://github.com/ghost.png",
            name=username,
            createdAt=datetime.now(timezone.utc),
            updatedAt=datetime.now(timezone.utc),
            installationId=[12345],
            token_version=0,
            subscription=SubscriptionData(
                isActive=False,
                type=SubscriptionType.FREE,
                credits=0,
                monthlyCredits=0,
                expiresAt=None,
                stripeSubscriptionId=None,
                lastRenewalAt=None,
            ),
        )
        await test_user.save()
        return test_user
