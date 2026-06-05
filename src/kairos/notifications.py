from kairos.db import create_notification, get_invites, get_poll, get_unread_notification_count


def notify_new_response(poll_id: str, respondent_name: str):
    """Create a notification for the poll creator when someone responds."""
    poll = get_poll(poll_id)
    if not poll:
        return
    create_notification(
        user_id=poll["creator_id"],
        poll_id=poll_id,
        notif_type="new_response",
        message=f"{respondent_name} responded to '{poll['title']}'",
    )


def notify_all_responded(poll_id: str):
    """Check if all invitees have responded, and notify the creator if so."""
    invites = get_invites(poll_id)
    if not invites:
        return
    if not all(inv["responded"] for inv in invites):
        return
    poll = get_poll(poll_id)
    if not poll:
        return
    create_notification(
        user_id=poll["creator_id"],
        poll_id=poll_id,
        notif_type="all_responded",
        message=f"All invitees have responded to '{poll['title']}'",
    )


def get_unread_count(user_id: str) -> int:
    return get_unread_notification_count(user_id)
