import tempfile
from pathlib import Path

from tracker.db import TrackerDB
from tracker.seed_sops import DEFAULT_SOPS, seed_default_sops


async def test_seeds_all_default_sops_into_empty_db():
    with tempfile.TemporaryDirectory() as tmp:
        db = TrackerDB(db_path=str(Path(tmp) / "test.db"))
        await seed_default_sops(db)
        sops = await db.list_sops()
        assert len(sops) == len(DEFAULT_SOPS)


async def test_seeding_does_not_overwrite_user_edited_sop():
    with tempfile.TemporaryDirectory() as tmp:
        db = TrackerDB(db_path=str(Path(tmp) / "test.db"))
        await db.upsert_sop("Phishing", "My own custom steps, already entered")
        await seed_default_sops(db)
        sop = await db.get_sop("Phishing")
        assert sop["steps"] == "My own custom steps, already entered"


async def test_seeding_twice_is_idempotent():
    with tempfile.TemporaryDirectory() as tmp:
        db = TrackerDB(db_path=str(Path(tmp) / "test.db"))
        await seed_default_sops(db)
        await seed_default_sops(db)
        sops = await db.list_sops()
        assert len(sops) == len(DEFAULT_SOPS)
