from fastapi import APIRouter, Path

from app import ModelCRUD, Schema

router = APIRouter(prefix="/clientele", tags=["clientele"])


@router.get("/{item_id}")
async def get_by_id(item_id: int = Path()) -> Schema | None:
    return await ModelCRUD.get_by_id(item_id)
