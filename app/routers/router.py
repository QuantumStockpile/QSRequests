from fastapi import Depends
from ms_core import BaseCRUDRouter, DefaultEndpoint, EndpointConfig

from app import RequestCRUD, RequestSchema, RequestCreate
from app.dependencies import require_role

router = BaseCRUDRouter(
    crud=RequestCRUD,
    schema=RequestSchema,
    schema_create=RequestCreate,
    endpoint_configs={
        DefaultEndpoint.CREATE: EndpointConfig(
            path="/",
            methods=["POST"],
            dependencies=[require_role("admin")],
        ),
        DefaultEndpoint.DELETE: EndpointConfig(
            path="/{item_id}", methods=["DELETE"], dependencies=[require_role("admin")]
        ),
        DefaultEndpoint.UPDATE: EndpointConfig(
            path="/{item_id}", methods=["PATCH"], dependencies=[require_role("admin")]
        ),
    },
    dependencies=[Depends(require_role("user"))],
)
