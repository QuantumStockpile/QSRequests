from tortoise import Tortoise
from tortoise.contrib.pydantic import pydantic_model_creator

from app.models import Request

Tortoise.init_models(["app.models"], "models")

RequestSchema = pydantic_model_creator(Request)
RequestCreate = pydantic_model_creator(
    Request,
    name="RequestCreate",
    exclude_readonly=True,
)
