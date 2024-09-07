from tortoise import Tortoise
from tortoise.contrib.pydantic import pydantic_model_creator

from app.models import Model

Tortoise.init_models(
    ["app.models"], "models"
)

Schema = pydantic_model_creator(Model)
Create = pydantic_model_creator(
    Model,
    name="ModelCreate",
    exclude_readonly=True,
)
