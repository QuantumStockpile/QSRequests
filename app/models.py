from tortoise import fields

from ms_core import AbstractModel


class Model(AbstractModel):
    field = fields.TextField()
