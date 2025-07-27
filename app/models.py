from ms_core import AbstractModel
from tortoise import fields, validators
from enum import Enum


class ExtendedAbstractModel(AbstractModel):
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:  # type: ignore
        abstract = True


class RequestStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    RETURNED = "returned"


class Request(ExtendedAbstractModel):
    user_id = fields.IntField()  # Reference to user in another microservice
    status = fields.CharEnumField(RequestStatus, default=RequestStatus.PENDING)
    approved_by_id = fields.IntField(
        null=True
    )  # Reference to user in another microservice
    approved_at = fields.DatetimeField(null=True)
    returned_at = fields.DatetimeField(null=True)
    note = fields.TextField(null=True)

    # Reverse relation to request_items
    items: fields.ReverseRelation["RequestItem"]

    class Meta:  # type: ignore
        table = "requests"


class RequestItem(ExtendedAbstractModel):
    request = fields.ForeignKeyField(
        "models.Request", related_name="items", on_delete=fields.CASCADE
    )
    equipment_id = fields.IntField()  # Reference to equipment in another microservice
    borrow_from = fields.DateField()
    borrow_to = fields.DateField()

    # Reverse relation to return_logs
    return_logs: fields.ReverseRelation["ReturnLog"]

    class Meta:  # type: ignore
        table = "request_items"


class ReturnLog(ExtendedAbstractModel):
    request_item = fields.ForeignKeyField(
        "models.RequestItem", related_name="return_logs", on_delete=fields.CASCADE
    )
    returned_by_id = fields.IntField()  # Reference to user in another microservice
    returned_at = fields.DatetimeField(auto_now_add=True)
    condition = fields.IntField(
        null=True,
        validators=[validators.MinValueValidator(0), validators.MaxValueValidator(10)],
    )
    note = fields.TextField(null=True)

    class Meta:  # type: ignore
        table = "return_logs"
