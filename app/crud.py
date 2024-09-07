from app import Model, Schema
from ms_core import BaseCRUD


class ModelCRUD(BaseCRUD[Model, Schema]):
    model = Model
    schema = Schema
