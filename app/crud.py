from ms_core import BaseCRUD

from app.models import Request
from app.schemas import RequestSchema


class RequestCRUD(BaseCRUD[Request, RequestSchema]):
    model = Request  # type: ignore
    schema = RequestSchema  # type: ignore
