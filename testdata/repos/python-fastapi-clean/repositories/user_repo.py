from sqlalchemy.orm import Session

class UserRepository:
    def __init__(self, session: Session = None):
        self.session = session

    def find_by_id(self, user_id: str) -> dict:
        return {"id": user_id, "name": "Alice"}

    def create(self, data: dict) -> dict:
        return {"id": "new", **data}
