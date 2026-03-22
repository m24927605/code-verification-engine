from repositories.user_repo import UserRepository

class UserService:
    def __init__(self):
        self.repo = UserRepository()

    def get_user(self, user_id: str) -> dict:
        return self.repo.find_by_id(user_id)

    def create_user(self, data: dict) -> dict:
        return self.repo.create(data)
