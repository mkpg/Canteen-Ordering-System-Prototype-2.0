from app import app, sql_db, PendingLoginModel, UserModel
from datetime import datetime, timedelta

def test_batch6():
    with app.app_context():
        # Create tables
        sql_db.create_all()
        print("1. Tables verified")

        user = UserModel.query.first()
        if not user:
            print("No users found.")
            return

        # Test creating a pending login
        pending = PendingLoginModel(
            username=user.username,
            email=user.email,
            organization_id=str(user.organization_id) if user.organization_id else None,
            token="test-token-123",
            correct_number=42,
            status="pending",
            remember_device=True,
            expires_at=datetime.now() + timedelta(minutes=10)
        )
        sql_db.session.add(pending)
        sql_db.session.commit()
        
        # Test retrieving
        fetched = PendingLoginModel.query.filter_by(token="test-token-123").first()
        print(f"2. Created and fetched: {fetched.to_dict()}")
        
        # Clean up
        PendingLoginModel.query.filter_by(token="test-token-123").delete()
        sql_db.session.commit()
        print("3. Cleaned up")
        print("Batch 6 Test Passed!")

if __name__ == '__main__':
    test_batch6()
