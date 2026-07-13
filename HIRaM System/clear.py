from app import app
from database.models import db, BorrowTracker

with app.app_context():
    BorrowTracker.query.delete()
    db.session.commit()
    print("BorrowTracker cleared.")