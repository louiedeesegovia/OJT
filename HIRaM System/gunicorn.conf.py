def on_starting(server):
    from app import app, db
    with app.app_context():
        db.create_all()