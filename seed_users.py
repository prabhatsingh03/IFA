from app import app, db, User

with app.app_context():
    print("Seeding users...")
    
    users = [
        {'username': 'admin@adventz.com', 'fullname': 'System Admin', 'role': 'ADMIN', 'pass': 'admin123'},
        {'username': 'ceo@adventz.com', 'fullname': 'CEO User', 'role': 'CEO', 'pass': 'ceo123'},
        {'username': 'user@adventz.com', 'fullname': 'Regular User', 'role': 'USER', 'pass': 'user123'}
    ]
    
    for u in users:
        existing = User.query.filter_by(username=u['username']).first()
        if not existing:
            user = User(
                username=u['username'],
                full_name=u['fullname'],
                phone_number='1234567890',
                role=u['role']
            )
            user.set_password(u['pass'])
            db.session.add(user)
            print(f"Created {u['role']}: {u['username']}")
    
    db.session.commit()
    print("Seeding complete.")
