from app import app, db, User

def seed_admin():
    with app.app_context():
        # Ensure tables exist
        db.create_all()
        
        # Check if admin exists
        admin_email = 'admin@adventz.com'
        if User.query.filter_by(username=admin_email).first():
            print(f"Admin {admin_email} already exists.")
            return

        # Create Admin
        admin = User(
            username=admin_email,
            full_name='System Admin',
            phone_number='0000000000',
            role='ADMIN'
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print(f"Created Admin user: {admin_email} / admin123")

        # Create CEO (Optional seed)
        ceo_email = 'ceo@adventz.com'
        if not User.query.filter_by(username=ceo_email).first():
            ceo = User(
                username=ceo_email,
                full_name='CEO',
                phone_number='1111111111',
                role='CEO'
            )
            ceo.set_password('ceo123')
            db.session.add(ceo)
            db.session.commit()
            print(f"Created CEO user: {ceo_email} / ceo123")

if __name__ == '__main__':
    try:
        seed_admin()
    except Exception as e:
        import traceback
        with open('error_log.txt', 'w') as f:
            f.write(traceback.format_exc())
            print(f"Error logged to error_log.txt: {e}")
