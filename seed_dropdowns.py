from app import app, db, DropdownOption
from datetime import datetime

def seed_dropdown_options():
    """Seed the database with initial dropdown options"""
    
    with app.app_context():
        # Check if already seeded
        existing = DropdownOption.query.first()
        if existing:
            print("Dropdown options already exist. Skipping seed.")
            return
        
        print("Seeding dropdown options...")
        
        # Define categories and their values
        categories = {
            'to_person': ['CFO', 'CO'],
            'project_name': [
                'Project A (Chemical)',
                'Project B (Fertilizer)',
                'Project C (Oil & Gas)',
                'Project D (Power)'
            ],
            'prepared_by': [
                'John Doe',
                'Jane Smith',
                'Robert Johnson',
                'Emily Davis'
            ],
            'approved_by': [
                'Director Operations',
                'Plant Manager',
                'CFO',
                'CEO'
            ]
        }
        
        # Create dropdown options
        for category, values in categories.items():
            for order, value in enumerate(values, start=1):
                option = DropdownOption(
                    category=category,
                    value=value,
                    display_order=order,
                    is_active=True
                )
                db.session.add(option)
        
        db.session.commit()
        print(f"✓ Successfully seeded {sum(len(v) for v in categories.values())} dropdown options")

if __name__ == '__main__':
    seed_dropdown_options()
