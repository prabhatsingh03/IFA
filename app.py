from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response
import base64
from flask_sqlalchemy import SQLAlchemy
from config import Config
from datetime import datetime, date
import os
from functools import wraps
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request, get_jwt, unset_jwt_cookies, set_access_cookies

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


# --- Database Model ---
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False) # Email
    full_name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(20))
    role = db.Column(db.String(20), default='USER') # ADMIN, USER, CEO
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

# --- Database Model ---
class DropdownOption(db.Model):
    __tablename__ = 'dropdown_options'
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(50), nullable=False)  # 'to_person', 'project_name', 'prepared_by', 'approved_by'
    value = db.Column(db.String(200), nullable=False)
    display_order = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<DropdownOption {self.category}: {self.value}>'

# --- Database Model ---
class IFAForm(db.Model):
    __tablename__ = 'ifa_forms'
    
    id = db.Column(db.Integer, primary_key=True)
    ifa_no = db.Column(db.String(20), unique=True, nullable=False)
    ifa_date = db.Column(db.Date, nullable=False)
    to_person = db.Column(db.String(100))
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    user = db.relationship('User', backref=db.backref('forms', lazy=True))
    
    po_no = db.Column(db.String(50))
    po_date = db.Column(db.Date)
    supplier_name = db.Column(db.String(100))
    po_basic_price = db.Column(db.Numeric(15, 2))
    gst_on_basic = db.Column(db.Numeric(15, 2))
    total_po_value = db.Column(db.Numeric(15, 2))
    
    service_name = db.Column(db.String(100))
    project_name = db.Column(db.String(200))
    payment_terms = db.Column(db.Text)
    
    invoice_claimed = db.Column(db.Numeric(15, 2))
    proforma_invoice_no = db.Column(db.String(50))
    passed_for = db.Column(db.Numeric(15, 2))
    proforma_invoice_date = db.Column(db.Date)
    advance_paid = db.Column(db.String(10)) # Yes/No
    delivery_status = db.Column(db.String(100))
    remark = db.Column(db.Text)
    
    amount_basic = db.Column(db.Numeric(15, 2))
    amount_gst = db.Column(db.Numeric(15, 2))
    amount_total = db.Column(db.Numeric(15, 2))
    amount_40_percent = db.Column(db.Numeric(15, 2))
    
    prepared_by = db.Column(db.String(100))
    approved_by = db.Column(db.String(100))
    
    # status = db.Column(db.String(20), default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<IFAForm {self.ifa_no}>'

# --- Helpers ---
@app.template_filter('currency')
def currency_filter(value):
    if value is None:
        return ""
    try:
        val = float(value)
        return "{:,.2f}".format(val)
    except:
        return value

def get_next_ifa_number():
    last_form = IFAForm.query.order_by(IFAForm.id.desc()).first()
    if not last_form:
        return 'IFA260001'
    
    try:
        # Expected format IFA26XXXX
        last_no = last_form.ifa_no
        # Extract numeric part (assuming standard format IFA26 + 4 digits)
        if last_no.startswith('IFA26'):
            num_part = int(last_no[5:])
            new_num = num_part + 1
            return f'IFA26{str(new_num).zfill(4)}'
        else:
             # Fallback if format is different somehow
            return 'IFA260001'
    except:
        return 'IFA260001'

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---

# --- Auth Routes & Decorators ---

# Token callback to add claims (role)
@jwt.additional_claims_loader
def add_claims_to_access_token(identity):
    user = User.query.get(identity)
    return {'role': user.role} if user else {}

# JWT Error Handlers
@jwt.unauthorized_loader
def unauthorized_callback(callback):
    flash('You must be logged in to view this page.')
    return redirect(url_for('login'))

@jwt.invalid_token_loader
def invalid_token_callback(callback):
    flash('Invalid session, please login again.')
    resp = redirect(url_for('login'))
    unset_jwt_cookies(resp)
    return resp

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    flash('Session has expired, please login again.')
    resp = redirect(url_for('login'))
    unset_jwt_cookies(resp)
    return resp

# Decorators
def role_required(required_role):
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorator(*args, **kwargs):
            claims = get_jwt()
            if claims.get('role') != required_role:
                 # Allow ADMIN to access USER routes if needed, or implement hierarchy?
                 # For now strict role check as per requirements.
                 # Actually prompt says: ADMIN can create USERS... 
                 # But specific "Protected Routes" says "Block unauthorized role access".
                 # I'll implement strict exact match or hierarchy if needed. 
                 # Goal: ADMIN can view ALL... USER can view OWN.
                 # Let's implementation hierarchy: ADMIN > USER for some things?
                 # No, requirement 5 says "USER: Can submit... ADMIN: Can view ALL".
                 # So simple check is fine.
                if required_role == 'ADMIN' and claims.get('role') == 'ADMIN':
                    pass
                elif required_role == 'USER' and claims.get('role') in ['USER', 'ADMIN', 'CEO']: 
                    # If USER role required, likely means "Logged in generic access" or specific? 
                    # Actually, usually decorators are strict. 
                    # I'll stick to strict @role_required for critical things, or just check role inside view.
                    # Or better: @admin_required, @ceo_required.
                    pass
                else: 
                     if claims.get('role') == required_role:
                         pass
                     else:
                        return "Access Denied: You do not have permission to view this page.", 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper

def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        claims = get_jwt()
        if claims.get('role') != 'ADMIN':
            return "Access Denied: Admin privileges required.", 403
        return fn(*args, **kwargs)
    return wrapper

def ceo_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        claims = get_jwt()
        if claims.get('role') not in ['CEO', 'ADMIN']: # Allow Admin to see CEO views? Or just CEO? Prompt says CEO dashboard.
             # Prompt: CEO Read-only access.
             if claims.get('role') == 'CEO':
                 pass
             else:
                 return "Access Denied: CEO privileges required.", 403
        return fn(*args, **kwargs)
    return wrapper

@app.route('/.well-known/appspecific/com.chrome.devtools.json')
def chrome_devtools_handler():
    return jsonify({}), 200

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/ifa', methods=['GET'])
@jwt_required()
def ifa_form():
    next_ifa_no = get_next_ifa_number()
    return render_template('ifa_form.html', ifa=None, is_admin=False, next_ifa_no=next_ifa_no)

@app.route('/ifa/submit', methods=['POST'])
@role_required('USER')
def submit_ifa():
    current_user_id = int(get_jwt_identity())
    try:
        def get_float(name):
            val = request.form.get(name, '').replace(',', '').strip()
            if not val: return 0.0
            try:
                return float(val)
            except ValueError:
                return 0.0
            
        def get_date(name):
            val = request.form.get(name)
            if not val: return None
            try:
                return datetime.strptime(val, '%Y-%m-%d').date()
            except:
                return None

        # Generate Sequential IFA No (Ignoring frontend input for safety/uniqueness)
        # Note: In high currency, we might need DB locking, but for this app:
        # We re-calculate right before save.
        next_ifa_no = get_next_ifa_number()
        
        # Double check uniqueness loop (simple race condition handling)
        while IFAForm.query.filter_by(ifa_no=next_ifa_no).first():
             # If exists (rare race condition), specific logic to increment?
             # get_next_ifa_number depends on 'last entry'. 
             # If DB shows last entry X, we generate X+1. 
             # If someone committed X+1 just now, get_next_ifa_number will see X+1 and return X+2.
             # So re-calling helper should be enough.
             next_ifa_no = get_next_ifa_number()

        new_ifa = IFAForm(
            ifa_no=next_ifa_no,
            ifa_date=get_date('ifa_date'),
            to_person=request.form.get('to_person'),
            
            po_no=request.form.get('po_no'),
            po_date=get_date('po_date'),
            supplier_name=request.form.get('supplier_name'),
            po_basic_price=get_float('po_basic_price'),
            gst_on_basic=get_float('gst_on_basic'),
            total_po_value=get_float('total_po_value'),
            
            service_name=request.form.get('service_name'),
            project_name=request.form.get('project_name'),
            payment_terms=request.form.get('payment_terms'),
            
            invoice_claimed=get_float('invoice_claimed'),
            proforma_invoice_no=request.form.get('proforma_invoice_no'),
            passed_for=get_float('passed_for'),
            proforma_invoice_date=get_date('proforma_invoice_date'),
            advance_paid=request.form.get('advance_paid'),
            delivery_status=request.form.get('delivery_status'),
            remark=request.form.get('remark'),
            
            amount_basic=get_float('amount_basic'),
            amount_gst=get_float('amount_gst'),
            amount_total=get_float('amount_total'),
            amount_40_percent=get_float('amount_40_percent'),
            
            prepared_by=request.form.get('prepared_by'),
            
            # Initial status Pending
            # status='Pending',
            user_id=current_user_id
        )
        
        db.session.add(new_ifa)
        db.session.commit()
        
        return jsonify({
            'message': 'Form Submitted Successfully',
            'ifa_no': new_ifa.ifa_no,
            'id': new_ifa.id
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/ifa/<int:id>/download_doc')
@jwt_required()
def download_doc(id):
    ifa = IFAForm.query.get_or_404(id)
    current_user_id = int(get_jwt_identity())
    claims = get_jwt()
    role = claims.get('role')
    
    # Access Control - User can download own, Admin/CEO can download all
    if role == 'USER' and ifa.user_id != current_user_id:
        return "Access Denied", 403

    # Encode images to base64
    def get_base64_image(filename):
        try:
            with open(os.path.join(app.static_folder, 'images', filename), "rb") as image_file:
                return base64.b64encode(image_file.read()).decode('utf-8')
        except Exception as e:
            print(f"Error loading image {filename}: {e}")
            return ""

    simon_logo = get_base64_image("simon_logo.png")
    adventz_logo = get_base64_image("adventz_logo.png")

    
    # Render template (Reusable for Print View)
    return render_template('ifa_form.html', 
                           ifa=ifa, 
                           is_doc=True, 
                           simon_logo_b64=simon_logo, 
                           adventz_logo_b64=adventz_logo)



@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        full_name = request.form.get('full_name')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        phone_number = request.form.get('phone_number')
        
        # Validation
        if not username.endswith('@adventz.com'):
            flash('Email must end with @adventz.com')
            return render_template('signup.html')
        
        if password != confirm_password:
            flash('Passwords do not match')
            return render_template('signup.html')
            
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return render_template('signup.html')
            
        # Create User
        new_user = User(
            username=username,
            full_name=full_name,
            phone_number=phone_number,
            role='USER' # Default role
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
        
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Check if user is already logged in
    verify_jwt_in_request(optional=True)
    if get_jwt_identity():
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        if user:
            if user.role == 'ADMIN':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'CEO':
                return redirect(url_for('ceo_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            # Create JWT
            access_token = create_access_token(identity=str(user.id))
            
            # Redirect based on role
            if user.role == 'ADMIN':
                resp = redirect(url_for('admin_dashboard'))
            elif user.role == 'CEO':
                resp = redirect(url_for('ceo_dashboard'))
            else:
                resp = redirect(url_for('user_dashboard'))
            
            set_access_cookies(resp, access_token)
            return resp
        else:
            flash('Invalid username or password')
            return render_template('login.html')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    resp = redirect(url_for('login'))
    unset_jwt_cookies(resp)
    return resp

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    ifas = IFAForm.query.order_by(IFAForm.created_at.desc()).all()
    return render_template('admin_dashboard.html', ifas=ifas)

# --- Dropdown Management Routes ---
@app.route('/admin/dropdown-options')
@admin_required
def get_all_dropdown_options():
    """Get all dropdown options grouped by category"""
    options = DropdownOption.query.filter_by(is_active=True).order_by(DropdownOption.category, DropdownOption.display_order).all()
    
    # Group by category
    grouped = {}
    for opt in options:
        if opt.category not in grouped:
            grouped[opt.category] = []
        grouped[opt.category].append({
            'id': opt.id,
            'value': opt.value,
            'display_order': opt.display_order
        })
    
    return jsonify(grouped)

@app.route('/admin/dropdown-option/add', methods=['POST'])
@admin_required
def add_dropdown_option():
    """Add a new dropdown option"""
    try:
        data = request.get_json()
        category = data.get('category')
        value = data.get('value')
        
        if not category or not value:
            return jsonify({'error': 'Category and value are required'}), 400
        
        # Get max display_order for this category
        max_order = db.session.query(db.func.max(DropdownOption.display_order)).filter_by(category=category).scalar() or 0
        
        new_option = DropdownOption(
            category=category,
            value=value,
            display_order=max_order + 1
        )
        
        db.session.add(new_option)
        db.session.commit()
        
        return jsonify({
            'id': new_option.id,
            'category': new_option.category,
            'value': new_option.value,
            'display_order': new_option.display_order
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/admin/dropdown-option/<int:id>/edit', methods=['PUT'])
@admin_required
def edit_dropdown_option(id):
    """Edit an existing dropdown option"""
    try:
        option = DropdownOption.query.get_or_404(id)
        data = request.get_json()
        
        if 'value' in data:
            option.value = data['value']
        
        db.session.commit()
        
        return jsonify({
            'id': option.id,
            'category': option.category,
            'value': option.value,
            'display_order': option.display_order
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/admin/dropdown-option/<int:id>/delete', methods=['DELETE'])
@admin_required
def delete_dropdown_option(id):
    """Delete a dropdown option (soft delete)"""
    try:
        option = DropdownOption.query.get_or_404(id)
        option.is_active = False
        db.session.commit()
        
        return jsonify({'message': 'Option deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/api/dropdown-options/<category>')
@jwt_required()
def get_dropdown_options_by_category(category):
    """Public API to get dropdown options by category for forms"""
    options = DropdownOption.query.filter_by(category=category, is_active=True).order_by(DropdownOption.display_order).all()
    
    return jsonify([{
        'id': opt.id,
        'value': opt.value
    } for opt in options])


@app.route('/ceo/dashboard')
@ceo_required
def ceo_dashboard():
    ifas = IFAForm.query.order_by(IFAForm.created_at.desc()).all()
    return render_template('ceo_dashboard.html', ifas=ifas)

@app.route('/user/dashboard')
@role_required('USER')
def user_dashboard():
    current_user_id = int(get_jwt_identity())
    ifas = IFAForm.query.filter_by(user_id=current_user_id).order_by(IFAForm.created_at.desc()).all()
    return render_template('user_dashboard.html', ifas=ifas)

@app.route('/ifa/<int:id>')
@jwt_required()
def view_ifa(id):
    ifa = IFAForm.query.get_or_404(id)
    current_user_id = int(get_jwt_identity())
    claims = get_jwt()
    role = claims.get('role')
    
    # Access Control
    if role == 'USER' and ifa.user_id != current_user_id:
        return "Access Denied: You can only view your own forms.", 403
        
    is_admin = (role == 'ADMIN')
    is_ceo = (role == 'CEO')
    
    return render_template('ifa_form.html', ifa=ifa, is_admin=is_admin, is_ceo=is_ceo, user_role=role)

@app.route('/user/ifa/<int:id>/update', methods=['POST'])
@role_required('USER')
def update_my_ifa(id):
    ifa = IFAForm.query.get_or_404(id)
    current_user_id = int(get_jwt_identity())
    
    # Strict Access Control
    if ifa.user_id != current_user_id:
        return "Access Denied: You cannot edit this form.", 403
        
    # if ifa.status != 'Pending':
    #     return "Access Denied: You can only edit Pending forms.", 403
        
    try:
        def get_float(name):
            val = request.form.get(name, '').replace(',', '').strip()
            if not val: return 0.0
            try:
                return float(val)
            except ValueError:
                return 0.0
            
        def get_date(name):
            val = request.form.get(name)
            if not val: return None
            try:
                return datetime.strptime(val, '%Y-%m-%d').date()
            except:
                return None

        # Update fields (Similar to admin update but NO STATUS/APPROVAL changes)
        # Note: IFA No is usually fixed, but if user wants to correct it? 
        # Usually IFA No is auto-generated and shouldn't change. Admin can, User shouldn't?
        # Plan said: "Update all data fields". Let's allow editing standard fields.
        
        # ifa.ifa_no = request.form.get('ifa_no') # Keep IFA No constant for user safety? Or allow?
        # Let's allow it as per "request to have admin function in user section".
        # But safest is to maybe keep it read-only for user? 
        # The form has it readonly by default in HTML for new forms mostly.
        # Let's simpler allow it to be safe.
        
        ifa.ifa_date = get_date('ifa_date')
        ifa.to_person = request.form.get('to_person')
        
        ifa.po_no = request.form.get('po_no')
        ifa.po_date = get_date('po_date')
        ifa.supplier_name = request.form.get('supplier_name')
        ifa.po_basic_price = get_float('po_basic_price')
        ifa.gst_on_basic = get_float('gst_on_basic')
        ifa.total_po_value = get_float('total_po_value')
        
        ifa.service_name = request.form.get('service_name')
        ifa.project_name = request.form.get('project_name')
        ifa.payment_terms = request.form.get('payment_terms')
        
        ifa.invoice_claimed = get_float('invoice_claimed')
        ifa.proforma_invoice_no = request.form.get('proforma_invoice_no')
        ifa.passed_for = get_float('passed_for')
        ifa.proforma_invoice_date = get_date('proforma_invoice_date')
        ifa.advance_paid = request.form.get('advance_paid')
        ifa.delivery_status = request.form.get('delivery_status')
        ifa.remark = request.form.get('remark')
        
        ifa.amount_basic = get_float('amount_basic')
        ifa.amount_gst = get_float('amount_gst')
        ifa.amount_total = get_float('amount_total')
        ifa.amount_40_percent = get_float('amount_40_percent')
        
        ifa.prepared_by = request.form.get('prepared_by')
        # ifa.approved_by = ... # User cannot approve
        
        db.session.commit()

        return jsonify({
            'message': 'Form Updated Successfully',
            'id': ifa.id
        })
        # flash('Form updated successfully.')
        # return redirect(url_for('user_dashboard'))
        
    except Exception as e:
        return f"Error updating: {str(e)}", 400

@app.route('/admin/ifa/<int:id>/update', methods=['POST'])
@admin_required
def update_ifa(id):
    ifa = IFAForm.query.get_or_404(id)
    
    try:
        def get_float(name):
            val = request.form.get(name, '').replace(',', '').strip()
            if not val: return 0.0
            try:
                return float(val)
            except ValueError:
                return 0.0
            
        def get_date(name):
            val = request.form.get(name)
            if not val: return None
            try:
                return datetime.strptime(val, '%Y-%m-%d').date()
            except:
                return None

        # Update fields
        ifa.ifa_no = request.form.get('ifa_no')
        ifa.ifa_date = get_date('ifa_date')
        ifa.to_person = request.form.get('to_person')
        
        ifa.po_no = request.form.get('po_no')
        ifa.po_date = get_date('po_date')
        ifa.supplier_name = request.form.get('supplier_name')
        ifa.po_basic_price = get_float('po_basic_price')
        ifa.gst_on_basic = get_float('gst_on_basic')
        ifa.total_po_value = get_float('total_po_value')
        
        ifa.service_name = request.form.get('service_name')
        ifa.project_name = request.form.get('project_name')
        ifa.payment_terms = request.form.get('payment_terms')
        
        ifa.invoice_claimed = get_float('invoice_claimed')
        ifa.proforma_invoice_no = request.form.get('proforma_invoice_no')
        ifa.passed_for = get_float('passed_for')
        ifa.proforma_invoice_date = get_date('proforma_invoice_date')
        ifa.advance_paid = request.form.get('advance_paid')
        ifa.delivery_status = request.form.get('delivery_status')
        ifa.remark = request.form.get('remark')
        
        ifa.amount_basic = get_float('amount_basic')
        ifa.amount_gst = get_float('amount_gst')
        ifa.amount_total = get_float('amount_total')
        ifa.amount_40_percent = get_float('amount_40_percent')
        
        ifa.prepared_by = request.form.get('prepared_by')
        ifa.approved_by = request.form.get('approved_by')
        
        # Admin specific
        # ifa.status = request.form.get('status')
        
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
        
    except Exception as e:
        return f"Error updating: {str(e)}", 400

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
