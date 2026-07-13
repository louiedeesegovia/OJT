from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
from database.models import db, BorrowTracker, Student, Office, Faculty, Category, Inventory, EquipmentApprover, Reports, Itemkind
from sqlalchemy import func, or_
from sqlalchemy.orm import joinedload, contains_eager
from forms import StudentLoginForm, StudentRegisterForm, LoginForm, SignupForm, BorrowForm, InventoryForm, OfficeForm, CategoryForm, FacultyForm, StudentFollowUpForm
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone, timedelta, date
from functools import wraps
from dotenv import load_dotenv
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
import random
import secrets
import string
import pandas as pd
import re
import os
import io
import csv
import zipfile

load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))


app = Flask(__name__)


def get_student_identifier():
    if 'student' in session:
        return f"student{session['student']['id']}"
    return get_remote_address()

limiter = Limiter(
    get_student_identifier,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = not app.debug

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')

mail = Mail(app)

# OTP helper functions
def generate_otp():
    return ''.join(secrets.choice(string.digits) for _ in range(6))

def send_verification_email(email, otp, name):
    try:
        msg = Message(
            subject='Your Verification Code — HIRaM System',
            recipients=[email]
        )
        msg.body = f"""Hello {name},

Your verification code is: {otp}

This code expires in 10 minutes.

If you did not request this, please ignore this email.

— HIRaM System team
"""
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Mail error: {e}")
        return False

# Check session expiry on every student request
@app.before_request
def check_session_expiry():
    if 'student' in session:
        last_active = session.get('last_active')
        now = datetime.now(timezone.utc).timestamp()

        if last_active and (now - last_active) > 1800:  # 30 minutes
            session.pop('student', None)
            flash('Your session has expired. Please log in again.', 'warning')
            return redirect(url_for('student_information'))

        session['last_active'] = now
        session.permanent = True

cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 300})

db.init_app(app)

with app.app_context():
    db.create_all()

#role based  decorator
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'faculty' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('admin'))
        role = session['faculty'].get('role')
        if role not in ['master_admin', 'approver']:
            flash('Access denied.', 'danger')
            session.pop('faculty', None)
            return redirect(url_for('admin'))
        return f(*args, **kwargs)
    return decorated

def master_admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'faculty' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('admin'))
        if session['faculty'].get('role') != 'master_admin':
            flash('Access denied. Master admin only.', 'danger')
            return redirect(url_for('admin_dashboard'))
        return f(*args, **kwargs)
    return decorated

# Routes for admin and student interfaces/landing page
@app.route('/')
def index():
    return render_template('index.html')

############# OTP verification routes #############
@app.route('/verify-otp', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def verify_otp():
    # Must have a pending verification in session
    if 'pending_verification' not in session:
        flash('No verification pending.', 'warning')
        return redirect(url_for('student_information'))

    if request.method == 'POST':
        entered_otp = request.form.get('otp', '').strip()
        pending = session['pending_verification']

        # Check expiry — 10 minutes
        created_at = pending.get('created_at')
        now = datetime.now(timezone.utc).timestamp()
        if now - created_at > 600:
            session.pop('pending_verification', None)
            flash('OTP expired. Please register again.', 'danger')
            return redirect(url_for('student_information'))

        if entered_otp != pending['otp']:
            flash('Incorrect OTP. Please try again.', 'danger')
            return render_template('verify-otp.html')

        # OTP correct — activate account
        user_type = pending.get('user_type')

        if user_type == 'student':
            student = Student.query.get(pending['user_id'])
            if student:
                # mark verified and redirect to login/info page (do not auto-login)
                student.is_verified = True
                db.session.commit()
                session.pop('pending_verification', None)
                flash('Email verified! You may now log in.', 'success')
                return redirect(url_for('student_information'))

        elif user_type == 'faculty':
            faculty = Faculty.query.get(pending['user_id'])
            if faculty:
                faculty.is_verified = True
                db.session.commit()
                session.pop('pending_verification', None)
                flash('Email verified! You can now log in.', 'success')
                return redirect(url_for('admin'))

        flash('Something went wrong.', 'danger')
        return redirect(url_for('student_information'))

    return render_template('verify-otp.html')


@app.route('/verify-otp/resend', methods=['POST'])
@limiter.limit("5 per minute")
def resend_otp():
    if 'pending_verification' not in session:
        flash('No verification pending.', 'warning')
        return redirect(url_for('student_information'))

    pending = session['pending_verification']
    new_otp = generate_otp()
    pending['otp'] = new_otp
    pending['created_at'] = datetime.now(timezone.utc).timestamp()
    session['pending_verification'] = pending

    sent = send_verification_email(pending['email'], new_otp, pending['name'])
    if sent:
        flash('A new OTP has been sent to your email.', 'success')
    else:
        flash('Failed to send email. Please try again.', 'danger')

    return redirect(url_for('verify_otp'))

######################Admin login#########################
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'faculty' in session:
        return redirect(url_for('admin_dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        faculty = Faculty.query.filter_by(username=form.username.data).first()

        if faculty:
            # Check lockout
            now = datetime.now(timezone.utc)
            if faculty.locked_until:
                locked_until = faculty.locked_until.replace(tzinfo=timezone.utc)
                if now < locked_until:
                    remaining = int((locked_until - now).total_seconds() / 60) + 1
                    flash(f'Account locked. Try again in {remaining} minute(s).', 'danger')
                    return render_template('admin-login.html', form=form)
                else:
                    faculty.failed_attempts = 0
                    faculty.locked_until = None
                    db.session.commit()

            if check_password_hash(faculty.password, form.password.data):
                if faculty.role not in ['master_admin', 'approver']:
                    flash('You do not have admin access.', 'danger')
                    return render_template('admin-login.html', form=form)

                if not faculty.is_verified:
                    flash('Please verify your email before logging in.', 'warning')
                    return render_template('admin-login.html', form=form)

                # Reset on successful login
                faculty.failed_attempts = 0
                faculty.locked_until = None
                db.session.commit()

                session['faculty'] = {
                    'id': faculty.faculty_id,
                    'name': faculty.faculty_nm,
                    'username': faculty.username,
                    'role': faculty.role
                }
                return redirect(url_for('admin_dashboard'))

            else:
                faculty.failed_attempts += 1
                if faculty.failed_attempts >= MAX_FAILED_ATTEMPTS:
                    faculty.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
                    db.session.commit()
                    flash(f'Too many failed attempts. Account locked for {LOCKOUT_MINUTES} minutes.', 'danger')
                else:
                    remaining_attempts = MAX_FAILED_ATTEMPTS - faculty.failed_attempts
                    db.session.commit()
                    flash(f'Invalid password. {remaining_attempts} attempt(s) remaining.', 'danger')
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('admin-login.html', form=form)

@app.route('/admin/logout')
def admin_logout():
    session.pop('faculty', None)
    flash('Logged out successfully.', 'info')
    return redirect(url_for('admin'))

@app.route('/admin/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        existing_user = Faculty.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists', 'danger')
            return render_template('admin-signup.html', form=form)

        email = form.email.data.strip().lower()
        existing_email = Faculty.query.filter_by(email=email).first()
        if existing_email:
            flash('Email already registered.', 'danger')
            return render_template('admin-signup.html', form=form)

        office = Office.query.first()
        if not office:
            office = Office(office_nm="Default Office", office_loc="Main Building")
            db.session.add(office)
            db.session.commit()

        existing_account = Faculty.query.count()
        role = 'master_admin' if existing_account == 0 else 'faculty'

        new_faculty = Faculty(
            username=form.username.data,
            password=generate_password_hash(form.password.data),
            faculty_nm=form.username.data,
            office_id=office.office_id,
            role=role,
            email=email,
            is_verified=False
        )
        db.session.add(new_faculty)
        db.session.commit()

        # Send OTP
        otp = generate_otp()
        sent = send_verification_email(email, otp, new_faculty.faculty_nm)

        if not sent:
            db.session.delete(new_faculty)
            db.session.commit()
            flash('Failed to send verification email.', 'danger')
            return render_template('admin-signup.html', form=form)

        session['pending_verification'] = {
            'otp': otp,
            'user_id': new_faculty.faculty_id,
            'user_type': 'faculty',
            'email': email,
            'name': new_faculty.faculty_nm,
            'created_at': datetime.now(timezone.utc).timestamp()
        }

        flash(f'A verification code has been sent to {email}.', 'info')
        return redirect(url_for('verify_otp'))

    return render_template('admin-signup.html', form=form)

@app.route('/admin/profile/edit', methods=['POST'])
@admin_required
def edit_profile():
    faculty_id = session['faculty']['id']
    fac = Faculty.query.get_or_404(faculty_id)

    faculty_nm = request.form.get('faculty_nm', '').strip()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    confirm_password = request.form.get('confirm_password', '').strip()

    # Check username not taken by someone else
    existing = Faculty.query.filter_by(username=username).first()
    if existing and existing.faculty_id != faculty_id:
        flash('Username already taken.', 'danger')
        return redirect(request.referrer or url_for('admin_dashboard'))

    if password:
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(request.referrer or url_for('admin_dashboard'))
        fac.password = generate_password_hash(password)

    fac.faculty_nm = faculty_nm
    fac.username = username
    db.session.commit()

    # Update session
    session['faculty'] = {
        'id': fac.faculty_id,
        'name': fac.faculty_nm,
        'username': fac.username,
        'role': fac.role
    }

    flash('Profile updated successfully.', 'success')
    return redirect(request.referrer or url_for('admin_dashboard'))

#########################Admin dashboard and management pages#########################
#helper function to check for overdue items and update their status
def check_overdue():
    today = date.today()
    # Find borrow records that are past their return date and still marked approved/borrowed
    overdue_records = (
        BorrowTracker.query
        .options(joinedload(BorrowTracker.student), joinedload(BorrowTracker.inventory))
        .filter(
            BorrowTracker.status.in_(['approved', 'borrowed']),
            BorrowTracker.return_date < today
        )
        .all()
    )

    for record in overdue_records:
        # Transition status and mark inventory unavailable
        record.status = 'overdue'
        if record.inventory:
            record.inventory.is_available = False

        # Send a single overdue email notification when we transition to overdue
        try:
            student = record.student
            inv = record.inventory
            if student and student.email:
                subject = f"Overdue Notice: {inv.inventory_nm if inv else 'Item'}"
                msg = Message(subject=subject, recipients=[student.email])
                msg.body = f"""Hello {student.student_nm or 'Student'},

The item '{inv.inventory_nm if inv else 'N/A'}' you borrowed was due on {record.return_date.strftime('%Y-%m-%d')}.

Please return it as soon as possible or contact the office to arrange a resolution.

If you have already returned the item, please ignore this message.

— CEGS Faculty
"""
                mail.send(msg)
        except Exception as e:
            # Log and continue without interrupting the process
            print(f"Failed sending overdue email for borrow_id={getattr(record, 'borrow_id', 'N/A')}: {e}")

    db.session.commit()

@app.route('/admin/dashboard', methods=['GET', 'POST'])
@admin_required
def admin_dashboard():
    check_overdue()  # Ensure overdue items are updated before showing dashboard stats

    total_items = Inventory.query.count()
    pending_count = BorrowTracker.query.filter_by(status='pending').count()
    overdue_count = BorrowTracker.query.filter_by(status='overdue').count()

    recent_requests = (
        BorrowTracker.query
        .options(
            joinedload(BorrowTracker.student),
            joinedload(BorrowTracker.inventory)
        )
        .filter(BorrowTracker.status == 'pending')
        .order_by(BorrowTracker.request_date.desc())
        .limit(5)
        .all()
    )

    recent_activities = (
    BorrowTracker.query
    .options(
        joinedload(BorrowTracker.student),
        joinedload(BorrowTracker.inventory)
    )
    .order_by(BorrowTracker.request_date.desc())
    .limit(10)
    .all()
    )

    return render_template(
        'admin-dashboard.html',
        total_items=total_items,
        pending_count=pending_count,
        overdue_count=overdue_count,
        recent_requests=recent_requests,
        recent_activities=recent_activities
    )

@app.route('/admin/borrowed-items', methods=['GET', 'POST'])
@admin_required
def borrowed_items():
    q = request.args.get('q', '').strip()
    role = session['faculty'].get('role')
    faculty_id = session['faculty']['id']

    if role == 'approver':
        assigned_offices = EquipmentApprover.query.filter_by(faculty_id=faculty_id).all()
        assigned_office_ids = [a.office_id for a in assigned_offices]
        inventory_ids = [
            inv.inventory_id for inv in
            Inventory.query.filter(Inventory.office_id.in_(assigned_office_ids)).all()
        ]
        base_query = BorrowTracker.query.filter(
            BorrowTracker.status.in_(['approved', 'borrowed', 'overdue']),
            BorrowTracker.inventory_id.in_(inventory_ids)
        )
    else:
        base_query = BorrowTracker.query.filter(
            BorrowTracker.status.in_(['approved', 'borrowed', 'overdue'])
        )

    if q:
        items = (
            base_query
            .join(BorrowTracker.student)
            .options(
                contains_eager(BorrowTracker.student),
                joinedload(BorrowTracker.inventory)
            )
            .filter(
                or_(
                    Student.student_nm.ilike(f"%{q}%"),
                    Student.student_number.ilike(f"%{q}%")
                )
            )
            .all()
        )
    else:
        items = (
            base_query
            .options(
                joinedload(BorrowTracker.student),
                joinedload(BorrowTracker.inventory)
            )
            .all()
        )

    return render_template('borrowed-items.html', items=items, q=q)

@app.route('/admin/borrowed-items/return/<int:borrow_id>', methods=['POST'])
@admin_required
def mark_returned(borrow_id):
    borrow = BorrowTracker.query.get_or_404(borrow_id)
    returned_condition = request.form.get('returned_condition', 'functional')
    return_remarks = request.form.get('return_remarks', '').strip()
    report_type = request.form.get('report_type', 'damaged').strip()
    report_description = request.form.get('report_description', '').strip()

    borrow.status = 'returned'
    borrow.inventory.inventory_condition = returned_condition
    borrow.inventory.is_available = returned_condition == 'functional'

    if return_remarks:
        existing = borrow.remarks or ''
        borrow.remarks = f"{existing} | Return note: {return_remarks}".strip(' |')

    # Auto-file report if damaged or lost
    if returned_condition in ['non-functional', 'lost']:
        report = Reports(
            borrow_id=borrow.borrow_id,
            inventory_id=borrow.inventory_id,
            student_id=borrow.student_id,
            report_type='lost' if returned_condition == 'lost' else 'damaged',
            description=report_description or return_remarks or 'No description provided.'
        )
        db.session.add(report)

    db.session.commit()
    cache.clear()

    if returned_condition == 'functional':
        flash('Item marked as returned and available.', 'success')
    elif returned_condition == 'lost':
        flash('Item marked as lost. Report has been filed.', 'danger')
    else:
        flash('Item marked as returned but reported as damaged. Report filed.', 'warning')

    return redirect(url_for('borrowed_items'))

@app.route('/admin/inventory', methods=['GET', 'POST'])
@admin_required
def inventory():
    add_form = InventoryForm()
    office_list = Office.query.all()
    itemkind_list = Itemkind.query.all()

    if add_form.validate_on_submit():
        cat_name = add_form.category.data.strip()
        category = Category.query.filter_by(category_nm=cat_name).first()
        if not category:
            category = Category(category_nm=cat_name)
            db.session.add(category)
            db.session.commit()

        office = Office.query.first()
        if not office:
            office = Office(office_nm="Default Office", office_loc="Main Building")
            db.session.add(office)
            db.session.commit()

        itemkind_nm = add_form.itemkind.data.strip() if add_form.itemkind.data else None
        itemkind = None
        if itemkind_nm:
            itemkind = Itemkind.query.filter_by(itemkind_nm=itemkind_nm).first()
            if not itemkind:
                itemkind = Itemkind(itemkind_nm=itemkind_nm)
                db.session.add(itemkind)
                db.session.commit()

        new_inv = Inventory(
            inventory_nm=add_form.name.data.strip(),
            inventory_desc=add_form.desc.data.strip() if add_form.desc.data else None,
            inventory_condition=add_form.condition.data.strip(),
            serial_number=add_form.serial.data.strip(),
            office_id=office.office_id,
            category_id=category.category_id,
            itemkind_id=itemkind.itemkind_id if itemkind else None
        )

        db.session.add(new_inv)
        db.session.commit()
        flash('Inventory item added.', 'success')
        return redirect(url_for('inventory'))

    
    q = request.args.get('q', '').strip()
    
    page = request.args.get('page', 1, type=int)
    per_page = 20 

    # Build the query depending on whether the user is searching or not
    if q:
        inv_query = Inventory.query.outerjoin(Category)
        inv_query = inv_query.filter(
            or_(
                Inventory.inventory_nm.ilike(f"%{q}%"),
                Inventory.serial_number.ilike(f"%{q}%"),
                Category.category_nm.ilike(f"%{q}%")
            )
        )
    else:
        inv_query = Inventory.query

    paginated_inventories = inv_query.paginate(page=page, per_page=per_page, error_out=False)

    
    items = []
    for inv in paginated_inventories.items:
        items.append({
            'id': inv.inventory_id,
            'name': inv.inventory_nm,
            'category': inv.category.category_nm if inv.category else '',
            'desc': inv.inventory_desc,
            'office': inv.office.office_nm if inv.office else '',
            'condition': inv.inventory_condition,
            'serial': inv.serial_number,
            'available': inv.is_available,
            'status': 'Available' if inv.is_available else 'Borrowed',
            'itemkind_id': inv.itemkind_id or '',
            'itemkind': next((k.itemkind_nm for k in itemkind_list if k.itemkind_id == inv.itemkind_id), 'N/A')
        })

    return render_template('manage-inventory.html',
                            items=items,
                            add_form=add_form,
                            q=q, 
                            office_list=office_list, 
                            itemkind_list=itemkind_list,
                            current_page=paginated_inventories.page,   
                            total_pages=paginated_inventories.pages
                            )   


@app.route('/admin/inventory/edit/<int:item_id>', methods=['POST'])
@admin_required
def edit_inventory(item_id):
    form = InventoryForm()
    if form.validate_on_submit():
        inv = Inventory.query.get_or_404(item_id)
        inv.inventory_nm = form.name.data.strip()
        inv.inventory_condition = form.condition.data.strip()
        inv.serial_number = form.serial.data.strip()
        inv.inventory_desc = form.desc.data.strip() if form.desc.data else None
        inv.is_available = form.condition.data.strip() == 'functional'

        cat_name = form.category.data.strip()
        category = Category.query.filter_by(category_nm=cat_name).first()
        if not category:
            category = Category(category_nm=cat_name)
            db.session.add(category)
            db.session.commit()
        inv.category_id = category.category_id
        inv.office_id = form.office.data

        # Handle itemkind
        itemkind_nm = form.itemkind.data.strip() if form.itemkind.data else None
        if itemkind_nm:
            itemkind = Itemkind.query.filter_by(itemkind_nm=itemkind_nm).first()
            if not itemkind:
                itemkind = Itemkind(itemkind_nm=itemkind_nm)
                db.session.add(itemkind)
                db.session.commit()
            inv.itemkind_id = itemkind.itemkind_id
        else:
            inv.itemkind_id = None

        db.session.commit()
        cache.clear()
        flash('Inventory item updated.', 'success')
    else:
        print("Form errors:", form.errors)
        flash('Failed to update item.', 'danger')

    return redirect(url_for('inventory'))

@app.route('/admin/inventory/delete/<int:item_id>', methods=['POST'])
@admin_required
def delete_inventory(item_id):
    inv = Inventory.query.get_or_404(item_id)
    BorrowTracker.query.filter_by(inventory_id=inv.inventory_id).delete()
    db.session.delete(inv)
    db.session.commit()
    cache.clear()
    flash('Inventory item deleted.', 'success')
    return redirect(url_for('inventory'))


@app.route('/admin/inventory/import', methods=['POST'])
@admin_required
def import_inventory():
    file = request.files.get('csv_file')

    if not file or not file.filename.endswith('.csv'):
        flash('Please upload a valid CSV file.', 'danger')
        return redirect(url_for('inventory'))

    try:
        df = pd.read_csv(file)
        df = df.dropna(how='all')

        # Force strict serial number uniqueness within the file
        df['Serial Number (serial_number)'] = df['Serial Number (serial_number)'].astype(str)
        seen_serials = {}  # serial → row number
        duplicate_errors = []

        for index, row in df.iterrows():
            serial = str(row['Serial Number (serial_number)']).strip(',').strip()
            df.at[index, 'Serial Number (serial_number)'] = serial  # normalize it

            if serial in seen_serials:
                duplicate_errors.append(
                    f"Row {index + 2}: Serial '{serial}' is a duplicate of Row {seen_serials[serial]}."
                )
            else:
                seen_serials[serial] = index + 2  # store row number for error message

        if duplicate_errors:
            for msg in duplicate_errors:
                flash(msg, 'danger')
            flash('Import cancelled due to duplicate serial numbers in the file. Please fix and re-upload.', 'danger')
            return redirect(url_for('inventory'))

        inserted = 0
        skipped = []
        errors = []

        for index, row in df.iterrows():
            # ── Validate BEFORE entering the savepoint ──
            office_nm = str(row['Office Name (office_nm)']).strip()
            office = Office.query.filter_by(office_nm=office_nm).first()
            if not office:
                errors.append(f"Row {index + 2}: Office '{office_nm}' not found. Please create it first.")
                continue

            serial = str(row['Serial Number (serial_number)']).strip()
            existing = Inventory.query.filter_by(serial_number=serial).first()
            if existing:
                skipped.append(f"Row {index + 2}: Serial '{serial}' already exists.")
                continue

            valid_conditions = ['functional', 'non-functional', 'under-maintenance', 'under-repair']
            condition = str(row['Condition (inventory_condition)']).strip().lower()
            if condition not in valid_conditions:
                errors.append(f"Row {index + 2}: Invalid condition '{condition}'. Must be one of {valid_conditions}.")
                continue

            # ── Only enter savepoint if validation passed ──
            try:
                with db.session.begin_nested():
                    # Handle category
                    cat_name = str(row['Category (category_nm)']).strip()
                    category = Category.query.filter_by(category_nm=cat_name).first()
                    if not category:
                        category = Category(category_nm=cat_name)
                        db.session.add(category)
                        db.session.flush()

                    # Handle itemkind
                    itemkind_nm = str(row['Itemkind (itemkind_nm)']).strip()
                    itemkind = Itemkind.query.filter_by(itemkind_nm=itemkind_nm).first()
                    if not itemkind:
                        itemkind = Itemkind(itemkind_nm=itemkind_nm)
                        db.session.add(itemkind)
                        db.session.flush()

                    new_inv = Inventory(
                        inventory_nm=str(row['Inventory Name (inventory_nm)']).strip(),
                        inventory_desc=str(row['Description (inventory_desc)']).strip() if pd.notna(row['Description (inventory_desc)']) else None,
                        inventory_condition=condition,
                        serial_number=serial,
                        is_available=condition == 'functional',
                        itemkind_id=itemkind.itemkind_id,
                        office_id=office.office_id,
                        category_id=category.category_id
                    )
                    db.session.add(new_inv)
                    inserted += 1

            except Exception as e:
                # Only this row's savepoint is rolled back, others are safe
                errors.append(f"Row {index + 2}: {str(e)}")
                continue

        # Commit everything that succeeded
        db.session.commit()
        cache.clear()

        if inserted > 0:
            flash(f'Successfully imported {inserted} inventory items.', 'success')
        if skipped:
            for msg in skipped:
                flash(msg, 'warning')
        if errors:
            for msg in errors:
                flash(msg, 'danger')

    except Exception as e:
        flash(f'Failed to read CSV: {str(e)}', 'danger')

    return redirect(url_for('inventory'))

@app.route('/admin/inventory/template')
@admin_required
def download_template():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Inventory Name (inventory_nm)',
        'Description (inventory_desc)',
        'Condition (inventory_condition)',
        'Serial Number (serial_number)',
        'Category (category_nm)',
        'Itemkind (itemkind_nm)',
        'Office Name (office_nm)'  # changed from Office ID
    ])

    # Add existing offices as sample rows so users know what to type
    offices = Office.query.all()
    if offices:
        writer.writerow([
            'Sample Item',
            'Sample description',
            'functional',
            'SN-2024-001',
            'Sample Category',
            'Sample Group',
            offices[0].office_nm  # use first office name as example
        ])
        # Add a comment row showing all available offices
        writer.writerow(['# Available offices:'] + [o.office_nm for o in offices])
    
    output.seek(0)
    return Response(
        output,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=inventory_template.csv'}
    )



@app.route('/admin/requests')
@admin_required
def requests():
    q = request.args.get('q', '').strip()
    role = session['faculty'].get('role')
    faculty_id = session['faculty']['id']

    if role == 'approver':
        # Get all office IDs this approver is assigned to
        assigned_offices = EquipmentApprover.query.filter_by(
            faculty_id=faculty_id
        ).all()
        assigned_office_ids = [a.office_id for a in assigned_offices]

        # Get inventory IDs belonging to those offices
        inventory_ids = [
            inv.inventory_id for inv in 
            Inventory.query.filter(
                Inventory.office_id.in_(assigned_office_ids)
            ).all()
        ]

        base_query = BorrowTracker.query.filter(
            BorrowTracker.status == 'pending',
            BorrowTracker.inventory_id.in_(inventory_ids)
        )
    else:  # master_admin
        base_query = BorrowTracker.query.filter(
            BorrowTracker.status.in_(['pending', 'approver_approved'])
        )

    if q:
        pending_requests = (
            base_query
            .join(BorrowTracker.student)
            .options(
                contains_eager(BorrowTracker.student),
                joinedload(BorrowTracker.inventory)
            )
            .filter(
                or_(
                    Student.student_nm.ilike(f"%{q}%"),
                    Student.student_number.ilike(f"%{q}%")
                )
            )
            .all()
        )
    else:
        pending_requests = (
            base_query
            .options(
                joinedload(BorrowTracker.student),
                joinedload(BorrowTracker.inventory)
            )
            .all()
        )

    return render_template('manage-request.html', requests=pending_requests, q=q)



@app.route('/admin/requests/approve/<int:borrow_id>', methods=['POST'])
@admin_required
def approve_request(borrow_id):
    borrow = BorrowTracker.query.get_or_404(borrow_id)

    if borrow.status != 'pending':
        flash('Request already processed.', 'warning')
        return redirect(url_for('requests'))

    borrow.status = 'approved'
    borrow.approve_date = datetime.now(timezone.utc)
    borrow.remarks = request.form.get('remarks', '').strip() or borrow.remarks

    borrow_date = request.form.get('borrow_date')
    return_date = request.form.get('return_date')

    if borrow_date:
        borrow.borrow_date = datetime.strptime(borrow_date, '%Y-%m-%d').date()
    if return_date:
        borrow.return_date = datetime.strptime(return_date, '%Y-%m-%d').date()

    # Only mark unavailable if borrow date is today or already passed
    today = date.today()
    if borrow.borrow_date and borrow.borrow_date <= today:
        borrow.inventory.is_available = False

    db.session.commit()
    cache.clear()
    flash('Request approved.', 'success')
    return redirect(url_for('requests'))

@app.route('/admin/requests/reject/<int:borrow_id>', methods=['POST'])
@admin_required
def reject_request(borrow_id):
    borrow = BorrowTracker.query.get_or_404(borrow_id)
    if borrow.status != 'pending':
        flash('Request already processed.', 'warning')
        return redirect(url_for('requests'))

    borrow.status = 'rejected'
    borrow.remarks = request.form.get('remarks', '').strip() or borrow.remarks
    db.session.commit()
    cache.clear()
    flash('Request rejected.', 'info')
    return redirect(url_for('requests'))

@app.route('/admin/reports', methods=['GET', 'POST'])
@admin_required
@cache.cached(timeout=300, query_string=True)
def reports():
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    month_filter = request.args.get('month', '')

    query = BorrowTracker.query

    #month filter overrides date range if provided
    if month_filter:
        try:
            month_date = datetime.strptime(month_filter, '%Y-%m')
            first_day = month_date.replace(day=1)
            if month_date.month == 12:
                last_day = month_date.replace(day=1)
            else:
                last_day = month_date.replace(month=month_date.month + 1, day=1) - timedelta(days=1)
            query = query.filter(
                BorrowTracker.request_date >= first_day,
                BorrowTracker.request_date <= last_day + timedelta(days=1)
            )
        except ValueError:
            flash('Invalid month format. Please use YYYY-MM.', 'danger')
            pass
    elif date_from or date_to:
        if date_from:
            query = query.filter(BorrowTracker.request_date >= datetime.strptime(date_from, '%Y-%m-%d'))
        if date_to:
            query = query.filter(BorrowTracker.request_date <= datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1))

    total_borrows = query.count()
    damage_reports = Reports.query.count()

    most_borrowed = (
        db.session.query(Inventory.inventory_nm, func.count(BorrowTracker.inventory_id).label('borrow_count'))
        .join(BorrowTracker, BorrowTracker.inventory_id == Inventory.inventory_id)
        .group_by(Inventory.inventory_nm)
        .order_by(func.count(BorrowTracker.inventory_id).desc())
        .first()
    )

    today = datetime.now(timezone.utc).date()
    days = [(today - timedelta(days=i)) for i in range(6, -1, -1)]
    daily_counts = []
    max_count = 1

    for day in days:
        count = BorrowTracker.query.filter(func.date(BorrowTracker.request_date) == day).count()
        daily_counts.append({'day': day.strftime('%a'), 'count': count})
        if count > max_count:
            max_count = count

    for d in daily_counts:
        d['height'] = int((d['count'] / max_count) * 100) if max_count > 0 else 0

    # Equipment quantity summary
    itemkind_summary = []
    for kind in Itemkind.query.all():
        total = Inventory.query.filter_by(itemkind_id=kind.itemkind_id).count()
        available = Inventory.query.filter_by(itemkind_id=kind.itemkind_id, is_available=True).count()
        itemkind_summary.append({
            'name': kind.itemkind_nm,
            'total': total,
            'available': available,
            'borrowed': total - available
        })

    recent_reports = (Reports.query
                      .options(
                          joinedload(Reports.inventory),
                          joinedload(Reports.student),
                          joinedload(Reports.borrow)
                      )).order_by(Reports.report_date.desc()).all()

    return render_template(
        'reports.html',
        total_borrows=total_borrows,
        most_borrowed=most_borrowed.inventory_nm if most_borrowed else 'N/A',
        damage_reports=damage_reports,
        daily_counts=daily_counts,
        month_filter=month_filter,
        date_from=date_from,
        date_to=date_to,
        itemkind_summary=itemkind_summary,
        recent_reports=recent_reports
    )



@app.route('/admin/reports/export')
@admin_required
def export_csv():
    month_filter = request.args.get('month', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')

    # ── Build filtered borrow query ──-
    base_query = BorrowTracker.query.options(
        joinedload(BorrowTracker.student),
        joinedload(BorrowTracker.inventory)
    ).filter(BorrowTracker.status != 'pending')

    if month_filter:
        try:
            month_date = datetime.strptime(month_filter, '%Y-%m')
            first_day = month_date.replace(day=1)
            if month_date.month == 12:
                last_day = month_date.replace(day=31)
            else:
                last_day = month_date.replace(month=month_date.month + 1, day=1) - timedelta(days=1)
            base_query = base_query.filter(
                BorrowTracker.request_date >= first_day,
                BorrowTracker.request_date <= last_day + timedelta(days=1)
            )
        except ValueError:
            pass
    elif date_from or date_to:
        if date_from:
            base_query = base_query.filter(
                BorrowTracker.request_date >= datetime.strptime(date_from, '%Y-%m-%d')
            )
        if date_to:
            base_query = base_query.filter(
                BorrowTracker.request_date <= datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            )

    records = base_query.all()

    # ── Borrow Records CSV ──
    borrow_output = io.StringIO()
    borrow_writer = csv.writer(borrow_output)
    borrow_writer.writerow(['Borrow ID', 'Student Name', 'Student Number', 'Faculty In Charge', 'Contact Number', 'Item', 'Status', 'Request Date', 'Borrow Date', 'Return Date', 'Remarks'])

    for r in records:
        borrow_writer.writerow([
            r.borrow_id,
            r.student.student_nm if r.student else 'N/A',
            r.student.student_number if r.student else 'N/A',
            r.faculty_incharge or 'N/A',
            r.contact_number or 'N/A',
            r.inventory.inventory_nm if r.inventory else 'N/A',
            r.status,
            r.request_date.strftime('%Y-%m-%d') if r.request_date else '',
            r.borrow_date.strftime('%Y-%m-%d') if r.borrow_date else '',
            r.return_date.strftime('%Y-%m-%d') if r.return_date else '',
            r.remarks or ''
        ])

    # ── Inventory CSV ──
    inventory_output = io.StringIO()
    inventory_writer = csv.writer(inventory_output)
    inventory_writer.writerow(['Inventory ID', 'Name', 'Category', 'Equipment Group', 'Description', 'Office', 'Condition', 'Serial Number', 'Status'])

    for inv in Inventory.query.all():
        inventory_writer.writerow([
            inv.inventory_id,
            inv.inventory_nm,
            inv.category.category_nm if inv.category else 'N/A',
            inv.itemkind.itemkind_nm if inv.itemkind else 'N/A',
            inv.inventory_desc or '',
            inv.office.office_nm if inv.office else 'N/A',
            inv.inventory_condition,
            inv.serial_number,
            'Available' if inv.is_available else 'Borrowed'
        ])

    # ── Equipment Quantity CSV ──
    itemkind_output = io.StringIO()
    itemkind_writer = csv.writer(itemkind_output)
    itemkind_writer.writerow(['Equipment Group', 'Total Units', 'Available', 'Borrowed'])

    for kind in Itemkind.query.all():
        total = Inventory.query.filter_by(itemkind_id=kind.itemkind_id).count()
        available = Inventory.query.filter_by(itemkind_id=kind.itemkind_id, is_available=True).count()
        itemkind_writer.writerow([
            kind.itemkind_nm,
            total,
            available,
            total - available
        ])

    # ── Filename reflects filter ──
    if month_filter:
        filename = f'reports_{month_filter}.zip'
    elif date_from or date_to:
        filename = f'reports_{date_from}_to_{date_to}.zip'
    else:
        filename = 'reports.zip'

    # ── Zip all three ──
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr('borrow_records.csv', borrow_output.getvalue())
        zip_file.writestr('inventory.csv', inventory_output.getvalue())
        zip_file.writestr('equipment_quantity.csv', itemkind_output.getvalue())

    zip_buffer.seek(0)
    return Response(
        zip_buffer,
        mimetype='application/zip',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )

@app.route('/admin/office', methods=['GET', 'POST'])
@master_admin_required
def office():
    form = OfficeForm()
    faculty_list = Faculty.query.all()

    if form.validate_on_submit():
        new_office = Office(
            office_nm=form.name.data.strip(),
            office_loc=form.location.data.strip()
        )
        db.session.add(new_office)
        db.session.commit()
        cache.clear()
        flash('Office added.', 'success')
        return redirect(url_for('office'))

    q = request.args.get('q', '').strip()

    if q:
        offices = Office.query.filter(
            or_(
                Office.office_nm.ilike(f"%{q}%"),
                Office.office_loc.ilike(f"%{q}%")
            )
        ).all()
    else:
        offices = Office.query.all()

    return render_template('manage-office.html', add_form=form, q=q, faculty_list=faculty_list, offices=offices)

@app.route('/admin/office/edit/<int:office_id>', methods=['POST'])
@master_admin_required
def edit_office(office_id):
    form = OfficeForm()
    if form.validate_on_submit():
        off = Office.query.get_or_404(office_id)
        off.office_nm = form.name.data.strip()
        off.office_loc = form.location.data.strip()
        db.session.commit()
        cache.clear()
        flash('Office updated.', 'success')
    else:
        flash('Failed to update office.', 'danger')
    return redirect(url_for('office'))

@app.route('/admin/office/delete/<int:office_id>', methods=['POST'])
@master_admin_required
def delete_office(office_id):
    off = Office.query.get_or_404(office_id)
    assigned_count = Inventory.query.filter_by(office_id=off.office_id).count()
    faculty_in_office = Faculty.query.filter_by(office_id=off.office_id).count()

    if assigned_count > 0:
        flash('Cannot delete office with assigned inventory.', 'danger')
        return redirect(url_for('office'))
    
    if faculty_in_office > 0:
        flash('Cannot delete office with faculty', 'danger')
        return redirect(url_for('office'))

    db.session.delete(off)
    db.session.commit()
    cache.clear()
    flash('Office deleted.', 'success')
    return redirect(url_for('office'))

@app.route('/admin/office/assign/<int:office_id>', methods=['POST'])
@master_admin_required
def assign_office_head(office_id):
    faculty_id = request.form.get('faculty_id')

    if not faculty_id:
        flash("Please select a faculty member.", "error")
        return redirect(url_for('office'))

    existing_record = EquipmentApprover.query.filter_by(office_id=office_id).first()
    if existing_record:
        old_faculty_id = existing_record.faculty_id
        existing_record.faculty_id = faculty_id

        # Only demote old approver if they have NO other office assignments
        if old_faculty_id != int(faculty_id):
            other_assignments = EquipmentApprover.query.filter(
                EquipmentApprover.faculty_id == old_faculty_id,
                EquipmentApprover.office_id != office_id
            ).count()
            if other_assignments == 0:
                old_faculty = Faculty.query.get(old_faculty_id)
                if old_faculty and old_faculty.role != 'master_admin':
                    old_faculty.role = 'faculty'
    else:
        new_head = EquipmentApprover(office_id=office_id, faculty_id=faculty_id)
        db.session.add(new_head)

    # Promote new faculty to approver
    new_approver = Faculty.query.get(faculty_id)
    if new_approver:
        if new_approver.role == 'master_admin':
            flash('Master admin cannot be assigned as an office approver.', 'danger')
            return redirect(url_for('office'))
        new_approver.role = 'approver'

    try:
        db.session.commit()
        cache.clear()
        flash(f"{new_approver.faculty_nm} has been assigned as approver!", "success")
    except Exception as e:
        db.session.rollback()
        flash("Error assigning office head.", "error")

    return redirect(url_for('office'))

@app.route('/admin/faculty', methods=['GET', 'POST'])
@master_admin_required
def faculty():
    form = FacultyForm()

    if form.validate_on_submit():
        existing_user = Faculty.query.filter_by(username=form.username.data.strip()).first()
        if existing_user:
            flash('Username already exists', 'danger')
            return redirect(url_for('faculty'))

        office_name = form.office.data.strip()
        office = Office.query.filter_by(office_nm=office_name).first()
        if not office:
            office = Office(office_nm=office_name, office_loc='')
            db.session.add(office)
            db.session.commit()

        new_faculty = Faculty(
            faculty_nm=form.name.data.strip(),
            username=form.username.data.strip(),
            password=generate_password_hash(form.password.data.strip()),
            office_id=office.office_id
        )
        db.session.add(new_faculty)
        db.session.commit()
        cache.clear()
        flash('Faculty added.', 'success')
        return redirect(url_for('faculty'))

    q = request.args.get('q', '').strip()

    if q:
        faculties = Faculty.query.join(Office).filter(
            or_(
                Faculty.faculty_nm.ilike(f"%{q}%"),
                Faculty.username.ilike(f"%{q}%"),
                Office.office_nm.ilike(f"%{q}%")
            )
        ).all()
    else:
        faculties = Faculty.query.all()

    items = []
    for f in faculties:
        items.append({
            'id': f.faculty_id,
            'name': f.faculty_nm,
            'username': f.username,
            'office': f.office.office_nm if f.office else '',
            'role': f.role
        })

    return render_template('manage-faculty.html', items=items, add_form=form, q=q)

@app.route('/admin/faculty/edit/<int:faculty_id>', methods=['POST'])
@admin_required
def edit_faculty(faculty_id):
    form = FacultyForm()

    if form.validate_on_submit():
        fac = Faculty.query.get_or_404(faculty_id)
        fac.faculty_nm = form.name.data.strip()
        fac.username = form.username.data.strip()

        if form.password.data and form.password.data.strip():
            fac.password = generate_password_hash(form.password.data.strip())

        office_name = form.office.data.strip()
        office = Office.query.filter_by(office_nm=office_name).first()
        if not office:
            office = Office(office_nm=office_name, office_loc='')
            db.session.add(office)
            db.session.commit()

        fac.office_id = office.office_id
        db.session.commit()
        cache.clear()
        flash('Faculty updated.', 'success')
    else:
        flash('Failed to update faculty.', 'danger')

    return redirect(url_for('faculty'))

@app.route('/admin/faculty/delete/<int:faculty_id>', methods=['POST'])
@master_admin_required
def delete_faculty(faculty_id):
    fac = Faculty.query.get_or_404(faculty_id)

    # Prevent deleting master admin
    if fac.role == 'master_admin':
        flash('Master admin account cannot be deleted.', 'danger')
        return redirect(url_for('faculty'))

    # Remove from EquipmentApprover if assigned
    EquipmentApprover.query.filter_by(faculty_id=fac.faculty_id).delete()

    db.session.delete(fac)
    db.session.commit()
    cache.clear()
    flash(f'{fac.faculty_nm} has been deleted.', 'success')
    return redirect(url_for('faculty'))

@app.route('/admin/category', methods=['GET', 'POST'])
@admin_required
def category():
    form = CategoryForm()
    return render_template('manage-category.html')

#########################Student dashboard and borrowing routes#########################

def send_borrow_notification(borrowed_items, student, borrow_records):
    try:
        # Collect unique recipients from all item offices
        recipients = set()

        master_admins = Faculty.query.filter_by(role='master_admin').all()
        for admin in master_admins:
            if admin.email:
                recipients.add(admin.email)

        for inventory_item in borrowed_items:
            approver_config = inventory_item.office.approver_config if inventory_item.office else None
            if approver_config:
                approver = Faculty.query.get(approver_config.faculty_id)
                if approver and approver.email:
                    recipients.add(approver.email)

        if not recipients:
            return

        # Build item list for email body
        item_lines = []
        for record, item in zip(borrow_records, borrowed_items):
            item_lines.append(
                f"  - {item.inventory_nm} (Serial: {item.serial_number}, "
                f"Office: {item.office.office_nm if item.office else 'N/A'})"
            )

        first_record = borrow_records[0] if borrow_records else None

        msg = Message(
            subject=f'New Borrow Request — HIRaM System',
            recipients=list(recipients)
        )
        msg.body = f"""A new borrow request has been submitted.

Student: {student['name']}
ID Number: {student['number']}
Borrow Date: {first_record.borrow_date if first_record else 'N/A'}
Return Date: {first_record.return_date if first_record else 'N/A'}
Faculty In Charge: {first_record.faculty_incharge or 'N/A' if first_record else 'N/A'}
Remarks: {first_record.remarks or 'None' if first_record else 'None'}

Items Requested ({len(borrowed_items)}):
{chr(10).join(item_lines)}

Please log in to the admin panel to approve or reject these requests.
"""
        mail.send(msg)
    except Exception as e:
        print(f"Bulk notification email error: {e}")


@app.route('/student/login', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
def student_information():
    if 'student' in session:
        return redirect(url_for('student_dashboard'))

    login_form = StudentLoginForm()
    
    if request.method == 'POST':
        user_type = request.form.get('user_type', 'student')

        # ── Faculty login ──
        if user_type == 'faculty':
            id_number = request.form.get('id_number', '').strip()
            faculty_password = request.form.get('faculty_password', '').strip()

            if not id_number or not faculty_password:
                flash('Please enter your username and password.', 'danger')
                return render_template('student-information.html', login_form=login_form)

            faculty = Faculty.query.filter_by(username=id_number).first()
            if not faculty:
                flash('Faculty username not found.', 'danger')
                return render_template('student-information.html', login_form=login_form)

            if not check_password_hash(faculty.password, faculty_password):
                flash('Incorrect password.', 'danger')
                return render_template('student-information.html', login_form=login_form)

            student_number = f"FAC-{faculty.faculty_id}"
            student = Student.query.filter_by(student_number=student_number).first()
            if not student:
                # Create a corresponding student record for faculty users.
                # The Student model requires non-null `email` and `password` fields
                # in the current schema, so provide empty placeholders to satisfy
                # the NOT NULL constraint. Faculty authenticate via the
                # `Faculty` table, not this student record.
                student = Student(
                    student_nm=faculty.faculty_nm,
                    student_number=student_number,
                    student_course='Faculty',
                    student_year='N/A',
                    email=f"faculty_{faculty.faculty_id}@internal.local",
                    password='',
                    is_verified=True
                )
                db.session.add(student)
                db.session.commit()

            session['student'] = {
                'id': student.student_id,
                'name': faculty.faculty_nm,
                'number': student_number,
                'course': 'Faculty',
                'year': 'N/A',
                'is_faculty': True
            }
            flash('Welcome, ' + faculty.faculty_nm + '!', 'success')
            return redirect(url_for('student_dashboard'))

        # ── Student login ──
        # If the student POST does not validate, show errors to help debugging
        if user_type == 'student' and request.method == 'POST' and not login_form.validate_on_submit():
            print('Student login form errors:', login_form.errors)
            flash('Login failed: please check the form fields.', 'danger')
            for field, msgs in login_form.errors.items():
                for m in msgs:
                    flash(f"{field}: {m}", 'danger')

        if login_form.validate_on_submit():
            student_number = login_form.id_number.data.strip()
            password = login_form.password.data.strip()

            student = Student.query.filter_by(student_number=student_number).first()

            if not student:
                flash('No account found. Please sign up first.', 'danger')
                return render_template('student-information.html', login_form=login_form)

            if not student.is_verified:
                flash('Please verify your email first.', 'warning')
                return render_template('student-information.html', login_form=login_form)

            if not student.password or not check_password_hash(student.password, password):
                flash('Incorrect password.', 'danger')
                return render_template('student-information.html', login_form=login_form)

            # Update course and year on every login. Update name only if provided.
            name_field = getattr(login_form, 'name', None)
            if name_field and name_field.data and name_field.data.strip():
                student.student_nm = name_field.data.strip()
            student.student_course = login_form.course.data.strip()
            student.student_year = login_form.year.data.strip()
            db.session.commit()

            session['student'] = {
                'id': student.student_id,
                'name': student.student_nm,
                'number': student.student_number,
                'course': student.student_course,
                'year': student.student_year,
                'is_faculty': False
            }
            flash('Welcome back, ' + student.student_nm + '!', 'success')
            return redirect(url_for('student_dashboard'))

    return render_template('student-information.html', login_form=login_form)


@app.route('/student/register', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def student_register():
    if 'student' in session:
        return redirect(url_for('student_dashboard'))

    register_form = StudentRegisterForm()

    if register_form.validate_on_submit():
        student_number = register_form.id_number.data.strip()
        email = register_form.email.data.strip().lower()
        password = register_form.password.data.strip()
        name = register_form.name.data.strip()
        course = register_form.course.data.strip()
        year = register_form.year.data.strip()

        # Check if student number already registered
        existing_student = Student.query.filter_by(student_number=student_number).first()
        if existing_student:
            flash('This ID number is already registered. Please log in instead.', 'danger')
            return render_template('student-register.html', register_form=register_form)

        # If POST but validation failed, show errors to help debug client-side issues
        if request.method == 'POST' and not register_form.validate_on_submit():
            errors = register_form.errors
            # Log to console and show flash so developer/user sees why submission failed
            print('Student register form errors:', errors)
            flash('Registration failed: please check the form fields.', 'danger')
            for field, msgs in errors.items():
                for m in msgs:
                    flash(f"{field}: {m}", 'danger')

        # Check if email already taken
        existing_email = Student.query.filter_by(email=email).first()
        if existing_email:
            flash('This email is already registered.', 'danger')
            return render_template('student-register.html', register_form=register_form)

        # Create unverified student
        student = Student(
            student_nm=name,
            student_number=student_number,
            student_course=course,
            student_year=year,
            email=email,
            password=generate_password_hash(password),
            is_verified=False
        )
        db.session.add(student)
        db.session.commit()

        # Send OTP
        otp = generate_otp()
        sent = send_verification_email(email, otp, name)

        if not sent:
            # Clean up if email fails
            db.session.delete(student)
            db.session.commit()
            flash('Failed to send verification email. Please check your email address.', 'danger')
            return render_template('student-register.html', register_form=register_form)

        # Store OTP in session
        session['pending_verification'] = {
            'otp': otp,
            'user_id': student.student_id,
            'user_type': 'student',
            'email': email,
            'name': name,
            'created_at': datetime.now(timezone.utc).timestamp()
        }

        flash(f'A verification code has been sent to {email}.', 'info')
        return redirect(url_for('verify_otp'))

    return render_template('student-register.html', register_form=register_form)

@app.route('/student/myrequests', methods=['GET', 'POST'])
def student_requests():
    requests = []
    student = None
    searched = False

    if request.method == 'POST':
        student_number = request.form.get('student_number', '').strip()
        searched = True
        student = Student.query.filter_by(student_number=student_number).first()

        if student:
            requests = (
                BorrowTracker.query
                .options(joinedload(BorrowTracker.inventory))
                .filter_by(student_id=student.student_id)
                .order_by(BorrowTracker.request_date.desc())
                .all()
            )

    return render_template('student-requests.html', requests=requests, student=student, searched=searched)

@app.route('/student/dashboard', methods=['GET', 'POST'])
def student_dashboard():
    if 'student' not in session:
        flash('Please enter your information first.', 'warning')
        return redirect(url_for('student_information'))

    student = session['student']
    search = request.args.get('search', '').strip()
    category_filter = request.args.get('category', 'all')

    inventories = Inventory.query.join(Category)  # join once

    if category_filter != 'all':
        inventories = inventories.filter(Category.category_nm == category_filter)

    if search:
        search_pattern = f"%{search}%"
        inventories = inventories.filter(
            or_(
                Inventory.inventory_nm.ilike(search_pattern),
                Inventory.serial_number.ilike(search_pattern),
                Inventory.inventory_condition.ilike(search_pattern),
                Category.category_nm.ilike(search_pattern)
            )
        )

    inventories = inventories.all()
    items = []

    for inv in inventories:
        active_borrow = BorrowTracker.query.filter(
        BorrowTracker.inventory_id == inv.inventory_id,
        BorrowTracker.status.in_(['approved', 'borrowed', 'overdue'])
        ).order_by(BorrowTracker.request_date.desc()).first()

        items.append({
            'id': inv.inventory_id,
            'name': inv.inventory_nm,
            'category': inv.category.category_nm if inv.category else '',
            'desc': inv.inventory_desc or '',
            'serial': inv.serial_number,
            'condition': inv.inventory_condition,
            'office': inv.office.office_nm if inv.office else 'N/A',
            'available': inv.is_available,
            'return_date': active_borrow.return_date.strftime('%b %d, %Y') if active_borrow and active_borrow.return_date else None,
        })

    return render_template(
        'student-dashboard.html',
        items=items,
        current_category=category_filter,
        search_query=search,
        student=student
    )

@app.route('/student/borrow', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def student_borrow():
    if 'student' not in session:
        return redirect(url_for('student_information'))

    student = session['student']
    form = BorrowForm()
    form.student_id.data = student['number']

    inventory_id = request.args.get('inventory_id') or form.inventory_id.data
    inventory_item = Inventory.query.get(inventory_id) if inventory_id else None

    if inventory_item and inventory_item.inventory_condition != 'functional':
        flash(f'This item is currently {inventory_item.inventory_condition} and unavailable for borrowing.', 'danger')
        return redirect(url_for('student_dashboard'))

    if inventory_item:
        form.inventory_id.data = inventory_item.inventory_id

    if form.validate_on_submit():
        inventory_item = Inventory.query.get(form.inventory_id.data)

        if not inventory_item:
            flash('Inventory not found.', 'danger')
            return render_template('student-borrow.html', form=form, inventory=None, student=student)

       # if not inventory_item.is_available:
        #    flash('Item is currently unavailable.', 'danger')
         #   return redirect(url_for('student_dashboard'))

        approver_id = None
        if inventory_item.office.approver_config:
            approver_id = inventory_item.office.approver_config.faculty_id

        borrow_record = BorrowTracker(
            student_id=student['id'],
            inventory_id=inventory_item.inventory_id,
            status='pending',
            remarks=form.remarks.data.strip() if form.remarks.data else None,
            borrow_date=form.borrow_date.data,
            return_date=form.return_date.data,
            faculty_incharge=form.faculty_incharge.data.strip() if form.faculty_incharge.data else None,
            contact_number=form.contact_number.data.strip() if form.contact_number.data else None,
            approved_by=approver_id
        )

        db.session.add(borrow_record)
        db.session.commit()

        send_borrow_notification([inventory_item], student, [borrow_record])

        return redirect(url_for('student_dashboard'))

    return render_template('student-borrow.html', form=form, inventory=inventory_item, student=student)

@app.route('/student/borrow/bulk', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def student_borrow_bulk():
    if 'student' not in session:
        return redirect(url_for('student_information'))

    student = session['student']
    form = BorrowForm()

    if request.method == 'POST':
        inventory_ids = request.form.getlist('inventory_ids')
        faculty_incharge = request.form.get('faculty_incharge', '').strip()
        contact_number = request.form.get('contact_number', '').strip()
        borrow_date = request.form.get('borrow_date')
        return_date = request.form.get('return_date')
        remarks = request.form.get('remarks', '').strip()

        borrow_date_obj = datetime.strptime(borrow_date, '%Y-%m-%d').date() if borrow_date else None
        return_date_obj = datetime.strptime(return_date, '%Y-%m-%d').date() if return_date else None

        borrowed = []
        skipped = []
        borrowed_inventory_items = []  # track inventory objects
        borrow_records_list = []       # track borrow records

        for inv_id in inventory_ids:
            inventory_item = db.session.get(Inventory, inv_id)

            if not inventory_item:
                skipped.append(f"ID {inv_id}")
                continue

            if inventory_item.inventory_condition != 'functional':
                skipped.append(inventory_item.inventory_nm)
                continue

            existing = BorrowTracker.query.filter_by(
                student_id=student['id'],
                inventory_id=inventory_item.inventory_id,
                status='pending'
            ).first()

            if existing:
                skipped.append(f"{inventory_item.inventory_nm} (already requested)")
                continue

            approver_id = None
            if inventory_item.office and inventory_item.office.approver_config:
                approver_id = inventory_item.office.approver_config.faculty_id

            borrow_record = BorrowTracker(
                student_id=student['id'],
                inventory_id=inventory_item.inventory_id,
                status='pending',
                remarks=remarks or None,
                approved_by=approver_id,
                faculty_incharge=faculty_incharge or None,
                contact_number=contact_number or None,
                borrow_date=borrow_date_obj,
                return_date=return_date_obj
            )

            db.session.add(borrow_record)
            borrowed.append(inventory_item.inventory_nm)
            borrowed_inventory_items.append(inventory_item)  # collect item
            borrow_records_list.append(borrow_record)        # collect record

        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            flash("Database error occurred.", "danger")
            return redirect(url_for('student_dashboard'))

        # Send one email for all borrowed items after commit
        if borrowed_inventory_items:
            send_borrow_notification(borrowed_inventory_items, student, borrow_records_list)

        if borrowed:
            flash(f'Borrow requests submitted for: {", ".join(borrowed)}.', 'success')
        if skipped:
            flash(f'{len(skipped)} item(s) were skipped: {", ".join(skipped)}', 'warning')

        return redirect(url_for('student_dashboard'))

    # GET — accept all items
    inventory_ids = request.args.getlist('inventory_ids')
    inventories = Inventory.query.filter(
        Inventory.inventory_id.in_(inventory_ids)
    ).all()

    if not inventories:
        flash('No items found.', 'warning')
        return redirect(url_for('student_cart'))

    return render_template('student-borrow-bulk.html', 
                           inventories=inventories, 
                           student=student, form=form)

@app.route('/student/cart', methods=['GET', 'POST'])
def student_cart():
    if 'student' not in session:
        return redirect(url_for('student_information'))

    student = session['student']
    
    return render_template('student-cart.html', student=student)

@app.route('/student/item/<int:item_id>/bookings')
def item_bookings(item_id):
    bookings = BorrowTracker.query.filter(
        BorrowTracker.inventory_id == item_id,
        BorrowTracker.status.in_(['pending', 'approved', 'borrowed', 'overdue'])
    ).all()

    result = []
    for b in bookings:
        if b.borrow_date and b.return_date:
            # Generate a date entry for each day in the borrow range
            current = b.borrow_date
            while current <= b.return_date:
                result.append({
                    'date': current.strftime('%Y-%m-%d'),
                    'status': 'pending' if b.status == 'pending' else 'approved'
                })
                current += timedelta(days=1)
        elif b.borrow_date:
            result.append({
                'date': b.borrow_date.strftime('%Y-%m-%d'),
                'status': 'pending' if b.status == 'pending' else 'approved'
            })

    return {'bookings': result}, 200

@app.route('/student/logout')
def student_logout():
    session.pop('student', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('student_information'))

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=8000)