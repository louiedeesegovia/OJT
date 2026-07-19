from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Enum
from datetime import datetime, timezone

db = SQLAlchemy()

class Itemkind(db.Model):
    __tablename__ = 'itemkind'
    itemkind_id = db.Column(db.Integer, primary_key=True)
    itemkind_nm = db.Column(db.String(100), nullable=False)

    inventories = db.relationship('Inventory', back_populates='itemkind')


class Inventory(db.Model):
    __tablename__ = 'inventory'

    inventory_id = db.Column(db.Integer, primary_key=True)
    inventory_nm = db.Column(db.String(100), nullable=False)
    inventory_desc = db.Column(db.String(500))
    inventory_condition = db.Column(
        Enum('functional', 'non-functional','under-maintenance','under-repair', 'lost', name='condition_enum'),
        nullable=False
    )
    serial_number = db.Column(db.String(100), unique=True, nullable=False)
    is_available = db.Column(db.Boolean, default=True, nullable=False)

    itemkind_id = db.Column(db.Integer, db.ForeignKey('itemkind.itemkind_id'), nullable=True, index=True)
    office_id = db.Column(db.Integer, db.ForeignKey('office.office_id'), nullable=False, index=True)
    category_id = db.Column(db.Integer, db.ForeignKey('category.category_id'), nullable=False, index=True)

    itemkind = db.relationship('Itemkind', back_populates='inventories')
    office = db.relationship('Office', backref='inventories')
    category = db.relationship('Category', backref='inventories')


class BorrowTracker(db.Model):
    __tablename__ = 'borrow_tracker'

    borrow_id = db.Column(db.Integer, primary_key=True)
    request_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    approve_date = db.Column(db.DateTime, nullable=True)
    borrow_date = db.Column(db.Date, nullable=True)
    return_date = db.Column(db.Date, nullable=True)
    faculty_incharge = db.Column(db.String(100), nullable=True)
    contact_number = db.Column(db.String(11), nullable=True)
    remarks = db.Column(db.String(500), nullable=True)

    status = db.Column(
        Enum(
            'pending', 'approved', 'rejected',
            'borrowed', 'returned', 'overdue',
            name='borrow_status'
        ),
        default='pending',
        nullable=False
    )

    approved_by = db.Column(db.Integer, db.ForeignKey('faculty.faculty_id'), nullable=True, index=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.student_id'), nullable=False, index=True)
    inventory_id = db.Column(db.Integer, db.ForeignKey('inventory.inventory_id'), nullable=False, index=True)

    approver = db.relationship('Faculty', foreign_keys=[approved_by], backref='approved_borrows')
    student = db.relationship('Student', backref='borrow_records')
    inventory = db.relationship('Inventory', backref='borrow_records')


class Student(db.Model):
    __tablename__ = 'student'
    student_id = db.Column(db.Integer, primary_key=True)
    student_nm = db.Column(db.String(100), nullable=False)
    student_number = db.Column(db.String(20), unique=True, nullable=False)
    student_year = db.Column(db.String(20), nullable=False)
    student_course = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)


class Office(db.Model):
    __tablename__ = 'office'
    office_id = db.Column(db.Integer, primary_key=True)
    office_nm = db.Column(db.String(100), nullable=False)
    office_loc = db.Column(db.String(100), nullable=False)

    faculties = db.relationship('Faculty', back_populates='office')
    approver_config = db.relationship('EquipmentApprover', back_populates='office', uselist=False)


class EquipmentApprover(db.Model):
    __tablename__ = 'equipment_approver'
    approver_id = db.Column(db.Integer, primary_key=True)
    office_id = db.Column(db.Integer, db.ForeignKey('office.office_id'), unique=True, nullable=False, index=True)
    faculty_id = db.Column(db.Integer, db.ForeignKey('faculty.faculty_id'), nullable=False, index=True)

    office = db.relationship('Office', back_populates='approver_config')
    faculty = db.relationship('Faculty', back_populates='approver_role')


class Faculty(db.Model):
    __tablename__ = 'faculty'
    faculty_id = db.Column(db.Integer, primary_key=True)
    faculty_nm = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(
        Enum('master_admin', 'approver', 'faculty', name = 'faculty_role'),
        default = 'faculty', 
        nullable=False
        )
    office_id = db.Column(db.Integer, db.ForeignKey('office.office_id'), nullable=False, index=True)
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)

    office = db.relationship('Office', back_populates='faculties')
    approver_role = db.relationship('EquipmentApprover', back_populates='faculty', uselist=False)


class Category(db.Model):
    __tablename__ = 'category'
    category_id = db.Column(db.Integer, primary_key=True)
    category_nm = db.Column(db.String(100), nullable=False)


class Reports(db.Model):
    __tablename__ = 'reports'
    report_id = db.Column(db.Integer, primary_key=True)
    inventory_id = db.Column(db.Integer, db.ForeignKey('inventory.inventory_id'), nullable=False, index=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.student_id'), nullable=False, index=True)
    borrow_id = db.Column(db.Integer, db.ForeignKey('borrow_tracker.borrow_id'), nullable=True, index=True)  # ← add
    report_type = db.Column(
        Enum('damaged', 'lost', name='report_type_enum'),
        nullable=False
    )  # ← add
    report_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    description = db.Column(db.String(200), nullable=False)

    inventory = db.relationship('Inventory', backref='reports')
    student = db.relationship('Student', backref='reports')
    borrow = db.relationship('BorrowTracker', backref='report')  