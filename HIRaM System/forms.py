from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, SelectField, DateField, EmailField
from wtforms.validators import DataRequired, Length, Regexp, Optional, Email, EqualTo


class StudentRegisterForm(FlaskForm):
    """For new students signing up for the first time."""
    id_number = StringField(
        'ID Number',
        validators=[
            DataRequired(),
            Regexp(r'^\d{3}\s*-\s*\d{5}$', message='ID must be like 201 - 00123')
        ]
    )
    name = StringField('Full Name', validators=[Optional(), Length(min=1, max=100)])
    course = StringField('Course', validators=[DataRequired(), Length(min=1, max=50)])
    year = StringField('Year Level', validators=[DataRequired(), Length(min=1, max=20)])
    email = EmailField(
        'Email Address',
        validators=[DataRequired(), Email(message='Enter a valid email address.'), Length(max=120)]
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired(), Length(min=6, max=100, message='Password must be at least 6 characters.')]
    )
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[DataRequired(), EqualTo('password', message='Passwords must match.')]
    )
    submit = SubmitField('Sign Up')


class StudentLoginForm(FlaskForm):
    """For returning students — updates name, course, year on each login."""
    id_number = StringField(
        'ID Number',
        validators=[
            DataRequired(),
            Regexp(r'^\d{3}\s*-\s*\d{5}$', message='ID must be like 201 - 00123')
        ]
    )
    name = StringField('Full Name', validators=[Optional(), Length(min=1, max=100)])
    
    course = StringField('Course', validators=[DataRequired(), Length(min=1, max=50)])
    year = StringField('Year Level', validators=[DataRequired(), Length(min=1, max=20)])
    password = PasswordField(
        'Password',
        validators=[DataRequired(), Length(min=1, max=100)]
    )
    submit = SubmitField('Login')


class StudentFollowUpForm(FlaskForm):
    student_id = StringField(
        'Student ID',
        validators=[
            DataRequired(),
            Regexp(r'^\d{3}\s*-\s*\d{5}$', message='ID must be like 201 - 00123')
        ]
    )
    submit = SubmitField('Submit')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=1, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=1, max=100)])
    submit = SubmitField('Login')


class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=1, max=50)])
    office = StringField('Office', validators=[DataRequired(), Length(min=1, max=100)])
    email = EmailField(
        'Email Address',
        validators=[DataRequired(), Email(message='Enter a valid email address.'), Length(max=120)]
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired(), Length(min=6, max=100, message='Password must be at least 6 characters.')]
    )
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[DataRequired(), EqualTo('password', message='Passwords must match.')]
    )
    submit = SubmitField('Sign Up')


class BorrowForm(FlaskForm):
    student_id = StringField(
        'Student ID',
        validators=[
            DataRequired(),
            Regexp(r'^\d{3}\s*-\s*\d{5}$', message='ID must be like 201 - 00123')
        ]
    )
    inventory_id = IntegerField(
        'Inventory ID',
        validators=[DataRequired()]
    )
    borrow_date = DateField(
        'Borrow Date',
        validators=[DataRequired()],
        format='%Y-%m-%d'
    )
    return_date = DateField(
        'Expected Return Date',
        validators=[DataRequired()],
        format='%Y-%m-%d'
    )
    faculty_incharge = StringField(
        'Faculty In Charge',
        validators=[DataRequired(), Length(max=100)]
    )
    contact_number = StringField('Contact Number', validators=[
        DataRequired(),
        Length(min=11, max=11, message='Contact number must be exactly 11 digits'),
        Regexp(r'^\d{11}$', message='Contact number must contain only digits')
    ])
    remarks = StringField(
        'Remarks',
        validators=[Optional(), Length(max=200)]
    )
    submit = SubmitField('Request to Borrow')


class InventoryForm(FlaskForm):
    name = StringField('Item Name', validators=[DataRequired(), Length(min=1, max=100)])
    desc = StringField('Description', validators=[Optional(), Length(max=200)])
    condition = SelectField('Condition', choices=[
        ('functional', 'Functional'),
        ('non-functional', 'Non Functional'),
        ('under-maintenance', 'Under Maintenance'),
        ('under-repair', 'Under Repair')
    ], validators=[DataRequired()])
    serial = StringField('Serial Number', validators=[DataRequired(), Length(min=1, max=100)])
    category = StringField('Category', validators=[DataRequired(), Length(min=1, max=100)])
    office = StringField('Office', validators=[DataRequired(), Length(min=1, max=100)])
    itemkind = StringField('Equipment Group', validators=[Optional(), Length(min=1, max=100)])
    submit = SubmitField('Add Item')


class OfficeForm(FlaskForm):
    name = StringField('Office Name', validators=[DataRequired(), Length(min=1, max=100)])
    location = StringField('Location', validators=[DataRequired(), Length(min=1, max=100)])
    submit = SubmitField('Add Office')


class CategoryForm(FlaskForm):
    name = StringField('Category Name', validators=[DataRequired(), Length(min=1, max=100)])
    submit = SubmitField('Add Category')


class FacultyForm(FlaskForm):
    name = StringField('Faculty Name', validators=[DataRequired(), Length(min=1, max=100)])
    username = StringField('Username', validators=[DataRequired(), Length(min=1, max=50)])
    password = PasswordField('Password', validators=[Optional(), Length(min=6, max=100)])
    office = StringField('Office', validators=[DataRequired(), Length(min=1, max=100)])
    submit = SubmitField('Add Faculty')