from flask import Flask, render_template, request, redirect, url_for, send_file, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import uuid
from datetime import datetime, timedelta
from flask_migrate import Migrate
from sqlalchemy import text
import hashlib
import shutil

# Create uploads directory if it doesn't exist
if not os.path.exists('uploads'):
    os.makedirs('uploads')

# Create recycle bin directory if it doesn't exist
RECYCLE_BIN = 'recycle_bin'
if not os.path.exists(RECYCLE_BIN):
    os.makedirs(RECYCLE_BIN)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///file_management.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    version = db.Column(db.Integer, default=1)
    share_link = db.Column(db.String(36), unique=True)
    share_expiry = db.Column(db.DateTime)
    share_permission = db.Column(db.String(10), default='view')
    is_deleted = db.Column(db.Boolean, default=False)  # New field


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
@login_required
def index():
    files = File.query.filter_by(user_id=current_user.id, is_deleted=False).order_by(
        File.filename, File.version.desc()).all()

    grouped_files = {}
    for file in files:
        if file.filename not in grouped_files:
            grouped_files[file.filename] = []
        grouped_files[file.filename].append(file)

    return render_template('index.html', grouped_files=grouped_files)


@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('index'))
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('index'))
    if file:
        try:
            filename = secure_filename(file.filename)
            existing_files = File.query.filter_by(
                user_id=current_user.id, filename=filename).all()
            version = len(existing_files) + 1

            # Ensure the uploads directory exists
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])

            file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{
                                     current_user.id}_{filename}_v{version}")
            file.save(file_path)
            new_file = File(filename=filename,
                            user_id=current_user.id, version=version)
            db.session.add(new_file)
            db.session.commit()
            flash(f'File uploaded successfully (Version {version})')
        except Exception as e:
            app.logger.error(f"File upload error: {str(e)}")
            flash(f'Error uploading file: {str(e)}')
    return redirect(url_for('index'))


@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)

    # Check if the user has permission to download the file
    if file.user_id != current_user.id and not current_user.is_admin:
        abort(403, description="You do not have permission to download this file")

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{
                             file.user_id}_{file.filename}_v{file.version}")

    # Check if the file exists
    if not os.path.exists(file_path):
        abort(404, description="File not found")

    try:
        return send_file(file_path, as_attachment=True)
    except Exception as e:
        app.logger.error(f"Error downloading file: {str(e)}")
        abort(500, description="An error occurred while downloading the file")


@app.route('/delete/<int:file_id>')
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to delete this file')
        return redirect(url_for('index'))

    # Move the file to the recycle bin
    source_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{
                               file.user_id}_{file.filename}_v{file.version}")
    dest_path = os.path.join(RECYCLE_BIN, f"{file.user_id}_{
                             file.filename}_v{file.version}")

    try:
        shutil.move(source_path, dest_path)
        file.is_deleted = True
        db.session.commit()
        flash('File moved to recycle bin')
    except Exception as e:
        app.logger.error(f"Error moving file to recycle bin: {str(e)}")
        flash('Error moving file to recycle bin')

    return redirect(url_for('index'))


@app.route('/share/<int:file_id>', methods=['GET', 'POST'])
@login_required
def share_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to share this file')
        return redirect(url_for('index'))

    if request.method == 'POST':
        expiry_days = int(request.form.get('expiry_days', 7))
        file.share_link = str(uuid.uuid4())
        file.share_expiry = datetime.utcnow() + timedelta(days=expiry_days)
        file.share_permission = request.form.get('permission', 'view')
        db.session.commit()
        flash(f'Share link created: {
              request.host_url}shared/{file.share_link}')
        return redirect(url_for('index'))

    return render_template('share.html', file=file)


@app.route('/revoke_share/<int:file_id>', methods=['POST'])
@login_required
def revoke_share(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to revoke sharing for this file')
        return redirect(url_for('index'))

    file.share_link = None
    file.share_expiry = None
    file.share_permission = None
    db.session.commit()
    flash('File sharing has been revoked')
    return redirect(url_for('index'))


@app.route('/shared/<share_link>', methods=['GET', 'POST'])
def access_shared_file(share_link):
    file = File.query.filter_by(share_link=share_link).first_or_404()
    if file.share_expiry and file.share_expiry < datetime.utcnow():
        flash('This share link has expired')
        return redirect(url_for('index'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{
                             file.user_id}_{file.filename}_v{file.version}")

    if request.method == 'POST' and file.share_permission == 'edit':
        uploaded_file = request.files.get('file')
        if uploaded_file:
            uploaded_file.save(file_path)
            flash('File updated successfully')
        else:
            flash('No file uploaded')

    if not os.path.exists(file_path):
        abort(404)

    return send_file(file_path, as_attachment=True)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/create_user')
def create_user():
    user = User(username='testuser', password=generate_password_hash(
        'testpassword'), is_admin=False)
    db.session.add(user)
    db.session.commit()
    return 'User created'


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists')
            return redirect(url_for('register'))

        new_user = User(username=username, password=generate_password_hash(
            password), is_admin=False)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')


def add_columns():
    with app.app_context():
        inspector = db.inspect(db.engine)
        columns = [c['name'] for c in inspector.get_columns('file')]
        with db.engine.connect() as conn:
            if 'share_permission' not in columns:
                conn.execute(
                    text('ALTER TABLE file ADD COLUMN share_permission VARCHAR(10) DEFAULT "view"'))
            if 'is_deleted' not in columns:
                conn.execute(
                    text('ALTER TABLE file ADD COLUMN is_deleted BOOLEAN DEFAULT 0'))
            conn.commit()


@app.route('/recycle_bin')
@login_required
def recycle_bin():
    deleted_files = File.query.filter_by(user_id=current_user.id, is_deleted=True).order_by(
        File.filename, File.version.desc()).all()
    return render_template('recycle_bin.html', files=deleted_files)


@app.route('/restore/<int:file_id>', methods=['POST'])
@login_required
def restore_file(file_id):
    file_to_restore = File.query.get_or_404(file_id)
    if file_to_restore.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to restore this file')
        return redirect(url_for('recycle_bin'))

    # Move the file back from the recycle bin
    source_path = os.path.join(RECYCLE_BIN, f"{file_to_restore.user_id}_{
                               file_to_restore.filename}_v{file_to_restore.version}")
    dest_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_to_restore.user_id}_{
                             file_to_restore.filename}_v{file_to_restore.version}")

    try:
        shutil.move(source_path, dest_path)
        file_to_restore.is_deleted = False
        db.session.commit()
        flash(f'File {file_to_restore.filename} (Version {
              file_to_restore.version}) restored successfully')
    except Exception as e:
        app.logger.error(f"Error restoring file: {str(e)}")
        flash('Error restoring file')

    return redirect(url_for('recycle_bin'))


@app.route('/permanent_delete/<int:file_id>', methods=['POST'])
@login_required
def permanent_delete(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to delete this file')
        return redirect(url_for('recycle_bin'))
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{
                             file.user_id}_{file.filename}_v{file.version}")
    if os.path.exists(file_path):
        os.remove(file_path)
    db.session.delete(file)
    db.session.commit()
    flash('File permanently deleted')
    return redirect(url_for('recycle_bin'))


@app.route('/empty_recycle_bin', methods=['POST'])
@login_required
def empty_recycle_bin():
    deleted_files = File.query.filter_by(
        user_id=current_user.id, is_deleted=True).all()

    for file in deleted_files:
        file_path = os.path.join(RECYCLE_BIN, f"{file.user_id}_{
                                 file.filename}_v{file.version}")
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
            db.session.delete(file)
        except Exception as e:
            app.logger.error(f"Error permanently deleting file {
                             file.filename}: {str(e)}")

    db.session.commit()
    flash('Recycle bin emptied')
    return redirect(url_for('recycle_bin'))


@app.errorhandler(403)
def forbidden_error(error):
    return render_template('error.html', error=error), 403


@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error=error), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error=error), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    add_columns()
    app.run(debug=True)
