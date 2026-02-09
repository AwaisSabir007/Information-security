
import pytest
from app import create_app
from database import db
from database.models import User
from config import TestConfig
import io

@pytest.fixture
def app():
    app = create_app(TestConfig)
    app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing
    
    with app.app_context():
        db.create_all()
        
        # Create a test user
        user = User(username='testuser', password_hash=b'fakehash', public_key='pub', private_key='priv')
        db.session.add(user)
        db.session.commit()
        
        yield app
        
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

def test_profile_update(client):
    # Simulate login (since we can't easily bypass @login_required with just session setting in this setup without helper)
    # Actually, we can just set the session in a transaction
    with client.session_transaction() as sess:
        sess['user_id'] = 1
        sess['username'] = 'testuser'

    # Get current profile page (ensure no error)
    response = client.get('/profile')
    assert response.status_code == 200
    assert b'testuser' in response.data

    # Post update
    data = {
        'username': 'newuser',
        'bio': 'This is a new bio',
        'picture': (io.BytesIO(b"fakeimagecontent"), 'test.jpg')
    }
    
    response = client.post('/profile', data=data, follow_redirects=True, content_type='multipart/form-data')
    assert response.status_code == 200
    assert b'Profile updated successfully' in response.data
    assert b'newuser' in response.data
    assert b'This is a new bio' in response.data

    # Verify DB update
    with client.application.app_context():
        user = User.query.get(1)
        assert user.username == 'newuser'
        assert user.bio == 'This is a new bio'
        assert user.profile_picture is not None
        assert 'user_1_test.jpg' in user.profile_picture

def test_unique_username_constraint(client):
    with client.application.app_context():
        # Add another user
        user2 = User(username='otheruser', password_hash=b'fake', public_key='p', private_key='p')
        db.session.add(user2)
        db.session.commit()

    with client.session_transaction() as sess:
        sess['user_id'] = 1
        sess['username'] = 'testuser'

    # Try to change username to existing one
    data = {
        'username': 'otheruser',
        'bio': 'bio'
    }
    
    response = client.post('/profile', data=data, follow_redirects=True)
    assert response.status_code == 200
    # Should stay on profile page with error (or redirect back to profile with flash, depending on impl)
    # The form validation failure re-renders the template, it doesn't redirect usually unless successful.
    # Logic in app.py: if form.validate_on_submit()... return redirect.
    # If invalid, it falls through to render_template.
    assert b'Username already exists' in response.data
