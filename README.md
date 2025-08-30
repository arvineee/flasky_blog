# Flasky Blog

A feature-rich blogging platform built with Flask that includes user management, content moderation, and DDoS protection.

## Features
- **User Authentication**: Secure signup, login, and logout system
- **Content Management**: Create, read, update, and delete blog posts
- **Category System**: Organize posts with categories and subcategories
- **Admin Panel**: Comprehensive administration interface
- **Comment System**: Users can comment on posts with moderation
- **Like System**: Users can like/unlike posts
- **Newsletter System**: Email subscription and management
- **DDoS Protection**: Built-in protection against malicious traffic
- **Traffic Analytics**: Track visitor statistics and engagement
- **Video Uploads**: Support for multimedia content
- **Announcements**: Admin announcements for all users
- **Responsive Design**: Bootstrap-powered responsive interface

## Admin Features
- User management (ban/unban, warnings)
- Post moderation (block/unblock content)
- Traffic statistics and analytics
- Newsletter management
- DDoS protection management
- Announcement system
- Ads.txt management

## Demo
Visit the live site at [Flasky Blog](https://flasky-blog.vercel.app).

## Setup

1. **Clone the repository**:
    ```bash
    git clone https://github.com/arvineee/flasky_blog.git
    cd flasky_blog
    ```

2. **Create and activate a virtual environment**:
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3. **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

4. **Configure environment variables**:
    Create a `.env` file in the root directory with your configuration:
    ```env
    SECRET_KEY=your-secret-key-here
    DATABASE_URL=sqlite:///app.db
    MAIL_SERVER=smtp.gmail.com
    MAIL_PORT=587
    MAIL_USE_TLS=True
    MAIL_USERNAME=your-email@gmail.com
    MAIL_PASSWORD=your-app-password
    ```

5. **Initialize the database**:
    ```bash
    flask db init
    flask db migrate
    flask db upgrade
    flask init-db  # Creates default categories
    ```

6. **Create an admin user**:
    ```bash
    flask create-admin
    ```
    Follow the prompts to create your first administrator account.

7. **Run the application**:
    ```bash
    flask run
    ```

## Admin Commands

The application includes several useful CLI commands:

- `flask create-admin` - Create a new administrator account
- `flask init-db` - Initialize the database with default categories
- `flask list-users` - List all users in the database

## Usage

1. Access the application at `http://127.0.0.1:5000/`
2. Register as a regular user or log in with admin credentials
3. Admins can access the dashboard at `/admin/dashboard`
4. Create, edit, or delete blog posts and categories
5. Moderate user content and comments

## Security Features

- CSRF protection
- DDoS protection with configurable thresholds
- IP banning system
- Content sanitization with Bleach
- Secure file upload validation
- Password hashing with Werkzeug

## Contributing

Feel free to submit issues or pull requests. Contributions are welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


