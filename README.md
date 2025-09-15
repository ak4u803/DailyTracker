# Life Tracker

A comprehensive daily activity tracking application that helps users monitor their daily activities, understand their habits, and gain insights into their time management and well-being.

## Features

- **Activity Tracking**: Log your daily activities with details like duration, category, and mood.
- **Data Visualization**: Interactive charts and graphs to visualize your activity patterns.
- **Trend Analysis**: Identify positive and negative trends in your daily routines.
- **Mood Tracking**: Monitor how different activities affect your mood over time.
- **Responsive Design**: Works on desktop, tablet, and mobile devices.
- **User Authentication**: Secure signup and login system.

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Web browser with JavaScript enabled

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/life-tracker.git
   cd life-tracker
   ```

2. **Create a virtual environment (recommended)**:
   ```bash
   # On Windows
   python -m venv venv
   venv\Scripts\activate
   
   # On macOS/Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up the database**:
   ```bash
   python init_db.py
   ```

## Configuration

1. Create a `.env` file in the root directory with the following content:
   ```
   FLASK_APP=app.py
   FLASK_ENV=development
   SECRET_KEY=your-secret-key-here
   DATABASE_URL=sqlite:///lifetracker.db
   ```

   Replace `your-secret-key-here` with a secure secret key.

## Running the Application

1. **Start the development server**:
   ```bash
   flask run
   ```

2. **Access the application**:
   Open your web browser and go to `http://localhost:5000`

## Usage

1. **Create an Account**:
   - Click on "Register" and fill in your details to create a new account.
   - Log in with your credentials.

2. **Add Activities**:
   - Click on "Add Activity" to log your daily activities.
   - Fill in the activity details including name, category, duration, and mood.

3. **View Dashboard**:
   - The dashboard shows your recent activities and quick stats.
   - Monitor your daily and weekly activity summaries.

4. **Analyze Data**:
   - Navigate to the "Analytics" page to view detailed charts and insights.
   - Filter data by different time periods (7, 30, or 90 days).
   - Identify patterns and trends in your activities and mood.

## Project Structure

```
life-tracker/
├── app.py                # Main application file
├── requirements.txt      # Python dependencies
├── instance/             # Instance folder (created at runtime)
│   └── lifetracker.db   # SQLite database
├── static/               # Static files (CSS, JS, images)
└── templates/            # HTML templates
    ├── base.html         # Base template
    ├── index.html        # Landing page
    ├── login.html        # Login page
    ├── register.html     # Registration page
    ├── dashboard.html    # User dashboard
    ├── add_activity.html # Add activity form
    └── analytics.html    # Analytics and visualizations
```

## Technologies Used

- **Backend**: Python, Flask, SQLAlchemy
- **Frontend**: HTML5, CSS3, JavaScript, Bootstrap 5, Chart.js
- **Database**: SQLite
- **Authentication**: Flask-Login

## Security Considerations

- Passwords are hashed using PBKDF2 with SHA-256.
- CSRF protection is enabled for all forms.
- Sensitive configuration is stored in environment variables.
- Always use HTTPS in production.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Support

For support, please open an issue on the GitHub repository.

## Acknowledgments

- Bootstrap for the responsive design
- Chart.js for beautiful data visualizations
- Flask community for the excellent web framework
