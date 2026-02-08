#!/usr/bin/env python
"""Development Server Startup Script for Security Intelligence"""
import os
import sys
import socket
import random
import webbrowser
import threading
import time

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)


def find_free_port(start=5000, end=5999):
    """Find a random free port in the given range."""
    ports = list(range(start, end))
    random.shuffle(ports)

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('127.0.0.1', port))
            sock.close()
            return port
        except OSError:
            continue

    raise RuntimeError(f"No free ports found in range {start}-{end}")


def open_browser(port, delay=2.0):
    """Open browser after a delay to allow server to start."""
    time.sleep(delay)
    url = f"http://localhost:{port}"
    print(f"\n🌐 Opening browser: {url}")
    webbrowser.open(url)


def load_demo_data():
    """Load demo data if database is empty."""
    from web.app import create_app
    from src.database.models import db, Organization
    from src.demo_data import load_demo_data_to_db
    import src.database.models as models

    app = create_app()
    with app.app_context():
        if Organization.query.count() == 0:
            print("🔒 Loading demo security data...")
            org_id = load_demo_data_to_db(db, models, "SecureTech Industries")
            print(f"✅ Demo data loaded for organization: {org_id}")
        else:
            print("🔒 Demo data already exists")

    return app


def main():
    """Start the development server."""
    print("=" * 60)
    print("  Security Intelligence - Development Server")
    print("=" * 60)

    # Find a free port
    port = find_free_port(5200, 5299)
    print(f"\n🔌 Using port: {port}")

    # Load demo data and create app
    app = load_demo_data()

    # Start browser opener in background
    browser_thread = threading.Thread(target=open_browser, args=(port,))
    browser_thread.daemon = True
    browser_thread.start()

    # Start the server
    print(f"\n🚀 Starting server at http://localhost:{port}")
    print("   Press Ctrl+C to stop\n")

    app.run(host='127.0.0.1', port=port, debug=True, use_reloader=False)


if __name__ == '__main__':
    main()
