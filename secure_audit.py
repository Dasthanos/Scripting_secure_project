"""Convenience launcher. Run: python3 secure_audit.py samples/vulnerable_app.py"""
from secureguard.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
