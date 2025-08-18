Payload Alchemist

A web-based offensive security suite for reconnaissance and payload generation, developed for educational purposes.
Overview

Payload Alchemist is a full-stack web application designed as a comprehensive toolkit for cybersecurity students and ethical hacking professionals. It integrates a powerful Python backend for network and web reconnaissance with a sleek, modern frontend. The platform provides a suite of tools for domain analysis, vulnerability scanning, and the generation of common web attack payloads.

This project was developed for academic purposes and is intended strictly for educational and ethical use in controlled environments.
Core Features

    Modern Web Interface: A responsive and visually engaging user interface built with HTML and Tailwind CSS, featuring interactive 3D models rendered by Spline.

    Comprehensive Scanner:

        Subdomain Discovery: Enumerates and validates live subdomains associated with a target domain.

        Port Scanning: Leverages nmap to identify open ports and discover running services.

        Web Fingerprinting: Identifies underlying web technologies, frameworks, and Content Management Systems (CMS).

        Misconfiguration Analysis: Scans for common security header misconfigurations (e.g., CSP, HSTS, X-Frame-Options).

    Payload Generator: An integrated utility to quickly generate, customize, and copy payloads for various web vulnerabilities, including:

        Cross-Site Scripting (XSS)

        SQL Injection (SQLi)

        Command Injection

    User Management: Includes dedicated pages for managing user profiles, API keys, and application preferences.

    API-Driven Architecture: A robust Flask server powers the core scanning logic and serves the frontend application.

Technology Stack

Category
	

Technology

Backend
	

Python, Flask, Gunicorn

Frontend
	

HTML5, Tailwind CSS, JavaScript

Scanning
	

Nmap, Sublist3r (or similar), Custom Python Scripts

3D Assets
	

Spline

Deployment
	

Netlify (Frontend), Render (Backend)
Installation and Usage

Follow these instructions to set up a local instance of the application for development and testing.
Prerequisites

    Python 3.8+ and pip

    Nmap: Ensure Nmap is installed on your system and its binary is included in the system's PATH.

        Linux: sudo apt-get install nmap

        macOS: brew install nmap

        Windows: Download the installer from the Nmap official website.

Installation & Setup

    Clone the repository:

    git clone https://github.com/your-username/payload-alchemist.git
    cd payload-alchemist

    Install Python dependencies:

    pip install -r requirements.txt

    Launch the Flask server:

    python web-scanner.py

    The server will initialize and become accessible, typically at http://127.0.0.1:5000.

    Access the application:
    Open a web browser and navigate to http://127.0.0.1:5000/index.html.

Disclaimer

This tool is intended for educational purposes only. The author assumes no liability for any misuse or damage caused by this program. Only perform security testing on systems for which you have explicit, legal authorization. Unauthorized scanning of computer systems is illegal.
License

This project is distributed under the MIT License. See the LICENSE file for more information.
