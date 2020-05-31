#!/usr/bin/env python3
import flask

from flask import Flask
app = Flask(__name__)

@app.route('/api/health')
def health():
        return 'yes'

@app.route('/api/welcome')
def welcome():
   return 'localhost'

@app.route('/api/hostname')
def hostname():
    with open("config.hostname") as f:
        return f.read().strip()

@app.route('/api/ratelimit')
def rate():
    return '20'

@app.route('/api/min_port')
def min_port():
    with open("config.port") as f:
        return f.read().strip()

@app.route('/api/max_port')
def max_port():
    with open("config.port") as f:
        return f.read().strip()

@app.route('/api/max_port')
def login_queue():
    return '0'
