from base64 import urlsafe_b64encode
import hashlib
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app import mongo
from bson import ObjectId
from werkzeug.utils import secure_filename
import os
import datetime

bp = Blueprint('file_management', __name__)